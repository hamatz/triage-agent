from typing import Any, Dict, List, Optional, Tuple
import httpx
from triage_agent.schemas import ComponentInfo

OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
OSV_VULN_ENDPOINT = "https://api.osv.dev/v1/vulns"

OSV_SUPPORTED_PURL_TYPES = {
    "pypi", "npm", "maven", "golang", "cargo", "nuget", "gem", "composer",
    "hex", "pub", "deb", "apk", "rpm", "alpm"
}

OSV_SUPPORTED_ECOSYSTEMS = {
    "pypi", "npm", "maven", "go", "crates.io", "nuget", "rubygems",
    "packagist", "hex", "pub", "debian", "ubuntu", "alpine", "rocky linux",
    "almalinux", "red hat enterprise linux", "oss-fuzz"
}


def is_osv_queryable(component: ComponentInfo) -> bool:
    """Determine whether a component can be queried against OSV.dev API safely.
    
    Generic runtime components (e.g. `pkg:generic/python@3.12`) or unknown
    ecosystems are excluded from OSV queries to prevent 400 Bad Request errors.
    """
    if component.purl:
        purl_lower = component.purl.lower()
        if purl_lower.startswith("pkg:generic/"):
            return False
        for ptype in OSV_SUPPORTED_PURL_TYPES:
            if purl_lower.startswith(f"pkg:{ptype}/"):
                return True
        return False

    eco = (component.ecosystem or "").strip().lower()
    return eco in OSV_SUPPORTED_ECOSYSTEMS


_osv_detail_cache: Dict[str, Optional[Dict[str, Any]]] = {}


def get_osv_vulnerability_detail(vuln_id: str, client: Optional[httpx.Client] = None) -> Optional[Dict[str, Any]]:
    """Retrieve full vulnerability details from OSV.dev API without authentication.
    
    Checks in-memory cache to prevent redundant HTTP GET requests.
    
    Args:
        vuln_id: Vulnerability ID (e.g. 'GHSA-542g-h47m-68v8' or 'CVE-2024-43796')
        client: Optional reusable httpx.Client
        
    Returns:
        Full vulnerability detail dict or None if not found/error
    """
    if not vuln_id:
        return None
    if vuln_id in _osv_detail_cache:
        return _osv_detail_cache[vuln_id]

    url = f"{OSV_VULN_ENDPOINT}/{vuln_id}"
    try:
        if client:
            resp = client.get(url)
            if resp.status_code == 200:
                res_json = resp.json()
                _osv_detail_cache[vuln_id] = res_json
                return res_json
        else:
            with httpx.Client(timeout=10.0, follow_redirects=True) as local_client:
                resp = local_client.get(url)
                if resp.status_code == 200:
                    res_json = resp.json()
                    _osv_detail_cache[vuln_id] = res_json
                    return res_json
    except Exception:
        pass

    # Do not cache failed lookups so transient network errors can be retried
    return None


def query_osv_batch(
    components: List[ComponentInfo],
    raise_on_error: bool = False,
    fetch_details: bool = True,
    max_vulns_per_component: int = 10,
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[str], List[str]]:
    """Query the OSV.dev batch API for known CVE/GHSA vulnerabilities across components.
    
    Note: OSV's querybatch endpoint only returns minimal stub IDs (google/osv.dev#466).
    When fetch_details=True, this function hydrates up to max_vulns_per_component stub IDs
    with full vulnerability details (aliases, CVSS score, fixed versions, and withdrawn status).
    Any vulnerabilities beyond max_vulns_per_component are preserved with stub info and
    explicitly recorded in errors as partially scanned / details omitted.
    
    Args:
        components: List of ComponentInfo to query
        raise_on_error: If True, raise exception on network failure instead of returning errors
        fetch_details: If True, fetch full vulnerability details for each vulnerability ID
        max_vulns_per_component: Max detail records to hydrate per component to stay snappy
        
    Returns:
        Tuple of:
          - Dictionary mapping component_name -> list of vulnerability entries (ONLY for components with >=1 hits)
          - List of error messages / failed component descriptions (empty if all succeeded)
          - List of components excluded from OSV queries (e.g. generic runtimes, C shared libraries)
    """
    if not components:
        return {}, [], []

    results_by_component: Dict[str, List[Dict[str, Any]]] = {}
    errors: List[str] = []
    unsupported_components: List[str] = []

    queryable_components: List[ComponentInfo] = []
    queries = []
    for c in components:
        if not is_osv_queryable(c):
            # Record unsupported/generic runtime components (e.g. python runtime, libc)
            unsupported_components.append(
                f"{c.name} ({c.version} / {c.ecosystem or 'Generic'} - OSV照合対象外・Web/LLM調査要)"
            )
            continue

        query_item: Dict[str, Any] = {}
        if c.purl:
            query_item["package"] = {"purl": c.purl}
        else:
            query_item["package"] = {
                "name": c.name,
                "ecosystem": c.ecosystem,
            }
            if c.version and c.version != "unknown":
                query_item["version"] = c.version
        queries.append(query_item)
        queryable_components.append(c)

    if not queries:
        return results_by_component, errors, unsupported_components

    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.post(OSV_BATCH_ENDPOINT, json={"queries": queries})
            if resp.status_code == 200:
                data = resp.json()
                batch_results = data.get("results", [])
                for idx, res in enumerate(batch_results):
                    vulns = res.get("vulns", [])
                    comp_name = queryable_components[idx].name
                    if vulns:
                        parsed_vulns = []
                        overflow_stubs = []

                        for v_idx, stub in enumerate(vulns):
                            vid = stub.get("id")
                            if not vid:
                                continue

                            # Check if within detail hydration limit
                            if fetch_details and v_idx < max_vulns_per_component:
                                detailed = get_osv_vulnerability_detail(vid, client=client)
                                v = detailed if detailed else stub
                            else:
                                v = stub
                                if v_idx >= max_vulns_per_component:
                                    overflow_stubs.append(vid)

                            # Skip retracted / withdrawn vulnerabilities (e.g. CVE-2022-23529)
                            if v.get("withdrawn"):
                                continue

                            # Extract aliases (e.g. CVE-2026-XXXX)
                            aliases = v.get("aliases", [])
                            cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                            
                            # Extract severity / score
                            score = None
                            for sev in v.get("severity", []):
                                if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
                                    score = sev.get("score")
                                    break
                            
                            # Extract affected version events (fixed versions)
                            fixed_versions = []
                            for aff in v.get("affected", []):
                                for r in aff.get("ranges", []):
                                    for ev in r.get("events", []):
                                        if "fixed" in ev:
                                            fixed_versions.append(ev["fixed"])

                            is_truncated = (v_idx >= max_vulns_per_component)
                            details_text = (v.get("details", "") or "")[:400]
                            if is_truncated and not details_text:
                                details_text = "[詳細未取得: 件数上限により基本情報のみ記録。個別に要確認]"

                            parsed_vulns.append({
                                "id": vid,
                                "cve_id": cve_id,
                                "aliases": aliases,
                                "summary": v.get("summary", ""),
                                "details": details_text,
                                "score": score,
                                "fixed_versions": fixed_versions,
                                "references": [ref.get("url") for ref in v.get("references", []) if ref.get("url")],
                                "published": v.get("published"),
                                "modified": v.get("modified"),
                                "is_detail_truncated": is_truncated,
                            })

                        if parsed_vulns:
                            results_by_component[comp_name] = parsed_vulns

                        # Record overflow warning explicitly so un-fetched details are never hidden
                        if overflow_stubs:
                            stub_preview = ", ".join(overflow_stubs[:5])
                            if len(overflow_stubs) > 5:
                                stub_preview += f" 等計 {len(overflow_stubs)} 件"
                            errors.append(
                                f"{comp_name}: OSV.dev で検出された全 {len(vulns)} 件中、"
                                f"上位 {max_vulns_per_component} 件の詳細を取得。残り {len(overflow_stubs)} 件は詳細未取得（要個別確認: {stub_preview}）"
                            )
            else:
                err_msg = f"OSV.dev API HTTP {resp.status_code}: {resp.text[:150]}"
                errors.append(err_msg)
                if raise_on_error:
                    raise RuntimeError(err_msg)
    except Exception as e:
        err_msg = f"OSV.dev API Connection Failed: {str(e)}"
        errors.append(err_msg)
        if raise_on_error:
            raise RuntimeError(err_msg) from e

    return results_by_component, errors, unsupported_components


def query_osv_single(
    name: str,
    version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    purl: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Query OSV.dev for a single component's known vulnerabilities without any authentication token.
    
    Args:
        name: Component name (e.g. 'fastapi')
        version: In-use version (e.g. '0.100.0')
        ecosystem: Package ecosystem (e.g. 'PyPI', 'npm', 'Go', 'Maven')
        purl: Package URL if available (e.g. 'pkg:pypi/fastapi@0.100.0')
        
    Returns:
        Tuple of (list of vulnerability entries, list of errors)
    """
    comp = ComponentInfo(
        name=name,
        version=version or "unknown",
        ecosystem=ecosystem or "unknown",
        purl=purl,
    )
    res_dict, errors, _ = query_osv_batch([comp], raise_on_error=False)
    return res_dict.get(name, []), errors

