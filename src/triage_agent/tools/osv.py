from typing import Any, Dict, List, Optional, Tuple
import httpx
from triage_agent.schemas import ComponentInfo

OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
OSV_VULN_ENDPOINT = "https://api.osv.dev/v1/vulns"


def query_osv_batch(
    components: List[ComponentInfo],
    raise_on_error: bool = False
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[str]]:
    """Query the OSV.dev batch API for known CVE/GHSA vulnerabilities across components.
    
    Args:
        components: List of ComponentInfo to query
        raise_on_error: If True, raise exception on network failure instead of returning errors
        
    Returns:
        Tuple of:
          - Dictionary mapping component_name -> list of vulnerability entries
          - List of error messages / failed component descriptions (empty if all succeeded)
    """
    if not components:
        return {}, []

    queries = []
    for c in components:
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

    results_by_component: Dict[str, List[Dict[str, Any]]] = {}
    errors: List[str] = []

    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.post(OSV_BATCH_ENDPOINT, json={"queries": queries})
            if resp.status_code == 200:
                data = resp.json()
                batch_results = data.get("results", [])
                for idx, res in enumerate(batch_results):
                    vulns = res.get("vulns", [])
                    comp_name = components[idx].name
                    if vulns:
                        parsed_vulns = []
                        for v in vulns:
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

                            parsed_vulns.append({
                                "id": v.get("id"),
                                "cve_id": cve_id,
                                "aliases": aliases,
                                "summary": v.get("summary", ""),
                                "details": (v.get("details", "") or "")[:400],
                                "score": score,
                                "fixed_versions": fixed_versions,
                                "references": [ref.get("url") for ref in v.get("references", []) if ref.get("url")],
                                "modified": v.get("modified"),
                            })
                        results_by_component[comp_name] = parsed_vulns
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

    return results_by_component, errors


def get_osv_vulnerability_detail(vuln_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full vulnerability details from OSV.dev API without authentication.
    
    Args:
        vuln_id: Vulnerability ID (e.g. 'GHSA-542g-h47m-68v8' or 'CVE-2024-43796')
        
    Returns:
        Full vulnerability detail dict or None if not found/error
    """
    if not vuln_id:
        return None
    url = f"{OSV_VULN_ENDPOINT}/{vuln_id}"
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None


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
    res_dict, errors = query_osv_batch([comp], raise_on_error=False)
    return res_dict.get(name, []), errors

