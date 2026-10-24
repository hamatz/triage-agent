from typing import Any, Dict, List, Tuple
import httpx
from triage_agent.schemas import ComponentInfo

OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"


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
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(OSV_BATCH_ENDPOINT, json={"queries": queries})
            if resp.status_code == 200:
                data = resp.json()
                batch_results = data.get("results", [])
                for idx, res in enumerate(batch_results):
                    vulns = res.get("vulns", [])
                    comp_name = components[idx].name
                    if vulns:
                        results_by_component[comp_name] = [
                            {
                                "id": v.get("id"),
                                "summary": v.get("summary", ""),
                                "details": (v.get("details", "") or "")[:200],
                                "modified": v.get("modified"),
                            }
                            for v in vulns
                        ]
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
