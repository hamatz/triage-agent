import json
from pathlib import Path
from typing import List
from triage_agent.schemas import ComponentInfo


def _extract_ecosystem_from_purl(purl: str) -> str:
    """Extract standard ecosystem name from a purl string (e.g. pkg:npm/... -> npm)."""
    if not purl or not purl.startswith("pkg:"):
        return "Unknown"
    scheme_body = purl[4:]
    parts = scheme_body.split("/", 1)
    ptype = parts[0].lower()
    mapping = {
        "pypi": "PyPI",
        "npm": "npm",
        "maven": "Maven",
        "golang": "Go",
        "gem": "RubyGems",
        "cargo": "crates.io",
        "nuget": "NuGet",
    }
    return mapping.get(ptype, ptype.capitalize())


def load_sbom_summary(sbom_path: str) -> List[ComponentInfo]:
    """Parse a Syft CycloneDX JSON or Syft native JSON file and return a clean list of components.
    
    Args:
        sbom_path: Path to the SBOM file (JSON)
        
    Returns:
        List of ComponentInfo objects
    """
    path = Path(sbom_path)
    if not path.exists():
        raise FileNotFoundError(f"SBOM file not found: {sbom_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    components: List[ComponentInfo] = []

    # Case 1: CycloneDX JSON format (standard Syft output with -o cyclonedx-json)
    if "bomFormat" in data and data.get("bomFormat") == "CycloneDX" or "components" in data:
        for c in data.get("components", []):
            name = c.get("name")
            version = c.get("version", "unknown")
            purl = c.get("purl", "")
            group = c.get("group")
            desc = c.get("description")
            ecosystem = _extract_ecosystem_from_purl(purl)
            
            # If ecosystem couldn't be extracted from purl, infer from group/type
            if ecosystem == "Unknown" and group and "." in group:
                ecosystem = "Maven"

            if name:
                components.append(
                    ComponentInfo(
                        name=name,
                        version=version,
                        ecosystem=ecosystem,
                        purl=purl,
                        group=group,
                        description=desc,
                    )
                )

    # Case 2: Syft Native JSON format (syft -o json)
    elif "artifacts" in data:
        for a in data.get("artifacts", []):
            name = a.get("name")
            version = a.get("version", "unknown")
            purl = a.get("purl", "")
            pkg_type = a.get("type", "")
            ecosystem = _extract_ecosystem_from_purl(purl) if purl else pkg_type
            
            if name:
                components.append(
                    ComponentInfo(
                        name=name,
                        version=version,
                        ecosystem=ecosystem,
                        purl=purl,
                        description=None,
                    )
                )

    return components
