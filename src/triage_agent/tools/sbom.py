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
    """Parse CycloneDX JSON, SPDX JSON (ISO/IEC 5962), or Syft native JSON files.
    
    Supports:
      1. CycloneDX JSON (e.g. `syft scan ... -o cyclonedx-json`, Trivy, etc.)
      2. SPDX JSON 2.2 / 2.3 / 3.0 (e.g. `syft scan ... -o spdx-json`, Trivy, cnspec)
      3. Syft Native JSON (e.g. `syft scan ... -o json`)
    
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

    # Case 1: CycloneDX JSON format
    if "bomFormat" in data and data.get("bomFormat") == "CycloneDX" or ("components" in data and not "spdxVersion" in data):
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

    # Case 2: SPDX JSON format (SPDX 2.2, 2.3, 3.0 ISO/IEC 5962 standard)
    elif "spdxVersion" in data or "packages" in data:
        for p in data.get("packages", []):
            name = p.get("name")
            version = p.get("versionInfo") or p.get("version", "unknown")
            desc = p.get("description") or p.get("summary")
            purl = ""
            for ref in p.get("externalRefs", []):
                ref_type = str(ref.get("referenceType", "")).lower()
                locator = str(ref.get("referenceLocator", ""))
                if ref_type in ("purl", "package-url") or locator.startswith("pkg:"):
                    purl = locator
                    break
            
            ecosystem = _extract_ecosystem_from_purl(purl)
            if ecosystem == "Unknown":
                pkg_file = (p.get("packageFileName") or "").lower()
                if pkg_file.endswith(".whl") or pkg_file.endswith(".tar.gz") or "pypi" in pkg_file:
                    ecosystem = "PyPI"
                elif pkg_file.endswith(".tgz") or "npm" in pkg_file:
                    ecosystem = "npm"
                elif pkg_file.endswith(".jar") or pkg_file.endswith(".pom"):
                    ecosystem = "Maven"

            if name:
                components.append(
                    ComponentInfo(
                        name=name,
                        version=version,
                        ecosystem=ecosystem,
                        purl=purl if purl else None,
                        description=desc,
                    )
                )

    # Case 3: Syft Native JSON format (syft -o json)
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
    else:
        raise ValueError(
            f"サポートされていないSBOM形式です: '{sbom_path}'\n"
            "CycloneDX JSON (components), SPDX JSON (spdxVersion/packages), "
            "または Syft native JSON (artifacts) を指定してください。"
        )

    return components
