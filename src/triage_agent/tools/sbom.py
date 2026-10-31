import fnmatch
import json
from pathlib import Path
from typing import List, Optional
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


def _is_excluded(
    name: str,
    purl: Optional[str],
    patterns: Optional[List[str]],
    group: Optional[str] = None,
) -> bool:
    """Check if component name, group/name, or purl matches any of the glob exclusion patterns."""
    if not patterns:
        return False
    import urllib.parse

    candidates = set()
    if name:
        candidates.add(name.strip().lower())
    if group and name:
        candidates.add(f"{group.strip().lower()}/{name.strip().lower()}")
    if purl:
        purl_raw = purl.strip().lower()
        candidates.add(purl_raw)
        # URL-decoded purl (e.g. %40company -> @company)
        purl_decoded = urllib.parse.unquote(purl_raw)
        candidates.add(purl_decoded)
        # Also extract package path after type if purl (e.g. pkg:npm/@company/payment-core@1.0.0 -> @company/payment-core)
        if purl_decoded.startswith("pkg:"):
            try:
                without_pkg = purl_decoded.split(":", 1)[1]  # "npm/@company/payment-core@1.0.0"
                if "/" in without_pkg:
                    after_type = without_pkg.split("/", 1)[1]  # "@company/payment-core@1.0.0"
                    clean_path = after_type.split("?")[0].split("#")[0]
                    # If there's an '@' for version after index 0 (e.g. @scope/pkg@1.0.0 or pkg@1.0.0)
                    if "@" in clean_path[1:]:
                        r_idx = clean_path.rfind("@")
                        pkg_only = clean_path[:r_idx]
                    else:
                        pkg_only = clean_path
                    candidates.add(pkg_only)
                    candidates.add(clean_path)
            except Exception:
                pass

    for pat in patterns:
        pat_l = pat.strip().lower()
        if not pat_l:
            continue
        for cand in candidates:
            if fnmatch.fnmatch(cand, pat_l):
                return True
    return False


def load_sbom_summary(
    sbom_path: str,
    exclude_patterns: Optional[List[str]] = None,
    excluded_names: Optional[List[str]] = None,
) -> List[ComponentInfo]:
    """Parse CycloneDX JSON, SPDX JSON (ISO/IEC 5962), or Syft native JSON files.
    
    Supports:
      1. CycloneDX JSON (e.g. `syft scan ... -o cyclonedx-json`, Trivy, etc.)
      2. SPDX JSON 2.2 / 2.3 / 3.0 (e.g. `syft scan ... -o spdx-json`, Trivy, cnspec)
      3. Syft Native JSON (e.g. `syft scan ... -o json`)
    
    Args:
        sbom_path: Path to the SBOM file (JSON)
        exclude_patterns: Optional glob patterns (e.g. ['@company/*', 'internal-*']) to omit internal packages.
        excluded_names: Optional output list to record names of components excluded by exclude_patterns.
        
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

            display_name = f"{group}/{name}" if group else (name or "unknown")
            if name and _is_excluded(name, purl, exclude_patterns, group=group):
                if excluded_names is not None:
                    excluded_names.append(display_name)
                continue

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

            if name and _is_excluded(name, purl, exclude_patterns):
                if excluded_names is not None:
                    excluded_names.append(name)
                continue

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
            
            if name and _is_excluded(name, purl, exclude_patterns):
                if excluded_names is not None:
                    excluded_names.append(name)
                continue

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


def generate_self_sbom(
    output_path: str | Path | None = None,
    include_transitive: bool = True,
) -> dict:
    """Generate a CycloneDX 1.4 JSON SBOM for triage-agent itself dynamically.
    
    Uses standard library `importlib.metadata` and `tomllib` to inspect the
    currently installed dependencies and versions without external tools.
    
    Args:
        output_path: Optional path to save the generated CycloneDX JSON file.
        include_transitive: Whether to include transitive dependencies.
        
    Returns:
        CycloneDX JSON format dictionary.
    """
    import importlib.metadata
    import tomllib
    import re

    # Locate pyproject.toml
    from triage_agent import __version__

    project_root = Path.cwd()
    pyproject_candidate = project_root / "pyproject.toml"
    if not pyproject_candidate.exists():
        pyproject_candidate = Path(__file__).resolve().parents[2] / "pyproject.toml"

    direct_pkgs: List[str] = []
    agent_version = __version__
    if pyproject_candidate.exists():
        try:
            with open(pyproject_candidate, "rb") as f:
                pdata = tomllib.load(f)
            if "version" in pdata.get("project", {}):
                agent_version = pdata["project"]["version"]
            deps = pdata.get("project", {}).get("dependencies", [])
            for dep in deps:
                clean = re.split(r"[><=~;\[(]", dep)[0].strip()
                if clean:
                    direct_pkgs.append(clean)
            agent_version = pdata.get("project", {}).get("version", agent_version)
        except Exception:
            pass

    if not direct_pkgs:
        direct_pkgs = ["google-genai", "pydantic", "httpx", "python-dotenv", "rich"]

    components = []
    visited = set()

    def _resolve(pkg_name: str, depth: int = 0):
        cname = pkg_name.strip()
        canon = cname.lower().replace("_", "-")
        if canon in visited:
            return
        visited.add(canon)

        try:
            dist = importlib.metadata.distribution(cname)
            ver = dist.version
            real_name = dist.metadata.get("Name", cname)
            purl = f"pkg:pypi/{real_name.lower()}@{ver}"
            comp_entry = {
                "type": "library",
                "name": real_name,
                "version": ver,
                "purl": purl,
                "description": dist.metadata.get("Summary", ""),
            }
            components.append(comp_entry)

            if include_transitive:
                reqs = dist.requires or []
                for r in reqs:
                    if "extra ==" in r:
                        continue
                    clean_req = re.split(r"[><=~;\[(]", r)[0].strip()
                    if clean_req:
                        _resolve(clean_req, depth + 1)
        except Exception:
            # Fallback if package is not locally installed
            components.append({
                "type": "library",
                "name": cname,
                "version": "unknown",
                "purl": f"pkg:pypi/{cname.lower()}",
                "description": "Declared dependency",
            })

    for p in direct_pkgs:
        _resolve(p, depth=0)

    # Include Python runtime itself to prevent runtime omissions (as learned from Brotli/Node issues)
    import sys
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    components.append({
        "type": "framework",
        "name": "python",
        "version": py_ver,
        "purl": f"pkg:generic/python@{py_ver}",
        "description": f"Python runtime environment ({sys.implementation.name} {py_ver})",
    })

    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "triage-agent",
                "version": agent_version,
                "description": "Autonomous SBOM Vulnerability Intelligence and Triage Multi-Agent System",
            }
        },
        "components": components,
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2, ensure_ascii=False)

    return sbom_data

