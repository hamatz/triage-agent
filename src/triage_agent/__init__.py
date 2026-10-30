"""triage-agent: Autonomous SBOM Vulnerability Intelligence and Triage Multi-Agent System."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import tomllib

__version__ = "0.3.0"

# 1. Primary: Installed package metadata
try:
    __version__ = version("triage-agent")
except PackageNotFoundError:
    # 2. Secondary: Dynamic sync with pyproject.toml in repository tree
    _pyproject_file = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
    if _pyproject_file.exists():
        try:
            with open(_pyproject_file, "rb") as _f:
                _data = tomllib.load(_f)
                __version__ = _data.get("project", {}).get("version", __version__)
        except Exception:
            pass



