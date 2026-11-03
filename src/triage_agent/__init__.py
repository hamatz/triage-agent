"""triage-agent: Autonomous SBOM Vulnerability Intelligence and Triage Multi-Agent System."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import tomllib

__version__ = "0.5.0"  # fallback; kept in sync with pyproject.toml

# 1. Primary: Dynamic sync with repository pyproject.toml when running from source
_pyproject_file = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
if _pyproject_file.exists():
    try:
        with open(_pyproject_file, "rb") as _f:
            _data = tomllib.load(_f)
            __version__ = _data.get("project", {}).get("version", __version__)
    except Exception:
        pass
else:
    # 2. Secondary: Installed package metadata (wheels / site-packages)
    try:
        __version__ = version("triage-agent")
    except PackageNotFoundError:
        pass


def user_agent(component: str = "") -> str:
    """User-Agent for requests to public data sources (identifies the tool and version only)."""
    return f"triage-agent/{__version__}" + (f" ({component})" if component else "")
