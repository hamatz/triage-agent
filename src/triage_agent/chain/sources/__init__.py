"""Kernel advisory source adapters (ADR-021). See base.py for the contract."""

import importlib
from pathlib import Path
from typing import Dict, Optional

import tomllib  # Python 3.11+ (project requirement)

from triage_agent.chain.sources.base import KernelAdvisoryAdapter

DEFAULT_REGISTRY = Path(__file__).resolve().parent.parent / "kernel_sources.toml"


def _load_toml(path: Optional[str]) -> dict:
    with open(path or DEFAULT_REGISTRY, "rb") as f:
        return tomllib.load(f)


def load_registry(path: Optional[str] = None) -> Dict[str, dict]:
    return _load_toml(path).get("adapters", {})


def load_signal_registry(path: Optional[str] = None) -> Dict[str, dict]:
    """Threat signal sources (``[signals.*]``), e.g. where CVSS for kernel CVEs comes from."""
    return _load_toml(path).get("signals", {})


def build_cvss_source(signals: Dict[str, dict], cache_dir: str = "triage-output/cache"):
    """The registered CVSS source (an object with ``lookup(cve_ids, offline)``), or None."""
    conf = signals.get("cvss")
    if not conf or not conf.get("class"):
        return None
    module_name, _, class_name = conf["class"].partition(":")
    cls = getattr(importlib.import_module(module_name), class_name)
    return cls(conf, cache_dir=cache_dir)


def build_adapters(registry: Dict[str, dict], cache_dir: str = "triage-output/cache") -> Dict[str, KernelAdvisoryAdapter]:
    """Instantiate adapters keyed by the os-release distro IDs they cover."""
    by_distro: Dict[str, KernelAdvisoryAdapter] = {}
    for name, conf in registry.items():
        module_name, _, class_name = conf["class"].partition(":")
        cls = getattr(importlib.import_module(module_name), class_name)
        adapter = cls(conf, cache_dir=cache_dir)
        for distro in conf.get("distros", []):
            by_distro[distro.lower()] = adapter
    return by_distro
