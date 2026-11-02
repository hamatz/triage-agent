"""Kernel advisory source adapters (ADR-021). See base.py for the contract."""

import importlib
from pathlib import Path
from typing import Dict, Optional

import tomllib  # Python 3.11+ (project requirement)

from triage_agent.chain.sources.base import KernelAdvisoryAdapter

DEFAULT_REGISTRY = Path(__file__).resolve().parent.parent / "kernel_sources.toml"


def load_registry(path: Optional[str] = None) -> Dict[str, dict]:
    with open(path or DEFAULT_REGISTRY, "rb") as f:
        return tomllib.load(f).get("adapters", {})


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
