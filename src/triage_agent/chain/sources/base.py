"""Common contract for kernel advisory source adapters (ADR-021 decision 0 / 3).

The core never talks to a distribution's data feed directly. Each adapter turns a distribution's
advisories into the same normalized shape, so that classification, chain evaluation and reporting stay
distribution neutral.

Contract every adapter must honour:
- Return fixed versions only for the exact kernel *lineage* that was asked for (never a generic
  kernel's fix for a cloud/variant kernel).
- Never drop what could not be fetched or parsed: report it in ``SourceResult.errors``.
- Attach provenance: a source URL and the retrieval time.
- Map the distribution's own severity scale onto ``SEVERITY_LEVELS``.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

# Common severity scale. Adapters map their distribution's scale onto it.
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "unknown")
SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITY_LEVELS))}


def upstream_series(version: Optional[str]) -> Optional[str]:
    """'6.1.189-236.399.amzn2023' -> '6.1'; '1:6.12.94-123.174' -> '6.12'; None if unknown."""
    if not version:
        return None
    v = version.split(":", 1)[-1]
    m = re.match(r"^(\d+)\.(\d+)", v)
    return f"{m.group(1)}.{m.group(2)}" if m else None


def lineage_key(distro: str, release: str, package: str, series: str) -> str:
    """Identity of one kernel line: distribution, release, binary/source package and upstream series.

    The upstream series is part of the key because some distributions ship several kernel lines under
    the same package name (e.g. Amazon Linux 2 'kernel' 4.14 in core and 5.10 / 5.15 in extras).
    """
    return f"{distro.lower()}:{release}:{package}@{series}"


@dataclass(frozen=True)
class PoolKernelIdentity:
    """What the core knows about the kernel running in one node pool."""
    pool_id: str
    distro: str
    release: str
    package: str                 # binary package owning the kernel image, else the source/flavor name
    version: str                 # version-release without epoch, as reported by the package manager
    epoch: Optional[str] = None  # None when unknown
    engine_flavor: str = ""      # flavor string the chain engine uses for this pool (range key)
    livepatch_packages: Sequence[str] = ()
    grounded_in_telemetry: bool = True

    @property
    def series(self) -> Optional[str]:
        return upstream_series(self.version)

    @property
    def evr(self) -> str:
        return f"{self.epoch}:{self.version}" if self.epoch not in (None, "") else self.version


@dataclass
class KernelAdvisoryFix:
    """One CVE fixed (or not yet fixed) in one kernel lineage."""
    cve_id: str
    lineage: str
    fixed_evr: Optional[str]          # None: the distribution has not shipped a fix
    severity: str = "unknown"         # one of SEVERITY_LEVELS (distribution scale mapped)
    advisory_ids: List[str] = field(default_factory=list)
    source_url: str = ""
    retrieved_at: str = ""
    advisory_url: Optional[str] = None
    # Set by sources that answer "which vulnerabilities affect THIS version" (e.g. OSV version queries):
    affected_confirmed: bool = False            # the source says the queried version is affected
    applies_to_versions: Optional[Set[str]] = None   # installed versions the answer is valid for
    # Fixed version / severity not fetched yet; the core asks the adapter to ``enrich`` the CVEs that
    # matter (tier 1 and 2), so tens of thousands of large records are never downloaded.
    details_pending: bool = False


@dataclass
class LivepatchFix:
    """A CVE addressed by a livepatch package built for one exact kernel build."""
    cve_id: str
    target_kernel: str                # kernel version-release the livepatch applies to (e.g. '6.12.94-123.174')
    livepatch_package: str            # e.g. 'kernel-livepatch-6.12.94-123.174'
    fixed_evr: str                    # livepatch package version that addresses the CVE


@dataclass
class SourceResult:
    adapter: str
    fixes: List[KernelAdvisoryFix] = field(default_factory=list)
    livepatch_fixes: List[LivepatchFix] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    retrieved_at: str = ""
    lineages_covered: Set[str] = field(default_factory=set)


class KernelAdvisoryAdapter:
    """Base class for adapters. Subclasses implement ``lineage_for`` and ``fetch``."""

    name = "base"

    def __init__(self, config: dict, cache_dir: str = "triage-output/cache", timeout: int = 60):
        self.config = config or {}
        self.cache_dir = cache_dir
        self.timeout = timeout

    def lineage_for(self, identity: PoolKernelIdentity) -> Optional[str]:
        """Lineage key for a pool, or None if this adapter cannot identify it precisely."""
        raise NotImplementedError

    def fetch(
        self,
        lineages: Set[str],
        offline: bool = False,
        identities: Optional[Dict[str, List[PoolKernelIdentity]]] = None,
    ) -> SourceResult:
        """Return fixes for the requested lineages (and livepatch fixes when available).

        ``identities`` maps each lineage to the pools running it, for sources that are queried per
        installed version. Sources that publish complete advisory lists may ignore it.
        """
        raise NotImplementedError

    def enrich(self, fixes: List[KernelAdvisoryFix], offline: bool = False) -> List[str]:
        """Fill fixed_evr / severity of fixes marked ``details_pending``. Returns error messages."""
        return []

    @staticmethod
    def livepatch_matches(target_kernel: str, running_version: str) -> bool:
        """'6.12.94-123.174' applies to running '6.12.94-123.174.amzn2023' (dist tag suffix ignored)."""
        return running_version == target_kernel or running_version.startswith(target_kernel + ".")
