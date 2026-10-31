"""Pydantic data models for Exploit Chain Triaging (v0.4.0 / ADR-019)."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExposureType(str, Enum):
    """Workload network & execution exposure categorization."""
    INTERNET_FACING = "internet_facing"  # Inbound traffic from external Internet/ELB
    UNTRUSTED_CODE = "untrusted_code"    # CI runner, customer code execution, shared shell
    INTERNAL_ONLY = "internal_only"      # Isolated internal workload with no external ingress
    UNKNOWN = "unknown"                  # Undefined exposure (defaults to internet_facing for safety)


class ChainLevel(str, Enum):
    """Exploit chain severity and operational urgency classification."""
    CRITICAL_CHAIN = "CRITICAL_CHAIN"              # Foothold (RCE) + LPE on co-located node (48h / immediate mitigation)
    HIGH_ISOLATED = "HIGH_ISOLATED"                # Isolated internal workload + LPE (2 weeks / lateral movement risk)
    HIGH_UNVERIFIED = "HIGH_UNVERIFIED"            # Unclassifiable foothold + LPE (2 weeks / human triage needed)
    MITIGATED_NEEDS_PATCH = "MITIGATED_NEEDS_PATCH" # Mitigated via modprobe/sysctl but kernel unpatched (30 days)
    SAFE = "SAFE"                                  # Kernel confirmed patched for target CVE


class WorkloadDefinition(BaseModel):
    """Application workload definition running within an environment."""
    name: str = Field(description="Workload identifier (e.g. 'web-frontend', 'ci-runner')")
    exposure: ExposureType = Field(
        default=ExposureType.UNKNOWN,
        description="Network/code exposure type. Unknown defaults to internet_facing."
    )
    node_pool: str = Field(description="Target node pool identifier where this workload can be scheduled")
    namespace: Optional[str] = Field(default="default", description="Kubernetes namespace or group")
    components: List[str] = Field(
        default_factory=list,
        description="List of component/package names running in this workload (e.g. ['php', 'nginx'])"
    )
    entry_cves: List[str] = Field(
        default_factory=list,
        description="Explicit entry CVE list (e.g. ['CVE-2026-109618'])"
    )
    sbom_path: Optional[str] = Field(default=None, description="Path to workload SBOM file if available")


class NodePoolDefinition(BaseModel):
    """Shared-kernel node pool / host group definition."""
    pool_id: str = Field(description="Node pool or host group ID (e.g. 'pool-dmz', 'host-bastion-01')")
    os_distribution: str = Field(description="OS distribution ID (e.g. 'ubuntu', 'debian', 'almalinux', 'rhel')")
    os_release: Optional[str] = Field(default=None, description="OS release version (e.g. '24.04', '22.04', '9')")
    kernel_package_name: str = Field(default="linux-image-generic", description="Kernel package name or flavor")
    kernel_flavor: Optional[str] = Field(default=None, description="Specific kernel source/flavor (e.g. 'linux-aws', 'linux-gcp', 'linux')")
    kernel_package_version: Optional[str] = Field(
        default=None,
        description="Exact installed kernel package version (e.g. '6.8.0-40.40')"
    )
    kernel_release: Optional[str] = Field(
        default=None,
        description="Uname release string (e.g. '6.8.0-40-generic')"
    )
    livepatch_active: bool = Field(default=False, description="True if Canonical Livepatch / kpatch is active")
    nodes_count: int = Field(default=1, description="Number of nodes in this pool sharing this configuration")


class EnvironmentDefinition(BaseModel):
    """Complete environment infrastructure topology mapping workloads to shared-kernel node pools."""
    environment_name: str = Field(description="Environment name (e.g. 'production', 'staging')")
    node_pools: List[NodePoolDefinition] = Field(default_factory=list)
    workloads: List[WorkloadDefinition] = Field(default_factory=list)


class DistroAffectedRange(BaseModel):
    """Distro-specific kernel package vulnerability affected range."""
    package: str = Field(description="Kernel package name in distro (e.g. 'linux', 'kernel')")
    fixed_version: str = Field(description="First patched package version in distro (e.g. '6.8.0-47.47')")


class KernelVulnerabilityEntry(BaseModel):
    """Linux kernel LPE vulnerability definition from ledger or live feeds."""
    cve_id: str = Field(description="CVE identifier (e.g. 'CVE-2026-46300')")
    name: str = Field(description="Vulnerability common name or summary")
    source_url: str = Field(description="Primary advisory source URL (mandatory for auditability)")
    retrieved_at: str = Field(description="Date retrieved (YYYY-MM-DD)")
    epss_score: Optional[float] = Field(default=None, description="FIRST EPSS probability score (0.0 - 1.0)")
    cisa_kev: bool = Field(default=False, description="Whether listed in CISA KEV catalog")
    poc_available: bool = Field(default=False, description="Whether attributed public PoC exists")
    poc_evidence: Optional[str] = Field(default=None, description="Evidence / attribution for PoC availability")
    distro_affected_ranges: Dict[str, DistroAffectedRange] = Field(
        default_factory=dict,
        description="Distro key (e.g. 'ubuntu') to affected package range"
    )


class FootholdResult(BaseModel):
    """Result of multi-signal Foothold / RCE analysis on an application vulnerability."""
    is_foothold: bool = Field(description="True if vulnerability represents an initial code execution foothold")
    basis: str = Field(description="Grounding reason (e.g. 'CISA KEV listed', 'CVSS AV:N and C:H/I:H', 'CWE-416')")
    is_unclassifiable: bool = Field(default=False, description="True if foothold risk cannot be ruled out")


class NodeTelemetry(BaseModel):
    """Observed live runtime telemetry from a host / node."""
    pool_id: str = Field(description="Associated node pool ID")
    os_distribution: Optional[str] = None
    os_release: Optional[str] = None
    kernel_package_name: Optional[str] = None
    kernel_flavor: Optional[str] = None
    kernel_package_version: Optional[str] = None
    kernel_release: Optional[str] = None
    loaded_modules: List[str] = Field(default_factory=list)
    builtin_modules: List[str] = Field(default_factory=list)
    modprobe_disabled_modules: List[str] = Field(default_factory=list)
    active_services: List[str] = Field(default_factory=list)
    xfrm_active: bool = Field(default=False, description="True if IPsec xfrm state/policy is configured (e.g. Cilium/Calico)")
    livepatch_modules: List[str] = Field(default_factory=list)


class ChainAuditItem(BaseModel):
    """Individual Exploit Chain evaluation outcome for a workload-kernel combination."""
    workload_name: str
    node_pool_id: str
    kernel_cve: str
    app_cve: Optional[str] = None
    chain_level: ChainLevel
    action_deadline: str
    foothold_detail: Optional[str] = None
    kernel_status: str
    mitigation_status: str
    blast_radius: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
