import hashlib
import re
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


def normalize_component_name(raw_name: str) -> str:
    """Normalize product or package name by stripping parentheticals, versions, and decoration text.
    
    Ensures that 'Brotli (HTTP2Shell)' and 'brotli' resolve to the exact same canonical identifier.
    """
    cleaned = re.sub(r"[\(（].*?[\)）]", "", raw_name)
    cleaned = re.sub(r"[:：].*$", "", cleaned)
    tokens = re.findall(r"[a-zA-Z0-9_\-]+", cleaned)
    if tokens:
        return tokens[0].lower()
    return re.sub(r"[^a-zA-Z0-9_\-]", "", raw_name.strip().lower())


def compute_check_point_id(target_name: str, cve_id: str, question: str) -> str:
    """Deterministically compute a check_point_id from target, CVE, and normalized question text.
    
    Prevents sequence-dependent index bugs (e.g. cp1 pointing to different items across editions).
    Canonicalizes target_name so LLM decoration text does not break attestation matching.
    """
    target_clean = normalize_component_name(target_name)
    cve_clean = re.sub(r"[^a-zA-Z0-9_\-]", "-", cve_id.strip().lower())
    norm_q = re.sub(r"\s+", " ", question.strip().lower())
    q_hash = hashlib.sha256(norm_q.encode("utf-8")).hexdigest()[:8]
    return f"{target_clean}-{cve_clean}-{q_hash}"


def compute_notice_hash(check_points: List["CheckPointItem"]) -> str:
    """Compute a deterministic hash fingerprint representing the exact set of check points in a notice.
    
    If check points are added, deleted, or modified in edition 2, the hash changes automatically,
    safely invalidating outdated attestations without manual version bumping.
    """
    tokens = []
    for cp in sorted(check_points, key=lambda x: x.check_point_id or ""):
        tokens.append(f"{cp.check_point_id}:{cp.target_or_cve}:{cp.check_point_yes_no}:{cp.affected_versions}")
    return hashlib.sha256("|".join(tokens).encode("utf-8")).hexdigest()[:12]


class ComponentInfo(BaseModel):
    name: str = Field(description="Name of the package/component")
    version: str = Field(description="Current version installed in the SBOM")
    ecosystem: str = Field(description="Ecosystem: PyPI, npm, Maven, Go, etc.")
    purl: Optional[str] = Field(default=None, description="Package URL if available")
    group: Optional[str] = Field(default=None, description="Group/organization (e.g. for Maven)")
    description: Optional[str] = Field(default=None, description="Short description")


class ReconTarget(BaseModel):
    name: str = Field(description="Package name to investigate")
    version: str = Field(description="Current in-use version")
    ecosystem: str = Field(description="Ecosystem (PyPI, npm, Maven, etc.)")
    purl: Optional[str] = Field(default=None, description="Package URL (purl) if available")
    github_repo: Optional[str] = Field(default=None, description="GitHub repository owner/repo if known or inferred")
    priority: str = Field(description="Priority: CRITICAL, HIGH, MEDIUM, LOW")
    rationale: str = Field(description="Why this component was selected for deep dynamic reconnaissance")
    search_queries: List[str] = Field(default_factory=list, description="Targeted search queries for web/news/blogs")
    github_search_keywords: List[str] = Field(
        default_factory=lambda: ["security", "RCE", "vulnerability"],
        description="Keywords to search in GitHub commits/releases"
    )


class ReconPlan(BaseModel):
    summary: str = Field(description="High-level overview of the SBOM analysis and reconnaissance strategy")
    total_components_scanned: int = Field(description="Total components found in the SBOM")
    known_osv_hits_count: int = Field(default=0, description="Number of components with known OSV CVE hits")
    targets: List[ReconTarget] = Field(
        description="Ranked list of components requiring dynamic reconnaissance (top high-risk components)"
    )


class ResearchFinding(BaseModel):
    id: str = Field(description="CVE ID, GHSA ID, or temporary Signal ID (e.g., PRE-RELEASE-NOTICE-01)")
    title: str = Field(description="Title or headline of the security issue or upcoming advisory")
    severity: str = Field(description="Severity: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    cvss: Optional[str] = Field(default=None, description="CVSS base score and rating (e.g. '7.5 (High)', '9.2 (Critical)', '未公表')")
    is_pre_announcement: bool = Field(
        default=False,
        description="True if this is an upcoming release notice / pre-patch notification / unpatched signal"
    )
    affected_versions: str = Field(description="Affected version range or description")
    applies_to_current_version: bool = Field(
        description="Whether the version used in our SBOM falls within the affected range"
    )
    summary: str = Field(description="Detailed summary of the vulnerability, threat model, or upcoming patch notice")
    source_urls: List[str] = Field(default_factory=list, description="Evidence URLs (GitHub, official blog, advisory)")
    commit_shas: List[str] = Field(default_factory=list, description="Relevant patch or POC commit SHAs if found")
    trigger_hint: Optional[str] = Field(
        default=None,
        description="Initial clue about configuration, feature flag, or specific API usage required to exploit"
    )


class TargetResearchResult(BaseModel):
    target: ReconTarget
    findings: List[ResearchFinding] = Field(default_factory=list)
    recon_notes: str = Field(description="Observations from web and GitHub searches, including non-findings if clean")
    errors: List[str] = Field(
        default_factory=list,
        description="List of errors encountered during investigation (e.g. GitHub 403 Rate Limit, Search errors)"
    )


class CheckPointItem(BaseModel):
    check_point_id: Optional[str] = Field(
        default=None,
        description="Deterministic unique ID for this check point (e.g. 'urllib3-cve-2026-97688-cp1') to bind audit sign-offs"
    )
    target_or_cve: str = Field(
        description="Target category, CVE/GHSA ID, and CVSS score if known (e.g. 'CVE-2026-103119 (CVSS 7.5 High)', 'CVE-2026-111497 (CVSS 9.2 Critical)', 'GHSA-gh4c-6fx4-qh6g (CVSS 5.3 Medium)')"
    )
    cvss: Optional[str] = Field(
        default=None,
        description="CVSS score and severity label (e.g. '7.5 (High)', '9.2 (Critical)', '5.3 (Medium)', '未公表')"
    )
    content_summary: str = Field(
        description="Concise description of the vulnerability effect (e.g. 'AJP で、レスポンスの一部が次のリクエストに混ざる。別の利用者へ情報が漏れるおそれ')"
    )
    affected_versions: str = Field(
        description="Affected version range (e.g. '11.0.0-M25〜11.0.26', '修正版より古いバージョン')"
    )
    check_point_yes_no: str = Field(
        description="Clear Yes/No question for IT/dev teams (e.g. 'AJP コネクタを有効にしているか', 'HTTP/2 を有効にしていて、かつ非同期サーブレットを使っているか')"
    )
    verification_method: str = Field(
        description="Concrete inspection method: exact config files, XML tags, ini directives, grep/ldd commands, code search terms"
    )


class TriageNotice(BaseModel):
    product_name: str = Field(description="Product name (e.g. 'Apache Tomcat', 'PHP CVE-2026-115560', 'Brotli (Node2Shell)')")
    component_name: Optional[str] = Field(
        default=None,
        description="Canonical package/library name from SBOM (e.g. 'brotli', 'urllib3') for stable ID calculation"
    )
    notice_hash: Optional[str] = Field(
        default=None,
        description="Cryptographic fingerprint of the check points in this notice to detect editions/modifications automatically"
    )
    announcement_date: str = Field(description="Public date / release date (e.g. '2026年10月20日公開')")
    conclusion: str = Field(
        description="Actionable conclusion and deadline (e.g. '下の確認ポイントに1つでも Yes なら外部公開のシステムは7日以内に更新。すべて No なら通常リリース（30日以内）で構いません。')"
    )
    fixed_versions: str = Field(description="Fixed versions or '修正版: なし (次回定例リリース予定)'")
    severity_note: str = Field(description="Severity assessment, CVSS, and RCE presence (e.g. 'Important × 3, RCEは含まれません', 'CVSS 4.0 で 9.2 (Critical)')")
    pre_check_note: Optional[str] = Field(
        default="先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。",
        description="Version pre-screening rule"
    )
    check_points: List[CheckPointItem] = Field(
        default_factory=list,
        description="Table of Yes/No verification points and concrete check methods"
    )
    workaround: Optional[str] = Field(
        default=None,
        description="Workaround details, side effects, and operational tips (e.g. 'session.upload_progress.enabled を 0 にする。進捗表示を使っていなければ副作用はほぼありません。')"
    )
    unconfirmed_points: List[str] = Field(
        default_factory=list,
        description="Points not yet confirmed or still under investigation (e.g. '9.0系の影響範囲', '各CVEのCVSSスコア')"
    )
    sources: List[str] = Field(
        default_factory=list,
        description="List of source URLs and references"
    )


class TriageReport(BaseModel):
    report_title: str = Field(description="Title of the triage report")
    report_version: str = Field(default="1.0", description="Version or edition of the triage report (e.g. '1.0', '2.0')")
    is_dry_run: bool = Field(default=False, description="True if generated in offline / dry-run simulation mode")
    unscanned_or_failed_components: List[str] = Field(
        default_factory=list,
        description="List of components or dependencies that could not be investigated due to network/API errors"
    )
    notices: List[TriageNotice] = Field(
        default_factory=list,
        description="List of structured triage notices formatted in the user's action-oriented standard"
    )
