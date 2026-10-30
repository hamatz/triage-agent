"""Data models for codebase verification and audit attestations."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from triage_agent.schemas import CheckPointItem, TriageNotice


class MatchSnippet(BaseModel):
    file_path: str
    line_number: int
    line_content: str
    context_content: Optional[str] = None
    is_test: bool = False


class AuditAttestation(BaseModel):
    check_point_id: Optional[str] = Field(
        default=None,
        description="Deterministic unique ID of the check point (e.g. 'urllib3-cve-2026-97688-a1b2c3d4'). Primary key.",
    )
    notice_hash: Optional[str] = Field(
        default=None,
        description="Notice content hash fingerprint. If check points are added/changed in edition 2, automatically invalidates outdated sign-offs.",
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="Exact CVE or GHSA ID (e.g. 'CVE-2026-11149'). Used in combination with check_point_yes_no.",
    )
    check_point_yes_no: Optional[str] = Field(
        default=None,
        description="Exact question text of the check point (e.g. 'HTTPS_PROXY 環境変数を利用しているか').",
    )
    report_version: Optional[str] = Field(
        default=None,
        description="Target report version (e.g. '1.0'). If mismatched with current report version, sign-off is invalidated.",
    )
    target_or_cve: Optional[str] = Field(
        default=None,
        description="Legacy field for backward compatibility. Must match CVE ID strictly if used.",
    )
    matches_hash: Optional[str] = Field(
        default=None,
        description="Fingerprint hash of detected code snippet matches at sign-off time. Invalidates sign-off if code changes.",
    )
    status: str = Field(default="NO (手動確認済み・非該当)")
    reviewer: str = Field(description="Name/ID of the security reviewer or engineer")
    date: str = Field(description="Date of attestation (e.g. '2026-10-25')")
    evidence: str = Field(description="Audit justification, config proof, or architecture rationale")
    environment: Optional[str] = Field(
        default=None,
        description="Target host/cluster environment ('Production', 'Staging', 'Development')",
    )
    valid_until: Optional[str] = Field(
        default=None,
        description="Expiration date of sign-off ('YYYY-MM-DD'). When expired, Verifier flags it for re-attestation.",
    )
    evidence_type: Optional[str] = Field(
        default=None,
        description="Category of rationale: 'iac_config' (intent in repo), 'live_telemetry' (script output), or 'vendor_attestation'",
    )
    history: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Audit trail of previous attestations and vendor replies"
    )


class AttestationFile(BaseModel):
    attestations: List[AuditAttestation] = Field(default_factory=list)


class CheckVerificationResult(BaseModel):
    check_point: CheckPointItem
    status: str = Field(description="'YES (該当・要対応)', 'コード内未検出 (外部設定/既定値の要確認)', '要手動確認', or 'NO (手動確認済み・非該当)'")
    matches: List[MatchSnippet] = Field(default_factory=list)
    matches_hash: Optional[str] = Field(default=None, description="Current fingerprint hash of code matches")
    reasoning: str
    external_check_advice: Optional[str] = Field(
        default=None,
        description="Advice on external config files (e.g. php.ini, server.xml, env vars, K8s manifests)"
    )
    attestation: Optional[AuditAttestation] = Field(
        default=None,
        description="Human audit sign-off if confirmed offline"
    )


class NoticeVerificationResult(BaseModel):
    notice: TriageNotice
    overall_status: str = Field(description="'YES (該当・要対応)', '要確認 (外部設定・環境設定の確認要)', or 'NO (安全・確認済み)'")
    action_deadline_advice: str
    results: List[CheckVerificationResult] = Field(default_factory=list)


class CodebaseAuditReport(BaseModel):
    code_dir: str
    overall_status: str
    summary_counts: Dict[str, int]
    notice_results: List[NoticeVerificationResult] = Field(default_factory=list)
