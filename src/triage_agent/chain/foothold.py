"""Multi-signal Foothold / Application RCE Analysis Engine (v0.4.0 / ADR-019).

Solves the critical zero-day blind spot where fresh vulnerabilities (such as PHP2Shell:
CVE-2026-109618 / 109619) lack official CWE identifiers upon release. Evaluates 4
defense-in-depth criteria to reliably detect actionable intrusion footholds.
"""

import re
from typing import List, Optional, Set

from triage_agent.chain.models import FootholdResult

# Direct Code Execution / Memory Corruption CWEs
CWE_DIRECT_FOOTHOLD_SET: Set[int] = {
    94,   # Code Injection
    78,   # OS Command Injection
    77,   # Command Injection
    502,  # Deserialization of Untrusted Data
    434,  # Unrestricted Upload of File with Dangerous Type
    98,   # Improper Control of Filename for Include/Require (PHP RFI)
    1336, # Improper Neutralization of Special Elements Used in a Template Engine
    917,  # Improper Neutralization of Special Elements used in an Expression Language
    416,  # Use After Free (PHP2Shell component)
    787,  # Out-of-bounds Write
    908,  # Use of Uninitialized Resource (PHP2Shell component)
}

# Buffer Overflow / Path Traversal CWEs that require AV:N and High Impact to prevent DoS/read-only false alarms
CWE_CONDITIONAL_FOOTHOLD_SET: Set[int] = {
    22,   # Path Traversal (Arbitrary file overwrite/write)
    120,  # Buffer Copy without Checking Size of Input
    121,  # Stack-based Buffer Overflow
    122,  # Heap-based Buffer Overflow
}


def _extract_cwe_numbers(cwe_entries: Optional[List[str]]) -> Set[int]:
    """Extract numeric IDs from CWE strings (e.g. 'CWE-416', 'CWE-94')."""
    nums = set()
    if not cwe_entries:
        return nums
    for entry in cwe_entries:
        matches = re.findall(r"CWE-(\d+)", str(entry), re.IGNORECASE)
        for m in matches:
            try:
                nums.add(int(m))
            except ValueError:
                pass
    return nums


def evaluate_application_foothold(
    cve_id: str,
    cisa_kev: bool = False,
    cvss_vector: Optional[str] = None,
    cvss_score: Optional[float] = None,
    summary_text: Optional[str] = None,
    cwe_list: Optional[List[str]] = None,
) -> FootholdResult:
    """Evaluate whether an application-layer vulnerability provides an initial intrusion foothold (RCE).
    
    Returns FootholdResult with grounding basis. Any of the 4 criteria is sufficient.
    """
    cwe_nums = _extract_cwe_numbers(cwe_list)
    vec = (cvss_vector or "").upper()
    summary = (summary_text or "").lower()

    # 1. Criterion 1: CISA KEV listing (Definitive real-world active exploitation)
    if cisa_kev:
        return FootholdResult(
            is_foothold=True,
            basis=f"CISA KEV（Known Exploited Vulnerabilities）掲載（実侵害悪用確認済み）",
            is_unclassifiable=False,
        )

    # Parse CVSS vector metrics if present
    is_network_vector = ("AV:N" in vec) or ("NETWORK" in vec)
    has_high_confidentiality = ("C:H" in vec)
    has_high_integrity = ("I:H" in vec)

    # 2. Criterion 2: CVSS Attack Vector Network + High Confidentiality & High Integrity
    if is_network_vector and has_high_confidentiality and has_high_integrity:
        score_str = f" (CVSS {cvss_score})" if cvss_score else ""
        return FootholdResult(
            is_foothold=True,
            basis=f"CVSS メトリクス合致: 攻撃元ネットワーク（AV:N）かつ機密性・完全性への致命的影響（C:H/I:H）{score_str}",
            is_unclassifiable=False,
        )

    # 3. Criterion 3: Official Advisory / Summary explicit RCE statement
    # Direction: Escalating severity based on official wording is safe (never declares safe on doubt)
    rce_patterns = [
        r"\bremote\s+code\s+execution\b",
        r"\bexecute\s+arbitrary\s+code\b",
        r"\bcode\s+execution\b",
        r"\brce\b",
        r"\bcommand\s+injection\b",
    ]
    for pattern in rce_patterns:
        if re.search(pattern, summary, re.IGNORECASE):
            # If network vector or unverified vector, treat as foothold
            return FootholdResult(
                is_foothold=True,
                basis="公式アドバイザリ・要約に任意コード実行（Remote Code Execution）の明記あり",
                is_unclassifiable=False,
            )

    # 4. Criterion 4: Direct Code Execution / Memory Corruption CWEs
    matched_direct = cwe_nums.intersection(CWE_DIRECT_FOOTHOLD_SET)
    if matched_direct:
        matched_str = ", ".join([f"CWE-{n}" for n in sorted(matched_direct)])
        return FootholdResult(
            is_foothold=True,
            basis=f"足場該当 CWE 検知: {matched_str}（コード実行・重大メモリ破壊）",
            is_unclassifiable=False,
        )

    # 5. Criterion 5: Conditional CWEs (Buffer Overflow / Path Traversal with Network + High Impact)
    matched_cond = cwe_nums.intersection(CWE_CONDITIONAL_FOOTHOLD_SET)
    if matched_cond:
        if is_network_vector and (has_high_integrity or has_high_confidentiality):
            matched_str = ", ".join([f"CWE-{n}" for n in sorted(matched_cond)])
            return FootholdResult(
                is_foothold=True,
                basis=f"条件付き足場 CWE 検知: {matched_str}（ネットワーク到達可能かつ高影響）",
                is_unclassifiable=False,
            )

    # 6. Fallback: If score is high (>= 8.5) but unclassified, do NOT declare non-foothold
    if cvss_score and cvss_score >= 8.5 and is_network_vector:
        return FootholdResult(
            is_foothold=False,
            basis="高深刻度ネットワーク脆弱性（足場分類不能・要人手精査）",
            is_unclassifiable=True,
        )

    return FootholdResult(
        is_foothold=False,
        basis="足場（RCE/侵入経路）としてのシグナル未検出（局所/情報漏洩/DoS）",
        is_unclassifiable=False,
    )
