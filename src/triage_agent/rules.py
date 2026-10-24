"""Standard Triage Rules & Decision Criteria for triage-agent.

Defines the enterprise security decision criteria to ensure consistency across prompts,
agents, and verification tools.
"""

from typing import Dict, Any

TRIAGE_RULES: Dict[str, Any] = {
    # Decision deadlines
    "CRITICAL_DEADLINE": "48時間以内",
    "CRITICAL_CRITERIA": "CVSS 9.0以上、Critical表記、または外部公開システムでのRCEリスク（PoCの有無に関わらず48時間以内に対処）",
    
    "HIGH_DEADLINE": "7日以内",
    "HIGH_CRITERIA": "CVSS 7.0〜8.9、Important / High相当、または情報漏洩・認証バイパスのリスク（確認ポイントに1つでもYesなら7日以内に対処）",
    
    "NORMAL_DEADLINE": "通常リリース（30日以内）",
    "NORMAL_CRITERIA": "確認ポイントがすべてNo、またはCVSS 6.9以下の低リスク項目",
    
    # Conflict resolution
    "SEVERITY_POLICY": "各機関・情報源で深刻度評価が複数ある場合は【最も高いもの】を採用する（例: Node.jsがHigh、GoogleがCritical 9.2ならCritical 9.2を採用）。",
    
    # Evidence & Verification policy
    "UNKNOWN_POLICY": "設定の有無が不明、またはコードベース外（php.ini, server.xml, 環境変数, K8s設定等）に依存する場合は【該当あり（要確認）】として扱う。否定の確証がない限り『安全』と断定してはならない。",
}

def format_rules_for_prompt() -> str:
    """Format the triage decision rules for inclusion in agent prompts."""
    return f"""### 【組織の判定基準・意思決定ルール (Enterprise Triage Rules)】
1. **深刻度の採用基準:**
   - {TRIAGE_RULES['SEVERITY_POLICY']}
2. **期限と対応基準:**
   - **Critical (CVSS 9.0+ / RCE):** {TRIAGE_RULES['CRITICAL_CRITERIA']} → 【{TRIAGE_RULES['CRITICAL_DEADLINE']}】に更新または回避策。
   - **High / Important (CVSS 7.0〜8.9):** {TRIAGE_RULES['HIGH_CRITERIA']} → 【{TRIAGE_RULES['HIGH_DEADLINE']}】に更新または回避策。
   - **通常対応 (Low / Medium / 全てNo):** {TRIAGE_RULES['NORMAL_CRITERIA']} → 【{TRIAGE_RULES['NORMAL_DEADLINE']}】。
3. **安全・不明の判定基準:**
   - {TRIAGE_RULES['UNKNOWN_POLICY']}
"""
