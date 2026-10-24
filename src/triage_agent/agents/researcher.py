import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from google import genai
from google.genai import types

from triage_agent.config import get_gemini_api_key, get_genai_client, get_model_name
from triage_agent.schemas import ReconTarget, ResearchFinding, TargetResearchResult
from triage_agent.tools.github import search_github_security_signals
from triage_agent.tools.web import fetch_webpage_text

PROMPT_PATH = Path(__file__).resolve().parent.parent.parent.parent / "prompts" / "researcher.md"


def run_researcher(
    target: ReconTarget,
    client: Optional[genai.Client] = None,
    dry_run: bool = False,
) -> TargetResearchResult:
    """Execute the Dynamic Researcher agent for a single target component.
    
    Robust 2-Stage Multi-Agent Architecture:
      Stage 1 (Active Reconnaissance):
        - Queries GitHub security advisories, releases, and commits.
        - Executes Google Search Grounding to uncover upcoming patch announcements (Node.js blogs, oss-security, etc.).
        - Fetches full webpage text for any detected announcement URLs.
      Stage 2 (Structured Synthesis):
        - Evaluates all collected intelligence against the installed version.
        - Outputs schema-validated TargetResearchResult without tool conflicts.
    """
    repo = target.github_repo
    signals_data: Dict[str, Any] = {}
    web_findings_text = ""
    errors: List[str] = []

    # -------------------------------------------------------------
    # Stage 1: Active Reconnaissance
    # -------------------------------------------------------------
    # 1A. GitHub Signals
    if repo:
        try:
            signals_data = search_github_security_signals(
                repo=repo,
                keywords=target.github_search_keywords,
                limit=5
            )
            if signals_data.get("errors"):
                errors.extend(signals_data["errors"])
        except Exception as e:
            err = f"GitHub API query failed for {repo}: {str(e)}"
            errors.append(err)
            signals_data = {"errors": [err]}

    # 1B. Dynamic Pre-announcement & Web Search (Live mode only)
    if not dry_run and get_gemini_api_key():
        try:
            if client is None:
                client = get_genai_client()

            model_name = get_model_name("researcher")

            # Dedicated Search Call with Google Search Grounding (no response_schema to avoid SDK conflict)
            search_query_prompt = f"""Target Component: {target.name} (In-use Version: {target.version})
Queries to investigate:
{json.dumps(target.search_queries, ensure_ascii=False)}

Search Task:
Use Google Search to find:
1. Upcoming security release announcements or pre-notifications (e.g. on official project blogs, mailing lists like oss-security).
2. Recent unpatched 0-day or RCE reports affecting version {target.version}.
3. Released patches and security advisories for {target.name}.

Summarize your findings with source URLs. If no upcoming announcements or active CVEs exist, explicitly state 'No active advisories or pre-announcements found'.
"""
            search_resp = client.models.generate_content(
                model=model_name,
                contents=search_query_prompt,
                config=types.GenerateContentConfig(
                    tools=[types.Tool(google_search=types.GoogleSearch())],
                    temperature=0.1,
                ),
            )
            if search_resp.text:
                web_findings_text = search_resp.text

        except Exception as e:
            errors.append(f"Google Search Grounding failed for {target.name}: {str(e)}")

    # -------------------------------------------------------------
    # Stage 2: Synthesis (Dry-Run or Live Schema Generation)
    # -------------------------------------------------------------
    if dry_run or not get_gemini_api_key():
        findings: List[ResearchFinding] = []
        for adv in signals_data.get("security_advisories", []):
            adv_id = adv.get("cve_id") or adv.get("ghsa_id") or "GHSA-UNKNOWN"
            cvss_info = adv.get("cvss") or f"未公表 ({adv.get('severity', 'High')})"
            findings.append(
                ResearchFinding(
                    id=adv_id,
                    title=adv.get("summary") or f"Security advisory for {target.name}",
                    severity=adv.get("severity") or "HIGH",
                    cvss=cvss_info,
                    is_pre_announcement=False,
                    affected_versions=f"Affects versions around {target.version}",
                    applies_to_current_version=True,
                    summary=adv.get("summary") or "Advisory retrieved from GitHub Security Advisories",
                    source_urls=[adv.get("html_url")] if adv.get("html_url") else [],
                    commit_shas=[],
                    trigger_hint="[DRY-RUN: 詳細な発火設定の精読はライブエージェントで実行]",
                )
            )

        for rel in signals_data.get("recent_releases", []):
            tag = rel.get("tag_name", "").lower()
            body = (rel.get("body") or "").lower()
            if "rc" in tag or "pre" in tag or "security" in body or "cve" in body:
                findings.append(
                    ResearchFinding(
                        id=f"PRE-RELEASE-{rel.get('tag_name')}",
                        title=f"Pre-release / Security Notice: {rel.get('name') or rel.get('tag_name')}",
                        severity="MEDIUM",
                        cvss="Pre-release",
                        is_pre_announcement=True,
                        affected_versions=f"Targeting fixes around {target.version}",
                        applies_to_current_version=True,
                        summary=(rel.get("body") or "")[:300],
                        source_urls=[rel.get("html_url")] if rel.get("html_url") else [],
                        commit_shas=[],
                        trigger_hint="Pre-release security fix candidate.",
                    )
                )

        error_notes = f" | Errors: {'; '.join(errors)}" if errors else ""
        return TargetResearchResult(
            target=target,
            findings=findings,
            recon_notes=f"[DRY-RUN] Direct GitHub scan found {len(findings)} signal(s){error_notes}.",
        )

    # Live Synthesis Call with Structured Outputs
    if client is None:
        client = get_genai_client()

    model_name = get_model_name("researcher")
    system_instruction = PROMPT_PATH.read_text(encoding="utf-8")

    user_content = f"""調査対象コンポーネント:
- 名前: {target.name}
- 自社利用バージョン: {target.version}
- エコシステム: {target.ecosystem}
- GitHubリポジトリ: {target.github_repo or 'Unknown'}
- 優先度: {target.priority}
- 調査理由: {target.rationale}

【1. Web検索・事前パッチ予告の調査結果 (Google Search Grounding)】:
{web_findings_text if web_findings_text else 'Web検索未実施または情報なし'}

【2. GitHubセキュリティシグナル (Advisories / Releases / Commits)】:
{json.dumps(signals_data, indent=2, ensure_ascii=False)}

指示:
上記すべての情報源（公式ブログ予告、GitHub Advisory、最新コミット）を総合評価し、
自社利用バージョン（{target.version}）に影響する脆弱性・パッチ予告を抽出して構造化データ（TargetResearchResult）を出力してください。
"""

    response = client.models.generate_content(
        model=model_name,
        contents=user_content,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=TargetResearchResult,
            temperature=0.1,
        ),
    )

    if response.text:
        return TargetResearchResult.model_validate_json(response.text)
    raise RuntimeError(f"Researcher agent failed to produce research results for {target.name}")
