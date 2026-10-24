import json
from pathlib import Path
from typing import List, Optional
from google import genai
from google.genai import types

from triage_agent.config import get_gemini_api_key, get_model_name
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
    
    Architecture (Robust 2-Step Agent Pattern):
      Step 1: Gathers empirical signals from GitHub Advisories, Releases, and Commits via direct tool calls.
      Step 2: Uses Gemini with response_schema=TargetResearchResult to synthesize and assess applicability
              without tool-declaration conflicts.
    """
    repo = target.github_repo
    signals_data = {}
    
    # Step 1: Collect empirical signals
    if repo:
        try:
            signals_data = search_github_security_signals(
                repo=repo,
                keywords=target.github_search_keywords,
                limit=5
            )
        except Exception as e:
            signals_data = {"error": f"GitHub API query failed for {repo}: {str(e)}"}

    if dry_run or not get_gemini_api_key():
        # Dry-Run mode: construct raw findings from GitHub signals without LLM inference
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
                        cvss="未公表 (Pre-release)",
                        is_pre_announcement=True,
                        affected_versions=f"Targeting fixes around {target.version}",
                        applies_to_current_version=True,
                        summary=(rel.get("body") or "")[:300],
                        source_urls=[rel.get("html_url")] if rel.get("html_url") else [],
                        commit_shas=[],
                        trigger_hint="Pre-release security fix candidate.",
                    )
                )

        return TargetResearchResult(
            target=target,
            findings=findings,
            recon_notes=f"[DRY-RUN] Direct GitHub scan found {len(findings)} signal(s).",
        )

    # Step 2: Live LLM Synthesis with response_schema
    if client is None:
        client = genai.Client(api_key=get_gemini_api_key())

    model_name = get_model_name("researcher")
    system_instruction = PROMPT_PATH.read_text(encoding="utf-8")

    user_content = f"""調査対象コンポーネント:
- 名前: {target.name}
- 自社利用バージョン: {target.version}
- エコシステム: {target.ecosystem}
- GitHubリポジトリ: {target.github_repo or 'Unknown'}
- 優先度: {target.priority}
- 調査理由: {target.rationale}

【取得されたGitHubセキュリティシグナル (Advisories / Releases / Commits)】:
{json.dumps(signals_data, indent=2, ensure_ascii=False)}

指示:
上記のシグナルを精読し、自社利用バージョン（{target.version}）に影響する脆弱性・パッチ予告を抽出し、
構造化データ（TargetResearchResult）として出力してください。推測で架空の脆弱性を捏造してはなりません。
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
