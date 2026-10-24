import json
from pathlib import Path
from typing import Optional
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
    
    1. Leverages GitHub security signals, webpage fetching, and Gemini Google Search Grounding.
    2. Identifies active advisories, pre-announcements, and unpatched/RC signals.
    3. Returns a structured TargetResearchResult.
    """
    if dry_run or not get_gemini_api_key():
        # Dry-run / Offline fallback: execute tools directly and extract actual GitHub signals
        repo = target.github_repo
        findings = []
        notes = f"[Dry-Run / Direct Tool Mode] Checked GitHub and search queries for {target.name}."
        
        if repo:
            signals = search_github_security_signals(repo, keywords=target.github_search_keywords, limit=3)
            # Convert any found GitHub Security Advisories
            for adv in signals.get("security_advisories", []):
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
                        trigger_hint="Requires investigation into specific configuration flags.",
                    )
                )
            
            # Check recent releases for pre-release / RC notices
            for rel in signals.get("recent_releases", []):
                tag = rel.get("tag_name", "").lower()
                body = (rel.get("body") or "").lower()
                if "rc" in tag or "pre" in tag or "security" in body or "cve" in body:
                    findings.append(
                        ResearchFinding(
                            id=f"PRE-RELEASE-{rel.get('tag_name')}",
                            title=f"Pre-release / Security Notice: {rel.get('name') or rel.get('tag_name')}",
                            severity="MEDIUM",
                            is_pre_announcement=True,
                            affected_versions=f"Targeting fixes for {target.version}",
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
            recon_notes=notes,
        )

    # Online Agent Mode: Call Gemini with function tools & search grounding
    if client is None:
        client = genai.Client(api_key=get_gemini_api_key())

    model_name = get_model_name("researcher")
    system_instruction = PROMPT_PATH.read_text(encoding="utf-8")

    user_content = f"""調査対象コンポーネント:
名前: {target.name}
自社利用バージョン: {target.version}
エコシステム: {target.ecosystem}
GitHubリポジトリ: {target.github_repo or 'Unknown'}
優先度: {target.priority}
調査理由: {target.rationale}
推奨検索クエリ: {json.dumps(target.search_queries, ensure_ascii=False)}

指示:
提供されたツール（GitHubシグナル検索、Webページ取得、Google検索グラウンディング等）を活用し、
このコンポーネントに関する直近のRCE・重大脆弱性・セキュリティパッチリリース予告（Pre-announcement）・未CVE化の修正コミットを能動的に調査し、
結果を構造化データとして出力してください。
"""

    # We provide Python function tools for GitHub & web scraping, plus Google Search grounding
    tools = [
        search_github_security_signals,
        fetch_webpage_text,
        types.Tool(google_search=types.GoogleSearch()),
    ]

    response = client.models.generate_content(
        model=model_name,
        contents=user_content,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=tools,
            response_mime_type="application/json",
            response_schema=TargetResearchResult,
            temperature=0.2,
        ),
    )

    if response.text:
        return TargetResearchResult.model_validate_json(response.text)
    raise RuntimeError(f"Researcher agent failed to produce research results for {target.name}")
