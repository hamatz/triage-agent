import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from google import genai
from google.genai import types

from triage_agent.config import call_with_retry, get_genai_client, get_github_token, get_model_name, is_llm_configured
from triage_agent.schemas import ReconTarget, ResearchFinding, TargetResearchResult
from triage_agent.tools.github import search_github_security_signals
from triage_agent.tools.osv import query_osv_single

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
        - Explicitly tracks any API failures (403 Rate Limit, 429, Search errors).
      Stage 2 (Structured Synthesis):
        - Evaluates all collected intelligence against the installed version.
        - Outputs schema-validated TargetResearchResult carrying forward any investigation errors.
    """
    repo = target.github_repo
    signals_data: Dict[str, Any] = {}
    web_findings_text = ""
    errors: List[str] = []

    # -------------------------------------------------------------
    # Stage 1: Active Reconnaissance
    # -------------------------------------------------------------
    # 1A. OSV.dev Database Query (Primary & Tokenless Vulnerability Investigation)
    osv_vulns: List[Dict[str, Any]] = []
    osv_success = False
    try:
        osv_vulns, osv_errors = query_osv_single(
            name=target.name,
            version=target.version,
            ecosystem=target.ecosystem,
            purl=getattr(target, "purl", None),
        )
        if osv_errors:
            errors.extend(osv_errors)
        else:
            osv_success = True
    except Exception as e:
        errors.append(f"OSV.dev query failed for {target.name}: {str(e)}")

    signals_data["osv_vulnerabilities"] = osv_vulns

    # 1B. GitHub Signals (Secondary: Releases & Commits)
    if repo:
        try:
            gh_signals = search_github_security_signals(
                repo=repo,
                keywords=target.github_search_keywords,
                limit=5
            )
            signals_data["security_advisories"] = gh_signals.get("security_advisories", [])
            signals_data["recent_releases"] = gh_signals.get("recent_releases", [])
            signals_data["relevant_commits"] = gh_signals.get("relevant_commits", [])

            gh_errors = gh_signals.get("errors", [])
            if gh_errors:
                # If OSV.dev succeeded and no GitHub token is provided, treat GitHub errors (e.g. rate limit 403)
                # as non-blocking supplementary notices rather than un-scanned component warnings.
                has_token = bool(get_github_token())
                if osv_success and not has_token:
                    signals_data["supplementary_notes"] = [
                        f"GitHub API notice (unauthenticated): {err}" for err in gh_errors
                    ]
                else:
                    errors.extend(gh_errors)
        except Exception as e:
            if not osv_success:
                errors.append(f"GitHub API query failed for {repo}: {str(e)}")

    # 1C. Dynamic Pre-announcement & Web Search (Live mode only)
    if not dry_run and is_llm_configured():
        try:
            if client is None:
                client = get_genai_client()

            model_name = get_model_name("researcher")

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
            search_resp = call_with_retry(
                lambda: client.models.generate_content(
                    model=model_name,
                    contents=search_query_prompt,
                    config=types.GenerateContentConfig(
                        tools=[types.Tool(google_search=types.GoogleSearch())],
                        temperature=0.1,
                    ),
                )
            )
            if search_resp.text:
                web_findings_text = search_resp.text

        except Exception as e:
            errors.append(f"Google Search Grounding failed for {target.name}: {str(e)}")

    # -------------------------------------------------------------
    # Stage 2: Synthesis (Dry-Run or Live Schema Generation)
    # -------------------------------------------------------------
    if dry_run or not is_llm_configured():
        findings: List[ResearchFinding] = []
        seen_ids = set()

        # 2A. Process OSV.dev Vulnerabilities (Tokenless Primary Source)
        for vuln in osv_vulns:
            vid = vuln.get("cve_id") or vuln.get("id") or "UNKNOWN-VULN"
            seen_ids.add(vuln.get("id"))
            if vuln.get("cve_id"):
                seen_ids.add(vuln.get("cve_id"))

            score = vuln.get("score")
            sev = "HIGH"
            if score:
                try:
                    s_float = float(score)
                    if s_float >= 9.0:
                        sev = "CRITICAL"
                    elif s_float >= 7.0:
                        sev = "HIGH"
                    elif s_float >= 4.0:
                        sev = "MEDIUM"
                    else:
                        sev = "LOW"
                except ValueError:
                    pass

            fixed_str = f" (Fixed: {', '.join(vuln['fixed_versions'])})" if vuln.get("fixed_versions") else ""
            findings.append(
                ResearchFinding(
                    id=vid,
                    title=vuln.get("summary") or f"Vulnerability in {target.name}{fixed_str}",
                    severity=sev,
                    cvss=str(score) if score else "未公表",
                    is_pre_announcement=False,
                    affected_versions=f"Affects version {target.version}{fixed_str}",
                    applies_to_current_version=True,
                    summary=vuln.get("details") or vuln.get("summary") or "Vulnerability reported via OSV.dev",
                    source_urls=vuln.get("references", []),
                    commit_shas=[],
                    trigger_hint="[OSV.dev / DRY-RUN: 発火条件の詳細検証は静的コード解析およびライブエージェントで実施]",
                )
            )

        # 2B. Process GitHub Advisories (if not already recorded from OSV)
        for adv in signals_data.get("security_advisories", []):
            adv_id = adv.get("cve_id") or adv.get("ghsa_id") or "GHSA-UNKNOWN"
            if adv.get("ghsa_id") in seen_ids or adv.get("cve_id") in seen_ids:
                continue
            seen_ids.add(adv_id)

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

        # 2C. Process Releases for pre-announcements
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
            recon_notes=f"[DRY-RUN] OSV.dev and repository scan found {len(findings)} signal(s){error_notes}.",
            errors=errors,
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

【1. OSV.dev 脆弱性データベース (Tokenless Primary Source)】:
{json.dumps(osv_vulns, indent=2, ensure_ascii=False) if osv_vulns else '該当する既知脆弱性なし (No known vulnerabilities reported)'}

【2. Web検索・事前パッチ予告の調査結果 (Google Search Grounding)】:
{web_findings_text if web_findings_text else 'Web検索未実施または情報なし'}

【3. GitHubセキュリティシグナル (Advisories / Releases / Commits)】:
{json.dumps(signals_data, indent=2, ensure_ascii=False)}

指示:
上記すべての情報源（OSV.dev脆弱性一覧、公式ブログ予告、GitHub Advisory、最新コミット）を総合評価し、
自社利用バージョン（{target.version}）に影響する脆弱性・パッチ予告を抽出して構造化データ（TargetResearchResult）を出力してください。
"""

    response = call_with_retry(
        lambda: client.models.generate_content(
            model=model_name,
            contents=user_content,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                response_schema=TargetResearchResult,
                temperature=0.1,
            ),
        )
    )

    if response.text:
        result = TargetResearchResult.model_validate_json(response.text)
        result.errors.extend(errors)
        return result

    raise RuntimeError(f"Researcher agent failed to produce research results for {target.name}")
