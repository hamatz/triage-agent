from typing import Any, Dict, List, Optional
import httpx
from triage_agent.config import get_github_token

GITHUB_API_BASE = "https://api.github.com"


def _get_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "triage-agent-ai",
    }
    token = get_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def search_github_security_signals(
    repo: str,
    keywords: Optional[List[str]] = None,
    limit: int = 5
) -> Dict[str, Any]:
    """Search a GitHub repository for security signals: security advisories, releases, and suspicious commits.
    
    Captures non-200 status codes (e.g. 403 Rate Limit, 429, 404) explicitly in 'errors'.
    """
    if not repo or "/" not in repo:
        return {"repo": repo, "errors": [f"Invalid repository format '{repo}'. Expected 'owner/repo'."]}

    repo = repo.strip().strip("/")
    if keywords is None:
        keywords = ["security", "cve", "vulnerability", "rce", "patch", "bypass", "sanitize"]

    signals: Dict[str, Any] = {
        "repo": repo,
        "security_advisories": [],
        "recent_releases": [],
        "relevant_commits": [],
        "errors": [],
    }

    headers = _get_headers()

    with httpx.Client(timeout=10.0, headers=headers) as client:
        # 1. Check Security Advisories
        try:
            adv_url = f"{GITHUB_API_BASE}/repos/{repo}/security-advisories"
            adv_resp = client.get(adv_url)
            if adv_resp.status_code == 200:
                for adv in adv_resp.json()[:limit]:
                    # Extract score from cvss or cvss_severities
                    cvss_data = adv.get("cvss") or {}
                    score = cvss_data.get("score")
                    if not score:
                        severities = adv.get("cvss_severities") or {}
                        score = (severities.get("cvss_v3") or {}).get("score") or \
                                (severities.get("cvss_v4") or {}).get("score")
                    
                    sev = (adv.get("severity") or "Unknown").capitalize()
                    cvss_str = f"{score} ({sev})" if score else sev
                    signals["security_advisories"].append({
                        "ghsa_id": adv.get("ghsa_id"),
                        "cve_id": adv.get("cve_id"),
                        "display_id": f"{adv.get('cve_id')} ({adv.get('ghsa_id')})" if adv.get("cve_id") else adv.get("ghsa_id"),
                        "summary": adv.get("summary"),
                        "severity": sev,
                        "cvss": cvss_str,
                        "published_at": adv.get("published_at"),
                        "html_url": adv.get("html_url"),
                    })
            elif adv_resp.status_code == 404:
                # Security advisories may be disabled for this repo
                pass
            else:
                signals["errors"].append(
                    f"GitHub Advisories API ({repo}): HTTP {adv_resp.status_code} - {adv_resp.text[:120]}"
                )
        except Exception as e:
            signals["errors"].append(f"GitHub Advisories Exception ({repo}): {str(e)}")

        # 2. Check Recent Releases (look for security pre-announcements or RC releases)
        try:
            rel_url = f"{GITHUB_API_BASE}/repos/{repo}/releases?per_page={limit}"
            rel_resp = client.get(rel_url)
            if rel_resp.status_code == 200:
                for rel in rel_resp.json():
                    signals["recent_releases"].append({
                        "tag_name": rel.get("tag_name"),
                        "name": rel.get("name"),
                        "published_at": rel.get("published_at"),
                        "body": (rel.get("body") or "")[:400],
                        "html_url": rel.get("html_url"),
                    })
            elif rel_resp.status_code != 404:
                signals["errors"].append(
                    f"GitHub Releases API ({repo}): HTTP {rel_resp.status_code} - {rel_resp.text[:120]}"
                )
        except Exception as e:
            signals["errors"].append(f"GitHub Releases Exception ({repo}): {str(e)}")

        # 3. Check Commits for security fixes/signals
        try:
            commits_url = f"{GITHUB_API_BASE}/repos/{repo}/commits?per_page=20"
            commits_resp = client.get(commits_url)
            if commits_resp.status_code == 200:
                for c in commits_resp.json():
                    msg = c.get("commit", {}).get("message", "")
                    msg_lower = msg.lower()
                    if any(k.lower() in msg_lower for k in keywords):
                        signals["relevant_commits"].append({
                            "sha": c.get("sha")[:10],
                            "full_sha": c.get("sha"),
                            "date": c.get("commit", {}).get("author", {}).get("date"),
                            "message": msg[:200],
                            "html_url": c.get("html_url"),
                        })
                        if len(signals["relevant_commits"]) >= limit:
                            break
            elif commits_resp.status_code != 404:
                signals["errors"].append(
                    f"GitHub Commits API ({repo}): HTTP {commits_resp.status_code} - {commits_resp.text[:120]}"
                )
        except Exception as e:
            signals["errors"].append(f"GitHub Commits Exception ({repo}): {str(e)}")

    return signals


def get_github_commit_or_advisory_detail(repo: str, ref_or_ghsa_id: str) -> Dict[str, Any]:
    """Retrieve detailed patch diff or security advisory details from GitHub.
    
    Args:
        repo: Repository in 'owner/repo' format
        ref_or_ghsa_id: Commit SHA or GHSA ID (e.g. 'GHSA-xxx' or 'c9b4e3f')
        
    Returns:
        Dict containing commit patch diff or advisory full text
    """
    repo = repo.strip().strip("/")
    headers = _get_headers()

    with httpx.Client(timeout=10.0, headers=headers) as client:
        # Check if ref is a GHSA advisory
        if ref_or_ghsa_id.upper().startswith("GHSA-"):
            url = f"{GITHUB_API_BASE}/repos/{repo}/security-advisories/{ref_or_ghsa_id}"
            resp = client.get(url)
            if resp.status_code == 200:
                return resp.json()
            return {"error": f"Advisory {ref_or_ghsa_id} not found in {repo} (HTTP {resp.status_code})"}

        # Otherwise treat as commit SHA
        url = f"{GITHUB_API_BASE}/repos/{repo}/commits/{ref_or_ghsa_id}"
        resp = client.get(url)
        if resp.status_code == 200:
            data = resp.json()
            files_diff = []
            for f in data.get("files", [])[:5]:
                files_diff.append({
                    "filename": f.get("filename"),
                    "status": f.get("status"),
                    "patch": (f.get("patch") or "")[:2000],
                })
            return {
                "sha": data.get("sha"),
                "message": data.get("commit", {}).get("message"),
                "files": files_diff,
            }
        return {"error": f"Commit {ref_or_ghsa_id} not found in {repo} (HTTP {resp.status_code})"}
