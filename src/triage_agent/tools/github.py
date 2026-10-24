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
    
    Args:
        repo: GitHub repository in 'owner/repo' format (e.g. 'urllib3/urllib3')
        keywords: Keywords to look for in commit messages (default: ['security', 'CVE', 'fix', 'overflow', 'bypass'])
        limit: Max items to return per category
        
    Returns:
        Dict containing security_advisories, recent_releases, and relevant_commits
    """
    if not repo or "/" not in repo:
        return {"error": f"Invalid repository format '{repo}'. Expected 'owner/repo'."}

    repo = repo.strip().strip("/")
    if keywords is None:
        keywords = ["security", "cve", "vulnerability", "rce", "patch", "bypass", "sanitize"]

    signals: Dict[str, Any] = {
        "repo": repo,
        "security_advisories": [],
        "recent_releases": [],
        "relevant_commits": [],
    }

    headers = _get_headers()

    with httpx.Client(timeout=10.0, headers=headers) as client:
        # 1. Check Security Advisories
        try:
            adv_resp = client.get(f"{GITHUB_API_BASE}/repos/{repo}/security-advisories")
            if adv_resp.status_code == 200:
                for adv in adv_resp.json()[:limit]:
                    cvss_data = adv.get("cvss") or {}
                    score = cvss_data.get("score")
                    sev = adv.get("severity", "unknown").capitalize()
                    cvss_str = f"{score} ({sev})" if score else f"未公表 ({sev})"
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
        except Exception as e:
            signals["security_advisories_error"] = str(e)

        # 2. Check Recent Releases (look for security pre-announcements or RC releases)
        try:
            rel_resp = client.get(f"{GITHUB_API_BASE}/repos/{repo}/releases?per_page={limit}")
            if rel_resp.status_code == 200:
                for rel in rel_resp.json():
                    signals["recent_releases"].append({
                        "tag_name": rel.get("tag_name"),
                        "name": rel.get("name"),
                        "published_at": rel.get("published_at"),
                        "body": (rel.get("body") or "")[:400],
                        "html_url": rel.get("html_url"),
                    })
        except Exception as e:
            signals["recent_releases_error"] = str(e)

        # 3. Check Commits for security fixes/signals
        try:
            commits_resp = client.get(f"{GITHUB_API_BASE}/repos/{repo}/commits?per_page=20")
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
        except Exception as e:
            signals["relevant_commits_error"] = str(e)

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
            return {"error": f"Advisory {ref_or_ghsa_id} not found in {repo} (status {resp.status_code})"}

        # Otherwise treat as commit SHA
        url = f"{GITHUB_API_BASE}/repos/{repo}/commits/{ref_or_ghsa_id}"
        resp = client.get(url)
        if resp.status_code == 200:
            data = resp.json()
            files_diff = []
            for f in data.get("files", [])[:5]:  # limit to top 5 modified files
                files_diff.append({
                    "filename": f.get("filename"),
                    "status": f.get("status"),
                    "patch": (f.get("patch") or "")[:2000],  # capture diff for trigger analysis
                })
            return {
                "sha": data.get("sha"),
                "message": data.get("commit", {}).get("message"),
                "files": files_diff,
            }
        return {"error": f"Commit {ref_or_ghsa_id} not found in {repo} (status {resp.status_code})"}
