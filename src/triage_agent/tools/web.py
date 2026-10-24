import re
import httpx


def fetch_webpage_text(url: str, max_chars: int = 4000) -> str:
    """Fetch the main text content of a security blog, mailing list post, or release note URL.
    
    Args:
        url: Web URL to fetch
        max_chars: Maximum characters to return
        
    Returns:
        Cleaned plain text of the webpage
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        return f"Error: Invalid URL scheme for '{url}'"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        with httpx.Client(timeout=10.0, follow_redirects=True, headers=headers) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                return f"Error: Failed to fetch {url} (HTTP {resp.status_code})"
            
            html = resp.text

            # Strip script and style tags
            clean = re.sub(r"<script.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
            clean = re.sub(r"<style.*?</style>", " ", clean, flags=re.DOTALL | re.IGNORECASE)
            # Strip other HTML tags
            clean = re.sub(r"<[^>]+>", " ", clean)
            # Collapse whitespace
            clean = re.sub(r"\s+", " ", clean).strip()

            if len(clean) > max_chars:
                clean = clean[:max_chars] + "... [truncated]"

            return clean if clean else "No text content found on webpage."
    except Exception as e:
        return f"Error fetching webpage: {str(e)}"
