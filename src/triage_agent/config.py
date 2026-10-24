import os
from typing import Optional
from dotenv import load_dotenv
from google import genai

# Load .env file if present
load_dotenv()


def get_model_name(role: str = "default") -> str:
    """Get Gemini model name by agent role, dynamically reading GEMINI_MODEL.
    
    Roles:
      - 'default'
      - 'planner'
      - 'researcher'
      - 'triage'
    """
    default_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    if role == "default":
        return default_model
    env_key = f"GEMINI_MODEL_{role.upper()}"
    return os.getenv(env_key, default_model)


def get_gemini_api_key() -> Optional[str]:
    """Get Gemini API Key from environment."""
    return os.getenv("GEMINI_API_KEY")


def get_github_token() -> Optional[str]:
    """Get GitHub Token from environment (optional)."""
    return os.getenv("GITHUB_TOKEN")


def is_vertex_ai_mode() -> bool:
    """Check if Vertex AI mode is enabled via environment variables."""
    return os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in ("true", "1") or \
           os.getenv("VERTEX_AI", "").lower() in ("true", "1")


def is_llm_configured() -> bool:
    """Check if either Vertex AI or Gemini API key is configured."""
    if is_vertex_ai_mode():
        project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("VERTEX_PROJECT")
        return bool(project)
    return bool(get_gemini_api_key())


def get_genai_client() -> genai.Client:
    """Instantiate a genai.Client configured for either standard Gemini API or Vertex AI.
    
    If GOOGLE_GENAI_USE_VERTEXAI or VERTEX_AI is 'true', uses Vertex AI backend.
    Otherwise uses standard Gemini API with GEMINI_API_KEY.
    """
    if is_vertex_ai_mode():
        project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("VERTEX_PROJECT")
        location = os.getenv("GOOGLE_CLOUD_REGION") or os.getenv("VERTEX_LOCATION", "us-central1")
        if not project:
            raise ValueError(
                "Vertex AI mode requested but GOOGLE_CLOUD_PROJECT (or VERTEX_PROJECT) is not set."
            )
        return genai.Client(vertexai=True, project=project, location=location)

    api_key = get_gemini_api_key()
    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY is not set. Please set GEMINI_API_KEY in .env or configure Vertex AI (GOOGLE_GENAI_USE_VERTEXAI=true)."
        )
    return genai.Client(api_key=api_key)


def call_with_retry(fn, max_retries: int = 3, initial_delay: float = 2.0):
    """Execute a function with exponential backoff retry on transient 503 / 429 API errors."""
    import time
    delay = initial_delay
    last_err = None

    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as e:
            err_str = str(e)
            is_transient = "503" in err_str or "UNAVAILABLE" in err_str or \
                           "429" in err_str or "RESOURCE_EXHAUSTED" in err_str or \
                           "high demand" in err_str.lower()
            if not is_transient or attempt == max_retries:
                raise e
            last_err = e
            time.sleep(delay)
            delay *= 2.0

    if last_err:
        raise last_err
