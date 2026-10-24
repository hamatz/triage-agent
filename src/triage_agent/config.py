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


def get_genai_client() -> genai.Client:
    """Instantiate a genai.Client configured for either standard Gemini API or Vertex AI.
    
    If GOOGLE_GENAI_USE_VERTEXAI or VERTEX_AI is 'true', uses Vertex AI backend.
    Otherwise uses standard Gemini API with GEMINI_API_KEY.
    """
    use_vertex = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in ("true", "1") or \
                 os.getenv("VERTEX_AI", "").lower() in ("true", "1")

    if use_vertex:
        project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("VERTEX_PROJECT")
        location = os.getenv("GOOGLE_CLOUD_REGION") or os.getenv("VERTEX_LOCATION", "us-central1")
        return genai.Client(vertexai=True, project=project, location=location)

    api_key = get_gemini_api_key()
    if not api_key:
        raise ValueError("GEMINI_API_KEY is not set. Please set GEMINI_API_KEY in .env or environment, or use --dry-run.")
    return genai.Client(api_key=api_key)
