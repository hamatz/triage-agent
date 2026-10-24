import os
from typing import Optional
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()

DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

def get_model_name(role: str = "default") -> str:
    """Get Gemini model name by agent role, falling back to GEMINI_MODEL.
    
    Roles:
      - 'default'
      - 'planner'
      - 'researcher'
      - 'triage'
    """
    env_key = f"GEMINI_MODEL_{role.upper()}"
    return os.getenv(env_key, DEFAULT_MODEL)

def get_gemini_api_key() -> Optional[str]:
    """Get Gemini API Key from environment."""
    return os.getenv("GEMINI_API_KEY")

def get_github_token() -> Optional[str]:
    """Get GitHub Token from environment (optional)."""
    return os.getenv("GITHUB_TOKEN")
