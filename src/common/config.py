"""Configuration loading and validation helpers."""
import os
from typing import Optional
from dotenv import load_dotenv

# Load .env file
load_dotenv()


def get_env(key: str, default: Optional[str] = None) -> str:
    """Get environment variable or return default."""
    value = os.getenv(key, default)
    if value is None:
        raise ValueError(f"Required environment variable {key} is not set")
    return value


def get_env_int(key: str, default: int = 0) -> int:
    """Get environment variable as integer."""
    value = os.getenv(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def get_env_float(key: str, default: float = 0.0) -> float:
    """Get environment variable as float."""
    value = os.getenv(key)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def get_env_bool(key: str, default: bool = False) -> bool:
    """Get environment variable as boolean."""
    value = os.getenv(key, "").lower()
    if not value:
        return default
    return value in ("true", "1", "yes", "on")


# Wazuh config
WAZUH_API_URL = get_env("WAZUH_API_URL", "http://localhost:55000")
WAZUH_API_USER = get_env("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS = get_env("WAZUH_API_PASS", "")
WAZUH_API_TOKEN = get_env("WAZUH_API_TOKEN", "")
WAZUH_MIN_LEVEL = get_env_int("WAZUH_MIN_LEVEL", 7)
WAZUH_POLL_INTERVAL_SEC = get_env_int("WAZUH_POLL_INTERVAL_SEC", 8)
WAZUH_PAGE_LIMIT = get_env_int("WAZUH_PAGE_LIMIT", 200)
CURSOR_PATH = get_env("CURSOR_PATH", "/app/state/cursor.json")

# Validate Wazuh authentication
if not WAZUH_API_TOKEN and (not WAZUH_API_USER or not WAZUH_API_PASS):
    raise ValueError(
        "Wazuh authentication required: either WAZUH_API_TOKEN or "
        "both WAZUH_API_USER and WAZUH_API_PASS must be set"
    )

# TheHive config
THEHIVE_URL = get_env("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = get_env("THEHIVE_API_KEY", "")

# Validate TheHive API key
if not THEHIVE_API_KEY:
    raise ValueError("THEHIVE_API_KEY is required")

# LLM config
OPENAI_API_BASE = get_env("OPENAI_API_BASE", "https://api.openai.com/v1")
OPENAI_API_KEY = get_env("OPENAI_API_KEY", "")
LLM_MODEL = get_env("LLM_MODEL", "gpt-4o-mini")
LLM_MAX_TOKENS = get_env_int("LLM_MAX_TOKENS", 512)
LLM_TIMEOUT_SEC = get_env_int("LLM_TIMEOUT_SEC", 20)
LLM_ENABLE = get_env_bool("LLM_ENABLE", False)

# Triage config
TRIAGE_THRESHOLD = get_env_float("TRIAGE_THRESHOLD", 0.70)
HEURISTIC_WEIGHT = get_env_float("HEURISTIC_WEIGHT", 0.6)
LLM_WEIGHT = get_env_float("LLM_WEIGHT", 0.4)

# Validate triage weights sum to 1.0 (allow small floating point errors)
if abs(HEURISTIC_WEIGHT + LLM_WEIGHT - 1.0) > 0.001:
    raise ValueError(
        f"HEURISTIC_WEIGHT ({HEURISTIC_WEIGHT}) + LLM_WEIGHT ({LLM_WEIGHT}) must equal 1.0"
    )

# n8n config
N8N_WEBHOOK_URL = get_env("N8N_WEBHOOK_URL", "")
N8N_WEBHOOK_PUBLIC_URL = get_env("N8N_WEBHOOK_PUBLIC_URL", "http://localhost:5678")

# API config
API_PORT = get_env_int("API_PORT", 8088)

# General config
ENV_NAME = get_env("ENV_NAME", "dev")
LOG_LEVEL = get_env("LOG_LEVEL", "INFO")

