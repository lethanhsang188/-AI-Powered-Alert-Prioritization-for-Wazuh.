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


# Project paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


# Wazuh config
WAZUH_API_URL = get_env("WAZUH_API_URL", "http://localhost:55000")
WAZUH_API_USER = get_env("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS = get_env("WAZUH_API_PASS", "")
WAZUH_API_TOKEN = get_env("WAZUH_API_TOKEN", "")
WAZUH_MIN_LEVEL = get_env_int("WAZUH_MIN_LEVEL", 7)

# SOC-grade filtering config (new)
SOC_MIN_LEVEL = get_env_int("MIN_LEVEL", 3)  # Minimum rule level to include (for custom rules)
SOC_MAX_LEVEL = get_env_int("MAX_LEVEL", 7)  # Maximum rule level for custom rule filtering
INCLUDE_RULE_IDS = [rid.strip() for rid in get_env("INCLUDE_RULE_IDS", "100100").split(",") if rid.strip()]  # Comma-separated list of rule IDs to include
INCLUDE_RULE_ID_PREFIX = get_env("INCLUDE_RULE_ID_PREFIX", "1001")  # Optional prefix for rule IDs
ALWAYS_REEVALUATE_LEVEL_GTE = get_env_int("ALWAYS_REEVALUATE_LEVEL_GTE", 7)  # Always include and re-evaluate alerts with level >= this
LOOKBACK_MINUTES_CORRELATION = get_env_int("LOOKBACK_MINUTES_CORRELATION", 30)  # Lookback window for correlation
DEDUP_WINDOW_MINUTES = get_env_int("DEDUP_WINDOW_MINUTES", 10)  # Deduplication window in minutes
WAZUH_POLL_INTERVAL_SEC = get_env_int("WAZUH_POLL_INTERVAL_SEC", 8)
WAZUH_REALTIME_MODE = get_env_bool("WAZUH_REALTIME_MODE", False)
WAZUH_REALTIME_INTERVAL_SEC = get_env_float("WAZUH_REALTIME_INTERVAL_SEC", 1.0)
WAZUH_PAGE_LIMIT = get_env_int("WAZUH_PAGE_LIMIT", 200)
WAZUH_MAX_BATCHES = get_env_int("WAZUH_MAX_BATCHES", 5)  # Fetch up to 5 batches per polling cycle
WAZUH_LOOKBACK_MINUTES = get_env_int("WAZUH_LOOKBACK_MINUTES", 10)  # For demo realtime mode: only fetch alerts from last N minutes
WAZUH_DEMO_MODE = get_env_bool("WAZUH_DEMO_MODE", False)  # Enable demo mode: ignore cursor, use LOOKBACK_MINUTES
WAZUH_START_FROM_NOW = get_env_bool("WAZUH_START_FROM_NOW", False)  # Start from now instead of old cursor (for testing)
CURSOR_PATH = get_env("CURSOR_PATH", "/app/state/cursor.json")
# WAZUH_API_VERIFY_SSL can be:
# - "true"/"false" (boolean) - verify with system CA or disable
# - Path to cert file (string) - verify with custom certificate
_verify_api_ssl_raw = os.getenv("WAZUH_API_VERIFY_SSL", "")
if not _verify_api_ssl_raw:
    WAZUH_API_VERIFY_SSL = True  # Default to True for security
elif _verify_api_ssl_raw.lower() in ("true", "1", "yes", "on"):
    WAZUH_API_VERIFY_SSL = True
elif _verify_api_ssl_raw.lower() in ("false", "0", "no", "off"):
    WAZUH_API_VERIFY_SSL = False
else:
    # Treat as file path
    WAZUH_API_VERIFY_SSL = _verify_api_ssl_raw
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "")
WAZUH_INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "")
# WAZUH_INDEXER_VERIFY_SSL can be:
# - "true"/"false" (boolean) - verify with system CA or disable
# - Path to cert file (string) - verify with custom certificate
_verify_ssl_raw = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "")
if not _verify_ssl_raw:
    # Default to WAZUH_API_VERIFY_SSL if not set
    WAZUH_INDEXER_VERIFY_SSL = WAZUH_API_VERIFY_SSL
elif _verify_ssl_raw.lower() in ("true", "1", "yes", "on"):
    WAZUH_INDEXER_VERIFY_SSL = True
elif _verify_ssl_raw.lower() in ("false", "0", "no", "off"):
    WAZUH_INDEXER_VERIFY_SSL = False
else:
    # Treat as file path
    WAZUH_INDEXER_VERIFY_SSL = _verify_ssl_raw
WAZUH_ALERTS_INDEX = get_env("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")

# Validate Wazuh authentication
if not WAZUH_API_TOKEN and (not WAZUH_API_USER or not WAZUH_API_PASS):
    raise ValueError(
        "Wazuh authentication required: either WAZUH_API_TOKEN or "
        "both WAZUH_API_USER and WAZUH_API_PASS must be set"
    )

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

# Telegram Bot config
TELEGRAM_BOT_TOKEN = get_env("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = get_env("TELEGRAM_CHAT_ID", "")

# API config
API_PORT = get_env_int("API_PORT", 8088)

# General config
ENV_NAME = get_env("ENV_NAME", "dev")
LOG_LEVEL = get_env("LOG_LEVEL", "INFO")
LOCAL_TIMEZONE = get_env("LOCAL_TIMEZONE", "Asia/Ho_Chi_Minh")

# Correlation config
CORRELATION_ENABLE = get_env_bool("CORRELATION_ENABLE", True)
CORRELATION_TIME_WINDOW_MINUTES = get_env_int("CORRELATION_TIME_WINDOW_MINUTES", 15)  # Default 15, can override with LOOKBACK_MINUTES_CORRELATION

# Enrichment config
ENRICHMENT_ENABLE = get_env_bool("ENRICHMENT_ENABLE", True)
GEOIP_ENABLE = get_env_bool("GEOIP_ENABLE", True)

# LLM Cache config
LLM_CACHE_ENABLE = get_env_bool("LLM_CACHE_ENABLE", True)
LLM_CACHE_TTL_SECONDS = get_env_int("LLM_CACHE_TTL_SECONDS", 3600)  # 1 hour
LLM_CACHE_MAX_SIZE = get_env_int("LLM_CACHE_MAX_SIZE", 1000)

