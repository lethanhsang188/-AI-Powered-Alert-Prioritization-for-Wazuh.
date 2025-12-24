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

# Cấu hình lọc SOC-grade (mới)
SOC_MIN_LEVEL = get_env_int("MIN_LEVEL", 3)  # Mức rule tối thiểu để bao gồm (cho custom rules)
SOC_MAX_LEVEL = get_env_int("MAX_LEVEL", 7)  # Mức rule tối đa cho lọc custom rule
INCLUDE_RULE_IDS = [rid.strip() for rid in get_env("INCLUDE_RULE_IDS", "100100").split(",") if rid.strip()]  # Danh sách rule IDs được phân tách bằng dấu phẩy để bao gồm
INCLUDE_RULE_ID_PREFIX = get_env("INCLUDE_RULE_ID_PREFIX", "1001")  # Tiền tố tùy chọn cho rule IDs
ALWAYS_REEVALUATE_LEVEL_GTE = get_env_int("ALWAYS_REEVALUATE_LEVEL_GTE", 7)  # Luôn bao gồm và đánh giá lại alerts có level >= này
LOOKBACK_MINUTES_CORRELATION = get_env_int("LOOKBACK_MINUTES_CORRELATION", 30)  # Cửa sổ lookback cho tương quan
DEDUP_WINDOW_MINUTES = get_env_int("DEDUP_WINDOW_MINUTES", 10)  # Cửa sổ deduplication tính bằng phút
WAZUH_POLL_INTERVAL_SEC = get_env_int("WAZUH_POLL_INTERVAL_SEC", 8)
WAZUH_REALTIME_MODE = get_env_bool("WAZUH_REALTIME_MODE", False)
WAZUH_REALTIME_INTERVAL_SEC = get_env_float("WAZUH_REALTIME_INTERVAL_SEC", 1.0)
WAZUH_PAGE_LIMIT = get_env_int("WAZUH_PAGE_LIMIT", 200)
WAZUH_MAX_BATCHES = get_env_int("WAZUH_MAX_BATCHES", 5)  # Lấy tối đa 5 batches mỗi chu kỳ polling
WAZUH_LOOKBACK_MINUTES = get_env_int("WAZUH_LOOKBACK_MINUTES", 10)  # Cho chế độ realtime demo: chỉ lấy alerts từ N phút cuối
WAZUH_DEMO_MODE = get_env_bool("WAZUH_DEMO_MODE", False)  # Bật chế độ demo: bỏ qua cursor, sử dụng LOOKBACK_MINUTES
WAZUH_START_FROM_NOW = get_env_bool("WAZUH_START_FROM_NOW", False)  # Bắt đầu từ bây giờ thay vì cursor cũ (để testing)
CURSOR_PATH = get_env("CURSOR_PATH", "/app/state/cursor.json")
# WAZUH_API_VERIFY_SSL có thể là:
# - "true"/"false" (boolean) - xác thực với CA hệ thống hoặc tắt
# - Đường dẫn đến file cert (string) - xác thực với chứng chỉ tùy chỉnh
_verify_api_ssl_raw = os.getenv("WAZUH_API_VERIFY_SSL", "")
if not _verify_api_ssl_raw:
    WAZUH_API_VERIFY_SSL = True  # Mặc định là True để bảo mật
elif _verify_api_ssl_raw.lower() in ("true", "1", "yes", "on"):
    WAZUH_API_VERIFY_SSL = True
elif _verify_api_ssl_raw.lower() in ("false", "0", "no", "off"):
    WAZUH_API_VERIFY_SSL = False
else:
    # Xử lý như đường dẫn file
    WAZUH_API_VERIFY_SSL = _verify_api_ssl_raw
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "")
WAZUH_INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "")
# WAZUH_INDEXER_VERIFY_SSL có thể là:
# - "true"/"false" (boolean) - xác thực với CA hệ thống hoặc tắt
# - Đường dẫn đến file cert (string) - xác thực với chứng chỉ tùy chỉnh
_verify_ssl_raw = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "")
if not _verify_ssl_raw:
    # Mặc định là WAZUH_API_VERIFY_SSL nếu không được đặt
    WAZUH_INDEXER_VERIFY_SSL = WAZUH_API_VERIFY_SSL
elif _verify_ssl_raw.lower() in ("true", "1", "yes", "on"):
    WAZUH_INDEXER_VERIFY_SSL = True
elif _verify_ssl_raw.lower() in ("false", "0", "no", "off"):
    WAZUH_INDEXER_VERIFY_SSL = False
else:
    # Xử lý như đường dẫn file
    WAZUH_INDEXER_VERIFY_SSL = _verify_ssl_raw
WAZUH_ALERTS_INDEX = get_env("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")

# Xác thực xác thực Wazuh
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

# Xác thực tổng trọng số triage bằng 1.0 (cho phép sai số dấu chấm động nhỏ)
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
CORRELATION_TIME_WINDOW_MINUTES = get_env_int("CORRELATION_TIME_WINDOW_MINUTES", 15)  # Mặc định 15, có thể ghi đè bằng LOOKBACK_MINUTES_CORRELATION

# Enrichment config
ENRICHMENT_ENABLE = get_env_bool("ENRICHMENT_ENABLE", True)
GEOIP_ENABLE = get_env_bool("GEOIP_ENABLE", True)

# LLM Cache config
LLM_CACHE_ENABLE = get_env_bool("LLM_CACHE_ENABLE", True)
LLM_CACHE_TTL_SECONDS = get_env_int("LLM_CACHE_TTL_SECONDS", 3600)  # 1 giờ
LLM_CACHE_MAX_SIZE = get_env_int("LLM_CACHE_MAX_SIZE", 1000)

# Active Response (containment) config - disabled by default for safety.
# To enable, set environment variable ENABLE_ACTIVE_RESPONSE=true and configure credentials securely.
ENABLE_ACTIVE_RESPONSE = get_env_bool("ENABLE_ACTIVE_RESPONSE", False)
# Method: "ssh" (execute remote firewall command) or "pfsense_api" (use pfSense API) or "wazuh" (use Wazuh active-response)
ACTIVE_RESPONSE_METHOD = get_env("ACTIVE_RESPONSE_METHOD", "ssh")
# Comma-separated list of management hosts/IPs that will receive block commands (optional)
ACTIVE_RESPONSE_TARGET_HOSTS = [h.strip() for h in get_env("ACTIVE_RESPONSE_TARGET_HOSTS", "").split(",") if h.strip()]
# Allowlist: IPs that must NEVER be blocked (comma-separated)
ACTIVE_RESPONSE_ALLOWLIST = [ip.strip() for ip in get_env("ACTIVE_RESPONSE_ALLOWLIST", "").split(",") if ip.strip()]
# SSH settings (if using SSH method) - supply path to private key on the service machine (DO NOT store private keys in repo)
ACTIVE_RESPONSE_SSH_USER = get_env("ACTIVE_RESPONSE_SSH_USER", "")
# For backwards compatibility, if not set default to "admin"
if not ACTIVE_RESPONSE_SSH_USER:
    ACTIVE_RESPONSE_SSH_USER = "admin"
ACTIVE_RESPONSE_SSH_KEY_PATH = get_env("ACTIVE_RESPONSE_SSH_KEY_PATH", "")
# Auto-unblock window (minutes); 0 = manual unblock
ACTIVE_RESPONSE_AUTO_UNBLOCK_MINUTES = get_env_int("ACTIVE_RESPONSE_AUTO_UNBLOCK_MINUTES", 0)
# Require manual confirmation via external operator before executing blocks (default true)
ACTIVE_RESPONSE_REQUIRE_CONFIRM = get_env_bool("ACTIVE_RESPONSE_REQUIRE_CONFIRM", True)

# Escalation numeric rules
# Number of "high" alerts within correlation window to auto-escalate to P1
ESCALATION_HIGH_COUNT = get_env_int("ESCALATION_HIGH_COUNT", 3)
# Score threshold to consider an alert "high" for escalation counting (default use TRIAGE_THRESHOLD)
ESCALATION_SCORE_HIGH = get_env_float("ESCALATION_SCORE_HIGH", 0.7)
#
# pfSense / pf table name used for runtime blocking via pfctl
ACTIVE_RESPONSE_PF_TABLE = get_env("ACTIVE_RESPONSE_PF_TABLE", "WAZUH_BLOCK")

# Agent priority settings: list of agent IDs to prioritize and threshold to auto-block
# Example: PRIORITY_AGENT_IDS="002" for pfSense agent id 002
PRIORITY_AGENT_IDS = [aid.strip() for aid in get_env("PRIORITY_AGENT_IDS", "002").split(",") if aid.strip()]
# If triage score >= PRIORITY_AGENT_THRESHOLD for prioritized agent, allow auto-block even if REQUIRE_CONFIRM true
PRIORITY_AGENT_THRESHOLD = get_env_float("PRIORITY_AGENT_THRESHOLD", 0.7)
# Confirmation heuristics for Active Response
CONFIRM_SURICATA_SEVERITY = get_env_int("CONFIRM_SURICATA_SEVERITY", 3)
CONFIRM_LLM_CONFIDENCE = get_env_float("CONFIRM_LLM_CONFIDENCE", 0.6)
CONFIRM_FLOW_PKTS_TO_SERVER = get_env_int("CONFIRM_FLOW_PKTS_TO_SERVER", 100)
CONFIRM_CORRELATION_SIZE = get_env_int("CONFIRM_CORRELATION_SIZE", 3)

# Fast-block settings (immediate block criteria for prioritized agents, e.g., pfSense)
# FAST_BLOCK_RULE_IDS: comma-separated rule IDs or signature IDs that should trigger immediate block
FAST_BLOCK_RULE_IDS = [rid.strip() for rid in get_env("FAST_BLOCK_RULE_IDS", "").split(",") if rid.strip()]
# FAST_BLOCK_TAGS: tags from triage.llm_tags or alert.tags that should trigger immediate block
FAST_BLOCK_TAGS = [t.strip().lower() for t in get_env("FAST_BLOCK_TAGS", "sql_injection,web_attack,xss,csrf,command_injection,lfi,syn,dos,brute_force").split(",") if t.strip()]
# FAST_BLOCK_UA_TOOLS: user-agent substrings (comma-separated) indicating automated tools (e.g., sqlmap) => immediate block
FAST_BLOCK_UA_TOOLS = [u.strip().lower() for u in get_env("FAST_BLOCK_UA_TOOLS", "sqlmap,nikto").split(",") if u.strip()]
# If True, fast-blocking still requires explicit confirm; default False (fast-block bypasses confirm)
FAST_BLOCK_REQUIRE_CONFIRM = get_env_bool("FAST_BLOCK_REQUIRE_CONFIRM", False)
# Fast-block suricata severity threshold (if suricata action=allowed and severity >= this => fast-block)
FAST_BLOCK_SURICATA_SEVERITY = get_env_int("FAST_BLOCK_SURICATA_SEVERITY", 1)

# Active Response suppression (to avoid spam)
# Time window to suppress repeated notifications/blocks for same target IP (seconds)
AR_SUPPRESSION_WINDOW_SECONDS = get_env_int("AR_SUPPRESSION_WINDOW_SECONDS", 600)
# Maximum number of notifications/active-response executions for same target IP within suppression window
AR_MAX_NOTIFICATIONS = get_env_int("AR_MAX_NOTIFICATIONS", 3)
# When suppression is active, aggregate notifications and send one message per this many events
NOTIFICATION_AGGREGATE_SIZE = get_env_int("NOTIFICATION_AGGREGATE_SIZE", 5)

# pfSense rule toggle support (use pfSsh.php to enable/disable a firewall rule index)
# If set (integer), pipeline will toggle this rule index on the management host instead of using pfctl table adds.
ACTIVE_RESPONSE_PF_RULE_ID = get_env_int("ACTIVE_RESPONSE_PF_RULE_ID", 0)
# Auto-disable minutes for pfSsh.php toggled rule (0 = don't auto-disable)
ACTIVE_RESPONSE_PF_RULE_AUTO_DISABLE_MINUTES = get_env_int("ACTIVE_RESPONSE_PF_RULE_AUTO_DISABLE_MINUTES", 5)

# Instead of toggling by numeric index, you can toggle a rule by its description (descr).
# Example: set ACTIVE_RESPONSE_PF_RULE_DESCR="DDOS_EMERGENCY_BLOCK" to enable/disable that rule.
ACTIVE_RESPONSE_PF_RULE_DESCR = get_env("ACTIVE_RESPONSE_PF_RULE_DESCR", "")
# Optional: remote script paths on the management host (pfSense) that will be executed
# Example: set ACTIVE_RESPONSE_PF_REMOTE_ENABLE_SCRIPT="/root/enable_ddos.php"
# and ACTIVE_RESPONSE_PF_REMOTE_DISABLE_SCRIPT="/root/disable_ddos.php"
ACTIVE_RESPONSE_PF_REMOTE_ENABLE_SCRIPT = get_env("ACTIVE_RESPONSE_PF_REMOTE_ENABLE_SCRIPT", "")
ACTIVE_RESPONSE_PF_REMOTE_DISABLE_SCRIPT = get_env("ACTIVE_RESPONSE_PF_REMOTE_DISABLE_SCRIPT", "")

