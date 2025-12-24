"""Client API Wazuh 4.14.0 để thu thập cảnh báo."""
import json
import logging
import os
from base64 import b64encode
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import urllib3
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError, RequestException
import time
import threading

from src.common.config import (
    BASE_DIR,
    WAZUH_API_URL,
    WAZUH_API_USER,
    WAZUH_API_PASS,
    WAZUH_API_TOKEN,
    WAZUH_API_VERIFY_SSL,
    WAZUH_INDEXER_URL,
    WAZUH_INDEXER_USER,
    WAZUH_INDEXER_PASS,
    WAZUH_INDEXER_VERIFY_SSL,
    WAZUH_ALERTS_INDEX,
    WAZUH_MIN_LEVEL,
    WAZUH_POLL_INTERVAL_SEC,
    WAZUH_PAGE_LIMIT,
    WAZUH_MAX_BATCHES,
    WAZUH_LOOKBACK_MINUTES,
    WAZUH_DEMO_MODE,
    WAZUH_START_FROM_NOW,
    CURSOR_PATH,
    LOCAL_TIMEZONE,
    SOC_MIN_LEVEL,
    SOC_MAX_LEVEL,
    INCLUDE_RULE_IDS,
    INCLUDE_RULE_ID_PREFIX,
    ALWAYS_REEVALUATE_LEVEL_GTE,
)
from src.common.web import RetrySession
from src.common.timezone import utc_iso_to_local

logger = logging.getLogger(__name__)

class _AlertThrottle:
    """
    Simple in-memory throttle/count window for alerts.
    Tracks counts per key with TTL (window_seconds). Not persistent across restarts.
    Thread-safe for simple concurrent use.
    """
    def __init__(self):
        self._store = {}  # key -> (count, expiry_ts)
        self._lock = threading.Lock()

    def increment_and_get(self, key: str, window_seconds: int = 300) -> int:
        """
        Increment counter for key and return new count.
        Resets counter when expiry passed.
        """
        now = time.time()
        with self._lock:
            entry = self._store.get(key)
            if entry:
                count, expiry = entry
                if now > expiry:
                    # expired -> reset
                    count = 1
                    expiry = now + window_seconds
                else:
                    count = count + 1
            else:
                count = 1
                expiry = now + window_seconds

            self._store[key] = (count, expiry)
            return count

    def get_count(self, key: str) -> int:
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return 0
            count, expiry = entry
            if time.time() > expiry:
                # expired
                self._store.pop(key, None)
                return 0
            return count

    def reset(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)


class WazuhClient:
    """Client for Wazuh 4.14.0 API."""

    def __init__(self):
        """Initialize Wazuh client with API and indexer connections."""
        self.base_url = WAZUH_API_URL.rstrip("/")
        self.indexer_url = WAZUH_INDEXER_URL.rstrip("/")
        self.alerts_index = WAZUH_ALERTS_INDEX

        # Thiết lập session API
        self.session = RetrySession()
        self._setup_api_session()

        # Thiết lập session indexer
        self.indexer_session = RetrySession()
        self._setup_indexer_session()

        logger.info(
            "Wazuh client initialized",
            extra={
                "component": "wazuh_client",
                "action": "init",
                "api_url": self.base_url,
                "indexer_url": self.indexer_url,
                "alerts_index": self.alerts_index,
                "timezone": LOCAL_TIMEZONE,
                "min_level": WAZUH_MIN_LEVEL,
            },
        )
        # In-memory throttle to limit noisy alerts (per src_ip+rule) for specific agents/rules
        # Structure: simple counter with expiry to enforce windowed caps (not persisted across restarts)
        self._alert_throttle = _AlertThrottle()
        # Track which aggregate suppression notices we've already emitted per key to avoid floods
        self._suppression_notice_emitted = set()

    def _setup_api_session(self) -> None:
        """Configure API session with authentication and SSL."""
        self._apply_ssl_config(self.session, WAZUH_API_VERIFY_SSL, "api")

        # Thử token auth trước, fallback về basic auth nếu không có
        if WAZUH_API_TOKEN:
            self._apply_bearer_token(WAZUH_API_TOKEN, source="environment variable")
        elif WAZUH_API_USER and WAZUH_API_PASS:
            self._fallback_basic_auth()
        else:
            raise ValueError(
                "Either WAZUH_API_TOKEN or both WAZUH_API_USER and WAZUH_API_PASS must be set"
            )

    def _setup_indexer_session(self) -> None:
        """Configure indexer session with authentication and SSL."""
        self._apply_ssl_config(
            self.indexer_session, WAZUH_INDEXER_VERIFY_SSL, "indexer"
        )

        if WAZUH_INDEXER_USER and WAZUH_INDEXER_PASS:
            from requests.auth import HTTPBasicAuth

            self.indexer_session.auth = HTTPBasicAuth(
                WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS
            )
            logger.info(
                "Using Wazuh indexer authentication with user '%s'", WAZUH_INDEXER_USER
            )
        else:
            raise ValueError(
                "Both WAZUH_INDEXER_USER and WAZUH_INDEXER_PASS must be set"
            )

    def _apply_ssl_config(
        self, session: RetrySession, verify_value: Any, component: str
    ) -> None:
        """Apply SSL verification configuration to session."""
        if verify_value == "" or verify_value is None:
            verify_value = True

        if isinstance(verify_value, str):
            verify_lower = verify_value.lower().strip()
            if verify_lower in ("false", "0", "no", "off", "disable", "disabled"):
                verify_value = False
            elif verify_lower in ("true", "1", "yes", "on", "enable", "enabled"):
                verify_value = True
            elif os.path.exists(verify_value):
                verify_value = verify_value
            else:
                logger.warning(
                    "SSL verify value '%s' is not a valid boolean or file path, defaulting to True",
                    verify_value,
                )
                verify_value = True

        # Sửa: Sử dụng tham số session, không dùng self.session
        session.verify = verify_value

        if verify_value is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            if component == "api":
                logger.warning(
                    "Wazuh API SSL verification disabled. Consider enabling WAZUH_API_VERIFY_SSL for production."
                )
            else:
                logger.warning(
                    "Wazuh indexer SSL verification disabled. Enable WAZUH_INDEXER_VERIFY_SSL for production deployments."
                )
        elif isinstance(verify_value, str):
            # Xác thực với file chứng chỉ tùy chỉnh
            if not os.path.exists(verify_value) or not os.path.isfile(verify_value):
                logger.error(
                    "Wazuh certificate file not found: %s",
                    verify_value,
                    extra={
                        "component": "wazuh_client",
                        "action": "ssl_config_error",
                        "cert_file": verify_value,
                        "component_type": component,
                    },
                )
                raise FileNotFoundError(
                    f"Wazuh {component} certificate file not found: {verify_value}"
                )
            logger.info(
                "Using Wazuh %s certificate: %s",
                component,
                verify_value,
                extra={
                    "component": "wazuh_client",
                    "action": "ssl_config",
                    "cert_file": verify_value,
                    "component_type": component,
                },
            )

    def _apply_bearer_token(self, token: str, *, source: str) -> None:
        """Apply bearer token to session headers."""
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        # Đảm bảo basic auth bị xóa nếu trước đó đã cấu hình
        self.session.auth = None
        logger.info("Using Wazuh API token authentication (%s)", source)

    def _fallback_basic_auth(self) -> None:
        """Fallback: chuyển sang HTTP Basic authentication."""
        from requests.auth import HTTPBasicAuth

        self.session.auth = HTTPBasicAuth(WAZUH_API_USER, WAZUH_API_PASS)
        logger.info("Using Wazuh API Basic authentication")

    def _retrieve_token(self) -> Optional[str]:
        """Obtain JWT token from Wazuh authenticate endpoint."""
        auth_endpoint = f"{self.base_url}/security/user/authenticate"
        basic = f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode("utf-8")
        headers = {
            "Authorization": f"Basic {b64encode(basic).decode('utf-8')}",
            "Content-Type": "application/json",
        }

        try:
            response = self.session.post(auth_endpoint, headers=headers, json={})
            response.raise_for_status()
        except HTTPError as http_err:
            logger.error("Wazuh token request failed with HTTP error: %s", http_err)
            raise
        except RequestException as req_err:
            logger.error("Error connecting to Wazuh token endpoint: %s", req_err)
            raise

        try:
            data = response.json()
        except json.JSONDecodeError as json_err:
            logger.error("Invalid JSON from Wazuh token endpoint: %s", json_err)
            raise

        token = data.get("data", {}).get("token")
        if not token:
            raise ValueError("Wazuh authentication response did not include a token")

        return token

    def _load_cursor(self) -> Optional[Dict[str, Any]]:
        """Load last processed position from cursor file."""
        if not os.path.exists(CURSOR_PATH):
            return None

        try:
            with open(CURSOR_PATH, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as exc:
            logger.warning("Failed to load cursor: %s", exc)
            return None

        if isinstance(data, dict):
            cursor: Dict[str, Any] = {}
            timestamp = data.get("timestamp")
            sort_values = data.get("sort")
            if isinstance(timestamp, str):
                cursor["timestamp"] = timestamp
            if isinstance(sort_values, list):
                cursor["sort"] = sort_values
            return cursor or None

        if isinstance(data, str):
            return {"timestamp": data}

        return None

    def _save_cursor(self, cursor: Dict[str, Any]) -> None:
        """Persist last processed position to cursor file."""
        try:
            os.makedirs(os.path.dirname(CURSOR_PATH), exist_ok=True)
        except OSError as exc:
            logger.error("Failed to prepare cursor directory: %s", exc)
            return

        try:
            logger.debug("Persisting cursor state to %s: %s", CURSOR_PATH, cursor)
            with open(CURSOR_PATH, "w") as f:
                json.dump(cursor, f)
        except IOError as exc:
            logger.error("Failed to save cursor: %s", exc)

    def _classify_alert_by_level(self, alert: Dict[str, Any]) -> str:
        """
        Classify alert by rule level for different filtering strategies.
        
        SOC Perspective: Phân loại alerts để áp dụng filtering strategies khác nhau.
        
        Args:
            alert: Normalized alert dictionary
            
        Returns:
            "high" (>= 7), "medium" (5-6), or "low" (3-4)
        """
        rule_level = alert.get("rule", {}).get("level", 0)
        
        if rule_level >= 7:
            return "high"
        elif rule_level >= 5:
            return "medium"
        else:
            return "low"

    def _is_internal_ip(self, ip: str) -> bool:
        """
        Check if IP is internal (RFC 1918).
        
        Args:
            ip: IP address string
            
        Returns:
            True if internal IP, False otherwise
        """
        if not ip:
            return False
        
        try:
            from ipaddress import ip_address, AddressValueError
            addr = ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except (ValueError, AddressValueError):
            # Fallback: kiểm tra đơn giản
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            try:
                first = int(parts[0])
                second = int(parts[1])
                # RFC 1918 private ranges
                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
                # Localhost
                if first == 127:
                    return True
            except ValueError:
                return False
            return False

    def _apply_level_specific_filter(self, alert: Dict[str, Any], level_class: str) -> Tuple[bool, str]:
        """
        Apply level-specific field-based filtering.
        
        SOC Perspective: Mỗi level có filtering strategy riêng:
        - High: Check false positive indicators
        - Medium: Check important indicators
        - Low: Strict filtering - require multiple indicators
        
        Args:
            alert: Normalized alert dictionary
            level_class: "high", "medium", or "low"
            
        Returns:
            Tuple of (should_process, reason)
        """
        if level_class == "high":
            # Mức Cao: Kiểm tra các chỉ dấu false positive
            http_context = alert.get("http", {})
            source = alert.get("source", {})
            src_ip = source.get("ip", "") or alert.get("srcip", "")
            
            # Lọc nếu: IP nội bộ + HTTP 404 (có thể là false positive do internal scan)
            if src_ip and self._is_internal_ip(src_ip):
                if http_context and http_context.get("status") == "404":
                    return False, "Internal IP with HTTP 404 (likely false positive from internal scan)"
            
            # Luôn xử lý các cảnh báo mức cao (nhưng có thể gắn nhãn các false positive rõ ràng)
            return True, "High-level alert passed filter"
        
        elif level_class == "medium":
            # Mức Trung bình: Kiểm tra các chỉ dấu quan trọng
            suricata_alert = alert.get("suricata_alert", {})
            http_context = alert.get("http", {})
            rule_groups = alert.get("rule", {}).get("groups", [])
            
            # Phải có ít nhất một chỉ dấu
            has_indicators = (
                (suricata_alert and isinstance(suricata_alert.get("severity"), (int, float)) and suricata_alert.get("severity", 0) >= 2) or
                (http_context and http_context.get("url")) or
                any(group in rule_groups for group in ["suricata", "web_attack", "ids", "attack", "web_scan", "recon"])
            )
            
            if has_indicators:
                return True, "Medium-level alert with important indicators"
            else:
                return False, "Medium-level alert without important indicators"
        
        else:  # low
            # Mức Thấp: Lọc chặt - phải có nhiều chỉ dấu
            suricata_alert = alert.get("suricata_alert", {})
            http_context = alert.get("http", {})
            flow = alert.get("flow", {})
            rule_groups = alert.get("rule", {}).get("groups", [])
            
            indicator_count = 0
            
            # Suricata severity >= 2
            if suricata_alert and isinstance(suricata_alert.get("severity"), (int, float)) and suricata_alert.get("severity", 0) >= 2:
                indicator_count += 1
            
            # Ngữ cảnh HTTP
            if http_context and http_context.get("url"):
                indicator_count += 1
            
            # Ngữ cảnh flow
            if flow and flow.get("src_ip"):
                indicator_count += 1
            
            # Các nhóm rule quan trọng
            if any(group in rule_groups for group in ["suricata", "web_attack", "ids", "attack", "web_scan", "recon"]):
                indicator_count += 1
            
            # Cần ít nhất 2 chỉ dấu cho các cảnh báo mức thấp
            if indicator_count >= 2:
                return True, f"Low-level alert with {indicator_count} indicators"
            else:
                return False, f"Low-level alert with only {indicator_count} indicator(s) (need at least 2)"

    def _apply_field_based_filter(self, alert: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Apply general field-based filtering after normalization.
        
        SOC Perspective: Lọc lại alerts dựa trên field indicators trong JSON,
        bất kể rule level. Đây là stage cuối cùng trước khi process.
        
        Args:
            alert: Normalized alert dictionary
            
        Returns:
            Tuple of (should_process, reason)
        """
        # Trích xuất các trường
        http_context = alert.get("http", {})
        suricata_alert = alert.get("suricata_alert", {})
        source = alert.get("source", {})
        src_ip = source.get("ip", "") or alert.get("srcip", "")
        
        # Lọc 1: IP nội bộ + HTTP 404 = Có khả năng false positive
        if src_ip and self._is_internal_ip(src_ip):
            if http_context and http_context.get("status") == "404":
                return False, "Internal IP with HTTP 404 (likely false positive)"
        
        # Lọc 2: Suricata action = \"blocked\" = Đã được giảm thiểu (vẫn xử lý nhưng chú ý)
        if suricata_alert and suricata_alert.get("action") == "blocked":
            return True, "Suricata blocked (already mitigated, but processing for awareness)"
        
        # Lọc 3: Kiểm tra chỉ dấu tấn công trong các cảnh báo mức thấp
        rule_level = alert.get("rule", {}).get("level", 0)
        if rule_level < 7:
            # Hàm trợ giúp chuyển severity sang int (xử lý string \"2\" -> int 2)
            def _to_int_safe(value):
                if isinstance(value, (int, float)):
                    return int(value)
                if isinstance(value, str):
                    try:
                        return int(float(value.strip()))
                    except (ValueError, AttributeError):
                        return 0
                return 0
            
            # Kiểm tra mức độ Suricata (chuyển string sang int nếu cần)
            suricata_severity = 0
            if suricata_alert:
                severity_raw = suricata_alert.get("severity")
                suricata_severity = _to_int_safe(severity_raw)
            
            # Kiểm tra category Suricata
            suricata_category = ""
            if suricata_alert:
                suricata_category = (suricata_alert.get("category", "") or "").lower()
            
            # Kiểm tra signature Suricata
            suricata_signature = ""
            if suricata_alert:
                suricata_signature = (suricata_alert.get("signature", "") or "").lower()
            
            # Kiểm tra event_type
            event_type = alert.get("event_type", "").lower()
            
            # Kiểm tra mẫu URL (mở rộng để bao gồm tất cả loại tấn công)
            url_patterns = [
                "sqli", "xss", "union", "select", "exec", "cmd", "shell", "csrf", "cross-site",
                "path", "traversal", "rce", "injection", "lfi", "file inclusion",
                "upload", "webshell", "etc/passwd", "proc/self", "../", "..\\",
                "include=", "file=", "cmd=", "exec="
            ]
            url_has_pattern = False
            if http_context and http_context.get("url"):
                url_lower = http_context.get("url", "").lower()
                url_has_pattern = any(pattern in url_lower for pattern in url_patterns)
            
            # Kiểm tra user agent để phát hiện công cụ tấn công
            user_agent_has_tool = False
            if http_context and http_context.get("user_agent"):
                user_agent_lower = http_context.get("user_agent", "").lower()
                attack_tools = ["sqlmap", "nmap", "nikto", "burp", "metasploit", "w3af", "acunetix"]
                user_agent_has_tool = any(tool in user_agent_lower for tool in attack_tools)
            
            # Chỉ dấu tấn công: severity >= 2, category tấn công, signature tấn công, event_type=alert, mẫu URL, hoặc công cụ tấn công
            attack_signature_patterns = [
                "xss", "sql", "sqli", "csrf", "exploit", "injection", "traversal", "rce", "command",
                "brute", "dos", "ddos", "lfi", "file inclusion", "file upload", "webshell",
                "syn flood", "synflood", "flood", "ssh", "authentication failed", "login attempt"
            ]
            has_attack_indicators = (
                (suricata_severity >= 2) or
                (suricata_category and any(cat in suricata_category for cat in ["web application attack", "exploit", "malware", "trojan", "virus", "worm", "dos", "network scan", "reconnaissance"])) or
                (suricata_signature and any(pattern in suricata_signature.lower() for pattern in attack_signature_patterns)) or
                (event_type == "alert") or
                url_has_pattern or
                user_agent_has_tool
            )
            
            if not has_attack_indicators:
                return False, "Low-level alert without attack indicators"
        
        return True, "Passed field-based filter"

    def _normalize_alert(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Wazuh alert to common format with full SOC-required fields."""
        timestamp = raw.get("@timestamp", "")
        localized_ts = utc_iso_to_local(timestamp)

        data_section = raw.get("data", {}) if isinstance(raw.get("data", {}), dict) else {}

        # ---- Trường mạng cốt lõi (Bộ 5-tuple của SOC)
        src_ip = data_section.get("src_ip", "") or ""
        src_port = data_section.get("src_port", "") or ""
        dest_ip = data_section.get("dest_ip", "") or ""
        dest_port = data_section.get("dest_port", "") or ""
        proto = data_section.get("proto", "") or ""
        app_proto = data_section.get("app_proto", "") or ""
        direction = data_section.get("direction", "") or ""
        in_iface = data_section.get("in_iface", "") or ""
        flow_id = data_section.get("flow_id", "") or ""
        tx_id = data_section.get("tx_id", "") or ""

        # ---- Ngữ cảnh flow (rất quan trọng để tránh nhầm lẫn attacker/victim)
        flow = data_section.get("flow", {}) if isinstance(data_section.get("flow", {}), dict) else {}
        flow_src_ip = flow.get("src_ip", "") or ""
        flow_src_port = flow.get("src_port", "") or ""
        flow_dest_ip = flow.get("dest_ip", "") or ""
        flow_dest_port = flow.get("dest_port", "") or ""
        flow_pkts_toserver = flow.get("pkts_toserver", "")
        flow_pkts_toclient = flow.get("pkts_toclient", "")
        flow_bytes_toserver = flow.get("bytes_toserver", "")
        flow_bytes_toclient = flow.get("bytes_toclient", "")
        flow_start = flow.get("start", "") or ""

        # ---- Ngữ cảnh HTTP
        http_context = None
        http_data = data_section.get("http", {}) if isinstance(data_section.get("http", {}), dict) else {}
        if http_data:
            http_context = {
                "url": http_data.get("url", ""),
                "method": http_data.get("http_method", ""),
                "user_agent": http_data.get("http_user_agent", ""),
                "referer": http_data.get("http_refer", ""),
                "status": http_data.get("status", ""),
                "hostname": http_data.get("hostname", ""),
                "protocol": http_data.get("protocol", ""),
                # các trường hữu ích cho SOC có trong mẫu của bạn
                "redirect": http_data.get("redirect", ""),
                "content_type": http_data.get("http_content_type", ""),
                "length": http_data.get("length", ""),
            }

        # ---- Ngữ cảnh cảnh báo Suricata
        suricata_alert = None
        alert_data = data_section.get("alert", {}) if isinstance(data_section.get("alert", {}), dict) else {}
        if alert_data:
            suricata_alert = {
                "action": alert_data.get("action", ""),
                "gid": alert_data.get("gid", ""),
                "signature_id": alert_data.get("signature_id"),
                "rev": alert_data.get("rev", ""),
                "signature": alert_data.get("signature"),
                "category": alert_data.get("category"),
                "severity": alert_data.get("severity"),
            }

        # ---- metadata (http anomaly count)
        # ---- metadata (số lượng bất thường HTTP)
        metadata = data_section.get("metadata", {}) if isinstance(data_section.get("metadata", {}), dict) else {}
        flowints = metadata.get("flowints", {}) if isinstance(metadata.get("flowints", {}), dict) else {}
        http_anomaly_count = ""
        http_anomaly = flowints.get("http.anomaly.count")
        if http_anomaly is not None:
            http_anomaly_count = http_anomaly

        # ---- event_type cho lọc pfSense
        event_type = data_section.get("event_type", "")

        # ---- Chọn trường \"srcip\" vững chắc để tương thích pipeline
        # Ưu tiên flow.src_ip nếu có (thường là client thực), nếu không thì data.src_ip
        normalized_srcip = flow_src_ip or src_ip or raw.get("srcip", "")
        
        # ---- Trích xuất các trường bổ sung cần cho SOC
        # event_id: từ _id (nếu có trong metadata của hit)
        event_id = raw.get("_id") or raw.get("id", "")
        
        # index: từ _index (nếu có)
        index = raw.get("_index", "")
        
        # manager: trích manager.name
        manager = raw.get("manager", {})
        manager_name = manager.get("name", "") if isinstance(manager, dict) else ""
        
        # decoder: trích decoder.name
        decoder = raw.get("decoder", {})
        decoder_name = decoder.get("name", "") if isinstance(decoder, dict) else ""
        
        # location: trích trường location
        location = raw.get("location", "")
        
        # full_data: giữ toàn bộ phần _source.data
        full_data = data_section.copy() if data_section else {}
        
        # tags: suy ra từ rule.groups, data.alert.category, signature, v.v.
        tags = []
        rule_groups = raw.get("rule", {}).get("groups", [])
        if isinstance(rule_groups, list):
            tags.extend(rule_groups)
        if suricata_alert and suricata_alert.get("category"):
            category = suricata_alert.get("category", "")
            if category and category not in tags:
                tags.append(category.lower().replace(" ", "_"))
        if suricata_alert and suricata_alert.get("signature"):
            # Trích các từ khoá từ signature để gắn tag
            signature = suricata_alert.get("signature", "").lower()
            if "sql" in signature or "sqli" in signature:
                if "sql_injection" not in tags:
                    tags.append("sql_injection")
            if "xss" in signature or "cross-site" in signature:
                if "xss" not in tags:
                    tags.append("xss")
        
        # raw_json: giữ toàn bộ _source (cho bằng chứng / phân tích sâu)
        raw_json = raw.copy()

        return {
            "@timestamp": timestamp,
            "@timestamp_local": localized_ts or "",
            
            # Các trường nhận dạng bắt buộc cho SOC
            "event_id": event_id,
            "index": index,
            "manager": {"name": manager_name} if manager_name else {},
            "decoder": {"name": decoder_name} if decoder_name else {},
            "location": location,

            "agent": raw.get("agent", {}),
            "rule": raw.get("rule", {}),

            # Các trường tương thích đang được pipeline sử dụng
            "srcip": normalized_srcip,
            "user": raw.get("user", ""),
            "message": raw.get("message", ""),

            # Các trường SOC đã được làm giàu
            "src_ip": src_ip, "src_port": src_port,
            "dest_ip": dest_ip, "dest_port": dest_port,
            "proto": proto, "app_proto": app_proto,
            "direction": direction, "in_iface": in_iface,
            "flow_id": flow_id, "tx_id": tx_id,

            "flow": {
                "src_ip": flow_src_ip, "src_port": flow_src_port,
                "dest_ip": flow_dest_ip, "dest_port": flow_dest_port,
                "pkts_toserver": flow_pkts_toserver, "pkts_toclient": flow_pkts_toclient,
                "bytes_toserver": flow_bytes_toserver, "bytes_toclient": flow_bytes_toclient,
                "start": flow_start,
            },

            "http_anomaly_count": http_anomaly_count,

            "http": http_context if http_context else None,
            "suricata_alert": suricata_alert if suricata_alert else None,

            "event_type": event_type,
            
            # Các trường dữ liệu bắt buộc cho SOC
            "full_data": full_data,
            "tags": tags,

            # Giữ toàn bộ raw cho phân tích sâu / làm bằng chứng
            "raw": raw,
            "raw_json": raw_json,  # Explicit raw_json field for LLM context
        }

    def _build_indexer_query(
        self, cursor: Optional[Dict[str, Any]], agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Construct OpenSearch query payload for retrieving alerts.
        
        Args:
            cursor: Optional cursor for pagination
            agent_id: Optional agent ID to filter by (for balanced agent fetching)
        """
        from datetime import datetime, timedelta

        size = WAZUH_PAGE_LIMIT if WAZUH_PAGE_LIMIT > 0 else 200
        
        # LỌC THEO MỨC ĐỘ SOC-GRADE: Phương pháp 3 tầng
        # Tầng 1: Bao gồm alerts có mức [SOC_MIN_LEVEL..SOC_MAX_LEVEL] VÀ rule.id thuộc INCLUDE_RULE_IDS hoặc bắt đầu bằng INCLUDE_RULE_ID_PREFIX
        # Tầng 2: Luôn bao gồm alerts có mức >= ALWAYS_REEVALUATE_LEVEL_GTE (để AI đánh giá lại)
        # Tầng 3: Bao gồm alerts có chỉ báo tấn công trong trường (data.alert.category, data.alert.signature, v.v.)
        #         Điều này đảm bảo không bỏ sót tấn công thật ngay cả khi không khớp rule ID
        # Điều này đảm bảo:
        # - Các rule tuỳ chỉnh (ví dụ: 100100) với mức 3-7 được bao gồm
        # - Tất cả cảnh báo mức cao (>=7) luôn được bao gồm để AI đánh giá lại
        # - Các tấn công thật được phát hiện qua trường/nội dung được bao gồm (ngăn ngừa false negatives)
        # - Không có cảnh báo nào bị bỏ qua một cách im lặng
        
        # Xây dựng bộ lọc rule ID cho Tầng 1
        rule_id_filters = []
        if INCLUDE_RULE_IDS:
            rule_id_filters.append({"terms": {"rule.id": INCLUDE_RULE_IDS}})
        if INCLUDE_RULE_ID_PREFIX:
            # Sử dụng truy vấn prefix cho các rule ID bắt đầu bằng tiền tố
            rule_id_filters.append({"prefix": {"rule.id": INCLUDE_RULE_ID_PREFIX}})
        # Ensure pfSense specific important rule(s) are always included to avoid false negatives
        if agent_id == "002":
            # Force include rule 20101 (Suricata/snort IDS event) for pfSense agent
            rule_id_filters.append({"terms": {"rule.id": ["20101"]}})
        
        # Xây dựng bộ lọc chỉ báo tấn công cho Tầng 3
        # Những bộ lọc này phát hiện tấn công thực sự dựa trên trường/nội dung, không chỉ dựa vào rule ID
        attack_indicator_filters = []
        
        # Các hạng mục tấn công (category cảnh báo Suricata/Wazuh)
        attack_categories = [
            "Web Application Attack",
            "Attempted Information Leak",
            "Attempted User Privilege Gain",
            "Attempted Administrator Privilege Gain",
            "Exploit",
            "Malware",
            "Trojan",
            "Virus",
            "Worm",
            "Denial of Service",
            "Network Scan",
            "Reconnaissance",
        ]
        if attack_categories:
            attack_indicator_filters.append({
                "terms": {"data.alert.category": attack_categories}
            })
        
        # Các từ khóa tấn công trong signature (không phân biệt hoa thường, sử dụng wildcard)
        attack_signature_keywords = [
            # Tấn công web
            "*XSS*", "*xss*", "*Cross-Site*", "*cross-site*",
            "*SQL*", "*sqli*", "*SQL Injection*", "*sql injection*",
            "*CSRF*", "*csrf*", "*Cross-Site Request Forgery*", "*cross-site request forgery*",
            "*Command Injection*", "*command injection*",
            "*Path Traversal*", "*path traversal*",
            "*Local File Inclusion*", "*local file inclusion*", "*LFI*", "*lfi*",
            "*File Inclusion*", "*file inclusion*",
            "*File Upload*", "*file upload*", "*webshell*", "*Webshell*",
            "*Remote Code Execution*", "*RCE*",
            # Exploit
            "*Exploit*", "*exploit*", "*L2-Exploit*",
            # Brute force
            "*Brute Force*", "*brute force*", "*Bruteforce*", "*bruteforce*",
            "*SSH Brute*", "*ssh brute*", "*SSH Bruteforce*", "*ssh bruteforce*",
            "*Authentication Failed*", "*authentication failed*",
            "*Login Attempt*", "*login attempt*",
            # DoS/DDoS
            "*DoS*", "*DDoS*", "*Denial of Service*", "*denial of service*",
            "*SYN Flood*", "*syn flood*", "*SYNFlood*", "*synflood*",
            "*TCP SYN Flood*", "*tcp syn flood*",
            "*Flood Attack*", "*flood attack*",
        ]
        if attack_signature_keywords:
            # Sử dụng truy vấn wildcard để khớp signature
            signature_wildcards = [
                {"wildcard": {"data.alert.signature": keyword}} for keyword in attack_signature_keywords
            ]
            attack_indicator_filters.append({
                "bool": {
                    "should": signature_wildcards,
                    "minimum_should_match": 1
                }
            })
        
        # Cảnh báo Suricata (event_type = "alert" cho thấy phát hiện bởi IDS/IPS)
        attack_indicator_filters.append({
            "term": {"data.event_type": "alert"}
        })
        
        # Xây dựng bộ lọc chính với ba tầng
        tier_filters = [
            # Tầng 1: Level 3-7 với rule ID tuỳ chỉnh
            {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": SOC_MIN_LEVEL, "lte": SOC_MAX_LEVEL}}},
                        {
                            "bool": {
                                "should": rule_id_filters if rule_id_filters else [{"match_all": {}}],
                                "minimum_should_match": 1 if rule_id_filters else 0
                            }
                        }
                    ]
                }
            },
            # Tầng 2: Level >= ALWAYS_REEVALUATE_LEVEL_GTE (luôn bao gồm)
            {"range": {"rule.level": {"gte": ALWAYS_REEVALUATE_LEVEL_GTE}}}
        ]
        
        # Tầng 3: Chỉ báo tấn công trong trường (bao gồm ngay cả khi rule ID không khớp)
        # Chỉ áp dụng cho alerts có level >= MIN_LEVEL để tránh quá nhiều nhiễu
        if attack_indicator_filters:
            tier_filters.append({
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": SOC_MIN_LEVEL}}},  # At least MIN_LEVEL
                        {
                            "bool": {
                                "should": attack_indicator_filters,
                                "minimum_should_match": 1
                            }
                        }
                    ]
                }
            })
        
        filters: List[Dict[str, Any]] = [
            {
                "bool": {
                    "should": tier_filters,
                    "minimum_should_match": 1
                }
            }
        ]
        
        # Ghi log cấu hình Tầng 3 phục vụ debug
        if attack_indicator_filters:
            logger.debug(
                "Tier 3 attack detection enabled: %d attack indicator filters",
                len(attack_indicator_filters),
                extra={
                    "component": "wazuh_client",
                    "action": "tier3_config",
                    "attack_categories_count": len(attack_categories) if attack_categories else 0,
                    "attack_signature_keywords_count": len(attack_signature_keywords) if attack_signature_keywords else 0,
                    "tier3_enabled": True,
                },
            )
        
        # Lưu ý: Lọc theo SOC-grade ở trên có độ ưu tiên cao hơn
        # WAZUH_MIN_LEVEL cũ vẫn được dùng để tương thích ngược ở các phần khác của mã

        # Bù trừ độ trễ indexer: Wazuh Indexer thường có độ trễ 5-30s
        # Trừ vài giây từ "now" để bù trừ cho độ trễ lập chỉ mục
        INDEXER_DELAY_SECONDS = 5  # Giả sử độ trễ 5s cho việc lập chỉ mục
        now_with_delay = datetime.utcnow() - timedelta(seconds=INDEXER_DELAY_SECONDS)
        
        # Chế độ real-time: sử dụng lookback động thay vì cursor
        # Điều này được xử lý trong fetch_alerts() - cursor_state đã được thiết lập với timestamp lookback
        if WAZUH_DEMO_MODE or WAZUH_START_FROM_NOW:
            # Sử dụng timestamp cursor_state từ fetch_alerts() (đã được tính với lookback)
            if cursor and cursor.get("timestamp"):
                cutoff_iso = cursor.get("timestamp")
                filters.append({"range": {"@timestamp": {"gt": cutoff_iso}}})
                logger.debug(
                    "Real-time mode: fetching from timestamp %s (lookback calculated dynamically)",
                    cutoff_iso,
                )
            else:
                # Fallback: sử dụng LOOKBACK_MINUTES
                time_window_minutes = max(WAZUH_LOOKBACK_MINUTES, 1)
                cutoff_time = now_with_delay - timedelta(minutes=time_window_minutes)
                cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                filters.append({"range": {"@timestamp": {"gt": cutoff_iso}}})
                logger.debug(
                    "Real-time mode (fallback): fetching from last %d minutes (cutoff: %s)",
                    time_window_minutes,
                    cutoff_iso,
                )
        else:
            # Chế độ bình thường: sử dụng cursor hoặc cửa sổ 24 giờ
            time_window_hours = 24
            cutoff_time = now_with_delay - timedelta(hours=time_window_hours)
            cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            if cursor:
                sort_values = cursor.get("sort")
                if isinstance(sort_values, list) and len(sort_values) >= 2:
                    # Sử dụng search_after cho phân trang chính xác (phương pháp ưu tiên)
                    # Lưu ý: search_after sẽ được thêm sau
                    pass
                else:
                    # Fallback: chuyển sang lọc theo timestamp
                    timestamp = cursor.get("timestamp")
                    if isinstance(timestamp, str) and timestamp:
                        # Sử dụng giá trị lớn hơn giữa timestamp cursor hoặc cutoff (để tránh cursor quá cũ)
                        # Đồng thời trừ độ trễ indexer để đảm bảo không bỏ sót alerts đang được lập chỉ mục
                        cursor_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                        cursor_with_delay = cursor_dt - timedelta(seconds=INDEXER_DELAY_SECONDS)
                        cursor_delayed_iso = cursor_with_delay.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                        effective_timestamp = max(cursor_delayed_iso, cutoff_iso)
                        filters.append(
                            {"range": {"@timestamp": {"gt": effective_timestamp}}}
                        )
                        logger.debug(
                            "Using timestamp filter: @timestamp > %s (source timezone: UTC, time_window: %d hours, indexer_delay: %ds)",
                            effective_timestamp,
                            time_window_hours,
                            INDEXER_DELAY_SECONDS,
                        )
                        if effective_timestamp != timestamp:
                            logger.info(
                                "Cursor timestamp adjusted for indexer delay and time window",
                                extra={
                                    "component": "wazuh_client",
                                    "action": "cursor_adjusted",
                                    "old_cursor": timestamp,
                                    "new_cursor": effective_timestamp,
                                    "time_window_hours": time_window_hours,
                                    "indexer_delay_seconds": INDEXER_DELAY_SECONDS,
                                },
                            )
            else:
                # No cursor: use time window cutoff
                filters.append({"range": {"@timestamp": {"gt": cutoff_iso}}})
                logger.debug(
                    "No cursor found, fetching from last %d hours (cutoff: %s)",
                    time_window_hours,
                    cutoff_iso,
                )

        # Filter by agent ID if specified (for balanced agent fetching)
        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})

        # Sort by timestamp ASC, then by agent.id to ensure we get alerts from all agents
        # QUAN TRỌNG: Không dùng _source_includes hay _source_excludes - ta fetch TẤT CẢ trường từ _source
        # Điều này đảm bảo cả Agent 001 và Agent 002 nhận được tập trường đầy đủ giống nhau để lọc
        payload: Dict[str, Any] = {
            "size": size,
            "sort": [
                {"@timestamp": {"order": "asc"}},
                {"agent.id": {"order": "asc"}},  # Sort by agent ID to balance agents
                {"_id": {"order": "asc"}},
            ],
            "track_total_hits": False,
            # LƯU Ý: Chúng tôi cố tình KHÔNG chỉ định _source_includes hoặc _source_excludes
            # Điều này có nghĩa OpenSearch sẽ trả về TẤT CẢ trường từ _source, đảm bảo:
            # 1. Cả Agent 001 và Agent 002 nhận được cùng một tập trường giống nhau
            # 2. Tất cả các trường cần cho lọc đều có sẵn
            # 3. Không có trường bị vô tình loại bỏ gây ra sự không nhất quán khi lọc
            "query": {
                "bool": {
                    "filter": filters,
                    # Không loại trừ theo agent riêng; tất cả alert của agent được fetch đồng đều.
                }
            },
        }

        # Thêm search_after nếu cursor có giá trị sort (và không ở chế độ real-time)
        # Ở chế độ real-time, không dùng search_after để tránh bỏ sót alerts
        if not WAZUH_DEMO_MODE and not WAZUH_START_FROM_NOW and cursor:
            sort_values = cursor.get("sort")
            if isinstance(sort_values, list) and len(sort_values) >= 2:
                payload["search_after"] = sort_values
                logger.debug("Using search_after cursor: %s", sort_values)

        return payload

    def _fetch_alerts_for_agent(
        self, agent_id: str, cursor: Optional[Dict[str, Any]], page_size: int = 100
    ) -> tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Fetch alerts for a specific agent.
        
        Returns:
            Tuple of (normalized_alerts, cursor_for_next_batch)
        """
        payload = self._build_indexer_query(cursor, agent_id=agent_id)
        payload["size"] = page_size  # Override size for per-agent queries
        search_url = (
            f"{self.indexer_url}/{self.alerts_index.lstrip('/')}/_search"
        )

        try:
            response = self.indexer_session.post(search_url, json=payload)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.warning(
                "Failed to fetch alerts for agent %s: %s",
                agent_id,
                exc,
                extra={
                    "component": "wazuh_client",
                    "action": "agent_fetch_error",
                    "agent_id": agent_id,
                    "error": str(exc),
                },
            )
            return [], cursor

        if isinstance(data, dict) and data.get("error"):
            logger.warning(
                "Indexer error for agent %s: %s",
                agent_id,
                data.get("error"),
                extra={
                    "component": "wazuh_client",
                    "action": "agent_indexer_error",
                    "agent_id": agent_id,
                },
            )
            return [], cursor

        hits = (
            data.get("hits", {}).get("hits", [])
            if isinstance(data, dict)
            else []
        )
        
        # Ghi log số hits thô từ indexer (trước khi lọc)
        total_hits = data.get("hits", {}).get("total", {}) if isinstance(data, dict) else {}
        if isinstance(total_hits, dict):
            total_count = total_hits.get("value", len(hits))
        else:
            total_count = len(hits) if isinstance(total_hits, int) else len(hits)
        
        logger.info(
            "Fetched raw alerts from indexer for agent %s",
            agent_id,
            extra={
                "component": "wazuh_client",
                "action": "agent_raw_fetch",
                "agent_id": agent_id,
                "raw_hits_count": len(hits),
                "total_available": total_count,
            },
        )

        if not hits:
            logger.info(
                "No alerts found in indexer for agent %s",
                agent_id,
                extra={
                    "component": "wazuh_client",
                    "action": "agent_no_alerts",
                    "agent_id": agent_id,
                },
            )
            return [], cursor

        normalized = [
            self._normalize_alert(hit.get("_source", {})) for hit in hits
        ]

        # TWO-STAGE FILTERING: Classification + Field-Based Filtering
        # SOC Perspective: Phân loại theo rule level, sau đó lọc lại theo field indicators
        filtered_alerts = []
        level_filtered_count = 0
        field_filtered_count = 0
        for alert in normalized:
            rule_id = alert.get("rule", {}).get("id")
            event_type = alert.get("event_type", "")
            agent_id_alert = alert.get("agent", {}).get("id", "")
            rule_level = alert.get("rule", {}).get("level", 0)

            # Stage 1: Keep all pfSense alerts (no silent drops). Noise will be labeled later.

            # Stage 2: Classification by rule level
            level_class = self._classify_alert_by_level(alert)
            
            # Stage 3: Level-specific field-based filtering
            should_process, filter_reason = self._apply_level_specific_filter(alert, level_class)
            if not should_process:
                level_filtered_count += 1
                logger.debug(
                    "Alert filtered by level-specific filter",
                    extra={
                        "component": "wazuh_client",
                        "action": "level_filter_rejected",
                        "agent_id": agent_id_alert,
                        "rule_id": rule_id,
                        "rule_level": rule_level,
                        "level_class": level_class,
                        "filter_reason": filter_reason
                    }
                )
                continue

            # Stage 4: General field-based filtering (check all alerts)
            should_process, filter_reason = self._apply_field_based_filter(alert)
            if not should_process:
                field_filtered_count += 1
                logger.debug(
                    "Alert filtered by field-based filter",
                    extra={
                        "component": "wazuh_client",
                        "action": "field_filter_rejected",
                        "agent_id": agent_id_alert,
                        "rule_id": rule_id,
                        "rule_level": rule_level,
                        "filter_reason": filter_reason
                    }
                )
                continue

            # Add classification info to alert for later use
            alert["classification"] = {
                "level_class": level_class,
                "filter_reason": filter_reason
            }

            filtered_alerts.append(alert)

        # Log filtering statistics
        logger.info(
            "Filtering complete for agent %s: %d raw alerts -> %d after filtering",
            agent_id,
            len(normalized),
            len(filtered_alerts),
            extra={
                "component": "wazuh_client",
                "action": "agent_filtering_stats",
                "agent_id": agent_id,
                "raw_alerts": len(normalized),
                "filtered_alerts": len(filtered_alerts),
                "level_filtered": level_filtered_count,
                "field_filtered": field_filtered_count,
            },
        )

        # Post-filter aggregation/prioritization:
        # - For WebServer (agent_id '001'): aggregate repetitive web/attack alerts and emit 1 aggregated alert per 5 similar events (windowed)
        # - For pfSense (agent_id '002'): keep all alerts (no suppression), we already prioritize pfSense fetches
        try:
            if agent_id == "001":
                # attack patterns to aggregate (by rule id or tag)
                repeatable_rule_ids = {31103, 31171, 31152, 5758, 2502, 5551}  # SQLi and common web/auth brute rules
                repeatable_tag_keywords = ["sql_injection", "sqli", "ssh_bruteforce", "auth_bruteforce", "dos", "syn", "web_scanning", "web_attack"]
                aggregation_window_seconds = 300
                aggregation_batch_size = 5

                aggregated_output: List[Dict[str, Any]] = []

                for alert in filtered_alerts:
                    rule_id = alert.get("rule", {}).get("id")
                    tags = [str(t).lower() for t in (alert.get("tags") or [])]
                    # robust src detection
                    source = alert.get("source", {}) or {}
                    src_ip = source.get("ip") or alert.get("srcip") or alert.get("flow", {}).get("src_ip") or ""

                    # determine a grouping key: rule_id + src_ip + optional url path
                    http_ctx = alert.get("http") or {}
                    url_path = ""
                    if http_ctx and http_ctx.get("url"):
                        url_path = http_ctx.get("url", "").split("?")[0]

                    group_key = f"{rule_id}:{src_ip}:{url_path}"

                    # detect if this alert belongs to repeatable attack families
                    is_repeatable = False
                    try:
                        if isinstance(rule_id, int) and rule_id in repeatable_rule_ids:
                            is_repeatable = True
                    except Exception:
                        pass
                    if not is_repeatable:
                        if any(k in "|".join(tags) for k in repeatable_tag_keywords):
                            is_repeatable = True

                    if is_repeatable:
                        count = self._alert_throttle.increment_and_get(group_key, window_seconds=aggregation_window_seconds)
                        # Only emit an aggregated summary every aggregation_batch_size events
                        if count % aggregation_batch_size == 0:
                            agg = {
                                "@timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                                "agent": alert.get("agent", {}),
                                "rule": {"id": 100200, "level": alert.get("rule", {}).get("level", 6), "description": f"Aggregated {aggregation_batch_size}x events for rule {rule_id}"},
                                    "message": f"Aggregated {aggregation_batch_size} similar alerts for rule {rule_id} from source {src_ip} (window {aggregation_window_seconds}s).",
                                    # Ensure aggregated alert carries a clear source IP for Active Response and audit
                                    "srcip": src_ip,
                                    "src_ip": src_ip,
                                "tags": ["aggregated", "rate_limited", "web_attack"],
                                "group_key": group_key,
                                "aggregated_count": aggregation_batch_size,
                                "sample_alert": {
                                    "original_rule_id": rule_id,
                                    "url": http_ctx.get("url"),
                                    "severity": alert.get("rule", {}).get("level"),
                                },
                            }
                            aggregated_output.append(agg)
                        else:
                            # suppress this individual alert (it's part of an aggregation batch)
                            # do not append to aggregated_output
                            continue
                    else:
                        # Non-repeatable: keep as-is
                        aggregated_output.append(alert)

                filtered_alerts = aggregated_output
            elif agent_id == "002":
                # pfSense: do not aggregate/suppress here (we prioritize pfSense elsewhere)
                pass
        except Exception as exc:
            logger.debug("Post-filter aggregation error: %s", exc, exc_info=True)
        # Update cursor
        last_hit = hits[-1]
        cursor_payload: Dict[str, Any] = {}
        last_source = (
            last_hit.get("_source", {}) if isinstance(last_hit, dict) else {}
        )
        last_timestamp = last_source.get("@timestamp")
        if last_timestamp:
            cursor_payload["timestamp"] = last_timestamp
        sort_values = (
            last_hit.get("sort") if isinstance(last_hit, dict) else None
        )
        if isinstance(sort_values, list) and len(sort_values) >= 2:
            cursor_payload["sort"] = sort_values

        new_cursor = cursor_payload if cursor_payload else cursor

        return filtered_alerts, new_cursor

    def fetch_alerts(self, max_batches: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Fetch alerts from the Wazuh indexer and normalize them.
        
        Chế độ Demo SOC: Truy vấn từng agent riêng để đảm bảo phân phối cân bằng.
        Điều này ngăn chặn một agent duy nhất (ví dụ: pfSense) làm ngập pipeline.
        
        Args:
            max_batches: Maximum number of batches to fetch (default: WAZUH_MAX_BATCHES).
        
        Returns:
            List of normalized alerts from all agents, balanced
        """
        if max_batches is None:
            max_batches = WAZUH_MAX_BATCHES

        # SOC Real-time Mode: Bỏ cursor hoàn toàn, dùng dynamic lookback để không miss alerts
        # Dynamic lookback = poll_interval + max_indexer_delay + safety_buffer
        # Đảm bảo không miss alerts do indexer delay nhưng vẫn real-time
        if WAZUH_START_FROM_NOW or WAZUH_DEMO_MODE:
            from datetime import datetime, timedelta
            
            # Tính toán lookback động dựa trên poll interval và độ trễ indexer
            # Điều này đảm bảo không bỏ sót alerts trong khi vẫn giữ chế độ real-time
            POLL_INTERVAL_SEC = WAZUH_POLL_INTERVAL_SEC  # Default: 8 seconds
            MAX_INDEXER_DELAY_SEC = 30  # Max indexer delay (5-30s, use 30s for safety)
            SAFETY_BUFFER_SEC = 10  # Safety buffer for edge cases
            lookback_seconds = POLL_INTERVAL_SEC + MAX_INDEXER_DELAY_SEC + SAFETY_BUFFER_SEC
            
            # Nếu LOOKBACK_MINUTES được đặt và > 0, dùng nó; nếu không thì dùng giá trị tính được
            if WAZUH_LOOKBACK_MINUTES > 0:
                lookback_minutes = max(WAZUH_LOOKBACK_MINUTES, lookback_seconds / 60)
            else:
                # Tự động tính toán từ poll interval
                lookback_minutes = max(lookback_seconds / 60, 1.0)  # At least 1 minute
            
            now_with_delay = datetime.utcnow() - timedelta(minutes=lookback_minutes)
            cursor_state = {
                "timestamp": now_with_delay.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            }
            logger.info(
                "Real-time mode: Ignoring cursor, using dynamic lookback",
                extra={
                    "component": "wazuh_client",
                    "action": "realtime_no_cursor",
                    "cursor_timestamp": cursor_state.get("timestamp"),
                    "lookback_minutes": round(lookback_minutes, 2),
                    "lookback_seconds": lookback_seconds,
                    "poll_interval_sec": POLL_INTERVAL_SEC,
                    "max_indexer_delay_sec": MAX_INDEXER_DELAY_SEC,
                    "safety_buffer_sec": SAFETY_BUFFER_SEC,
                    "note": f"Dynamic lookback ensures no missed alerts while staying real-time (covers {lookback_seconds}s = {POLL_INTERVAL_SEC}s poll + {MAX_INDEXER_DELAY_SEC}s indexer + {SAFETY_BUFFER_SEC}s buffer)"
                }
            )
        else:
            cursor_state = self._load_cursor()
        
        all_alerts = []
        seen_agents = set()

        # SOC Strategy: Query each agent separately to ensure balanced distribution.
        # To prioritize pfSense (agent '002') we use per-agent page sizes (weights).
        # You can tune these weights to favor pfSense over WebServer.
        expected_agents = ["002", "001"]  # Prioritize pfSense first
        per_agent_base_sizes = {"001": 40, "002": 120}  # WebServer:40, pfSense:120 (tunable)
        # Start with per-agent size map (may be adapted below)
        per_agent_size_map = per_agent_base_sizes.copy()

        # Track cursors per agent
        agent_cursors: Dict[str, Optional[Dict[str, Any]]] = {}
        if cursor_state:
            # If we have a global cursor, use it for all agents initially
            for agent_id in expected_agents:
                agent_cursors[agent_id] = cursor_state
        else:
            for agent_id in expected_agents:
                agent_cursors[agent_id] = None

        # Track agent statistics for balanced fetching
        agent_alert_counts = {agent_id: 0 for agent_id in expected_agents}
        
        # Track critical alerts (level >= 12) for debugging
        critical_alerts_found = []
        
        for batch_num in range(max_batches):
            batch_alerts = []
            batch_agent_counts = {agent_id: 0 for agent_id in expected_agents}

            # Fetch from each agent separately
            # QUAN TRỌNG: Truy vấn TẤT CẢ agents dự kiến để đảm bảo phân phối cân bằng
            for agent_id in expected_agents:
                agent_cursor = agent_cursors.get(agent_id)
                
                # Log query attempt for each agent (for debugging)
                logger.debug(
                    "Querying agent %s (batch %d/%d)",
                    agent_id,
                    batch_num + 1,
                    max_batches,
                    extra={
                        "component": "wazuh_client",
                        "action": "agent_query_start",
                        "agent_id": agent_id,
                        "batch_number": batch_num + 1,
                    },
                )
                
                # Use per-agent page size to prioritize agents (pfSense gets larger window)
                page_size_for_agent = per_agent_size_map.get(agent_id, 50)
                alerts, new_cursor = self._fetch_alerts_for_agent(
                    agent_id, agent_cursor, page_size=page_size_for_agent
                )

                # Update cursor even if no alerts (to track progress)
                if new_cursor:
                    agent_cursors[agent_id] = new_cursor

                if alerts:
                    batch_alerts.extend(alerts)
                    seen_agents.add(agent_id)
                    batch_agent_counts[agent_id] = len(alerts)
                    agent_alert_counts[agent_id] += len(alerts)
                    
                    # Track critical alerts (level >= 12) for debugging
                    for alert in alerts:
                        rule_level = alert.get("rule", {}).get("level", 0)
                        rule_id = alert.get("rule", {}).get("id", "unknown")
                        if rule_level >= 12:
                            critical_alerts_found.append({
                                "rule_id": rule_id,
                                "rule_level": rule_level,
                                "agent_id": agent_id,
                                "timestamp": alert.get("@timestamp", "unknown")
                            })

                    logger.info(
                        "Fetched %d alerts from agent %s (batch %d/%d)",
                        len(alerts),
                        agent_id,
                        batch_num + 1,
                        max_batches,
                        extra={
                            "component": "wazuh_client",
                            "action": "agent_fetch_success",
                            "agent_id": agent_id,
                            "alert_count": len(alerts),
                            "batch_number": batch_num + 1,
                            "total_for_agent": agent_alert_counts[agent_id],
                        },
                    )
                else:
                    # Log when agent has no alerts (important for debugging)
                    logger.debug(
                        "No alerts returned for agent %s (batch %d/%d)",
                        agent_id,
                        batch_num + 1,
                        max_batches,
                        extra={
                            "component": "wazuh_client",
                            "action": "agent_fetch_empty",
                            "agent_id": agent_id,
                            "batch_number": batch_num + 1,
                            "total_for_agent": agent_alert_counts[agent_id],
                        },
                    )
            
            # Adaptive balancing: Adjust per-agent sizes if imbalance detected
            if batch_num > 0 and batch_agent_counts:
                max_count = max(batch_agent_counts.values())
                min_count = min(batch_agent_counts.values())
                if max_count > 0:
                    imbalance_ratio = max_count / (min_count + 1)
                    if imbalance_ratio > 2.0:
                        # Reduce page size for the agent producing most alerts and
                        # increase for the underrepresented agent (favor pfSense)
                        for aid, cnt in batch_agent_counts.items():
                            if cnt == max_count:
                                # scale down but keep at least 20
                                per_agent_size_map[aid] = max(20, int(per_agent_size_map.get(aid, 50) / imbalance_ratio))
                            elif cnt == min_count:
                                # boost small producers up to a cap
                                per_agent_size_map[aid] = min(200, int(per_agent_size_map.get(aid, 50) * imbalance_ratio))
                        logger.debug(
                            "Agent imbalance detected, adjusted per_agent_size_map",
                            extra={
                                "component": "wazuh_client",
                                "action": "adaptive_balancing_per_agent",
                                "imbalance_ratio": round(imbalance_ratio, 2),
                                "per_agent_size_map": per_agent_size_map,
                                "agent_counts": batch_agent_counts
                            }
                        )

            if not batch_alerts:
                # No more alerts from any agent
                logger.debug(
                    "No more alerts from any agent (batch %d/%d)",
                    batch_num + 1,
                    max_batches,
                )
                break

            # Sort by timestamp to maintain chronological order
            batch_alerts.sort(
                key=lambda x: x.get("@timestamp", ""), reverse=False
            )

            all_alerts.extend(batch_alerts)

            logger.info(
                "Fetched batch %d/%d: %d alerts from agents %s",
                batch_num + 1,
                max_batches,
                len(batch_alerts),
                list(seen_agents),
                extra={
                    "component": "wazuh_client",
                    "action": "batch_fetch",
                    "batch_number": batch_num + 1,
                    "alert_count": len(batch_alerts),
                    "agents_seen": list(seen_agents),
                    "agent_counts_this_batch": batch_agent_counts,
                    "agent_counts_total": dict(agent_alert_counts),
                },
            )

            # If we got fewer alerts than expected (based on per-agent sizes), we've likely reached the end
            expected_total_per_batch = sum(per_agent_size_map.get(aid, 50) for aid in expected_agents)
            if len(batch_alerts) < expected_total_per_batch:
                logger.debug(
                    "Reached end of alerts (got %d alerts, expected ~%d)",
                    len(batch_alerts),
                    expected_total_per_batch,
                )
                break

        # Save cursor (use the most recent cursor from any agent)
        if agent_cursors:
            # Sử dụng cursor từ agent có timestamp mới nhất
            latest_cursor = None
            latest_timestamp = None
            for agent_id, cursor in agent_cursors.items():
                if cursor and cursor.get("timestamp"):
                    cursor_ts = cursor.get("timestamp")
                    if latest_timestamp is None or cursor_ts > latest_timestamp:
                        latest_timestamp = cursor_ts
                        latest_cursor = cursor

            if latest_cursor and latest_cursor != cursor_state:
                self._save_cursor(latest_cursor)
                utc_ts = latest_cursor.get("timestamp")
                local_ts = utc_iso_to_local(utc_ts) if utc_ts else None
            elif cursor_state:
                utc_ts = cursor_state.get("timestamp")
                local_ts = utc_iso_to_local(utc_ts) if utc_ts else None
            else:
                utc_ts = None
                local_ts = None
        else:
            utc_ts = None
            local_ts = None

        # Calculate statistics across all batches
        rule_levels = []
        agent_distribution = {}
        for alert in all_alerts:
            rule_level = alert.get("rule", {}).get("level", 0)
            if rule_level:
                rule_levels.append(rule_level)

            agent = alert.get("agent", {})
            agent_id = agent.get("id", "unknown")
            agent_name = agent.get("name", "unknown")
            agent_key = f"{agent_id}:{agent_name}"
            agent_distribution[agent_key] = agent_distribution.get(agent_key, 0) + 1

        expected_total_per_batch = sum(per_agent_size_map.get(aid, 50) for aid in expected_agents)
        batches_fetched = len(all_alerts) // expected_total_per_batch + (
            1 if len(all_alerts) % expected_total_per_batch > 0 else 0
        )

        # Log critical alerts found
        if critical_alerts_found:
            logger.warning(
                "CRITICAL ALERTS (level >= 12) found during fetch",
                extra={
                    "component": "wazuh_client",
                    "action": "critical_alerts_found",
                    "critical_count": len(critical_alerts_found),
                    "critical_alerts": critical_alerts_found
                }
            )
        
        logger.info(
            "Alerts fetched and normalized successfully",
            extra={
                "component": "wazuh_client",
                "action": "fetch_complete",
                "alert_count": len(all_alerts),
                "batches_fetched": batches_fetched,
                "critical_alerts_count": len(critical_alerts_found),
                "cursor_timestamp_utc": utc_ts,
                "cursor_timestamp_local": local_ts,
                "min_rule_level": min(rule_levels) if rule_levels else None,
                "max_rule_level": max(rule_levels) if rule_levels else None,
                "avg_rule_level": round(sum(rule_levels) / len(rule_levels), 2)
                if rule_levels
                else None,
                "agent_distribution": agent_distribution,  # Show alerts per agent across all batches
                "agents_seen": list(seen_agents),  # Show which agents were included
                "agent_alert_counts": dict(agent_alert_counts),  # Total alerts per agent
                "balancing_ratio": round(
                    max(agent_alert_counts.values()) / (min(agent_alert_counts.values()) + 1), 2
                ) if agent_alert_counts.values() else None,  # Imbalance ratio
            },
        )

        return all_alerts
