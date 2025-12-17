"""Wazuh 4.14.0 API client for alert collection."""
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


class WazuhClient:
    """Client for Wazuh 4.14.0 API."""

    def __init__(self):
        """Initialize Wazuh client with API and indexer connections."""
        self.base_url = WAZUH_API_URL.rstrip("/")
        self.indexer_url = WAZUH_INDEXER_URL.rstrip("/")
        self.alerts_index = WAZUH_ALERTS_INDEX

        # Setup API session
        self.session = RetrySession()
        self._setup_api_session()

        # Setup indexer session
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

    def _setup_api_session(self) -> None:
        """Configure API session with authentication and SSL."""
        self._apply_ssl_config(self.session, WAZUH_API_VERIFY_SSL, "api")

        # Try token auth first, fallback to basic auth
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

        # Fix: Use the session parameter, not self.session
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
            # Verify with custom cert file
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
        # Ensure basic auth is cleared if previously configured
        self.session.auth = None
        logger.info("Using Wazuh API token authentication (%s)", source)

    def _fallback_basic_auth(self) -> None:
        """Fallback to HTTP Basic authentication."""
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
            # Fallback to simple check
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
            # High level: Check for false positive indicators
            http_context = alert.get("http", {})
            source = alert.get("source", {})
            src_ip = source.get("ip", "") or alert.get("srcip", "")
            
            # Filter if: Internal IP + HTTP 404 (likely false positive from internal scan)
            if src_ip and self._is_internal_ip(src_ip):
                if http_context and http_context.get("status") == "404":
                    return False, "Internal IP with HTTP 404 (likely false positive from internal scan)"
            
            # Always process high-level alerts (but can filter obvious false positives)
            return True, "High-level alert passed filter"
        
        elif level_class == "medium":
            # Medium level: Check for important indicators
            suricata_alert = alert.get("suricata_alert", {})
            http_context = alert.get("http", {})
            rule_groups = alert.get("rule", {}).get("groups", [])
            
            # Must have at least one indicator
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
            # Low level: Strict filtering - must have multiple indicators
            suricata_alert = alert.get("suricata_alert", {})
            http_context = alert.get("http", {})
            flow = alert.get("flow", {})
            rule_groups = alert.get("rule", {}).get("groups", [])
            
            indicator_count = 0
            
            # Suricata severity >= 2
            if suricata_alert and isinstance(suricata_alert.get("severity"), (int, float)) and suricata_alert.get("severity", 0) >= 2:
                indicator_count += 1
            
            # HTTP context
            if http_context and http_context.get("url"):
                indicator_count += 1
            
            # Flow context
            if flow and flow.get("src_ip"):
                indicator_count += 1
            
            # Important rule groups
            if any(group in rule_groups for group in ["suricata", "web_attack", "ids", "attack", "web_scan", "recon"]):
                indicator_count += 1
            
            # Need at least 2 indicators for low-level alerts
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
        # Extract fields
        http_context = alert.get("http", {})
        suricata_alert = alert.get("suricata_alert", {})
        source = alert.get("source", {})
        src_ip = source.get("ip", "") or alert.get("srcip", "")
        
        # Filter 1: Internal IP + HTTP 404 = Likely false positive
        if src_ip and self._is_internal_ip(src_ip):
            if http_context and http_context.get("status") == "404":
                return False, "Internal IP with HTTP 404 (likely false positive)"
        
        # Filter 2: Suricata action = "blocked" = Already mitigated (still process but note)
        if suricata_alert and suricata_alert.get("action") == "blocked":
            return True, "Suricata blocked (already mitigated, but processing for awareness)"
        
        # Filter 3: Check for attack indicators in low-level alerts
        rule_level = alert.get("rule", {}).get("level", 0)
        if rule_level < 7:
            # Helper to convert severity to int (handles string "2" -> int 2)
            def _to_int_safe(value):
                if isinstance(value, (int, float)):
                    return int(value)
                if isinstance(value, str):
                    try:
                        return int(float(value.strip()))
                    except (ValueError, AttributeError):
                        return 0
                return 0
            
            # Check Suricata severity (convert string to int if needed)
            suricata_severity = 0
            if suricata_alert:
                severity_raw = suricata_alert.get("severity")
                suricata_severity = _to_int_safe(severity_raw)
            
            # Check Suricata category
            suricata_category = ""
            if suricata_alert:
                suricata_category = (suricata_alert.get("category", "") or "").lower()
            
            # Check Suricata signature
            suricata_signature = ""
            if suricata_alert:
                suricata_signature = (suricata_alert.get("signature", "") or "").lower()
            
            # Check event_type
            event_type = alert.get("event_type", "").lower()
            
            # Check URL patterns (expanded to include CSRF and other attacks)
            url_patterns = ["sqli", "xss", "union", "select", "exec", "cmd", "shell", "csrf", "cross-site", "path", "traversal", "rce", "injection"]
            url_has_pattern = False
            if http_context and http_context.get("url"):
                url_lower = http_context.get("url", "").lower()
                url_has_pattern = any(pattern in url_lower for pattern in url_patterns)
            
            # Check user agent for attack tools
            user_agent_has_tool = False
            if http_context and http_context.get("user_agent"):
                user_agent_lower = http_context.get("user_agent", "").lower()
                attack_tools = ["sqlmap", "nmap", "nikto", "burp", "metasploit", "w3af", "acunetix"]
                user_agent_has_tool = any(tool in user_agent_lower for tool in attack_tools)
            
            # Attack indicators: severity >= 2, attack category, attack signature, event_type=alert, URL patterns, or attack tools
            has_attack_indicators = (
                (suricata_severity >= 2) or
                (suricata_category and any(cat in suricata_category for cat in ["web application attack", "exploit", "malware", "trojan", "virus", "worm", "dos", "network scan", "reconnaissance"])) or
                (suricata_signature and any(pattern in suricata_signature for pattern in ["xss", "sql", "sqli", "csrf", "exploit", "injection", "traversal", "rce", "command", "brute", "dos"])) or
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

        # ---- Core network fields (SOC 5-tuple)
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

        # ---- Flow context (very important to avoid attacker/victim inversion)
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

        # ---- HTTP context
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
                # extra SOC-useful fields present in your sample
                "redirect": http_data.get("redirect", ""),
                "content_type": http_data.get("http_content_type", ""),
                "length": http_data.get("length", ""),
            }

        # ---- Suricata alert context
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
        metadata = data_section.get("metadata", {}) if isinstance(data_section.get("metadata", {}), dict) else {}
        flowints = metadata.get("flowints", {}) if isinstance(metadata.get("flowints", {}), dict) else {}
        http_anomaly_count = ""
        http_anomaly = flowints.get("http.anomaly.count")
        if http_anomaly is not None:
            http_anomaly_count = http_anomaly

        # ---- event_type for pfSense filtering
        event_type = data_section.get("event_type", "")

        # ---- choose a robust "srcip" for pipeline compatibility
        # Prefer flow.src_ip if present (often the real client), else data.src_ip
        normalized_srcip = flow_src_ip or src_ip or raw.get("srcip", "")
        
        # ---- Extract additional SOC-required fields
        # event_id: from _id (if available in hit metadata)
        event_id = raw.get("_id") or raw.get("id", "")
        
        # index: from _index (if available)
        index = raw.get("_index", "")
        
        # manager: extract manager.name
        manager = raw.get("manager", {})
        manager_name = manager.get("name", "") if isinstance(manager, dict) else ""
        
        # decoder: extract decoder.name
        decoder = raw.get("decoder", {})
        decoder_name = decoder.get("name", "") if isinstance(decoder, dict) else ""
        
        # location: extract location field
        location = raw.get("location", "")
        
        # full_data: keep entire _source.data section
        full_data = data_section.copy() if data_section else {}
        
        # tags: derive from rule.groups, data.alert.category, signature, etc.
        tags = []
        rule_groups = raw.get("rule", {}).get("groups", [])
        if isinstance(rule_groups, list):
            tags.extend(rule_groups)
        if suricata_alert and suricata_alert.get("category"):
            category = suricata_alert.get("category", "")
            if category and category not in tags:
                tags.append(category.lower().replace(" ", "_"))
        if suricata_alert and suricata_alert.get("signature"):
            # Extract key words from signature for tagging
            signature = suricata_alert.get("signature", "").lower()
            if "sql" in signature or "sqli" in signature:
                if "sql_injection" not in tags:
                    tags.append("sql_injection")
            if "xss" in signature or "cross-site" in signature:
                if "xss" not in tags:
                    tags.append("xss")
        
        # raw_json: keep entire _source (for evidence/deep-dive)
        raw_json = raw.copy()

        return {
            "@timestamp": timestamp,
            "@timestamp_local": localized_ts or "",
            
            # SOC-required identity fields
            "event_id": event_id,
            "index": index,
            "manager": {"name": manager_name} if manager_name else {},
            "decoder": {"name": decoder_name} if decoder_name else {},
            "location": location,

            "agent": raw.get("agent", {}),
            "rule": raw.get("rule", {}),

            # compatibility fields used by pipeline today
            "srcip": normalized_srcip,
            "user": raw.get("user", ""),
            "message": raw.get("message", ""),

            # enriched SOC fields
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
            
            # SOC-required data fields
            "full_data": full_data,
            "tags": tags,

            # keep full raw for deep-dive / evidence
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
        
        # SOC-GRADE FILTERING: Three-tier approach
        # Tier 1: Include alerts with level [SOC_MIN_LEVEL..SOC_MAX_LEVEL] AND rule.id in INCLUDE_RULE_IDS or starts with INCLUDE_RULE_ID_PREFIX
        # Tier 2: Always include alerts with level >= ALWAYS_REEVALUATE_LEVEL_GTE (for AI re-evaluation)
        # Tier 3: Include alerts with attack indicators in fields (data.alert.category, data.alert.signature, etc.)
        #         This ensures we don't miss real attacks even if they don't match rule IDs
        # This ensures:
        # - Custom rules (e.g., 100100) with level 3-7 are included
        # - All high-level alerts (>=7) are always included for AI re-evaluation
        # - Real attacks detected by fields/content are included (prevents false negatives)
        # - No alerts are silently dropped
        
        # Build rule ID filters for Tier 1
        rule_id_filters = []
        if INCLUDE_RULE_IDS:
            rule_id_filters.append({"terms": {"rule.id": INCLUDE_RULE_IDS}})
        if INCLUDE_RULE_ID_PREFIX:
            # Use prefix query for rule IDs starting with prefix
            rule_id_filters.append({"prefix": {"rule.id": INCLUDE_RULE_ID_PREFIX}})
        
        # Build attack indicator filters for Tier 3
        # These detect real attacks from fields/content, not just rule IDs
        attack_indicator_filters = []
        
        # Attack categories (Suricata/Wazuh alert categories)
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
        
        # Attack keywords in signature (case-insensitive via wildcard)
        attack_signature_keywords = [
            "*XSS*", "*xss*", "*Cross-Site*", "*cross-site*",
            "*SQL*", "*sqli*", "*SQL Injection*", "*sql injection*",
            "*CSRF*", "*csrf*", "*Cross-Site Request Forgery*", "*cross-site request forgery*",
            "*Exploit*", "*exploit*", "*L2-Exploit*",
            "*Command Injection*", "*command injection*",
            "*Path Traversal*", "*path traversal*",
            "*Remote Code Execution*", "*RCE*",
            "*File Upload*", "*file upload*",
            "*Brute Force*", "*brute force*",
            "*DoS*", "*DDoS*",
        ]
        if attack_signature_keywords:
            # Use wildcard queries for signature matching
            signature_wildcards = [
                {"wildcard": {"data.alert.signature": keyword}} for keyword in attack_signature_keywords
            ]
            attack_indicator_filters.append({
                "bool": {
                    "should": signature_wildcards,
                    "minimum_should_match": 1
                }
            })
        
        # Suricata alerts (event_type = "alert" indicates IDS/IPS detection)
        attack_indicator_filters.append({
            "term": {"data.event_type": "alert"}
        })
        
        # Build main filter with three tiers
        tier_filters = [
            # Tier 1: Level 3-7 with custom rule IDs
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
            # Tier 2: Level >= ALWAYS_REEVALUATE_LEVEL_GTE (always include)
            {"range": {"rule.level": {"gte": ALWAYS_REEVALUATE_LEVEL_GTE}}}
        ]
        
        # Tier 3: Attack indicators in fields (include even if rule ID doesn't match)
        # Only apply to alerts with level >= MIN_LEVEL to avoid too much noise
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
        
        # Log Tier 3 configuration for debugging
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
        
        # Note: SOC-grade filtering above takes precedence
        # Legacy WAZUH_MIN_LEVEL is still used for backward compatibility in other parts of the code

        # Indexer delay compensation: Wazuh Indexer typically has 5-30s delay
        # Subtract a few seconds from "now" to account for indexing delay
        INDEXER_DELAY_SECONDS = 5  # Assume 5s delay for indexing
        now_with_delay = datetime.utcnow() - timedelta(seconds=INDEXER_DELAY_SECONDS)
        
        # Real-time mode: Use dynamic lookback instead of cursor
        # This is handled in fetch_alerts() - cursor_state is already set with lookback timestamp
        if WAZUH_DEMO_MODE or WAZUH_START_FROM_NOW:
            # Use cursor_state timestamp from fetch_alerts() (already calculated with lookback)
            if cursor and cursor.get("timestamp"):
                cutoff_iso = cursor.get("timestamp")
                filters.append({"range": {"@timestamp": {"gt": cutoff_iso}}})
                logger.debug(
                    "Real-time mode: fetching from timestamp %s (lookback calculated dynamically)",
                    cutoff_iso,
                )
            else:
                # Fallback: use LOOKBACK_MINUTES
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
            # Normal mode: use cursor or 24h window
            time_window_hours = 24
            cutoff_time = now_with_delay - timedelta(hours=time_window_hours)
            cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            if cursor:
                sort_values = cursor.get("sort")
                if isinstance(sort_values, list) and len(sort_values) >= 2:
                    # Use search_after for precise pagination (preferred method)
                    # Note: search_after will be added later
                    pass
                else:
                    # Fallback to timestamp-based filtering
                    timestamp = cursor.get("timestamp")
                    if isinstance(timestamp, str) and timestamp:
                        # Use max of cursor timestamp or cutoff time (to avoid very old cursor)
                        # Also subtract indexer delay to ensure we don't miss alerts being indexed
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
        # IMPORTANT: No _source_includes or _source_excludes - we fetch ALL fields from _source
        # This ensures both Agent 001 and Agent 002 get the same complete field set for filtering
        payload: Dict[str, Any] = {
            "size": size,
            "sort": [
                {"@timestamp": {"order": "asc"}},
                {"agent.id": {"order": "asc"}},  # Sort by agent ID to balance agents
                {"_id": {"order": "asc"}},
            ],
            "track_total_hits": False,
            # NOTE: We intentionally do NOT specify _source_includes or _source_excludes
            # This means OpenSearch will return ALL fields from _source, ensuring:
            # 1. Both Agent 001 and Agent 002 get identical field sets
            # 2. All fields needed for filtering are available
            # 3. No silent field drops that could cause filtering inconsistencies
            "query": {
                "bool": {
                    "filter": filters,
                    # No agent-specific exclusions; all agent alerts are fetched uniformly.
                }
            },
        }

        # Add search_after if cursor has sort values (and not in real-time mode)
        # In real-time mode, we don't use search_after to avoid missing alerts
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
        
        # Log raw hits count from indexer (before filtering)
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
        
        SOC Demo Mode: Query each agent separately to ensure balanced distribution.
        This prevents one agent (e.g., pfSense) from flooding the pipeline.
        
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
            
            # Calculate dynamic lookback based on poll interval and indexer delay
            # This ensures we don't miss alerts while staying real-time
            POLL_INTERVAL_SEC = WAZUH_POLL_INTERVAL_SEC  # Default: 8 seconds
            MAX_INDEXER_DELAY_SEC = 30  # Max indexer delay (5-30s, use 30s for safety)
            SAFETY_BUFFER_SEC = 10  # Safety buffer for edge cases
            lookback_seconds = POLL_INTERVAL_SEC + MAX_INDEXER_DELAY_SEC + SAFETY_BUFFER_SEC
            
            # If LOOKBACK_MINUTES is set and > 0, use it; otherwise use calculated value
            if WAZUH_LOOKBACK_MINUTES > 0:
                lookback_minutes = max(WAZUH_LOOKBACK_MINUTES, lookback_seconds / 60)
            else:
                # Auto-calculate from poll interval
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

        # SOC Strategy: Query each agent separately to ensure balanced distribution
        # This prevents pfSense from flooding the pipeline
        expected_agents = ["001", "002"]  # WebServer and pfSense
        base_per_agent_size = 50  # Base size for adaptive balancing
        per_agent_size = base_per_agent_size  # Start with base size

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
            # IMPORTANT: Query ALL expected agents to ensure balanced distribution
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
                
                alerts, new_cursor = self._fetch_alerts_for_agent(
                    agent_id, agent_cursor, page_size=per_agent_size
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
            
            # Adaptive balancing: Adjust per_agent_size if imbalance detected
            if batch_num > 0 and batch_agent_counts:
                max_count = max(batch_agent_counts.values())
                min_count = min(batch_agent_counts.values())
                if max_count > 0:
                    imbalance_ratio = max_count / (min_count + 1)  # +1 to avoid division by zero
                    if imbalance_ratio > 2.0:  # More than 2x difference
                        # Reduce size for high-volume agents, increase for low-volume
                        per_agent_size = max(20, min(100, int(base_per_agent_size / imbalance_ratio)))
                        logger.debug(
                            "Agent imbalance detected, adjusting per_agent_size to %d",
                            per_agent_size,
                            extra={
                                "component": "wazuh_client",
                                "action": "adaptive_balancing",
                                "imbalance_ratio": round(imbalance_ratio, 2),
                                "new_per_agent_size": per_agent_size,
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

            # If we got fewer alerts than expected, we've likely reached the end
            if len(batch_alerts) < per_agent_size * len(expected_agents):
                logger.debug(
                    "Reached end of alerts (got %d alerts, expected ~%d)",
                    len(batch_alerts),
                    per_agent_size * len(expected_agents),
                )
                break

        # Save cursor (use the most recent cursor from any agent)
        if agent_cursors:
            # Use the cursor from the agent with the most recent timestamp
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

        batches_fetched = len(all_alerts) // (per_agent_size * len(expected_agents)) + (
            1 if len(all_alerts) % (per_agent_size * len(expected_agents)) > 0 else 0
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
