"""Động cơ tương quan alert để nhóm các cảnh báo liên quan."""
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class AlertCorrelationEngine:
    """
    Tương quan các cảnh báo liên quan dựa trên các thuộc tính chung.
    
    Nhóm các cảnh báo theo:
    - Cùng source IP (campaign - tất cả loại tấn công) - MỚI: cho phát hiện chuỗi cung ứng
    - Cùng source IP + cùng loại tấn công
    - Cùng destination + cùng loại tấn công
    - Cùng signature + cửa sổ thời gian
    - Cùng mẫu rule + cửa sổ thời gian
    """
    
    def __init__(self, time_window_minutes: int = 15):
        """
        Initialize correlation engine.
        
        Args:
            time_window_minutes: Time window for correlation (default: 15 minutes)
        """
        self.time_window_minutes = time_window_minutes
        self.alert_groups: Dict[str, List[Dict[str, Any]]] = {}
        self.group_metadata: Dict[str, Dict[str, Any]] = {}
        self._cleanup_interval = timedelta(hours=1)
        self._last_cleanup = datetime.utcnow()
    
    def _generate_group_key(
        self,
        alert: Dict[str, Any],
        correlation_type: str = "source_attack"
    ) -> Optional[str]:
        """
        Generate correlation key for grouping alerts.
        
        Args:
            alert: Normalized alert dictionary
            correlation_type: Type of correlation (source_attack, destination_attack, signature)
            
        Returns:
            Group key string or None
        """
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        http_context = alert.get("http")
        suricata_alert = alert.get("suricata_alert")
        
        srcip = alert.get("srcip", "")
        dstip = agent.get("ip", "")
        rule_id = str(rule.get("id", ""))
        
        # Trích loại tấn công (dùng loại tấn công đã chuẩn hóa nếu có, fallback sang rule groups)
        attack_type = alert.get("attack_type_normalized")
        if not attack_type:
            rule_groups = rule.get("groups", [])
            # Priority: specific attack tags > rule groups
            if "sql_injection" in rule_groups or "sqlinjection" in rule_groups:
                attack_type = "sql_injection"
            elif "command_injection" in rule_groups:
                attack_type = "command_injection"
            elif "xss" in rule_groups:
                attack_type = "xss"
            elif "lfi" in rule_groups or "local_file_inclusion" in rule_groups:
                attack_type = "lfi"
            elif "file_upload" in rule_groups or "webshell" in rule_groups:
                attack_type = "file_upload"
            elif "path_traversal" in rule_groups:
                attack_type = "path_traversal"
            elif "csrf" in rule_groups:
                attack_type = "csrf"
            elif "ssh_bruteforce" in rule_groups or ("ssh" in rule_groups and "bruteforce" in rule_groups):
                attack_type = "ssh_bruteforce"
            elif "bruteforce" in rule_groups or "authentication_failed" in rule_groups:
                attack_type = "brute_force"
            elif "syn_flood" in rule_groups or ("syn" in rule_groups and "flood" in rule_groups):
                attack_type = "syn_flood"
            elif "dos" in rule_groups or "ddos" in rule_groups:
                attack_type = "dos"
            elif "web_attack" in rule_groups:
                attack_type = "web_attack"
            elif "attack" in rule_groups:
                attack_type = "attack"
        
        # Tạo khóa tương quan dựa trên loại
        if correlation_type == "source_campaign":
            # MỚI: Nhóm tất cả tấn công từ cùng một nguồn (cho phát hiện chuỗi cung ứng)
            if srcip:
                return f"campaign:src:{srcip}"
        elif correlation_type == "source_attack":
            if srcip and attack_type:
                return f"src:{srcip}:attack:{attack_type}"
        elif correlation_type == "destination_attack":
            if dstip and attack_type:
                return f"dst:{dstip}:attack:{attack_type}"
        elif correlation_type == "signature":
            if suricata_alert and suricata_alert.get("signature_id"):
                sig_id = suricata_alert.get("signature_id")
                return f"sig:{sig_id}"
        elif correlation_type == "rule_pattern":
            if rule_id:
                return f"rule:{rule_id}"
        
        return None
    
    def _is_in_time_window(
        self,
        alert_timestamp: str,
        group_timestamp: str,
        window_minutes: int
    ) -> bool:
        """Kiểm tra xem alert có nằm trong cửa sổ thời gian của nhóm hay không."""
        try:
            alert_dt = datetime.fromisoformat(alert_timestamp.replace("Z", "+00:00"))
            group_dt = datetime.fromisoformat(group_timestamp.replace("Z", "+00:00"))
            
            time_diff = abs((alert_dt - group_dt).total_seconds() / 60)
            return time_diff <= window_minutes
        except Exception:
            return False
    
    def _cleanup_old_groups(self):
        """Remove correlation groups older than cleanup interval."""
        now = datetime.utcnow()
        if (now - self._last_cleanup) < self._cleanup_interval:
            return
        
        cutoff_time = now - timedelta(hours=2)  # Keep groups for 2 hours
        
        groups_to_remove = []
        for group_key, metadata in self.group_metadata.items():
            try:
                group_time = datetime.fromisoformat(
                    metadata.get("first_seen", "").replace("Z", "+00:00")
                )
                if group_time < cutoff_time:
                    groups_to_remove.append(group_key)
            except Exception:
                groups_to_remove.append(group_key)
        
        for group_key in groups_to_remove:
            self.alert_groups.pop(group_key, None)
            self.group_metadata.pop(group_key, None)
        
        self._last_cleanup = now
        logger.debug(
            f"Cleaned up {len(groups_to_remove)} old correlation groups",
            extra={
                "component": "correlation",
                "action": "cleanup",
                "removed_groups": len(groups_to_remove)
            }
        )
    
    def correlate(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate alert with existing groups.
        
        Args:
            alert: Normalized alert dictionary
            
        Returns:
            Dict with correlation info:
            - is_correlated: bool
            - group_key: str (if correlated)
            - group_size: int (number of alerts in group)
            - first_seen: str (timestamp of first alert in group)
            - attack_pattern: str (type of attack pattern)
        """
        self._cleanup_old_groups()
        
        timestamp = alert.get("@timestamp", "")
        if not timestamp:
            return {
                "is_correlated": False,
                "group_key": None,
                "group_size": 1,
                "first_seen": timestamp,
                "attack_pattern": None
            }
        
        # Try different correlation types (priority order)
        # source_campaign first to detect supply chain attacks (multiple attack types from same source)
        correlation_types = ["source_campaign", "source_attack", "destination_attack", "signature", "rule_pattern"]
        
        for corr_type in correlation_types:
            group_key = self._generate_group_key(alert, corr_type)
            if not group_key:
                continue
            
            # Check if group exists and is within time window
            if group_key in self.alert_groups:
                group = self.alert_groups[group_key]
                metadata = self.group_metadata[group_key]
                
                # Check time window
                first_seen = metadata.get("first_seen", timestamp)
                if self._is_in_time_window(timestamp, first_seen, self.time_window_minutes):
                    # Add alert to group
                    group.append(alert)
                    metadata["last_seen"] = timestamp
                    metadata["count"] = len(group)
                    
                    logger.debug(
                        f"Alert correlated with existing group",
                        extra={
                            "component": "correlation",
                            "action": "correlate",
                            "group_key": group_key,
                            "correlation_type": corr_type,
                            "group_size": len(group)
                        }
                    )
                    
                    # Check for supply chain attack (multiple attack types in campaign)
                    supply_chain_info = None
                    if corr_type == "source_campaign":
                        supply_chain_info = self._detect_supply_chain_attack(group)
                    
                    correlation_result = {
                        "is_correlated": True,
                        "group_key": group_key,
                        "group_size": len(group),
                        "first_seen": first_seen,
                        "attack_pattern": metadata.get("attack_pattern"),
                        "correlation_type": corr_type
                    }
                    
                    if supply_chain_info:
                        correlation_result["supply_chain"] = supply_chain_info
                    
                    return correlation_result
            
            # Create new group
            self.alert_groups[group_key] = [alert]
            
            # Extract attack pattern (use normalized attack type if available, fallback to rule groups)
            attack_pattern = alert.get("attack_type_normalized")
            if not attack_pattern:
                rule = alert.get("rule", {})
                rule_groups = rule.get("groups", [])
                if "sql_injection" in rule_groups or "sqlinjection" in rule_groups:
                    attack_pattern = "sql_injection"
                elif "command_injection" in rule_groups:
                    attack_pattern = "command_injection"
                elif "xss" in rule_groups:
                    attack_pattern = "xss"
                elif "lfi" in rule_groups or "local_file_inclusion" in rule_groups:
                    attack_pattern = "lfi"
                elif "file_upload" in rule_groups or "webshell" in rule_groups:
                    attack_pattern = "file_upload"
                elif "csrf" in rule_groups:
                    attack_pattern = "csrf"
                elif "ssh_bruteforce" in rule_groups or ("ssh" in rule_groups and "bruteforce" in rule_groups):
                    attack_pattern = "ssh_bruteforce"
                elif "bruteforce" in rule_groups or "authentication_failed" in rule_groups:
                    attack_pattern = "brute_force"
                elif "syn_flood" in rule_groups or ("syn" in rule_groups and "flood" in rule_groups):
                    attack_pattern = "syn_flood"
                elif "dos" in rule_groups or "ddos" in rule_groups:
                    attack_pattern = "dos"
                elif "web_attack" in rule_groups:
                    attack_pattern = "web_attack"
            
            # For source_campaign, check supply chain after adding first alert
            supply_chain_info = None
            if corr_type == "source_campaign":
                supply_chain_info = self._detect_supply_chain_attack([alert])
            
            self.group_metadata[group_key] = {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "count": 1,
                "attack_pattern": attack_pattern,
                "correlation_type": corr_type,
                "supply_chain": supply_chain_info
            }
        
        return {
            "is_correlated": False,
            "group_key": None,
            "group_size": 1,
            "first_seen": timestamp,
            "attack_pattern": None,
            "supply_chain": None
        }
    
    def get_group_summary(self, group_key: str) -> Optional[Dict[str, Any]]:
        """Get summary of correlation group."""
        if group_key not in self.alert_groups:
            return None
        
        group = self.alert_groups[group_key]
        metadata = self.group_metadata[group_key]
        
        # Calculate statistics
        scores = [a.get("triage_score", 0.0) for a in group if "triage_score" in a]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        max_score = max(scores) if scores else 0.0
        
        return {
            "group_key": group_key,
            "count": len(group),
            "first_seen": metadata.get("first_seen"),
            "last_seen": metadata.get("last_seen"),
            "attack_pattern": metadata.get("attack_pattern"),
            "correlation_type": metadata.get("correlation_type"),
            "avg_score": round(avg_score, 3),
            "max_score": round(max_score, 3),
            "time_span_minutes": self._calculate_time_span(
                metadata.get("first_seen"),
                metadata.get("last_seen")
            )
        }
    
    def _calculate_time_span(self, first_seen: str, last_seen: str) -> Optional[int]:
        """Calculate time span in minutes."""
        try:
            first_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            last_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            return int((last_dt - first_dt).total_seconds() / 60)
        except Exception:
            return None
    
    def _detect_supply_chain_attack(self, campaign_group: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Detect supply chain attack: Multiple attack types from same source.
        
        Args:
            campaign_group: List of alerts from same source (campaign group)
            
        Returns:
            Dict with supply chain info if detected, None otherwise:
            - is_supply_chain: bool
            - attack_types: List[str] (unique attack types)
            - attack_type_counts: Dict[str, int] (count per attack type)
            - severity: str (high/medium/low)
        """
        if len(campaign_group) < 2:
            return None
        
        # Import here to avoid circular dependency
        from src.common.attack_type_normalizer import normalize_attack_type
        
        attack_types: Set[str] = set()
        attack_type_counts: Dict[str, int] = {}
        
        for alert in campaign_group:
            attack_type = normalize_attack_type(alert)
            if attack_type:
                attack_types.add(attack_type)
                attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
        
        # Supply chain = 2+ different attack types from same source
        if len(attack_types) >= 2:
            # Determine severity
            severity = "low"
            if len(attack_types) >= 3:
                severity = "high"
            elif len(attack_types) == 2:
                # Check if it's a critical combination
                critical_combos = [
                    {"xss", "sql_injection"},
                    {"sql_injection", "command_injection"},
                    {"xss", "command_injection"},
                    {"path_traversal", "command_injection"},
                    {"sql_injection", "file_upload"},
                    {"xss", "file_upload"},
                    {"lfi", "command_injection"},
                    {"lfi", "file_upload"},
                    {"brute_force", "sql_injection"},
                    {"ssh_bruteforce", "command_injection"},
                    {"dos", "sql_injection"},  # DoS to distract + SQL injection
                    {"syn_flood", "xss"}  # DoS + web attack
                ]
                if attack_types in critical_combos:
                    severity = "high"
                else:
                    severity = "medium"
            
            logger.info(
                f"Supply chain attack detected: {len(attack_types)} attack types from same source",
                extra={
                    "component": "correlation",
                    "action": "supply_chain_detected",
                    "attack_types": list(attack_types),
                    "attack_type_counts": attack_type_counts,
                    "severity": severity,
                    "total_alerts": len(campaign_group)
                }
            )
            
            return {
                "is_supply_chain": True,
                "attack_types": sorted(list(attack_types)),
                "attack_type_counts": attack_type_counts,
                "severity": severity,
                "total_alerts": len(campaign_group)
            }
        
        return None


# Global correlation engine instance
_correlation_engine: Optional[AlertCorrelationEngine] = None


def get_correlation_engine() -> AlertCorrelationEngine:
    """Get or create global correlation engine instance."""
    global _correlation_engine
    if _correlation_engine is None:
        from src.common.config import CORRELATION_TIME_WINDOW_MINUTES
        _correlation_engine = AlertCorrelationEngine(
            time_window_minutes=CORRELATION_TIME_WINDOW_MINUTES
        )
    return _correlation_engine


def correlate_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlate alert with existing groups.
    
    Args:
        alert: Normalized alert dictionary
        
    Returns:
        Correlation info dict
    """
    engine = get_correlation_engine()
    return engine.correlate(alert)

