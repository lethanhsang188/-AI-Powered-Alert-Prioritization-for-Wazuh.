"""Telegram bot notification for high-severity cases."""
import logging
import math
import re
from typing import Any, Dict, Tuple, Optional

from src.common.config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TRIAGE_THRESHOLD
from src.common.web import RetrySession
from src.common.alert_formatter import format_alert_card, format_alert_card_short

logger = logging.getLogger(__name__)


def _to_int(value: Any) -> Optional[int]:
    """
    Best-effort convert a value to int (handles numeric strings from JSON).
    
    SOC Perspective: Wazuh alerts may have numeric fields as strings (e.g., "120" instead of 120).
    This helper safely converts them to int for comparisons and display.
    
    Args:
        value: Value to convert (int, float, str, None, etc.)
        
    Returns:
        int value or None if conversion fails
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            # Try exact integer match first (faster)
            if re.fullmatch(r"-?\d+", s):
                return int(s)
            # Fallback to float conversion then int
            return int(float(s))
        except (ValueError, TypeError):
            return None
    return None

# Critical attack rules that MUST notify regardless of score
# These are high-priority attacks that SOC must be aware of
CRITICAL_ATTACK_RULES = {
    # Web attacks
    "31105",  # XSS (Cross-Site Scripting)
    "31103", "31104",  # SQL Injection
    "31106",  # Successful web attack (HTTP 200)
    "31110", "31111",  # CSRF (Apache accesslog)
    "100133", "100143",  # CSRF (Suricata)
    
    # Command Injection
    "100130", "100131",  # Command Injection Attempt (DVWA exec endpoint)
    "100144", "100145", "100146",  # Command Injection (Reverse shell patterns)
    
    # File Upload / Webshell
    "100140", "100141",  # Suspicious Upload (PHP/webshell)
    "110201",  # FIM: Suspicious script uploaded (Level 10)
    "110202",  # CONFIRMED: Webshell indicators found (Level 13)
    
    # CONFIRMED Attacks (Level 13 - Highest Priority)
    "110230",  # CONFIRMED: Command execution by web server (auditd)
    "110231",  # CONFIRMED: Network connect (reverse shell) (auditd)
    
    # DoS/DDoS
    "100160",  # HTTP DoS/Flood (Level 10)
    "100170",  # TCP SYN Flood (Level 12)
}

# Critical attack tags that indicate high-priority threats
CRITICAL_ATTACK_TAGS = {
    "xss",
    "sql_injection",
    "command_injection",
    "path_traversal",
    "csrf",
}


def should_notify_critical_attack(
    alert: Dict[str, Any], triage: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Check if alert represents a critical attack that MUST notify regardless of score.
    
    This prevents false negatives where critical attacks are suppressed due to low scores.
    
    Args:
        alert: Normalized alert dictionary
        triage: Triage result dictionary
        
    Returns:
        Tuple of (should_override, reason)
    """
    rule = alert.get("rule", {})
    rule_id = str(rule.get("id", ""))
    rule_level = rule.get("level", 0)
    
    tags = triage.get("tags", [])
    threat_level = triage.get("threat_level", "").lower()
    
    # Rule-based override: Critical attack rules
    if rule_id in CRITICAL_ATTACK_RULES:
        return True, f"Critical attack rule {rule_id} (level {rule_level})"
    
    # Tag-based override: Critical attack tags
    critical_tags_found = [tag for tag in tags if tag in CRITICAL_ATTACK_TAGS]
    if critical_tags_found:
        return True, f"Critical attack tags detected: {critical_tags_found}"
    
    # Rule level override: Very high rule levels (12+) indicate critical threats
    if rule_level >= 12:
        return True, f"High rule level {rule_level} indicates critical threat"
    
    # NEW: Suricata severity override (independent of rule level)
    suricata_alert = alert.get("suricata_alert", {})
    if suricata_alert:
        suricata_severity = suricata_alert.get("severity", 0)
        alert_action = suricata_alert.get("action", "")
        if isinstance(suricata_severity, (int, float)) and suricata_severity >= 3:
            if alert_action == "allowed":
                return True, f"High Suricata severity {suricata_severity} with action 'allowed' (attack passed firewall)"
            else:
                return True, f"High Suricata severity {suricata_severity} detected"
    
    # NEW: Attack tool detection override
    http_context = alert.get("http", {})
    if http_context:
        user_agent = http_context.get("user_agent", "").lower()
        attack_tools = ["sqlmap", "nmap", "nikto", "burp", "metasploit", "w3af", "acunetix"]
        detected_tools = [tool for tool in attack_tools if tool in user_agent]
        if detected_tools:
            return True, f"Attack tool detected in user agent: {', '.join(detected_tools)}"
    
    # NEW: Supply chain attack override (highest priority)
    correlation = alert.get("correlation", {})
    if correlation and correlation.get("is_correlated"):
        supply_chain = correlation.get("supply_chain")
        if supply_chain and supply_chain.get("is_supply_chain"):
            attack_types = supply_chain.get("attack_types", [])
            attack_type_counts = supply_chain.get("attack_type_counts", {})
            total_alerts = supply_chain.get("total_alerts", 0)
            severity = supply_chain.get("severity", "medium")
            
            # Format attack types with counts
            attack_types_str = ", ".join([
                f"{at} ({attack_type_counts.get(at, 0)} alerts)"
                for at in attack_types
            ])
            
            return True, (
                f"🚨 SUPPLY CHAIN ATTACK DETECTED 🚨\n"
                f"Multiple attack types from same source: {attack_types_str}\n"
                f"Total alerts: {total_alerts}, Severity: {severity.upper()}"
            )
        
        # Correlation override (attack campaign)
        group_size = correlation.get("group_size", 1)
        if isinstance(group_size, (int, float)) and group_size >= 5:
            return True, f"Large attack campaign detected: {group_size} alerts from same source"
    
    # Threat level override: Critical/High threat levels from LLM
    if threat_level in ["critical", "high"]:
        # Additional check: Only override if LLM confidence is reasonable (> 0.3)
        llm_confidence = triage.get("llm_confidence", 0.0)
        if llm_confidence > 0.3:
            return True, f"High threat level '{threat_level}' with confidence {llm_confidence:.2f}"
    
    return False, None


def _escape_markdown_content(text: str) -> str:
    """
    Escape Markdown special characters in content.
    
    Note: We don't escape * and _ as they're used in our formatting tags.
    Only escape characters that would break parsing in free text.
    
    For Telegram Markdown mode, we need to escape:
    - Parentheses () - can break entity parsing
    - Brackets [] - can break entity parsing  
    - Backticks ` - code formatting
    - But NOT * and _ (used for bold/italic)
    """
    if not text:
        return ""
    # Escape backslashes first (must be first!)
    text = text.replace('\\', '\\\\')
    # Escape parentheses (can break entity parsing)
    text = text.replace('(', '\\(')
    text = text.replace(')', '\\)')
    # Escape brackets (can break entity parsing)
    text = text.replace('[', '\\[')
    text = text.replace(']', '\\]')
    # Escape backticks (code formatting)
    text = text.replace('`', '\\`')
    return text


def _validate_telegram_message(message: str) -> Tuple[bool, Optional[str]]:
    """
    Validate Telegram message before sending to avoid parsing errors.
    
    Checks for:
    - Message length (max 4096 chars)
    - Unescaped parentheses () in content (not in formatting tags)
    - Unescaped brackets [] in content
    - Balanced asterisks for formatting
    
    Args:
        message: Telegram message text to validate
        
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if message is valid, False otherwise
        - error_message: Error description if invalid, None if valid
    """
    if not message:
        return False, "Message is empty"
    
    # Check message length
    MAX_LENGTH = 4096
    if len(message) > MAX_LENGTH:
        return False, f"Message too long: {len(message)} characters (max {MAX_LENGTH})"
    
    # Check for balanced formatting tags (basic check)
    # Count * characters - should be even (pairs)
    asterisk_count = message.count('*')
    if asterisk_count % 2 != 0:
        return False, f"Unbalanced asterisks: {asterisk_count} (should be even for proper Markdown formatting)"
    
    # Check for unescaped problematic characters
    # We need to be smart: formatting tags like "*Title:*" can have escaped parentheses
    # But content lines should have all parentheses escaped
    
    lines = message.split('\n')
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Skip empty lines
        if not line.strip():
            continue
        
        # Check for unescaped parentheses in content
        # Formatting lines like "*Rule ID:* 110231 \\(Level 13\\)" are OK (already escaped)
        # But content like "Summary: Test (example)" should have escaped parentheses
        if '(' in line:
            # Count total parentheses and escaped parentheses
            total_open = line.count('(')
            escaped_open = line.count('\\(')
            unescaped_open = total_open - escaped_open
            
            if unescaped_open > 0:
                # Check if this is a formatting line (has *Title:* or similar)
                is_formatting_line = line.strip().startswith('*') and ':' in line
                
                if is_formatting_line:
                    # Formatting line - check if parentheses are in the value part (after :)
                    # Like "*Rule ID:* 110231 (Level 13)" - the (Level 13) should be escaped
                    if ':' in line:
                        value_part = line.split(':', 1)[1] if ':' in line else line
                        if '(' in value_part and '\\(' not in value_part:
                            return False, f"Line {line_num}: Unescaped '(' in formatting value: {line[:60]}"
                else:
                    # Content line - all parentheses should be escaped
                    return False, f"Line {line_num}: Unescaped '(' in content: {line[:60]}"
        
        # Check for unescaped brackets in content
        if '[' in line:
            total_brackets = line.count('[')
            escaped_brackets = line.count('\\[')
            unescaped_brackets = total_brackets - escaped_brackets
            
            if unescaped_brackets > 0:
                # Check if it's part of our intentional formatting (like [truncated])
                if '[truncated]' in line or '[Message truncated' in line:
                    # These should be escaped
                    return False, f"Line {line_num}: Unescaped '[' in truncation notice: {line[:60]}"
                else:
                    # Content line - brackets should be escaped
                    return False, f"Line {line_num}: Unescaped '[' in content: {line[:60]}"
    
    return True, None


def _format_telegram_message(alert: Dict[str, Any], triage: Dict[str, Any], alert_card: Dict[str, Any], alert_card_short: str, is_critical_override: bool, override_reason: str = None) -> str:
    """
    Format alert as Telegram message with Markdown.
    
    Args:
        alert: Normalized alert dictionary
        triage: Triage result dictionary
        alert_card: Formatted alert card
        alert_card_short: Short alert card text
        is_critical_override: Whether this is a critical attack override
        override_reason: Reason for override (if applicable)
        
    Returns:
        Formatted Telegram message (Markdown)
    """
    score = triage.get("score", 0.0)
    threat_level = triage.get("threat_level", "unknown").upper()
    tags = triage.get("tags", [])
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    rule_id = str(rule.get("id", ""))
    rule_level = rule.get("level", 0)
    agent_name = agent.get("name", "unknown")
    
    # Extract network and context fields early (for use throughout function)
    http_context = alert.get("http") or {}  # Handle None case
    suricata_alert = alert.get("suricata_alert") or {}
    source = alert_card.get("source", {})
    destination = alert_card.get("destination", {})
    protocol = alert_card.get("protocol", {})
    flow = alert.get("flow", {})
    src_ip = source.get("ip", "") or alert.get("srcip", "") or alert.get("src_ip", "")
    dst_ip = destination.get("ip", "") or alert.get("dest_ip", "") or agent.get("ip", "")
    
    # SOC Perspective: If critical override, threat level should reflect criticality
    # Fix inconsistency: Critical override should show as HIGH or CRITICAL, not MEDIUM
    if is_critical_override:
        # Override threat level to HIGH if it's MEDIUM or LOW
        if threat_level in ["MEDIUM", "LOW", "UNKNOWN"]:
            threat_level = "HIGH"
    
    # Format severity emoji
    severity_emoji = "⚠️"
    if threat_level == "CRITICAL":
        severity_emoji = "🔴"
    elif threat_level == "HIGH":
        severity_emoji = "🟠"
    elif threat_level == "MEDIUM":
        severity_emoji = "🟡"
    else:
        severity_emoji = "🔵"
    
    # Build message
    message_parts = []
    
    # Critical override warning
    if is_critical_override and score < TRIAGE_THRESHOLD:
        message_parts.append("🚨 *CRITICAL ATTACK OVERRIDE* 🚨")
        if override_reason:
            message_parts.append(f"*Reason:* {_escape_markdown_content(override_reason)}")
        message_parts.append(f"*Score:* {score:.3f} \\(below threshold {TRIAGE_THRESHOLD}, but critical attack\\)")
        message_parts.append("")
    
    # Header
    message_parts.append(f"{severity_emoji} *SOC Alert - {threat_level}*")
    message_parts.append("")
    
    # NEW: Supply chain attack warning (display prominently at top if detected)
    correlation = alert.get("correlation", {})
    if correlation and correlation.get("is_correlated"):
        supply_chain = correlation.get("supply_chain")
        if supply_chain and supply_chain.get("is_supply_chain"):
            attack_types = supply_chain.get("attack_types", [])
            attack_type_counts = supply_chain.get("attack_type_counts", {})
            severity = supply_chain.get("severity", "medium")
            total_alerts = supply_chain.get("total_alerts", correlation.get("group_size", 1))
            
            message_parts.append("🚨 *SUPPLY CHAIN ATTACK DETECTED* 🚨")
            message_parts.append("")
            message_parts.append(f"*Multiple attack types from same source:*")
            
            # Format attack types with counts
            attack_types_list = []
            for at in attack_types:
                count = attack_type_counts.get(at, 0)
                attack_types_list.append(f"{at.upper()} ({count} alerts)")
            message_parts.append(", ".join(attack_types_list))
            
            message_parts.append(f"*Total Campaign Alerts:* {total_alerts}")
            message_parts.append(f"*Severity:* {severity.upper()}")
            message_parts.append("")
            message_parts.append("⚠️ *This indicates a coordinated multi-stage attack!*")
            message_parts.append("")
    
    # Title
    title = alert_card.get("title", "Unknown Alert")
    message_parts.append(f"*Title:* {_escape_markdown_content(title)}")
    message_parts.append("")
    
    # Scores Section
    message_parts.append("*Scores:*")
    message_parts.append(f"Severity: {score:.3f} \\({threat_level}\\)")
    confidence = triage.get("confidence", score)
    message_parts.append(f"Confidence: {confidence:.2f}")
    
    # FP Risk (if available)
    fp_filtering = alert.get("fp_filtering", {})
    if fp_filtering:
        fp_risk = fp_filtering.get("fp_risk", "LOW")
        message_parts.append(f"FP Risk: {fp_risk}")
    message_parts.append("")
    
    # Identity Section (SOC-grade)
    message_parts.append("*Identity:*")
    
    # Timestamp
    timestamps = alert_card.get("timestamp", {})
    timestamp_local = timestamps.get("local", alert.get("@timestamp_local", "N/A"))
    timestamp_utc = timestamps.get("utc", alert.get("@timestamp", "N/A"))
    if timestamp_local != "N/A" and timestamp_utc != "N/A":
        message_parts.append(f"Time: {timestamp_local} \\({timestamp_utc} UTC\\)")
    elif timestamp_local != "N/A":
        message_parts.append(f"Time: {timestamp_local}")
    elif timestamp_utc != "N/A":
        message_parts.append(f"Time: {timestamp_utc} UTC")
    
    # Agent
    agent_id = agent.get("id", "")
    agent_ip = agent.get("ip", "")
    agent_line = f"Agent: {_escape_markdown_content(agent_name)}"
    if agent_id:
        agent_line += f" \\(ID: {agent_id}\\)"
    if agent_ip:
        agent_line += f", IP: {agent_ip}"
    message_parts.append(agent_line)
    
    # Rule
    rule_description = rule.get("description", "")
    rule_line = f"Rule: {rule_id} \\(Level {rule_level}\\)"
    if rule_description:
        rule_desc_short = rule_description[:60] + "..." if len(rule_description) > 60 else rule_description
        rule_line += f" - {_escape_markdown_content(rule_desc_short)}"
    message_parts.append(rule_line)
    
    # Index and Event ID
    index = alert.get("index", "")
    event_id = alert.get("event_id", "")
    if index:
        message_parts.append(f"Index: {index}")
    if event_id:
        message_parts.append(f"Event ID: {event_id}")
    
    # Manager and Decoder (if available)
    manager = alert.get("manager", {})
    manager_name = manager.get("name", "") if isinstance(manager, dict) else ""
    if manager_name:
        message_parts.append(f"Manager: {manager_name}")
    
    decoder = alert.get("decoder", {})
    decoder_name = decoder.get("name", "") if isinstance(decoder, dict) else ""
    if decoder_name:
        message_parts.append(f"Decoder: {decoder_name}")
    
    location = alert.get("location", "")
    if location:
        message_parts.append(f"Location: {_escape_markdown_content(location)}")
    
    message_parts.append("")
    
    # What Happened (Summary) - SOC-grade factual description
    summary = triage.get("summary", alert_card_short)
    # Truncate summary if too long (Telegram limit is 4096 chars for entire message)
    if len(summary) > 600:
        summary = summary[:600] + "...\\[truncated\\]"
    message_parts.append("*What Happened:*")
    message_parts.append(_escape_markdown_content(summary))
    message_parts.append("")
    
    # Evidence Section (SOC-grade) - Top 5 evidence items
    evidence_items = []
    
    # Extract evidence from alert fields
    if http_context and http_context.get("url"):
        evidence_items.append(f"data.http.url={http_context.get('url')[:100]}")
    if http_context and http_context.get("user_agent"):
        evidence_items.append(f"data.http.http_user_agent={http_context.get('user_agent')[:80]}")
    if http_context and http_context.get("status"):
        evidence_items.append(f"data.http.status={http_context.get('status')}")
    if suricata_alert and suricata_alert.get("signature_id"):
        evidence_items.append(f"data.alert.signature_id={suricata_alert.get('signature_id')}")
    if suricata_alert and suricata_alert.get("action"):
        evidence_items.append(f"data.alert.action={suricata_alert.get('action')}")
    if src_ip:
        evidence_items.append(f"data.flow.src_ip={src_ip}")
    # Safe conversion for flow statistics (may be string from JSON)
    pkts_to_server = _to_int(flow.get("pkts_toserver")) if flow else None
    if pkts_to_server is not None and pkts_to_server > 100:
        evidence_items.append(f"data.flow.pkts_toserver={pkts_to_server} \\(DoS indicator\\)")
    
    if evidence_items:
        message_parts.append("*Evidence:*")
        for i, evidence in enumerate(evidence_items[:5], 1):  # Limit to top 5
            message_parts.append(f"{i}\\. {_escape_markdown_content(evidence)}")
        if len(evidence_items) > 5:
            message_parts.append(f"\\[+{len(evidence_items) - 5} more evidence items\\]")
        message_parts.append("")
    
    # IOC Section (SOC-grade)
    ioc_items = []
    if src_ip:
        ioc_items.append(f"Source IP: {src_ip}")
    if dst_ip:
        ioc_items.append(f"Destination IP: {dst_ip}")
    if http_context and http_context.get("hostname"):
        ioc_items.append(f"Domain: {http_context.get('hostname')}")
    if http_context and http_context.get("url"):
        # Extract domain from URL if possible
        url = http_context.get("url", "")
        if url.startswith("http"):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.netloc:
                    ioc_items.append(f"URL: {parsed.netloc}{parsed.path[:50]}")
            except:
                pass
    
    if ioc_items:
        message_parts.append("*IOC:*")
        for ioc in ioc_items[:5]:  # Limit to 5
            message_parts.append(f"\\- {_escape_markdown_content(ioc)}")
        message_parts.append("")
    
    # Correlation Section (if available)
    # Note: Supply chain info already shown at top of message, so only show additional correlation details here
    correlation = alert.get("correlation", {})
    if correlation and correlation.get("is_correlated"):
        message_parts.append("*Correlation:*")
        correlated_count = correlation.get("group_size", 1)
        message_parts.append(f"Correlated Count: {correlated_count}")
        
        # Supply chain info (if not already shown at top, or show additional details)
        supply_chain = correlation.get("supply_chain")
        if supply_chain and supply_chain.get("is_supply_chain"):
            # Show additional correlation details (time span, etc.)
            message_parts.append("*Campaign Type:* Supply Chain Attack")
        
        if correlation.get("first_seen"):
            message_parts.append(f"First Seen: {correlation.get('first_seen')}")
        if correlation.get("last_seen"):
            message_parts.append(f"Last Seen: {correlation.get('last_seen')}")
        message_parts.append("")
    
    # Network Section (SOC-grade) - using already extracted variables
    # Check if we have network info
    has_network_info = (
        src_ip or 
        dst_ip or 
        (http_context and http_context.get("url")) or 
        protocol.get("method")
    )
    
    if has_network_info:
        message_parts.append("*Network:*")
        
        # Source IP (CRITICAL for SOC - needed for blocking)
        if src_ip:
            src_line = f"Source: {src_ip}"
            src_port = source.get("port") or alert.get("src_port", "")
            if src_port:
                src_line += f":{src_port}"
            # Add GeoIP info if available
            source_geo = source.get("geo", {})
            if source_geo:
                country = source_geo.get("country", "")
                city = source_geo.get("city", "")
                if country:
                    src_line += f" \\({country}"
                    if city:
                        src_line += f", {city}"
                    src_line += "\\)"
            # Add threat intel if available
            threat_intel = source.get("threat_intel")
            if threat_intel and threat_intel.get("is_malicious"):
                src_line += " ⚠️ *KNOWN THREAT*"
            message_parts.append(src_line)
        else:
            # SOC needs source IP - show warning if missing
            message_parts.append("Source: *NOT AVAILABLE* ⚠️")
        
        # Destination IP
        if dst_ip:
            dst_line = f"Destination: {dst_ip}"
            dst_port = destination.get("port") or alert.get("dest_port", "")
            if dst_port:
                dst_line += f":{dst_port}"
            if destination.get("hostname"):
                dst_line += f" \\({destination.get('hostname')}\\)"
            message_parts.append(dst_line)
        
        # Protocol
        proto = alert.get("proto", "")
        app_proto = alert.get("app_proto", "")
        if proto or app_proto:
            proto_line = "Protocol: "
            if app_proto:
                proto_line += f"{proto}/{app_proto}" if proto else app_proto
            else:
                proto_line += proto
            message_parts.append(proto_line)
        
        # Direction (if available)
        direction = alert.get("direction", "")
        if direction:
            message_parts.append(f"Direction: {direction}")
        
        message_parts.append("")
        
        # HTTP Context (URL, Method, User Agent, Status) - Critical for investigation
        if http_context and (http_context.get("url") or http_context.get("method") or http_context.get("user_agent")):
            message_parts.append("*HTTP Context:*")
            
            if http_context.get("url"):
                url = http_context.get("url", "")
                # Truncate long URLs for display
                if len(url) > 100:
                    url = url[:97] + "..."
                message_parts.append(f"URL: {_escape_markdown_content(url)}")
            
            if http_context.get("method"):
                method_line = f"Method: {http_context.get('method')}"
                if http_context.get("status"):
                    method_line += f" | Status: {http_context.get('status')}"
                message_parts.append(method_line)
            
            if http_context.get("user_agent"):
                user_agent = http_context.get("user_agent", "")
                # Truncate long user agents
                if len(user_agent) > 80:
                    user_agent = user_agent[:77] + "..."
                message_parts.append(f"User-Agent: {_escape_markdown_content(user_agent)}")
            
            message_parts.append("")
        
        # Flow Statistics (for DoS attacks) - using already extracted flow variable
        # Safe conversion (may be string from JSON)
        pkts_to_server = _to_int(flow.get("pkts_toserver")) if flow else None
        pkts_to_client = _to_int(flow.get("pkts_toclient")) if flow else None
        bytes_to_server = _to_int(flow.get("bytes_toserver")) if flow else None
        bytes_to_client = _to_int(flow.get("bytes_toclient")) if flow else None
        
        if pkts_to_server is not None or pkts_to_client is not None or bytes_to_server is not None or bytes_to_client is not None:
            message_parts.append("*Flow Statistics:*")
            if pkts_to_server is not None:
                message_parts.append(f"Packets to Server: {pkts_to_server}")
            if pkts_to_client is not None:
                message_parts.append(f"Packets to Client: {pkts_to_client}")
            if bytes_to_server is not None:
                message_parts.append(f"Bytes to Server: {bytes_to_server}")
            if bytes_to_client is not None:
                message_parts.append(f"Bytes to Client: {bytes_to_client}")
            message_parts.append("")
        
        # Suricata Alert Details (if available) - using already extracted suricata_alert variable
        if suricata_alert:
            message_parts.append("*Suricata Alert:*")
            if suricata_alert.get("signature"):
                sig = suricata_alert.get("signature", "")
                if len(sig) > 80:
                    sig = sig[:77] + "..."
                message_parts.append(f"Signature: {_escape_markdown_content(sig)}")
            if suricata_alert.get("signature_id"):
                message_parts.append(f"Signature ID: {suricata_alert.get('signature_id')}")
            if suricata_alert.get("severity") is not None:
                message_parts.append(f"Severity: {suricata_alert.get('severity')}")
            if suricata_alert.get("action"):
                action = suricata_alert.get("action", "")
                if action == "allowed":
                    message_parts.append(f"Action: {action} ⚠️ \\(attack passed firewall\\)")
                else:
                    message_parts.append(f"Action: {action}")
            if suricata_alert.get("category"):
                message_parts.append(f"Category: {suricata_alert.get('category')}")
            message_parts.append("")
    
    # Recommended actions - SOC needs actionable steps
    analysis = alert_card.get("analysis", {})
    next_steps = analysis.get("next_steps", [])
    
    # Also check recommended_actions for backward compatibility
    actions = alert_card.get("recommended_actions", [])
    if not next_steps and actions:
        next_steps = actions
    
    if next_steps:
        message_parts.append("*Recommended Actions:*")
        for i, action in enumerate(next_steps[:5], 1):  # Limit to 5 actions
            message_parts.append(f"{i}\\. {_escape_markdown_content(action)}")
        if len(next_steps) > 5:
            message_parts.append(f"\\[+{len(next_steps) - 5} more actions\\]")
        message_parts.append("")
    else:
        # SOC needs at least basic actions - provide defaults
        message_parts.append("*Recommended Actions:*")
        message_parts.append("1\\. Review alert details in Wazuh dashboard")
        if source.get("ip"):
            message_parts.append(f"2\\. Investigate source IP: {source.get('ip')}")
        message_parts.append("3\\. Check for related alerts from same source")
        message_parts.append("")
    
    # MITRE ATT&CK Section
    detection = alert_card.get("detection", {})
    mitre_data = detection.get("mitre")
    if mitre_data:
        # mitre_data can be either a list (from _extract_mitre_ids) or a dict
        if isinstance(mitre_data, list):
            mitre_ids = mitre_data
        elif isinstance(mitre_data, dict):
            mitre_ids = mitre_data.get("technique_ids", [])
        else:
            mitre_ids = []
        
        if mitre_ids:
            message_parts.append(f"*MITRE ATT&CK:* {', '.join(mitre_ids)}")
            message_parts.append("")
    
    # Query Section (SOC-grade) - Kibana/Discover query
    query_parts = []
    if index:
        query_parts.append(f"index={index}")
    if rule_id:
        query_parts.append(f"rule.id={rule_id}")
    if src_ip:
        query_parts.append(f"data.flow.src_ip={src_ip}")
    
    if query_parts:
        query_str = " AND ".join(query_parts)
        message_parts.append("*Query:*")
        message_parts.append(f"`{query_str}`")
        message_parts.append("")
    
    # Tags (if not already shown)
    if tags:
        tags_str = ", ".join(tags)
        message_parts.append(f"*Tags:* {_escape_markdown_content(tags_str)}")
    
    return "\n".join(message_parts)


def notify(alert: Dict[str, Any], triage: Dict[str, Any]) -> bool:
    """
    Send notification to Telegram bot if configured.
    
    Args:
        alert: Normalized alert dictionary
        triage: Triage result dictionary
        
    Returns:
        True if notification sent (or skipped), False on error
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.debug(
            "Telegram bot not configured, skipping notification",
            extra={
                "component": "notify",
                "action": "skip_no_config"
            }
        )
        return True
    
    # Check if this is a critical attack that must notify regardless of score
    score = triage.get("score", 0.0)
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    rule_id = str(rule.get("id", ""))
    
    is_critical_attack, override_reason = should_notify_critical_attack(alert, triage)
    
    # Check threshold
    if score < TRIAGE_THRESHOLD:
        if is_critical_attack:
            # CRITICAL: Override threshold for critical attacks
            logger.warning(
                "CRITICAL ATTACK OVERRIDE: Alert score below threshold but critical attack detected",
                extra={
                    "component": "notify",
                    "action": "critical_attack_override",
                    "rule_id": rule_id,
                    "rule_level": rule.get("level", 0),
                    "score": round(score, 3),
                    "threshold": TRIAGE_THRESHOLD,
                    "override_reason": override_reason,
                    "tags": triage.get("tags", []),
                    "threat_level": triage.get("threat_level", "unknown"),
                    "agent_name": agent.get("name", "unknown")
                }
            )
            # Continue to send notification (don't return early)
        else:
            # Normal alert below threshold - suppress
            logger.debug(
                "Alert score below notification threshold (suppressed)",
                extra={
                    "component": "notify",
                    "action": "skip_low_score",
                    "rule_id": rule_id,
                    "rule_level": rule.get("level", 0),
                    "score": round(score, 3),
                    "threshold": TRIAGE_THRESHOLD,
                    "tags": triage.get("tags", []),
                    "threat_level": triage.get("threat_level", "unknown")
                }
            )
            return True
    else:
        # Score is above threshold - normal notification
        if is_critical_attack:
            logger.info(
                "Critical attack detected (score above threshold)",
                extra={
                    "component": "notify",
                    "action": "critical_attack_normal",
                    "rule_id": rule_id,
                    "score": round(score, 3),
                    "override_reason": override_reason
                }
            )
    
    # Format alert as SOC-standardized card
    alert_card = format_alert_card(alert, triage)
    alert_card_short = format_alert_card_short(alert_card)
    
    # Format Telegram message with fallback on error
    is_critical_override = is_critical_attack and score < TRIAGE_THRESHOLD
    try:
        telegram_message = _format_telegram_message(
            alert, triage, alert_card, alert_card_short,
            is_critical_override, override_reason if is_critical_override else None
        )
    except Exception as format_error:
        # SOC Perspective: Don't crash entire alert if message formatting fails
        # Send fallback message with essential info instead
        logger.error(
            "Failed to format Telegram message, using fallback",
            extra={
                "component": "notify",
                "action": "format_fallback",
                "rule_id": rule_id,
                "error": str(format_error),
                "error_type": type(format_error).__name__
            },
            exc_info=True
        )
        
        # Fallback message: Essential SOC info only
        agent_name = agent.get("name", "unknown")
        rule_level = rule.get("level", 0)
        threat_level = triage.get("threat_level", "unknown").upper()
        summary = triage.get("summary", "Alert details unavailable due to formatting error")
        src_ip = alert.get("srcip", "") or alert.get("src_ip", "") or "N/A"
        dst_ip = alert.get("dest_ip", "") or agent.get("ip", "") or "N/A"
        
        # Truncate summary for fallback
        if len(summary) > 300:
            summary = summary[:300] + "...[truncated]"
        
        telegram_message = f"""⚠️ *SOC Alert - {threat_level}* (Fallback Message)

*Title:* {alert_card.get('title', 'Security Alert')}

*Scores:*
Severity: {score:.3f} ({threat_level})
Confidence: {triage.get('confidence', score):.2f}

*Identity:*
Agent: {agent_name} (ID: {agent.get('id', 'N/A')})
Rule: {rule_id} (Level {rule_level})
Time: {alert.get('@timestamp_local', alert.get('@timestamp', 'N/A'))}

*Network:*
Source: {src_ip}
Destination: {dst_ip}

*What Happened:*
{_escape_markdown_content(summary)}

*Note:* Full message formatting failed. Review alert in Wazuh dashboard for complete details.

*Query:*
`index={alert.get('index', 'wazuh-alerts-*')} AND rule.id={rule_id} AND data.flow.src_ip={src_ip}`"""
    
    # Telegram message limit is 4096 characters
    MAX_TELEGRAM_MESSAGE_LENGTH = 4096
    if len(telegram_message) > MAX_TELEGRAM_MESSAGE_LENGTH:
        # Truncate message and add warning
        truncated_length = MAX_TELEGRAM_MESSAGE_LENGTH - 100  # Reserve space for truncation notice
        telegram_message = telegram_message[:truncated_length] + "\\n\\n...\\[Message truncated due to length limit\\]"
        logger.warning(
            "Telegram message truncated",
            extra={
                "component": "notify",
                "action": "message_truncated",
                "original_length": len(telegram_message) + 100,
                "truncated_length": len(telegram_message),
                "rule_id": rule_id
            }
        )
    
    # Validate message before sending
    is_valid, validation_error = _validate_telegram_message(telegram_message)
    if not is_valid:
        logger.error(
            "Telegram message validation failed",
            extra={
                "component": "notify",
                "action": "message_validation_failed",
                "rule_id": rule_id,
                "error": validation_error,
                "message_preview": telegram_message[:500],
                "message_length": len(telegram_message)
            }
        )
        # Log full message for debugging (truncated to 1000 chars)
        logger.debug(
            "Invalid message content (for debugging)",
            extra={
                "component": "notify",
                "action": "invalid_message_debug",
                "rule_id": rule_id,
                "message_content": telegram_message[:1000]
            }
        )
        # Still try to send - Telegram API will give better error message
        logger.warning(
            "Attempting to send message despite validation warning",
            extra={
                "component": "notify",
                "action": "send_despite_validation_warning",
                "rule_id": rule_id,
                "validation_error": validation_error
            }
        )
    else:
        logger.debug(
            "Telegram message validation passed",
            extra={
                "component": "notify",
                "action": "message_validation_passed",
                "rule_id": rule_id,
                "message_length": len(telegram_message)
            }
        )
    
    # Build Telegram API payload
    telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": telegram_message,
        "parse_mode": "Markdown",  # Use Markdown (not MarkdownV2)
        "disable_web_page_preview": True
    }
    
    # Log message for debugging (first 500 chars)
    logger.debug(
        "Preparing Telegram message",
        extra={
            "component": "notify",
            "action": "message_prepared",
            "rule_id": rule_id,
            "message_preview": telegram_message[:500],
            "message_length": len(telegram_message),
            "validation_passed": is_valid
        }
    )
    
    try:
        session = RetrySession()
        response = session.request_with_backoff("POST", telegram_url, json=payload)
        
        # Check if request failed
        if response.status_code != 200:
            try:
                error_data = response.json()
                error_description = error_data.get("description", "Unknown error")
                error_code = error_data.get("error_code", "Unknown")
                
                # Check if it's a Markdown parsing error (error_code 400 with "can't parse" in description)
                is_markdown_error = (
                    response.status_code == 400 and 
                    error_code == 400 and
                    ("can't parse" in error_description.lower() or 
                     "bad request" in error_description.lower() or
                     "parse" in error_description.lower())
                )
                
                if is_markdown_error:
                    # Try again without parse_mode (plain text)
                    logger.warning(
                        "Markdown parsing error detected, retrying without parse_mode",
                        extra={
                            "component": "notify",
                            "action": "markdown_parse_error_retry",
                            "rule_id": rule_id,
                            "error_description": error_description,
                            "message_preview": telegram_message[:200]
                        }
                    )
                    
                    # Remove parse_mode and try again
                    payload_plain = payload.copy()
                    payload_plain.pop("parse_mode", None)
                    response = session.request_with_backoff("POST", telegram_url, json=payload_plain)
                    
                    if response.status_code == 200:
                        result = response.json()
                        if result.get("ok"):
                            logger.info(
                                "Notification sent to Telegram bot (without Markdown formatting)",
                                extra={
                                    "component": "notify",
                                    "action": "notification_sent_plain",
                                    "rule_id": rule_id,
                                    "message_id": result.get("result", {}).get("message_id")
                                }
                            )
                            return True
                
                # Log error response
                logger.error(
                    "Telegram API error response",
                    extra={
                        "component": "notify",
                        "action": "telegram_api_error",
                        "status_code": response.status_code,
                        "error_code": error_code,
                        "description": error_description,
                        "rule_id": rule_id,
                        "message_length": len(telegram_message),
                        "message_preview": telegram_message[:500]
                    }
                )
                # Log full error response for debugging
                logger.debug(
                    "Full Telegram API error response",
                    extra={
                        "component": "notify",
                        "action": "telegram_api_error_full",
                        "error_response": error_data,
                        "rule_id": rule_id
                    }
                )
            except Exception as e:
                logger.error(
                    f"Telegram API error (status {response.status_code}): {response.text[:500]}",
                    extra={
                        "component": "notify",
                        "action": "telegram_api_error",
                        "status_code": response.status_code,
                        "rule_id": rule_id,
                        "parse_error": str(e)
                    }
                )
        
        response.raise_for_status()
        
        result = response.json()
        if not result.get("ok"):
            error_description = result.get("description", "Unknown error")
            raise Exception(f"Telegram API error: {error_description}")
        
        logger.info(
            "Notification sent to Telegram bot",
            extra={
                "component": "notify",
                "action": "notification_sent",
                "rule_id": rule_id,
                "rule_level": rule.get("level", 0),
                "agent_name": agent.get("name", "unknown"),
                "score": round(score, 3),
                "threat_level": triage.get("threat_level", "unknown").upper(),
                "is_critical_attack": is_critical_attack,
                "override_applied": is_critical_override,
                "message_id": result.get("result", {}).get("message_id")
            }
        )
        return True
    
    except Exception as e:
        # Extract Telegram API error details if available
        error_msg = str(e)
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                error_description = error_data.get("description", "Unknown error")
                error_code = error_data.get("error_code", "Unknown")
                error_msg = f"Telegram API Error {error_code}: {error_description}"
                logger.error(
                    "Failed to send notification to Telegram bot",
                    extra={
                        "component": "notify",
                        "action": "notification_failed",
                        "rule_id": rule.get("id", "unknown"),
                        "score": round(score, 3),
                        "error": error_msg,
                        "error_code": error_code,
                        "error_description": error_description,
                        "chat_id": TELEGRAM_CHAT_ID[:10] + "..." if len(TELEGRAM_CHAT_ID) > 10 else TELEGRAM_CHAT_ID,
                        "message_length": len(telegram_message),
                        "message_preview": telegram_message[:200]
                    },
                    exc_info=True
                )
            except Exception:
                # Fallback if we can't parse error response
                logger.error(
                    "Failed to send notification to Telegram bot",
                    extra={
                        "component": "notify",
                        "action": "notification_failed",
                        "rule_id": rule.get("id", "unknown"),
                        "score": round(score, 3),
                        "error": error_msg,
                        "response_text": e.response.text[:500] if hasattr(e, 'response') and e.response else None
                    },
                    exc_info=True
                )
        else:
            logger.error(
                "Failed to send notification to Telegram bot",
                extra={
                    "component": "notify",
                    "action": "notification_failed",
                    "rule_id": rule.get("id", "unknown"),
                    "score": round(score, 3),
                    "error": error_msg
                },
                exc_info=True
            )
        return False

