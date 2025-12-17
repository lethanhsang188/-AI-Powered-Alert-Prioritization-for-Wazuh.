"""Format alerts for SOC triage - standardized alert card format."""
import hashlib
import logging
from typing import Any, Dict, Optional
from datetime import datetime

from src.common.config import WAZUH_API_URL, LOCAL_TIMEZONE
from src.common.timezone import utc_iso_to_local

logger = logging.getLogger(__name__)


def _is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private."""
    if not ip:
        return False
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


def _generate_dedup_key(alert: Dict[str, Any], window_minutes: int = 5) -> str:
    """Generate deduplication key for correlation."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    http_context = alert.get("http")
    suricata_alert = alert.get("suricata_alert")
    
    # Build dedup components
    components = [
        alert.get("srcip", ""),
        agent.get("ip", ""),
        str(rule.get("id", "")),
    ]
    
    # Add signature ID if available
    if suricata_alert and suricata_alert.get("signature_id"):
        components.append(str(suricata_alert.get("signature_id")))
    
    # Add URL path if available
    if http_context and http_context.get("url"):
        # Extract path only (remove query params)
        url_path = http_context.get("url", "").split("?")[0]
        components.append(url_path)
    
    # Add timestamp window (round to nearest window_minutes)
    timestamp = alert.get("@timestamp", "")
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            window_seconds = window_minutes * 60
            rounded_ts = int(dt.timestamp() / window_seconds) * window_seconds
            components.append(str(rounded_ts))
        except Exception:
            pass
    
    dedup_string = "+".join(components)
    return hashlib.sha256(dedup_string.encode()).hexdigest()[:16]


def _extract_mitre_ids(rule: Dict[str, Any]) -> list:
    """Extract MITRE ATT&CK IDs from rule."""
    mitre = rule.get("mitre", {})
    if isinstance(mitre, dict):
        mitre_ids = mitre.get("id", [])
        if isinstance(mitre_ids, list):
            return mitre_ids
        elif isinstance(mitre_ids, str):
            return [mitre_ids]
    return []


def _build_wazuh_dashboard_link(alert: Dict[str, Any]) -> Optional[str]:
    """Build link to Wazuh dashboard for this alert."""
    if not WAZUH_API_URL:
        return None
    
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    rule_id = rule.get("id", "")
    agent_id = agent.get("id", "")
    timestamp = alert.get("@timestamp", "")
    
    if not rule_id or not agent_id or not timestamp:
        return None
    
    # Extract base URL (remove /api if present)
    base_url = WAZUH_API_URL.replace("/api", "").rstrip("/")
    
    # Build Wazuh dashboard link (format may vary by Wazuh version)
    # Example: https://wazuh-server:55000/app/wazuh#/agents?agent=001&tab=events&event=533
    link = f"{base_url}/app/wazuh#/agents?agent={agent_id}&tab=events&event={rule_id}"
    
    return link


def _build_indexer_link(alert: Dict[str, Any]) -> Optional[str]:
    """Build link to raw event in indexer (if indexer UI available)."""
    # This would require indexer UI URL - can be added to config if needed
    # For now, return None
    return None


def _format_timestamp(timestamp: str, local_timestamp: Optional[str] = None) -> Dict[str, str]:
    """Format timestamp in both UTC and local timezone."""
    if not timestamp:
        return {"utc": "N/A", "local": "N/A", "timezone": LOCAL_TIMEZONE}
    
    try:
        # Parse UTC timestamp
        dt_utc = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        utc_str = dt_utc.strftime("%Y-%m-%d %H:%M:%SZ")
        
        # Convert to local
        if local_timestamp:
            try:
                dt_local = datetime.fromisoformat(local_timestamp.replace("Z", "+00:00"))
                # Extract timezone abbreviation (simplified)
                tz_abbr = LOCAL_TIMEZONE.split("/")[-1] if "/" in LOCAL_TIMEZONE else "LOCAL"
                local_str = dt_local.strftime(f"%Y-%m-%d %H:%M:%S {tz_abbr}")
            except Exception:
                # Fallback: use utc_iso_to_local helper
                local_ts = utc_iso_to_local(timestamp)
                if local_ts:
                    try:
                        dt_local = datetime.fromisoformat(local_ts.replace("Z", "+00:00"))
                        tz_abbr = LOCAL_TIMEZONE.split("/")[-1] if "/" in LOCAL_TIMEZONE else "LOCAL"
                        local_str = dt_local.strftime(f"%Y-%m-%d %H:%M:%S {tz_abbr}")
                    except Exception:
                        local_str = local_ts
                else:
                    local_str = "N/A"
        else:
            # Fallback: use utc_iso_to_local helper
            local_ts = utc_iso_to_local(timestamp)
            if local_ts:
                try:
                    dt_local = datetime.fromisoformat(local_ts.replace("Z", "+00:00"))
                    tz_abbr = LOCAL_TIMEZONE.split("/")[-1] if "/" in LOCAL_TIMEZONE else "LOCAL"
                    local_str = dt_local.strftime(f"%Y-%m-%d %H:%M:%S {tz_abbr}")
                except Exception:
                    local_str = local_ts
            else:
                local_str = "N/A"
        
        return {
            "utc": utc_str,
            "local": local_str,
            "timezone": LOCAL_TIMEZONE
        }
    except Exception:
        return {"utc": timestamp, "local": "N/A", "timezone": LOCAL_TIMEZONE}


def _generate_title(alert: Dict[str, Any], triage: Dict[str, Any]) -> str:
    """Generate standardized alert title."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    http_context = alert.get("http")
    suricata_alert = alert.get("suricata_alert")
    
    # Extract attack type from tags or rule description
    tags = triage.get("tags", [])
    attack_type = None
    
    # Priority: specific attack tags > rule description > generic
    if "sql_injection" in tags:
        attack_type = "SQL Injection"
    elif "command_injection" in tags:
        attack_type = "Command Injection"
    elif "xss" in tags:
        attack_type = "XSS"
    elif "path_traversal" in tags:
        attack_type = "Path Traversal"
    elif "csrf" in tags:
        attack_type = "CSRF"
    elif "web_attack" in tags:
        attack_type = "Web Attack"
    
    # Extract location
    agent_name = agent.get("name", "unknown")
    location = agent_name
    
    # Extract target endpoint
    target = ""
    if http_context:
        url = http_context.get("url", "")
        if url:
            # Extract path only
            path = url.split("?")[0]
            target = path
    
    # Build title
    if attack_type and target:
        title = f"{attack_type} attempt on {agent_name} {target}"
    elif attack_type:
        title = f"{attack_type} attempt on {agent_name}"
    else:
        rule_desc = rule.get("description", "")
        if rule_desc:
            # Extract key part from rule description
            if "Suricata:" in rule_desc:
                title = f"{rule_desc.split('Suricata:')[1].strip()} on {agent_name}"
            else:
                title = f"{rule_desc[:50]} on {agent_name}"
        else:
            title = f"Security alert on {agent_name}"
    
    return title


def _generate_impact_guess(triage: Dict[str, Any], alert: Dict[str, Any]) -> str:
    """Generate impact assessment based on triage result."""
    tags = triage.get("tags", [])
    threat_level = triage.get("threat_level", "medium").lower()
    http_context = alert.get("http")
    
    impact_parts = []
    
    # Check for successful exploitation indicators
    if http_context:
        status = http_context.get("status", "")
        if status in ["200", "302"]:
            impact_parts.append("Request returned success status - verify if exploitation succeeded")
    
    # Attack-specific impact
    if "sql_injection" in tags:
        impact_parts.append("Potential database access or data exfiltration")
    elif "command_injection" in tags:
        impact_parts.append("Potential remote code execution on target server")
    elif "xss" in tags:
        impact_parts.append("Potential session hijacking or credential theft")
    elif "path_traversal" in tags:
        impact_parts.append("Potential file system access or sensitive file disclosure")
    
    # Threat level based
    if threat_level == "critical":
        impact_parts.append("Immediate containment recommended")
    elif threat_level == "high":
        impact_parts.append("Investigation and monitoring required")
    
    if not impact_parts:
        return "Review alert details and verify if attack was successful"
    
    return "; ".join(impact_parts)


def _generate_next_steps(triage: Dict[str, Any], alert: Dict[str, Any]) -> list:
    """Generate recommended next steps based on alert type."""
    steps = []
    tags = triage.get("tags", [])
    http_context = alert.get("http")
    srcip = alert.get("srcip", "")
    
    # Check if request succeeded
    if http_context:
        status = http_context.get("status", "")
        if status in ["200", "302"]:
            steps.append("Check web server logs for successful exploitation")
            steps.append("Search for follow-up events (RCE, file upload) within 5-10 minutes")
    
    # Source IP actions
    if srcip and not _is_internal_ip(srcip):
        steps.append(f"Consider blocking/rate-limiting source IP {srcip} if repeated")
        steps.append("Check for other alerts from same source IP")
    
    # Attack-specific steps
    if "sql_injection" in tags:
        steps.append("Review database logs for suspicious queries")
    elif "command_injection" in tags:
        steps.append("Check for reverse shell connections or outbound traffic")
    elif "xss" in tags:
        steps.append("Verify if payload executed in user browsers")
    
    # Correlation
    steps.append("Search for related alerts/cases with same source IP or signature")
    
    return steps


def format_alert_card(alert: Dict[str, Any], triage: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format alert into SOC-standardized card format.
    
    Returns dict with all fields needed for SOC triage in 30-60 seconds.
    """
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    http_context = alert.get("http")
    suricata_alert = alert.get("suricata_alert")
    
    score = triage.get("score", 0.0)
    threat_level = triage.get("threat_level", "medium").upper()
    tags = triage.get("tags", [])
    summary = triage.get("summary", "")
    
    # Calculate confidence percentage
    confidence_pct = int(score * 100)
    
    # Format timestamps
    timestamps = _format_timestamp(
        alert.get("@timestamp", ""),
        alert.get("@timestamp_local")
    )
    
    # Generate title
    title = _generate_title(alert, triage)
    
    # Build detection details
    detection = {
        "rule": {
            "id": str(rule.get("id", "N/A")),
            "level": rule.get("level", 0),
            "description": rule.get("description", ""),
            "groups": rule.get("groups", [])
        },
        "signature": None,
        "mitre": []
    }
    
    if suricata_alert:
        detection["signature"] = {
            "id": suricata_alert.get("signature_id"),
            "name": suricata_alert.get("signature"),
            "category": suricata_alert.get("category"),
            "severity": suricata_alert.get("severity")
        }
    
    mitre_ids = _extract_mitre_ids(rule)
    if mitre_ids:
        detection["mitre"] = mitre_ids
    
    # Build evidence (redacted)
    evidence = {
        "url": http_context.get("url") if http_context else None,
        "method": http_context.get("method") if http_context else None,
        "status": http_context.get("status") if http_context else None,
        "hostname": http_context.get("hostname") if http_context else None,
        "payload_snippet": None  # Will be extracted from message if available
    }
    
    # Extract payload snippet from message (first 200-500 chars)
    message = alert.get("message", "")
    if message:
        # Try to extract interesting parts
        payload_snippet = message[:500] if len(message) <= 500 else message[:200] + "...[truncated]"
        evidence["payload_snippet"] = payload_snippet
    
    # Build links
    links = {
        "wazuh_dashboard": _build_wazuh_dashboard_link(alert),
        "raw_event": _build_indexer_link(alert)
    }
    
    # Extract enrichment data if available
    enrichment = alert.get("enrichment", {})
    source_geo = enrichment.get("source_geo", {}) if enrichment else {}
    threat_intel = enrichment.get("threat_intel", {}) if enrichment else {}
    
    # Extract correlation data if available
    correlation = alert.get("correlation", {}) if alert.get("correlation") else {}
    
    # Generate impact and next steps
    impact_guess = _generate_impact_guess(triage, alert)
    next_steps = _generate_next_steps(triage, alert)
    
    # Build full card
    card = {
        # Header
        "title": title,
        "timestamp": timestamps,
        "severity": {
            "label": threat_level,
            "confidence_pct": confidence_pct,
            "score": round(score, 3)
        },
        "status": "New",  # Default status
        "dedup_key": _generate_dedup_key(alert),
        
        # What/Where
        "asset": {
            "name": agent.get("name", "unknown"),
            "ip": agent.get("ip", ""),
            "id": agent.get("id", ""),
            "role": None  # Can be enriched from config
        },
        "destination": {
            "ip": alert.get("dest_ip") or agent.get("ip", ""),  # Prefer top-level dest_ip if available
            "port": alert.get("dest_port") or (http_context.get("status") if http_context else None),
            "hostname": http_context.get("hostname") if http_context else None,
            "url": http_context.get("url") if http_context else None
        },
        "source": {
            "ip": alert.get("src_ip") or alert.get("srcip", ""),  # Prefer top-level src_ip if available
            "port": alert.get("src_port") or None,
            "is_internal": source_geo.get("is_internal", _is_internal_ip(alert.get("src_ip") or alert.get("srcip", ""))),
            "geo": {
                "country": source_geo.get("country"),
                "country_code": source_geo.get("country_code"),
                "region": source_geo.get("region"),
                "city": source_geo.get("city")
            } if source_geo else None,
            "asn": source_geo.get("asn") if source_geo else None,
            "org": source_geo.get("org") if source_geo else None,
            "threat_intel": threat_intel if threat_intel else None
        },
        "user": {
            "username": alert.get("user", ""),
            "auth_result": None  # Can be extracted from message
        },
        "protocol": {
            "name": "HTTP" if http_context else "Unknown",
            "method": http_context.get("method") if http_context else None,
            "status_code": http_context.get("status") if http_context else None,
            "redirect": http_context.get("redirect") if http_context else None,  # HTTP 302 redirect
            "tls": None  # Can be extracted if available
        },
        "network": {
            "direction": alert.get("direction") or (alert.get("flow", {}).get("direction") if alert.get("flow") else None),
            "proto": alert.get("proto"),
            "app_proto": alert.get("app_proto"),
            "in_iface": alert.get("in_iface"),
        },
        "flow": alert.get("flow") if alert.get("flow") else None,  # Flow statistics (bytes, pkts)
        
        # Detection details
        "detection": detection,
        
        # Evidence
        "evidence": evidence,
        "links": links,
        
        # So what
        "analysis": {
            "score": round(score, 3),
            "score_rationale": summary,  # LLM summary explains why
            "impact_guess": impact_guess,
            "next_steps": next_steps
        },
        
        # Outcome tracking (defaults)
        "outcome": {
            "disposition": "Needs Review",
            "owner": None,
            "sla_minutes": 60 if threat_level in ["HIGH", "CRITICAL"] else 240,
            "notes": [],
            "related_alerts": []
        },
        
        # Raw data reference (for deep dive)
        "raw_alert_id": alert.get("raw", {}).get("_id") if isinstance(alert.get("raw"), dict) else None
    }
    
    return card


def format_alert_card_short(card: Dict[str, Any]) -> str:
    """
    Format alert card as short text (for Slack/Telegram/Email).
    
    Returns formatted string ready for messaging platforms.
    """
    severity = card.get("severity", {})
    threat_level = severity.get("label", "MEDIUM")
    confidence = severity.get("confidence_pct", 0)
    
    timestamps = card.get("timestamp", {})
    time_str = timestamps.get("local", "N/A")
    
    asset = card.get("asset", {})
    asset_name = asset.get("name", "unknown")
    asset_ip = asset.get("ip", "")
    
    destination = card.get("destination", {})
    url = destination.get("url", "")
    
    source = card.get("source", {})
    src_ip = source.get("ip", "")
    dst_ip = destination.get("ip", asset_ip)
    
    protocol = card.get("protocol", {})
    method = protocol.get("method", "")
    status = protocol.get("status_code", "")
    
    detection = card.get("detection", {})
    rule = detection.get("rule", {})
    rule_id = rule.get("id", "N/A")
    rule_level = rule.get("level", 0)
    
    signature = detection.get("signature")
    signature_info = ""
    if signature:
        sig_id = signature.get("id", "")
        sig_name = signature.get("name", "")
        if sig_id and sig_name:
            signature_info = f"Suricata {sig_id} ({sig_name})"
        elif sig_name:
            signature_info = f"Suricata ({sig_name})"
    
    mitre = detection.get("mitre", [])
    mitre_str = ", ".join(mitre) if mitre else ""
    
    analysis = card.get("analysis", {})
    next_steps = analysis.get("next_steps", [])
    next_steps_str = "; ".join(next_steps[:2]) if next_steps else "Review alert details"
    
    links = card.get("links", {})
    wazuh_link = links.get("wazuh_dashboard", "")
    links_str = ""
    if wazuh_link:
        links_str = f"Wazuh Alert: {wazuh_link}"
    
    # Build formatted message
    lines = [
        f"[{threat_level} | {confidence}% confidence] {card.get('title', 'Security Alert')}",
        f"Time: {time_str}",
    ]
    
    # Asset and path
    asset_line = f"Asset: {asset_name} ({asset_ip})"
    if url:
        # Extract path only (remove query params for display)
        path = url.split("?")[0]
        asset_line += f"  Path: {path}"
    lines.append(asset_line)
    
    # Source and destination
    if src_ip and dst_ip:
        dst_port = protocol.get("port", "80") if protocol.get("port") else ""
        if dst_port:
            lines.append(f"Src: {src_ip} -> Dst: {dst_ip}:{dst_port}")
        else:
            lines.append(f"Src: {src_ip} -> Dst: {dst_ip}")
    
    # Method and status
    if method and status:
        lines.append(f"Method: {method}  Status: {status}")
    
    # Detection info
    detection_parts = []
    if signature_info:
        detection_parts.append(signature_info)
    if rule_id != "N/A":
        detection_parts.append(f"Wazuh rule {rule_id} lvl {rule_level}")
    if detection_parts:
        lines.append(f"Detection: {' | '.join(detection_parts)}")
    
    # MITRE
    if mitre_str:
        lines.append(f"MITRE: {mitre_str}")
    
    # Next steps
    lines.append(f"Next: {next_steps_str}")
    
    # Links
    if links_str:
        lines.append(f"Links: {links_str}")
    
    # Filter out empty lines and return
    return "\n".join([line for line in lines if line.strip()])

