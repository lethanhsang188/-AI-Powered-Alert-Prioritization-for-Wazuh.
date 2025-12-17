"""Optional LLM-based alert analysis."""
import logging
from typing import Any, Dict, Optional

from src.common.config import (
    OPENAI_API_BASE,
    OPENAI_API_KEY,
    LLM_MODEL,
    LLM_MAX_TOKENS,
    LLM_TIMEOUT_SEC,
    LLM_ENABLE,
    LLM_CACHE_ENABLE,
)
from src.common.web import RetrySession
from src.common.llm_cache import get_llm_cache

logger = logging.getLogger(__name__)

# Controlled vocabulary for tags (Prompt III)
ALLOWED_TAGS = [
    "benign_config_change",
    "suspicious_config_change",
    "ssh_bruteforce",
    "auth_bruteforce",
    "web_attack",
    "sql_injection",      # Web-specific: SQL injection attacks
    "xss",                # Web-specific: Cross-site scripting
    "path_traversal",     # Web-specific: Directory traversal attacks
    "command_injection",   # Web-specific: Command injection attacks
    "web_scanning",       # Web-specific: Web scanning/reconnaissance
    "inbound_scan",
    "lateral_movement",
    "privilege_escalation",
    "persistence",
    "malware",
    "data_exfiltration",
    "policy_violation",
    "suspicious_package",
    "suspicious_process",
    "network_intrusion",
    "suricata_alert",
    "wazuh_rule_high",
    "wazuh_rule_medium",
]

ALLOWED_THREAT_LEVELS = ["none", "low", "medium", "high", "critical"]


def _calculate_temperature(rule_level: int) -> float:
    """
    Calculate dynamic temperature based on rule level.
    
    Higher rule levels (more critical) use lower temperature for more precise analysis.
    Lower rule levels use higher temperature for more flexible interpretation.
    """
    if rule_level >= 12:
        return 0.2  # Very precise for critical alerts
    elif rule_level >= 9:
        return 0.25  # Precise for high-severity alerts
    elif rule_level >= 7:
        return 0.3  # Standard temperature
    else:
        return 0.35  # Slightly more flexible for lower-severity alerts


def triage_llm(alert_text: str, rule_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Analyze alert using LLM (if enabled).
    
    Args:
        alert_text: Alert message/text (may be redacted)
        rule_context: Optional dict with rule information (id, level, description, groups, mitre)
        
    Returns:
        Dict with keys: summary, threat_level, confidence (0.0-1.0), tags (list)
    """
    if not LLM_ENABLE:
        return {
            "summary": "LLM disabled",
            "threat_level": "medium",
            "confidence": 0.0,
            "tags": [],
        }
    
    if not OPENAI_API_KEY:
        logger.warning("LLM_ENABLE=true but OPENAI_API_KEY is not set")
        return {
            "summary": "LLM API key not configured",
            "threat_level": "medium",
            "confidence": 0.0,
            "tags": [],
        }
    
    # Check cache first
    if LLM_CACHE_ENABLE:
        cache = get_llm_cache()
        cached_result = cache.get(alert_text, rule_context)
        if cached_result:
            logger.debug(
                "Using cached LLM result",
                extra={
                    "component": "llm",
                    "action": "cache_hit",
                    "rule_id": rule_context.get("id") if rule_context else "N/A"
                }
            )
            return cached_result
    
    # Extract rule context if provided
    rule_id = rule_context.get("id", "N/A") if rule_context else "N/A"
    rule_level = rule_context.get("level", 0) if rule_context else 0
    rule_description = rule_context.get("description", "") if rule_context else ""
    rule_groups = rule_context.get("groups", []) if rule_context else []
    mitre_ids = rule_context.get("mitre", {}).get("id", []) if rule_context and rule_context.get("mitre") else []
    
    # Build rule context string with rule-specific guidance
    rule_context_str = ""
    rule_specific_guidance = ""
    
    if rule_context:
        rule_context_str = f"\nRule Context:\n"
        rule_context_str += f"- Rule ID: {rule_id}\n"
        rule_context_str += f"- Rule Level: {rule_level} (0-15 scale, higher = more severe)\n"
        if rule_description:
            rule_context_str += f"- Rule Description: {rule_description}\n"
        if rule_groups:
            groups_str = ", ".join(rule_groups) if isinstance(rule_groups, list) else str(rule_groups)
            rule_context_str += f"- Rule Groups: {groups_str}\n"
        if mitre_ids:
            mitre_str = ", ".join(mitre_ids) if isinstance(mitre_ids, list) else str(mitre_ids)
            rule_context_str += f"- MITRE ATT&CK IDs: {mitre_str}\n"
        
        # Add rule-specific guidance for critical rules
        # NOTE: Also check for normalized attack type to ensure consistent analysis across agents
        normalized_attack_type = rule_context.get("normalized_attack_type") if rule_context else None
        
        if rule_id == "31105" or normalized_attack_type == "xss":
            rule_specific_guidance = """
**CRITICAL: XSS (Cross-Site Scripting) Detection**
- This is a HIGH priority web attack that can steal sessions, inject malware, or deface websites.
- Look for XSS patterns: <script>, onerror=, javascript:, <img src=x onerror=, etc.
- Rule 31105 (Wazuh) or rule 86601 (Suricata) or any XSS signature indicates same attack type.
- If XSS detected → threat_level: "high" or "critical", confidence: >= 0.7
- Required tags: ["xss", "web_attack"]
- IMPORTANT: Evaluate based on attack content, not rule ID or agent type.
"""
        elif rule_id in ["31103", "31104"]:
            rule_specific_guidance = """
**CRITICAL: Rule 31103/31104 = SQL Injection Detection**
- This is a CRITICAL web attack that can lead to data breach.
- Look for SQL patterns: SELECT, UNION, OR '1'='1, etc.
- If SQL injection detected → threat_level: "critical", confidence: >= 0.8
- Required tags: ["sql_injection", "web_attack"]
"""
        elif rule_id == "31106":
            rule_specific_guidance = """
**CRITICAL: Rule 31106 = Successful Web Attack (HTTP 200)**
- This indicates a SUCCESSFUL attack (not just an attempt).
- If HTTP status is 200 → threat_level: "critical", confidence: >= 0.85
- Required tags: ["web_attack"] + specific attack type tag
"""
        elif rule_id in ["100144", "100145", "100146"]:
            rule_specific_guidance = """
**CRITICAL: Rule 100144/100145/100146 = Command Injection Detection**
- This is a CRITICAL attack that can lead to remote code execution.
- Look for command patterns: /bin/bash, /dev/tcp, |, &&, etc.
- If command injection detected → threat_level: "critical", confidence: >= 0.8
- Required tags: ["command_injection", "web_attack"]
"""
        elif rule_id in ["100133", "100143"]:
            rule_specific_guidance = """
**HIGH: Rule 100133/100143 = CSRF (Cross-Site Request Forgery) Detection**
- This is a HIGH priority web attack that can perform unauthorized actions.
- Look for CSRF patterns: cross-origin referer, unauthorized state change, etc.
- If CSRF detected → threat_level: "high", confidence: >= 0.7
- Required tags: ["web_attack"]
"""
    
    # Increase alert text limit for better context (was 500, now 1200)
    alert_text_truncated = alert_text[:1200]
    if len(alert_text) > 1200:
        alert_text_truncated += "\n[... truncated ...]"
    
    # Prepare enhanced prompt
    prompt = f"""
You are a senior SOC (Security Operations Center) analyst. 

You are given a single security alert from a SIEM/SOC pipeline (Wazuh). 

The text may be truncated and may contain redacted fields.

{rule_context_str}

{rule_specific_guidance}

Your job is to:

1. Briefly explain what is happening in 1–2 short sentences, written for a SOC incident ticket.

2. Assess how likely this alert represents a real security issue (not just a benign or noisy event).

3. Assign technical tags from a controlled vocabulary.

Consider:

- The alert message content (e.g. authentication failures, dpkg install, Suricata network alerts, web attack patterns, SQL injection, XSS, path traversal, etc.).

- The rule context provided above (rule ID, level, description, groups, MITRE ATT&CK mapping).

- Whether this looks like normal admin activity, configuration change, scanning, brute-force, exploitation, malware, or data exfiltration.

- For web attacks: Look for patterns like SQL injection (SELECT, UNION, etc.), XSS (<script>, onerror, etc.), path traversal (../, ..\\, etc.), command injection (cmd.exe, /bin/sh, etc.).

Use ONLY tags from this list when applicable (zero or more):

[
  "benign_config_change",
  "suspicious_config_change",
  "ssh_bruteforce",
  "auth_bruteforce",
  "web_attack",
  "sql_injection",
  "xss",
  "path_traversal",
  "command_injection",
  "web_scanning",
  "inbound_scan",
  "lateral_movement",
  "privilege_escalation",
  "persistence",
  "malware",
  "data_exfiltration",
  "policy_violation",
  "suspicious_package",
  "suspicious_process",
  "network_intrusion",
  "suricata_alert",
  "wazuh_rule_high",
  "wazuh_rule_medium"
]

Threat level scale:

- "none": clearly benign or pure noise, no security urgency.

- "low": low risk, likely benign or expected (e.g. routine package install on admin box).

- "medium": potentially suspicious, needs review but not obviously critical.

- "high": likely malicious or very suspicious, should be investigated quickly.

- "critical": strong evidence of active compromise or severe impact (e.g. successful SQL injection, successful XSS, successful command execution).

Input alert (free-form text, may be truncated):

---

{alert_text_truncated}

---

Respond with a single JSON object ONLY, no markdown, no extra text, with exactly this schema:

{{
  "summary": "<string, 1-2 sentences>",
  "threat_level": "<one of: none, low, medium, high, critical>",
  "confidence": <float between 0.0 and 1.0>,
  "tags": ["tag1", "tag2", ...]
}}

Rules:

- "confidence" MUST be a bare number, not a string.

- "tags" MUST be an array of zero or more strings from the allowed list (no custom tags).

- Do not include any explanation outside the JSON.

- For web attacks, use specific tags like "sql_injection", "xss", "path_traversal", "command_injection" in addition to "web_attack" if applicable.

"""
    
    try:
        session = RetrySession()
        api_key_preview = f"{OPENAI_API_KEY[:10]}..." if OPENAI_API_KEY else "none"
        session.headers.update({
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        })
        
        # Calculate dynamic temperature based on rule level
        rule_level = rule_context.get("level", 0) if rule_context else 0
        temperature = _calculate_temperature(rule_level)
        
        url = f"{OPENAI_API_BASE.rstrip('/')}/chat/completions"
        payload = {
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": "You are a security analyst."},
                {"role": "user", "content": prompt},
            ],
            "max_completion_tokens": LLM_MAX_TOKENS,  # Use max_completion_tokens instead of deprecated max_tokens
            "temperature": temperature,
            "response_format": {"type": "json_object"},  # Enforce JSON mode for structured output
        }
        
        logger.debug(
            "Calling LLM API",
            extra={
                "component": "llm",
                "action": "api_call",
                "url": url,
                "model": LLM_MODEL,
                "api_key_preview": api_key_preview,
                "max_completion_tokens": LLM_MAX_TOKENS,
                "response_format": "json_object"
            }
        )
        
        response = session.request_with_backoff(
            "POST",
            url,
            json=payload,
            timeout=LLM_TIMEOUT_SEC,
        )
        
        # Log error details before raising
        if response.status_code != 200:
            try:
                error_data = response.json()
                error_message = error_data.get("error", {}).get("message", "Unknown error")
                error_type = error_data.get("error", {}).get("type", "Unknown")
                error_code = error_data.get("error", {}).get("code", "Unknown")
                logger.error(
                    "LLM API error response",
                    extra={
                        "component": "llm",
                        "action": "api_error",
                        "status_code": response.status_code,
                        "error_type": error_type,
                        "error_code": error_code,
                        "error_message": error_message,
                        "model": LLM_MODEL,
                        "url": url
                    }
                )
            except Exception:
                # If we can't parse error response, log raw text
                logger.error(
                    f"LLM API error (status {response.status_code}): {response.text[:500]}",
                    extra={
                        "component": "llm",
                        "action": "api_error",
                        "status_code": response.status_code,
                        "model": LLM_MODEL,
                        "url": url
                    }
                )
        
        response.raise_for_status()
        
        data = response.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        logger.debug(
            "LLM API response received",
            extra={
                "component": "llm",
                "action": "api_response",
                "status_code": response.status_code,
                "response_length": len(content)
            }
        )
        
        # Parse JSON response with error handling
        import json
        import re
        
        try:
            # With response_format: {"type": "json_object"}, model should return valid JSON
            # But keep regex fallback for edge cases
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                # Fallback: Try to extract JSON from response (in case model adds extra text)
                json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', content, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group(0))
                else:
                    raise
        except (json.JSONDecodeError, AttributeError) as e:
            logger.warning(f"Failed to parse LLM JSON response: {e}. Content: {content[:200]}")
            # Return fallback result
            return {
                "summary": "LLM response parsing failed",
                "threat_level": "medium",
                "confidence": 0.0,
                "tags": [],
            }
        
        # Validate and normalize threat_level
        threat_level = result.get("threat_level", "medium")
        if threat_level not in ALLOWED_THREAT_LEVELS:
            logger.warning(f"Invalid threat_level: {threat_level}, using 'medium'")
            threat_level = "medium"
        
        # Validate and normalize confidence
        confidence = result.get("confidence", 0.0)
        try:
            confidence = float(confidence)
            confidence = max(0.0, min(1.0, confidence))  # Clamp to [0, 1]
        except (ValueError, TypeError):
            logger.warning(f"Invalid confidence value: {confidence}, using 0.0")
            confidence = 0.0
        
        # Validate and filter tags
        tags = result.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        # Filter to only allowed tags
        original_tag_count = len(tags)
        tags = [tag for tag in tags if tag in ALLOWED_TAGS]
        if original_tag_count > len(tags):
            logger.debug(
                f"Filtered {original_tag_count - len(tags)} invalid tags. "
                f"Allowed tags: {ALLOWED_TAGS}"
            )
        
        return {
            "summary": result.get("summary", "LLM analysis failed"),
            "threat_level": threat_level,
            "confidence": confidence,
            "tags": tags,
        }
    
    except Exception as e:
        logger.error(f"LLM analysis failed: {e}", exc_info=True)
        return {
            "summary": f"LLM error: {str(e)[:50]}",
            "threat_level": "medium",
            "confidence": 0.0,
            "tags": [],
        }

