"""Active Response (containment) utilities.

This module implements safe helper functions to perform containment (block IP)
via SSH or other methods. It is disabled by default and guarded by configuration
flags and allowlists. The functions are careful to require explicit enablement,
support dry-run mode, and log audit events.

Important safety notes:
- ENABLE_ACTIVE_RESPONSE must be true to execute actions.
- ACTIVE_RESPONSE_ALLOWLIST must be configured to prevent blocking trusted IPs.
- ACTIVE_RESPONSE_REQUIRE_CONFIRM defaults to True to avoid accidental automatic blocks.
- Supply SSH private key path via environment variable on the runner machine; do NOT commit private keys.
"""
from typing import Tuple, Optional
import logging
import shlex
import subprocess
import time
import threading
import json
import os
from datetime import datetime

from src.common.config import (
    ENABLE_ACTIVE_RESPONSE,
    ACTIVE_RESPONSE_METHOD,
    ACTIVE_RESPONSE_TARGET_HOSTS,
    ACTIVE_RESPONSE_ALLOWLIST,
    ACTIVE_RESPONSE_SSH_USER,
    ACTIVE_RESPONSE_SSH_KEY_PATH,
    ACTIVE_RESPONSE_AUTO_UNBLOCK_MINUTES,
    ACTIVE_RESPONSE_REQUIRE_CONFIRM,
    ACTIVE_RESPONSE_PF_TABLE,
        ACTIVE_RESPONSE_PF_RULE_ID,
        ACTIVE_RESPONSE_PF_RULE_AUTO_DISABLE_MINUTES,
        ACTIVE_RESPONSE_PF_RULE_DESCR,
        ACTIVE_RESPONSE_PF_REMOTE_ENABLE_SCRIPT,
        ACTIVE_RESPONSE_PF_REMOTE_DISABLE_SCRIPT,
    PRIORITY_AGENT_IDS,
    PRIORITY_AGENT_THRESHOLD,
    CONFIRM_SURICATA_SEVERITY,
    CONFIRM_LLM_CONFIDENCE,
    CONFIRM_FLOW_PKTS_TO_SERVER,
    CONFIRM_CORRELATION_SIZE,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    FAST_BLOCK_RULE_IDS,
    FAST_BLOCK_TAGS,
    FAST_BLOCK_UA_TOOLS,
    FAST_BLOCK_REQUIRE_CONFIRM,
    FAST_BLOCK_SURICATA_SEVERITY,
)

logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_AUTO_UNBLOCK_STORE = os.path.join(BASE_DIR, "state", "auto_unblock.json")
_BLOCKED_STORE = os.path.join(BASE_DIR, "state", "blocked_ips.json")

# Ensure state dir exists
os.makedirs(os.path.dirname(_AUTO_UNBLOCK_STORE), exist_ok=True)


def is_ip_allowlisted(ip: str) -> bool:
    """Return True if IP is explicitly allowlisted (must never be blocked)."""
    return ip in ACTIVE_RESPONSE_ALLOWLIST


def extract_target_ip(alert: dict) -> Optional[str]:
    """
    Extract attacker/source IP from alert using multiple known field names.
    Checks common Wazuh/Suricata paths so both agent types (agent 1 and pfSense agent 2)
    are supported. Returns first non-empty string or None.
    """
    def _deep_get(d: dict, keys: list):
        cur = d
        for k in keys:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(k)
            if cur is None:
                return None
        return cur

    # Candidate key paths in order of preference
    key_paths = [
        ["srcip"],
        ["ip"],
        ["data", "srcip"],            # agent 1: data.srcip
        ["data", "src_ip"],
        ["data", "flow", "src_ip"],  # agent 2: data.flow.src_ip
        ["data", "flow", "srcip"],
        ["data", "flow", "srcIP"],
        ["data", "alert", "srcip"],
        ["data", "alert", "src_ip"],
        ["data", "flow", "src"],      # fallback
    ]

    for path in key_paths:
        v = _deep_get(alert, path)
        if v:
            return str(v)
    return None


def confirm_attack(alert: dict, triage: dict) -> (bool, str):
    """
    Heuristic confirmation that an alert represents a real attack before blocking.
    Returns (confirmed: bool, reason: str).
    Checks multiple signals: suricata severity/action, http user_agent, llm tags/confidence,
    flow stats, correlation group size, and FP risk.
    """
    # 1) FP risk
    fp = alert.get("fp_filtering", {}) or {}
    if fp.get("fp_risk", "").upper() == "HIGH":
        return False, "fp_high"

    # 2) Suricata signals
    suricata = alert.get("suricata_alert", {}) or {}
    try:
        sev = int(suricata.get("severity", 0) or 0)
    except Exception:
        sev = 0
    action = (suricata.get("action") or "").lower()
    if sev >= CONFIRM_SURICATA_SEVERITY:
        # If action == allowed, this means attack passed => confirm
        if action == "allowed" or action == "pass":
            return True, f"suricata_severity_{sev}_allowed"
        return True, f"suricata_severity_{sev}"

    # 3) HTTP context (user-agent contains known attack tools or URL patterns)
    http = alert.get("http") or {}
    ua = (http.get("user_agent") or "").lower()
    attack_tools = ["sqlmap", "nmap", "nikto", "burp", "metasploit", "acunetix"]
    for tool in attack_tools:
        if tool in ua:
            return True, f"user_agent_tool_{tool}"
    url = http.get("url", "") or ""
    # crude SQLi pattern keywords
    sqli_indicators = ["select", "union", "concat(", "order by", "sleep(", "benchmark("]
    if any(k in url.lower() for k in sqli_indicators):
        return True, "http_url_sqli_pattern"

    # 4) Flow stats (DoS/exfil indicators)
    flow = alert.get("flow") or {}
    try:
        pkts = int(flow.get("pkts_toserver") or 0)
    except Exception:
        pkts = 0
    if pkts >= CONFIRM_FLOW_PKTS_TO_SERVER:
        return True, f"flow_pkts_{pkts}"

    # 5) LLM tags + confidence
    llm_conf = float(triage.get("llm_confidence", 0.0) or 0.0)
    tags = triage.get("tags", []) or []
    if llm_conf >= CONFIRM_LLM_CONFIDENCE and any(t in ["sql_injection", "command_injection", "web_attack", "malware"] for t in tags):
        return True, f"llm_conf_{llm_conf}"

    # 6) Correlation severity (group size)
    corr = alert.get("correlation", {}) or {}
    try:
        group_size = int(corr.get("group_size") or 0)
    except Exception:
        group_size = 0
    if group_size >= CONFIRM_CORRELATION_SIZE:
        return True, f"correlation_size_{group_size}"

    return False, "no_confirm_signal"


def matches_fast_block(alert: dict, triage: dict) -> (bool, str):
    """
    Fast-block heuristic: return True if alert should be immediately blocked for prioritized agents.
    Checks rule ids, triage tags, http user-agent tools, and suricata severity/action.
    """
    # 1) Rule ID / signature id match
    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", "") or "")
    if rule_id and rule_id in FAST_BLOCK_RULE_IDS:
        return True, f"rule_id:{rule_id}"

    # 2) triage/alert tags
    tags = []
    tags.extend(triage.get("tags", []) or [])
    tags.extend(triage.get("llm_tags", []) or [])
    tags.extend(alert.get("tags", []) or [])
    tags_lower = [str(t).lower() for t in tags]
    for t in tags_lower:
        if t in FAST_BLOCK_TAGS:
            return True, f"tag:{t}"

    # 3) HTTP user-agent contains known attack tool substrings
    http = alert.get("http") or {}
    ua = (http.get("user_agent") or http.get("user_agent_string") or http.get("user-agent") or "").lower()
    for tool in FAST_BLOCK_UA_TOOLS:
        if tool and tool in ua:
            return True, f"user_agent_tool:{tool}"

    # 4) Suricata: if action == allowed and severity >= threshold
    suricata = alert.get("suricata_alert", {}) or {}
    try:
        sev = int(suricata.get("severity", 0) or 0)
    except Exception:
        sev = 0
    action = (suricata.get("action") or "").lower()
    if action in ("allowed", "pass") and sev >= FAST_BLOCK_SURICATA_SEVERITY:
        return True, f"suricata_allowed_sev:{sev}"

    return False, ""


def trigger_active_response(alert: dict, triage: dict, dry_run: bool = True) -> dict:
    """
    Helper to safely trigger active response only for pfSense (agent id "002").
    Ensures a top-level srcip is present, copies alert, and calls block_ip().
    Returns the audit dict from block_ip or a skipped audit-like dict.
    """
    agent = alert.get("agent", {}) or {}
    agent_id = str(agent.get("id", ""))

    # Only allow automatic containment from perimeter sensor (pfSense agent 002)
    if agent_id != "002":
        logger.debug("trigger_active_response: skipping non-pfSense agent", extra={"agent_id": agent_id})
        return {"timestamp": int(time.time()), "result": "skipped", "policy_decision": "not_pfSense"}

    # Extract src ip robustly
    src_ip = extract_target_ip(alert)
    if not src_ip:
        data = alert.get("data", {}) or {}
        src_ip = data.get("srcip") or data.get("src_ip") or data.get("client_ip")

    if not src_ip:
        logger.info("Active Response: no src_ip found for pfSense alert, skipping.", extra={"agent": agent})
        return {"timestamp": int(time.time()), "result": "skipped", "policy_decision": "no_target_ip"}

    # Ensure alert passed to block_ip has top-level srcip
    ar_alert = dict(alert)
    ar_alert["srcip"] = src_ip
    # Call block_ip (will respect ENABLE_ACTIVE_RESPONSE and dry_run) and log detailed audit
    logger.info("trigger_active_response: executing block_ip", extra={"agent_id": agent_id, "target_ip": src_ip, "dry_run": dry_run})
    try:
        audit = block_ip(ar_alert, triage, dry_run=dry_run)
        # Log audit result summary
        logger.info("trigger_active_response: block_ip returned", extra={"audit_result": audit.get("result"), "policy_decision": audit.get("policy_decision"), "messages": audit.get("messages")})
        return audit
    except Exception as e:
        logger.exception("trigger_active_response: block_ip raised exception", exc_info=True, extra={"error": str(e)})
        return {"timestamp": int(time.time()), "result": "failed", "messages": [str(e)], "policy_decision": "exception"}


def policy_should_block(alert: dict, triage: dict) -> Tuple[bool, str]:
    """
    Policy decision whether to block an IP automatically.

    Basic default policy (safe):
    - Only consider blocking when ACTIVE_RESPONSE is enabled.
    - Only block when triage indicates 'critical' OR triage has critical_attack_override True.
    - Do not block allowlisted IPs.
    - If ACTIVE_RESPONSE_REQUIRE_CONFIRM is True, return False and reason 'requires_confirm'.
    """
    if not ENABLE_ACTIVE_RESPONSE:
        return False, "active_response_disabled"

    target_ip = extract_target_ip(alert)
    if not target_ip:
        # include attempted extraction fields in log for debugging
        logger.info("No target IP found in alert using known paths", extra={"agent": alert.get("agent"), "attempted": ["srcip","data.srcip","data.flow.src_ip","data.flow.srcip"]})
        return False, "no_target_ip"

    if is_ip_allowlisted(target_ip):
        return False, "allowlisted"

    threat_level = triage.get("threat_level", "").lower() if triage.get("threat_level") else ""
    critical_override = triage.get("critical_attack_override", False)

    # Priority agent override: if alert from a prioritized agent and score >= threshold,
    # allow block even if ACTIVE_RESPONSE_REQUIRE_CONFIRM is True (useful for pfSense agent 002).
    agent = alert.get("agent", {}) or {}
    agent_id = str(agent.get("id", ""))
    triage_score = float(triage.get("score", 0.0) or 0.0)

    # Fast-block path for prioritized agents (e.g., pfSense) - immediate containment on clear indicators
    if agent_id in PRIORITY_AGENT_IDS:
        # Debug log: show values used for fast-block decision to aid troubleshooting
        try:
            debug_tags = {
                "triage_tags": triage.get("tags", []),
                "alert_tags": alert.get("tags", []),
                "llm_tags": triage.get("llm_tags", triage.get("tags", [])),
                "suricata_action": (alert.get("suricata_alert") or {}).get("action"),
                "suricata_severity": (alert.get("suricata_alert") or {}).get("severity"),
                "fast_block_tags_cfg": FAST_BLOCK_TAGS,
                "fast_block_rules_cfg": FAST_BLOCK_RULE_IDS,
                "fast_block_ua_tools_cfg": FAST_BLOCK_UA_TOOLS,
            }
            logger.debug("Priority agent fast-block debug", extra={"agent_id": agent_id, "debug": debug_tags})
        except Exception:
            pass

        fast_match, fast_reason = matches_fast_block(alert, triage)
        if fast_match:
            logger.warning("FAST-BLOCK matched for priority agent", extra={"agent_id": agent_id, "fast_reason": fast_reason})
            # If fast-block requires confirm by config, refuse; otherwise allow
            if FAST_BLOCK_REQUIRE_CONFIRM:
                logger.info("FAST-BLOCK requires confirm, skipping automatic block", extra={"agent_id": agent_id, "fast_reason": fast_reason})
                return False, f"fast_block_requires_confirm:{fast_reason}"
            logger.info("FAST-BLOCK policy allowed automatic block", extra={"agent_id": agent_id, "fast_reason": fast_reason})
            return True, f"fast_block_policy_match:{fast_reason}"

        # Otherwise fall back to threshold+confirmation path
        if triage_score >= PRIORITY_AGENT_THRESHOLD:
            # Instead of immediate allow, run confirmation checks to avoid false positives.
            confirmed, reason = confirm_attack(alert, triage)
            if confirmed:
                logger.info("Priority agent confirmed attack - allowing block", extra={"agent_id": agent_id, "score": triage_score, "confirm_reason": reason})
                return True, f"priority_agent_confirmed:{reason}"
            logger.info("Priority agent threshold met but not confirmed - skipping block", extra={"agent_id": agent_id, "score": triage_score, "confirm_reason": reason})
            return False, f"priority_not_confirmed:{reason}"

    if threat_level == "critical" or critical_override:
        if ACTIVE_RESPONSE_REQUIRE_CONFIRM:
            return False, "requires_confirm"
        return True, "policy_match"

    return False, "not_critical"


def _run_ssh_block_command(management_host: str, ssh_user: str, ssh_key_path: str, block_command: str, dry_run: bool = True) -> Tuple[bool, str]:
    """
    Execute block_command on management_host via SSH.
    Returns (success, message). Uses subprocess/ssh to avoid hard dependency on paramiko.
    """
    ssh_cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "BatchMode=yes",
    ]
    if ssh_key_path:
        ssh_cmd += ["-i", ssh_key_path]
    ssh_cmd += [f"{ssh_user}@{management_host}", block_command]

    cmd_display = " ".join(shlex.quote(p) for p in ssh_cmd)
    logger.debug("Prepared SSH command: %s (dry_run=%s)", cmd_display, dry_run)

    if dry_run:
        return True, f"dry_run: {cmd_display}"

    try:
        # Increase timeout for slower/remote management hosts
        proc = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        stderr = proc.stderr.decode("utf-8", errors="ignore")
        if proc.returncode == 0:
            return True, stdout
        return False, stderr
    except Exception as e:
        return False, str(e)


def _run_ssh_unblock_command(management_host: str, ssh_user: str, ssh_key_path: str, target_ip: str, dry_run: bool = True) -> Tuple[bool, str]:
    """
    High-level helper to remove an IP from the pf table (or iptables).
    """
    pf_table = ACTIVE_RESPONSE_PF_TABLE or "WAZUH_BLOCK"
    # Run commands without sudo on pfSense (pfctl runs as root on management host)
    unblock_cmd = f"pfctl -t {pf_table} -T delete {target_ip} || iptables -D INPUT -s {target_ip} -j DROP"
    # Reuse _run_ssh_block_command logic
    return _run_ssh_block_command(management_host, ssh_user, ssh_key_path, unblock_cmd, dry_run=dry_run)


def _run_ssh_toggle_rule(management_host: str, ssh_user: str, ssh_key_path: str, rule_id: int, enable: bool = True, dry_run: bool = True) -> Tuple[bool, str]:
    """
    Toggle a pfSense firewall rule by index using pfSsh.php via SSH.
    - enable=True will set ['disabled'] = '' (enable the rule)
    - enable=False will set ['disabled'] = '1' (disable the rule)
    """
    if not rule_id:
        return False, "no_rule_id"

    disabled_val = "''" if enable else "'1'"
    # Build heredoc command
    pfssh_payload = (
        "pfSsh.php <<'EOF'\n"
        f"$config['filter']['rule'][{rule_id}]['disabled'] = {disabled_val};\n"
        "write_config();\n"
        "filter_configure();\n"
        "EOF"
    )
    # Reuse generic SSH runner (it handles dry-run and timeout)
    return _run_ssh_block_command(management_host, ssh_user, ssh_key_path, pfssh_payload, dry_run=dry_run)


def _schedule_rule_disable(management_host: str, ssh_user: str, ssh_key_path: str, rule_id: int, minutes: int):
    """
    Schedule a background timer to disable a previously enabled pfSense rule after `minutes`.
    Runs in a daemon thread.
    """
    def _task():
        try:
            time.sleep(max(0, minutes * 60))
            success, msg = _run_ssh_toggle_rule(management_host, ssh_user, ssh_key_path, rule_id, enable=False, dry_run=False)
            if success:
                logger.info("Auto-disable pfSense rule executed", extra={"management_host": management_host, "rule_id": rule_id})
            else:
                logger.warning("Auto-disable pfSense rule failed", extra={"management_host": management_host, "rule_id": rule_id, "error": msg})
        except Exception:
            logger.exception("Auto-disable pfSense rule exception", exc_info=True, extra={"management_host": management_host, "rule_id": rule_id})

    t = threading.Thread(target=_task, daemon=True)
    t.start()
    t = threading.Thread(target=_task, daemon=True)
    t.start()


def _run_ssh_toggle_rule_by_descr(management_host: str, ssh_user: str, ssh_key_path: str, descr: str, enable: bool = True, dry_run: bool = True) -> Tuple[bool, str]:
    """
    Toggle a pfSense firewall rule by searching for its 'descr' field using pfSsh.php.
    Uses the PHP loop payload provided by the user to locate the rule and set/unset 'disabled'.
    """
    if not descr:
        return False, "no_rule_descr"

    if enable:
        php_action = (
            "<?php\n"
            "global $config;\n"
            "foreach ($config['filter']['rule'] as &$rule) {\n"
            f"  if ($rule['descr'] === '{descr}') {{\n"
            "    unset($rule['disabled']);    // enable rule\n"
            "    break;\n"
            "  }\n"
            "}\n"
            "write_config('Enable DDOS emergency block from LAN script');\n"
            "filter_configure();\n"
            "?>\n"
        )
    else:
        php_action = (
            "<?php\n"
            "global $config;\n"
            "foreach ($config['filter']['rule'] as &$rule) {\n"
            f"  if ($rule['descr'] === '{descr}') {{\n"
            "    $rule['disabled'] = 'true';  // disable rule\n"
            "    break;\n"
            "  }\n"
            "}\n"
            "write_config('Disable DDOS emergency block from LAN script');\n"
            "filter_configure();\n"
            "?>\n"
        )

    pfssh_payload = "pfSsh.php << 'EOF'\n" + php_action + "EOF"
    return _run_ssh_block_command(management_host, ssh_user, ssh_key_path, pfssh_payload, dry_run=dry_run)


def _schedule_rule_disable_by_descr(management_host: str, ssh_user: str, ssh_key_path: str, descr: str, minutes: int):
    """
    Schedule a background timer to disable a pfSense rule found by description after `minutes`.
    """
    def _task():
        try:
            time.sleep(max(0, minutes * 60))
            success, msg = _run_ssh_toggle_rule_by_descr(management_host, ssh_user, ssh_key_path, descr, enable=False, dry_run=False)
            if success:
                logger.info("Auto-disable pfSense rule by descr executed", extra={"management_host": management_host, "rule_descr": descr})
            else:
                logger.warning("Auto-disable pfSense rule by descr failed", extra={"management_host": management_host, "rule_descr": descr, "error": msg})
        except Exception:
            logger.exception("Auto-disable pfSense rule by descr exception", exc_info=True, extra={"management_host": management_host, "rule_descr": descr})

    t = threading.Thread(target=_task, daemon=True)
    t.start()


def _run_ssh_execute_remote_file(management_host: str, ssh_user: str, ssh_key_path: str, remote_path: str, dry_run: bool = True) -> Tuple[bool, str]:
    """
    Execute a remote script file on the management host by invoking pfSsh.php reading from that file.
    Uses: pfSsh.php < /path/to/script.php
    Returns (success, output).
    """
    if not remote_path:
        return False, "no_remote_path"

    # Build ssh command; avoid heredoc and send remote redirection so it works on Windows and Unix clients.
    remote_cmd = f"pfSsh.php < {shlex.quote(remote_path)}"
    ssh_cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "BatchMode=yes",
    ]
    # Optional verbose if env set for debugging
    if os.getenv("SSH_VERBOSE", "").lower() in ("1", "true", "yes", "on"):
        ssh_cmd += ["-vvv", "-o", "ConnectTimeout=15"]
    if ssh_key_path:
        ssh_cmd += ["-i", ssh_key_path]
    ssh_cmd += [f"{ssh_user}@{management_host}", remote_cmd]

    cmd_display = " ".join(shlex.quote(p) for p in ssh_cmd)
    logger.debug("Prepared SSH exec command: %s (dry_run=%s)", cmd_display, dry_run)

    if dry_run:
        return True, f"dry_run: {cmd_display}"

    try:
        proc = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        stderr = proc.stderr.decode("utf-8", errors="ignore")
        if proc.returncode == 0:
            return True, stdout
        return False, stderr or stdout
    except Exception as e:
        return False, str(e)


def _schedule_remote_file_run(management_host: str, ssh_user: str, ssh_key_path: str, remote_path: str, minutes: int):
    """
    Schedule a background timer to execute a remote script file after `minutes`.
    """
    def _task():
        try:
            time.sleep(max(0, minutes * 60))
            success, msg = _run_ssh_execute_remote_file(management_host, ssh_user, ssh_key_path, remote_path, dry_run=False)
            if success:
                logger.info("Auto remote-file execution succeeded", extra={"management_host": management_host, "remote_path": remote_path})
            else:
                logger.warning("Auto remote-file execution failed", extra={"management_host": management_host, "remote_path": remote_path, "error": msg})
        except Exception:
            logger.exception("Auto remote-file execution exception", exc_info=True, extra={"management_host": management_host, "remote_path": remote_path})

    t = threading.Thread(target=_task, daemon=True)
    t.start()


def _schedule_auto_unblock(management_host: str, ssh_user: str, ssh_key_path: str, target_ip: str, minutes: int):
    """
    Schedule a background timer to auto-unblock the IP after `minutes`.
    Runs in a daemon thread so it doesn't block process exit.
    """
    def _task():
        try:
            # Sleep then attempt unblock (non-dry-run)
            time.sleep(max(0, minutes * 60))
            success, msg = _run_ssh_unblock_command(management_host, ssh_user, ssh_key_path, target_ip, dry_run=False)
            if success:
                logger.info("Auto-unblock executed", extra={"component": "active_response", "management_host": management_host, "target_ip": target_ip})
                # Remove from blocked store on successful unblock
                try:
                    _remove_blocked_ip(target_ip)
                except Exception:
                    logger.exception("Failed to remove blocked IP from store after auto-unblock", exc_info=True)
            else:
                logger.warning("Auto-unblock failed", extra={"component": "active_response", "management_host": management_host, "target_ip": target_ip, "error": msg})
        except Exception as e:
            logger.exception("Auto-unblock task exception", exc_info=True, extra={"component": "active_response", "target_ip": target_ip})

    t = threading.Thread(target=_task, daemon=True)
    t.start()


def _load_pending_unblocks():
    try:
        if not os.path.exists(_AUTO_UNBLOCK_STORE):
            return []
        with open(_AUTO_UNBLOCK_STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception as e:
        logger.warning("Failed to load pending unblocks store", exc_info=True)
        return []


def _load_blocked_ips():
    try:
        if not os.path.exists(_BLOCKED_STORE):
            return []
        with open(_BLOCKED_STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        logger.warning("Failed to load blocked ips store", exc_info=True)
        return []


def _save_blocked_ips(entries):
    try:
        tmp = _BLOCKED_STORE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(entries, f)
        os.replace(tmp, _BLOCKED_STORE)
    except Exception as e:
        logger.warning("Failed to save blocked ips store", exc_info=True)


def _mark_ip_blocked(management_host: str, ssh_user: str, ssh_key_path: str, target_ip: str):
    entries = _load_blocked_ips()
    now = int(time.time())
    entries = [e for e in entries if e.get("target_ip") != target_ip]  # dedupe
    entries.append({
        "management_host": management_host,
        "ssh_user": ssh_user,
        "ssh_key_path": ssh_key_path,
        "target_ip": target_ip,
        "blocked_at": now
    })
    _save_blocked_ips(entries)


def _remove_blocked_ip(target_ip: str):
    entries = _load_blocked_ips()
    entries = [e for e in entries if e.get("target_ip") != target_ip]
    _save_blocked_ips(entries)


def is_ip_currently_blocked(target_ip: str) -> bool:
    try:
        entries = _load_blocked_ips()
        return any(e.get("target_ip") == target_ip for e in entries)
    except Exception:
        return False


def _save_pending_unblocks(entries):
    try:
        tmp = _AUTO_UNBLOCK_STORE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(entries, f)
        os.replace(tmp, _AUTO_UNBLOCK_STORE)
    except Exception as e:
        logger.warning("Failed to save pending unblocks store", exc_info=True)


def _add_pending_unblock(management_host: str, ssh_user: str, ssh_key_path: str, target_ip: str, unblock_at_ts: int):
    entries = _load_pending_unblocks()
    entries.append({
        "management_host": management_host,
        "ssh_user": ssh_user,
        "ssh_key_path": ssh_key_path,
        "target_ip": target_ip,
        "unblock_at": unblock_at_ts
    })
    _save_pending_unblocks(entries)


def _remove_pending_unblock(target_ip: str):
    entries = _load_pending_unblocks()
    entries = [e for e in entries if e.get("target_ip") != target_ip]
    _save_pending_unblocks(entries)


def _resume_pending_unblocks():
    """Call on module import/startup to resume timers for pending unblock entries."""
    now_ts = int(time.time())
    entries = _load_pending_unblocks()
    for e in entries:
        unblock_at = int(e.get("unblock_at", now_ts))
        delay_sec = max(0, unblock_at - now_ts)
        minutes = max(0, int(delay_sec / 60))

        # Schedule as background thread
        try:
            logger.info("Resuming pending auto-unblock", extra={"target_ip": e.get("target_ip"), "in_seconds": delay_sec})
            t = threading.Thread(
                target=lambda mh=e.get("management_host"), su=e.get("ssh_user"), sk=e.get("ssh_key_path"), tip=e.get("target_ip"), ds=delay_sec: (
                    time.sleep(ds),
                    _run_ssh_unblock_command(mh, su, sk, tip, dry_run=False),
                    _remove_pending_unblock(tip)
                ),
                daemon=True
            )
            t.start()
        except Exception as e:
            logger.exception("Failed to resume pending unblock", exc_info=True)

def _send_telegram_message(text: str) -> Tuple[bool, str]:
    """Send a simple Telegram message using configured bot token/chat_id."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "telegram_not_configured"
    try:
        session = __import__("src.common.web", fromlist=["RetrySession"]).RetrySession()
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
        resp = session.request_with_backoff("POST", url, json=payload)
        resp.raise_for_status()
        return True, "sent"
    except Exception as e:
        logger.exception("Failed to send Telegram message", exc_info=True)
        return False, str(e)
 


# Resume pending unblocks on import/startup
_resume_pending_unblocks()


def block_ip(alert: dict, triage: dict, management_host: Optional[str] = None, dry_run: bool = True) -> dict:
    """
    High-level function to attempt containment (block IP).

    - Checks policy via policy_should_block()
    - For SSH method, runs a standard block command on the management_host for the target IP
      (management_host must be provided or taken from ACTIVE_RESPONSE_TARGET_HOSTS).
    - Returns an audit dict with status and messages.
    """
    audit = {
        "timestamp": int(time.time()),
        "enabled": ENABLE_ACTIVE_RESPONSE,
        "method": ACTIVE_RESPONSE_METHOD,
        "dry_run": dry_run,
        "result": "skipped",
        "messages": [],
    }

    allowed, reason = policy_should_block(alert, triage)
    audit["policy_decision"] = reason
    if not allowed:
        audit["messages"].append(f"Policy denied action: {reason}")
        return audit

    target_ip = extract_target_ip(alert)
    if not management_host:
        if ACTIVE_RESPONSE_TARGET_HOSTS:
            management_host = ACTIVE_RESPONSE_TARGET_HOSTS[0]
        else:
            audit["messages"].append("No management_host configured")
            return audit

    # Fallback to pfctl table add / iptables for per-IP blocking
    pf_table = ACTIVE_RESPONSE_PF_TABLE or "WAZUH_BLOCK"
    # Execute commands without sudo on pfSense (pfctl runs as root on the management host).
    # Fallback to iptables commands for Linux management hosts (also without sudo).
    block_cmd = (
        f"pfctl -t {pf_table} -T add {target_ip} "
        f"|| iptables -C INPUT -s {target_ip} -j DROP || iptables -I INPUT -s {target_ip} -j DROP"
    )

    success, msg = _run_ssh_block_command(management_host, ACTIVE_RESPONSE_SSH_USER or "root", ACTIVE_RESPONSE_SSH_KEY_PATH, block_cmd, dry_run=dry_run)
    audit["result"] = "success" if success else "failed"
    audit["messages"].append(msg)
    audit["management_host"] = management_host
    audit["target_ip"] = target_ip
    # If block succeeded (and this was not a dry-run), record as blocked so we can
    # re-assert blocks later even if suppression is active.
    if success and not dry_run:
        try:
            _mark_ip_blocked(management_host, ACTIVE_RESPONSE_SSH_USER or "root", ACTIVE_RESPONSE_SSH_KEY_PATH, target_ip)
        except Exception:
            logger.exception("Failed to mark IP as blocked in store", exc_info=True)
    # Schedule auto-unblock if configured (pfctl table removal)
    if success and ACTIVE_RESPONSE_AUTO_UNBLOCK_MINUTES > 0 and not dry_run:
        audit["messages"].append(f"Will auto-unblock after {ACTIVE_RESPONSE_AUTO_UNBLOCK_MINUTES} minutes")
        try:
            _schedule_auto_unblock(management_host, ACTIVE_RESPONSE_SSH_USER or "root", ACTIVE_RESPONSE_SSH_KEY_PATH, target_ip, ACTIVE_RESPONSE_AUTO_UNBLOCK_MINUTES)
        except Exception as e:
            audit["messages"].append(f"Auto-unblock scheduling failed: {e}")

    # Send Telegram notification on success
    if success and not dry_run:
        try:
            title = f"SOC Auto-Response - Blocked {target_ip}"
            body = (
                f"Auto-response blocked IP: {target_ip}\n"
                f"Management host: {management_host}\n"
                f"Reason: {audit.get('policy_decision')}\n"
                f"Score: {triage.get('score')}\n"
                f"Threat level: {triage.get('threat_level')}\n"
            )
            sent, msg = _send_telegram_message(f"{title}\n\n{body}")
            audit["messages"].append(f"telegram:{msg}")
        except Exception as e:
            audit["messages"].append(f"telegram_error:{e}")

    return audit


