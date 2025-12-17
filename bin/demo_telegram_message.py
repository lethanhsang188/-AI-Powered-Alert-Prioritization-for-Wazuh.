#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demo script to show how Telegram messages will look.
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Fix encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

from src.orchestrator.notify import _format_telegram_message
from src.common.alert_formatter import format_alert_card, format_alert_card_short

def demo_message_1():
    """Demo: Critical Reverse Shell Alert (Level 13)"""
    print("=" * 70)
    print("VÍ DỤ 1: Critical Attack - Reverse Shell (Rule 110231, Level 13)")
    print("=" * 70)
    print()
    
    # Mock alert data
    alert = {
        "rule": {
            "id": "110231",
            "level": 13,
            "description": "CONFIRMED: Network connect by web server user (possible reverse shell)",
            "mitre": {
                "id": ["T1059"]
            }
        },
        "agent": {
            "id": "001",
            "name": "WebServer",
            "ip": "192.168.20.125"
        },
        "srcip": "172.16.69.175",
        "dstip": "192.168.20.125",
        "@timestamp": "2025-12-14T13:21:03.536Z",
        "http": {
            "url": "/dvwa/vulnerabilities/exec/",
            "method": "POST"
        }
    }
    
    triage = {
        "score": 0.962,
        "threat_level": "high",
        "tags": ["wazuh_rule_high", "network_intrusion", "suspicious_process", "web_attack"],
        "summary": "Auditd on WebServer detected an outbound network connection initiated by the web server user, which is commonly associated with a webshell spawning a reverse shell. This behavior is unusual for a web server process and indicates potential compromise."
    }
    
    alert_card = format_alert_card(alert, triage)
    alert_card_short = format_alert_card_short(alert_card)
    
    # Format as Telegram message
    message = _format_telegram_message(
        alert, triage, alert_card, alert_card_short,
        is_critical_override=True,
        override_reason="Critical attack rule 110231 (level 13)"
    )
    
    print(message)
    print()
    print(f"Message length: {len(message)} characters")
    print()


def demo_message_2():
    """Demo: High Severity XSS Alert (Rule 31105, Level 7)"""
    print("=" * 70)
    print("VÍ DỤ 2: High Severity - XSS Attack (Rule 31105, Level 7)")
    print("=" * 70)
    print()
    
    alert = {
        "rule": {
            "id": "31105",
            "level": 7,
            "description": "Cross-Site Scripting (XSS) attempt detected",
            "mitre": {
                "id": ["T1190"]
            }
        },
        "agent": {
            "id": "001",
            "name": "WebServer",
            "ip": "192.168.20.125"
        },
        "srcip": "172.16.69.175",
        "dstip": "192.168.20.125",
        "@timestamp": "2025-12-14T13:21:03.536Z",
        "http": {
            "url": "/dvwa/vulnerabilities/xss/?name=<script>alert('XSS')</script>",
            "method": "GET"
        }
    }
    
    triage = {
        "score": 0.855,
        "threat_level": "high",
        "tags": ["web_attack", "xss", "wazuh_rule_high"],
        "summary": "Wazuh rule 31105 triggered on the WebServer, indicating a potential Cross-Site Scripting (XSS) attempt observed in web access logs. The alert lacks request details (message/src IP/user), so the specific payload and target endpoint cannot be determined from this event alone."
    }
    
    alert_card = format_alert_card(alert, triage)
    alert_card_short = format_alert_card_short(alert_card)
    
    message = _format_telegram_message(
        alert, triage, alert_card, alert_card_short,
        is_critical_override=False,
        override_reason=None
    )
    
    print(message)
    print()
    print(f"Message length: {len(message)} characters")
    print()


def demo_message_3():
    """Demo: Medium Severity - Normal Threshold"""
    print("=" * 70)
    print("VÍ DỤ 3: Medium Severity - Package Installation (Rule 2902, Level 7)")
    print("=" * 70)
    print()
    
    alert = {
        "rule": {
            "id": "2902",
            "level": 7,
            "description": "New Debian package installed via dpkg"
        },
        "agent": {
            "id": "001",
            "name": "WebServer",
            "ip": "192.168.20.125"
        },
        "@timestamp": "2025-12-14T13:21:03.536Z"
    }
    
    triage = {
        "score": 0.724,
        "threat_level": "medium",
        "tags": ["suspicious_config_change", "wazuh_rule_medium"],
        "summary": "Wazuh detected that a new Debian package was installed via dpkg on the WebServer host. The alert lacks package name, user, and source IP, so the change cannot be attributed from this event alone."
    }
    
    alert_card = format_alert_card(alert, triage)
    alert_card_short = format_alert_card_short(alert_card)
    
    message = _format_telegram_message(
        alert, triage, alert_card, alert_card_short,
        is_critical_override=False,
        override_reason=None
    )
    
    print(message)
    print()
    print(f"Message length: {len(message)} characters")
    print()


if __name__ == "__main__":
    print()
    print("📱 DEMO: Telegram Message Format")
    print()
    
    demo_message_1()
    demo_message_2()
    demo_message_3()
    
    print("=" * 70)
    print("✅ Demo hoàn tất!")
    print("=" * 70)
    print()
    print("Lưu ý:")
    print("- Messages sẽ được format với Markdown")
    print("- Tự động truncate nếu > 4096 ký tự")
    print("- Critical attacks (level >= 12) luôn được gửi, kể cả khi score < 0.7")
    print()

