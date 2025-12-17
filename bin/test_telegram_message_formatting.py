#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Telegram message formatting with real alert data.
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

from src.orchestrator.notify import _format_telegram_message, _escape_markdown_content
from src.common.alert_formatter import format_alert_card, format_alert_card_short
import os
from dotenv import load_dotenv
from src.common.web import RetrySession

# Load environment variables
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def test_escape_function():
    """Test escape function with problematic characters."""
    print("=" * 70)
    print("TEST 1: Markdown Escape Function")
    print("=" * 70)
    print()
    
    test_cases = [
        ("Normal text", "Normal text"),
        ("Text with (parentheses)", "Text with \\(parentheses\\)"),
        ("Text with [brackets]", "Text with \\[brackets\\]"),
        ("Text with `backticks`", "Text with \\`backticks\\`"),
        ("Text with *asterisks*", "Text with *asterisks*"),  # Should NOT escape
        ("Text with _underscores_", "Text with _underscores_"),  # Should NOT escape
        ("Complex: (test) [test] `test`", "Complex: \\(test\\) \\[test\\] \\`test\\`"),
        ("Summary with (parentheses) and [brackets]", "Summary with \\(parentheses\\) and \\[brackets\\]"),
    ]
    
    all_passed = True
    for input_text, expected in test_cases:
        result = _escape_markdown_content(input_text)
        passed = result == expected
        status = "✅ PASS" if passed else "❌ FAIL"
        if not passed:
            all_passed = False
        print(f"{status}: '{input_text}'")
        print(f"   Expected: '{expected}'")
        print(f"   Got:      '{result}'")
        print()
    
    return all_passed


def test_real_alert_message():
    """Test with real alert data from log."""
    print("=" * 70)
    print("TEST 2: Real Alert Message Formatting")
    print("=" * 70)
    print()
    
    # Real alert data from log
    alert = {
        "rule": {
            "id": "110231",
            "level": 13,
            "description": "CONFIRMED: Network connect by web server user (possible reverse shell)"
        },
        "agent": {
            "id": "001",
            "name": "WebServer",
            "ip": "192.168.20.125"
        },
        "@timestamp": "2025-12-14T14:04:56.286Z"
    }
    
    triage = {
        "score": 0.938,
        "threat_level": "high",
        "tags": ["network_intrusion", "suspicious_process", "web_attack", "wazuh_rule_high"],
        "summary": "Auditd on WebServer detected an outbound network connection initiated by the web server user, which is commonly associated with a webshell or reverse shell activity. The rule fired twice, suggesting repeated connection attempts."
    }
    
    alert_card = format_alert_card(alert, triage)
    alert_card_short = format_alert_card_short(alert_card)
    
    message = _format_telegram_message(
        alert, triage, alert_card, alert_card_short,
        is_critical_override=True,
        override_reason="Critical attack rule 110231 (level 13)"
    )
    
    print("Formatted message:")
    print("-" * 70)
    print(message)
    print("-" * 70)
    print()
    print(f"Message length: {len(message)} characters")
    print(f"Max Telegram limit: 4096 characters")
    print()
    
    # Check for unescaped problematic characters
    problematic = []
    if '(' in message and '\\(' not in message.replace('\\\\(', ''):
        # Check if there are unescaped parentheses (but not in formatting tags)
        lines = message.split('\n')
        for i, line in enumerate(lines):
            if '*' in line and ':' in line:
                # This is a formatting line, skip
                continue
            if '(' in line and '\\(' not in line:
                problematic.append(f"Line {i+1}: Unescaped '(' in: {line[:50]}")
    
    if problematic:
        print("⚠️  WARNING: Potential unescaped characters found:")
        for p in problematic:
            print(f"   {p}")
        print()
        return False
    else:
        print("✅ No unescaped problematic characters found")
        print()
        return True


def test_send_to_telegram():
    """Test sending formatted message to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️  Skipping Telegram send test (credentials not configured)")
        return True
    
    print("=" * 70)
    print("TEST 3: Send Test Message to Telegram")
    print("=" * 70)
    print()
    
    # Create test message with problematic characters
    alert = {
        "rule": {
            "id": "110231",
            "level": 13,
            "description": "CONFIRMED: Network connect (reverse shell)"
        },
        "agent": {
            "id": "001",
            "name": "WebServer",
            "ip": "192.168.20.125"
        },
        "@timestamp": "2025-12-14T14:04:56.286Z"
    }
    
    triage = {
        "score": 0.938,
        "threat_level": "high",
        "tags": ["network_intrusion", "suspicious_process"],
        "summary": "Auditd detected outbound connection (webshell or reverse shell). The rule fired twice (repeated attempts)."
    }
    
    alert_card = format_alert_card(alert, triage)
    alert_card_short = format_alert_card_short(alert_card)
    
    message = _format_telegram_message(
        alert, triage, alert_card, alert_card_short,
        is_critical_override=True,
        override_reason="Critical attack rule 110231 (level 13)"
    )
    
    print("Sending test message to Telegram...")
    print()
    
    try:
        session = RetrySession()
        telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        
        response = session.request("POST", telegram_url, json=payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("ok"):
                message_id = result.get("result", {}).get("message_id")
                print(f"✅ Message sent successfully! (message_id: {message_id})")
                print()
                return True
            else:
                error_desc = result.get("description", "Unknown error")
                print(f"❌ Telegram API error: {error_desc}")
                print()
                return False
        else:
            try:
                error_data = response.json()
                error_desc = error_data.get("description", response.text[:200])
                print(f"❌ HTTP {response.status_code}: {error_desc}")
                print()
                print("Message that failed:")
                print("-" * 70)
                print(message[:500])
                print("-" * 70)
                return False
            except:
                print(f"❌ HTTP {response.status_code}: {response.text[:200]}")
                return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == "__main__":
    print()
    print("🧪 Testing Telegram Message Formatting")
    print()
    
    test1 = test_escape_function()
    test2 = test_real_alert_message()
    test3 = test_send_to_telegram()
    
    print("=" * 70)
    if test1 and test2 and test3:
        print("✅ ALL TESTS PASSED!")
        print("✅ Messages should now send successfully to Telegram")
    else:
        print("❌ SOME TESTS FAILED")
        if not test1:
            print("   - Escape function test failed")
        if not test2:
            print("   - Message formatting test failed")
        if not test3:
            print("   - Telegram send test failed")
    print("=" * 70)
    print()

