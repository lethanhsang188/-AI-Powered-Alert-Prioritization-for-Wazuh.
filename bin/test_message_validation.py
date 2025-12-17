#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test message validation function.
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

from src.orchestrator.notify import _validate_telegram_message, _format_telegram_message, _escape_markdown_content
from src.common.alert_formatter import format_alert_card, format_alert_card_short

def test_validation():
    """Test validation function with various messages."""
    print("=" * 70)
    print("TEST: Message Validation")
    print("=" * 70)
    print()
    
    test_cases = [
        # (message, should_be_valid, description)
        ("*Title:* Test", True, "Simple formatting"),
        ("*Title:* Test \\(Level 13\\)", True, "Escaped parentheses"),
        ("*Title:* Test (Level 13)", False, "Unescaped parentheses in formatting"),
        ("Summary: Test (example)", False, "Unescaped parentheses in content"),
        ("Summary: Test \\(example\\)", True, "Escaped parentheses in content"),
        ("*Tags:* test, xss, web_attack", True, "Tags line"),
        ("Test [truncated]", False, "Unescaped brackets"),
        ("Test \\[truncated\\]", True, "Escaped brackets"),
        ("*Rule ID:* 110231 \\(Level 13\\)", True, "Rule ID with escaped parentheses"),
        ("*Rule ID:* 110231 (Level 13)", False, "Rule ID with unescaped parentheses"),
    ]
    
    all_passed = True
    for message, should_be_valid, description in test_cases:
        is_valid, error = _validate_telegram_message(message)
        passed = (is_valid == should_be_valid)
        status = "✅ PASS" if passed else "❌ FAIL"
        if not passed:
            all_passed = False
        
        print(f"{status}: {description}")
        print(f"   Message: {message[:50]}")
        print(f"   Expected valid: {should_be_valid}, Got valid: {is_valid}")
        if error:
            print(f"   Error: {error}")
        print()
    
    return all_passed


def test_real_alert_validation():
    """Test validation with real alert data."""
    print("=" * 70)
    print("TEST: Real Alert Message Validation")
    print("=" * 70)
    print()
    
    # Real alert data
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
        "tags": ["network_intrusion", "suspicious_process", "web_attack"],
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
    
    is_valid, error = _validate_telegram_message(message)
    
    if is_valid:
        print("✅ Message validation PASSED")
        print(f"   Message length: {len(message)} characters")
    else:
        print("❌ Message validation FAILED")
        print(f"   Error: {error}")
        print()
        print("Message content (first 500 chars):")
        print(message[:500])
    
    print()
    return is_valid


if __name__ == "__main__":
    print()
    print("🧪 Testing Message Validation")
    print()
    
    test1 = test_validation()
    test2 = test_real_alert_validation()
    
    print("=" * 70)
    if test1 and test2:
        print("✅ ALL VALIDATION TESTS PASSED!")
        print("✅ Messages are properly validated before sending")
    else:
        print("❌ SOME VALIDATION TESTS FAILED")
    print("=" * 70)
    print()

