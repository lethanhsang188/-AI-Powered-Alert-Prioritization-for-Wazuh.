#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Telegram bot connection and message sending.
"""
import os
import sys
import json
from pathlib import Path

# Fix encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
from src.common.web import RetrySession

# Load environment variables
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def test_telegram_connection():
    """Test Telegram bot connection with a simple message."""
    if not TELEGRAM_BOT_TOKEN:
        print("❌ ERROR: TELEGRAM_BOT_TOKEN not set in .env")
        return False
    
    if not TELEGRAM_CHAT_ID:
        print("❌ ERROR: TELEGRAM_CHAT_ID not set in .env")
        return False
    
    print(f"📱 Testing Telegram bot connection...")
    print(f"   Bot Token: {TELEGRAM_BOT_TOKEN[:20]}...")
    print(f"   Chat ID: {TELEGRAM_CHAT_ID}")
    print()
    
    # Test 1: Get bot info
    print("1️⃣ Testing bot info...")
    try:
        session = RetrySession()
        bot_info_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getMe"
        response = session.request("GET", bot_info_url, timeout=10)
        response.raise_for_status()
        bot_info = response.json()
        
        if bot_info.get("ok"):
            bot_data = bot_info.get("result", {})
            print(f"   ✅ Bot is valid: @{bot_data.get('username', 'unknown')} ({bot_data.get('first_name', 'unknown')})")
        else:
            print(f"   ❌ Bot info error: {bot_info.get('description', 'Unknown error')}")
            return False
    except Exception as e:
        print(f"   ❌ Failed to get bot info: {e}")
        return False
    
    print()
    
    # Test 2: Send simple text message (no Markdown)
    print("2️⃣ Testing simple text message (no formatting)...")
    try:
        session = RetrySession()
        send_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": "🧪 Test message from SOC Pipeline\n\nThis is a simple test without Markdown formatting.",
            "disable_web_page_preview": True
        }
        
        response = session.request("POST", send_url, json=payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("ok"):
                message_id = result.get("result", {}).get("message_id")
                print(f"   ✅ Simple message sent successfully (message_id: {message_id})")
            else:
                error_desc = result.get("description", "Unknown error")
                error_code = result.get("error_code", "?")
                print(f"   ❌ Telegram API error: {error_code} - {error_desc}")
                print(f"   💡 Common issues:")
                print(f"      - Bot not added to group/channel")
                print(f"      - Chat ID incorrect")
                print(f"      - Bot doesn't have permission to send messages")
                return False
        else:
            print(f"   ❌ HTTP {response.status_code}: {response.text[:200]}")
            return False
    except Exception as e:
        print(f"   ❌ Failed to send simple message: {e}")
        return False
    
    print()
    
    # Test 3: Send Markdown message
    print("3️⃣ Testing Markdown formatted message...")
    try:
        session = RetrySession()
        send_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": "*SOC Alert Test*\n\n*Title:* Test Alert\n*Score:* 0.855\n*Rule ID:* 31105",
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        
        response = session.request("POST", send_url, json=payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("ok"):
                message_id = result.get("result", {}).get("message_id")
                print(f"   ✅ Markdown message sent successfully (message_id: {message_id})")
            else:
                error_desc = result.get("description", "Unknown error")
                error_code = result.get("error_code", "?")
                print(f"   ❌ Markdown message error: {error_code} - {error_desc}")
                print(f"   💡 This might indicate Markdown formatting issues")
                return False
        else:
            print(f"   ❌ HTTP {response.status_code}: {response.text[:200]}")
            return False
    except Exception as e:
        print(f"   ❌ Failed to send Markdown message: {e}")
        return False
    
    print()
    print("✅ All tests passed! Telegram bot is configured correctly.")
    return True

if __name__ == "__main__":
    success = test_telegram_connection()
    sys.exit(0 if success else 1)

