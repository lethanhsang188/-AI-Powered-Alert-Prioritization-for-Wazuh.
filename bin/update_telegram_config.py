#!/usr/bin/env python3
"""Update .env file with Telegram bot credentials."""
import os
import sys
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent
env_path = base_dir / ".env"

def update_telegram_config(bot_token: str, chat_id: str):
    """Update .env file with Telegram bot credentials."""
    lines = []
    telegram_token_found = False
    telegram_chat_found = False
    
    # Read existing .env file if it exists
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("TELEGRAM_BOT_TOKEN="):
                    lines.append(f"TELEGRAM_BOT_TOKEN={bot_token}\n")
                    telegram_token_found = True
                elif stripped.startswith("TELEGRAM_CHAT_ID="):
                    lines.append(f"TELEGRAM_CHAT_ID={chat_id}\n")
                    telegram_chat_found = True
                else:
                    lines.append(line)
    
    # Add Telegram config if not found
    if not telegram_token_found:
        lines.append(f"TELEGRAM_BOT_TOKEN={bot_token}\n")
    if not telegram_chat_found:
        lines.append(f"TELEGRAM_CHAT_ID={chat_id}\n")
    
    # Write updated .env file
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    
    print(f"[OK] Updated .env file with Telegram credentials")
    print(f"     Bot Token: {bot_token[:20]}...")
    print(f"     Chat ID: {chat_id}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python update_telegram_config.py <BOT_TOKEN> <CHAT_ID>")
        sys.exit(1)
    
    bot_token = sys.argv[1]
    chat_id = sys.argv[2]
    
    update_telegram_config(bot_token, chat_id)

