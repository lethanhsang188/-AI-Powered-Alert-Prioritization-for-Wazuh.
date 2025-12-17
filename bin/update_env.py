#!/usr/bin/env python3
"""Update .env file with required configuration values."""
import os
import sys
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir))

def update_env_file():
    """Update .env file with required configuration values."""
    env_path = base_dir / ".env"
    template_path = base_dir / "env.template"
    
    # Read current .env file
    env_vars = {}
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # Parse key=value
                if "=" in line:
                    key, value = line.split("=", 1)
                    env_vars[key.strip()] = value.strip()
    
    # Read template for comments and structure
    template_lines = []
    if template_path.exists():
        with open(template_path, "r", encoding="utf-8") as f:
            template_lines = f.readlines()
    
    # Required updates (priority: keep existing values, add missing ones)
    required_updates = {
        # SSL Configuration (fix SSL error)
        "WAZUH_INDEXER_VERIFY_SSL": "false",
        "WAZUH_API_VERIFY_SSL": env_vars.get("WAZUH_API_VERIFY_SSL", "false"),
        
        # Real-time processing (fetch new alerts, not old ones)
        "WAZUH_START_FROM_NOW": "true",
        "WAZUH_LOOKBACK_MINUTES": "5",
        "WAZUH_DEMO_MODE": "false",
        "WAZUH_REALTIME_MODE": "false",
        "WAZUH_REALTIME_INTERVAL_SEC": "1.0",
        
        # Indexer delay compensation
        "INDEXER_DELAY_SECONDS": "5",
        
        # Batch configuration
        "WAZUH_MAX_BATCHES": "5",
        "WAZUH_PAGE_LIMIT": env_vars.get("WAZUH_PAGE_LIMIT", "200"),
        
        # Timezone
        "LOCAL_TIMEZONE": "Asia/Ho_Chi_Minh",
        
        # Cursor path
        "CURSOR_PATH": env_vars.get("CURSOR_PATH", "/app/state/cursor.json"),
        
        # Wazuh API Configuration (keep existing or use defaults)
        "WAZUH_API_URL": env_vars.get("WAZUH_API_URL", "https://192.168.10.128:55000"),
        "WAZUH_API_USER": env_vars.get("WAZUH_API_USER", "wazuh-wui"),
        "WAZUH_API_PASS": env_vars.get("WAZUH_API_PASS", "wazuh-wui"),
        "WAZUH_API_TOKEN": env_vars.get("WAZUH_API_TOKEN", ""),
        "WAZUH_MIN_LEVEL": env_vars.get("WAZUH_MIN_LEVEL", "5"),
        "WAZUH_POLL_INTERVAL_SEC": env_vars.get("WAZUH_POLL_INTERVAL_SEC", "8"),
        
        # Wazuh Indexer Configuration (keep existing or use defaults)
        "WAZUH_INDEXER_URL": env_vars.get("WAZUH_INDEXER_URL", "https://192.168.10.128:9200"),
        "WAZUH_INDEXER_USER": env_vars.get("WAZUH_INDEXER_USER", "admin"),
        "WAZUH_INDEXER_PASS": env_vars.get("WAZUH_INDEXER_PASS", "admin"),
        "WAZUH_ALERTS_INDEX": env_vars.get("WAZUH_ALERTS_INDEX", "wazuh-alerts-*"),
        
        # LLM Configuration (keep existing values)
        "LLM_ENABLE": env_vars.get("LLM_ENABLE", "true"),
        "OPENAI_API_KEY": env_vars.get("OPENAI_API_KEY", "your-openai-api-key-here"),
        "OPENAI_API_BASE": env_vars.get("OPENAI_API_BASE", "https://api.openai.com/v1"),
        "LLM_MODEL": env_vars.get("LLM_MODEL", "gpt-5.2"),
        "LLM_MAX_TOKENS": env_vars.get("LLM_MAX_TOKENS", "1024"),
        "LLM_TIMEOUT_SEC": env_vars.get("LLM_TIMEOUT_SEC", "20"),
        
        # Triage Configuration
        "HEURISTIC_WEIGHT": env_vars.get("HEURISTIC_WEIGHT", "0.6"),
        "LLM_WEIGHT": env_vars.get("LLM_WEIGHT", "0.4"),
        "TRIAGE_THRESHOLD": env_vars.get("TRIAGE_THRESHOLD", "0.70"),
        
        # Telegram Bot Configuration
        "TELEGRAM_BOT_TOKEN": env_vars.get("TELEGRAM_BOT_TOKEN", ""),
        "TELEGRAM_CHAT_ID": env_vars.get("TELEGRAM_CHAT_ID", ""),
        
        # API Configuration
        "API_PORT": env_vars.get("API_PORT", "8088"),
        
        # General Configuration
        "ENV_NAME": env_vars.get("ENV_NAME", "dev"),
        "LOG_LEVEL": env_vars.get("LOG_LEVEL", "INFO"),
        
        # Correlation Configuration
        "CORRELATION_ENABLE": env_vars.get("CORRELATION_ENABLE", "true"),
        "CORRELATION_TIME_WINDOW_MINUTES": env_vars.get("CORRELATION_TIME_WINDOW_MINUTES", "15"),
        
        # Enrichment Configuration
        "ENRICHMENT_ENABLE": env_vars.get("ENRICHMENT_ENABLE", "true"),
        "GEOIP_ENABLE": env_vars.get("GEOIP_ENABLE", "true"),
        
        # LLM Cache Configuration
        "LLM_CACHE_ENABLE": env_vars.get("LLM_CACHE_ENABLE", "true"),
        "LLM_CACHE_TTL_SECONDS": env_vars.get("LLM_CACHE_TTL_SECONDS", "3600"),
        "LLM_CACHE_MAX_SIZE": env_vars.get("LLM_CACHE_MAX_SIZE", "1000"),
    }
    
    # Update env_vars with required values (only if not already set or needs update)
    for key, value in required_updates.items():
        if key not in env_vars or key in ["WAZUH_INDEXER_VERIFY_SSL", "WAZUH_START_FROM_NOW", "WAZUH_LOOKBACK_MINUTES", "INDEXER_DELAY_SECONDS"]:
            env_vars[key] = value
    
    # Write updated .env file
    output_lines = []
    
    # Add header
    output_lines.append("# Wazuh Configuration")
    output_lines.append("")
    
    # Wazuh API Configuration
    output_lines.append("# Wazuh API Configuration")
    output_lines.append(f"WAZUH_API_URL={env_vars['WAZUH_API_URL']}")
    output_lines.append(f"WAZUH_API_USER={env_vars['WAZUH_API_USER']}")
    output_lines.append(f"WAZUH_API_PASS={env_vars['WAZUH_API_PASS']}")
    output_lines.append(f"WAZUH_API_TOKEN={env_vars['WAZUH_API_TOKEN']}")
    output_lines.append(f"WAZUH_MIN_LEVEL={env_vars['WAZUH_MIN_LEVEL']}")
    output_lines.append(f"WAZUH_POLL_INTERVAL_SEC={env_vars['WAZUH_POLL_INTERVAL_SEC']}")
    output_lines.append(f"WAZUH_PAGE_LIMIT={env_vars['WAZUH_PAGE_LIMIT']}")
    output_lines.append(f"WAZUH_MAX_BATCHES={env_vars['WAZUH_MAX_BATCHES']}")
    output_lines.append(f"WAZUH_LOOKBACK_MINUTES={env_vars['WAZUH_LOOKBACK_MINUTES']}")
    output_lines.append(f"WAZUH_DEMO_MODE={env_vars['WAZUH_DEMO_MODE']}")
    output_lines.append(f"WAZUH_START_FROM_NOW={env_vars['WAZUH_START_FROM_NOW']}")
    output_lines.append(f"WAZUH_REALTIME_MODE={env_vars['WAZUH_REALTIME_MODE']}")
    output_lines.append(f"WAZUH_REALTIME_INTERVAL_SEC={env_vars['WAZUH_REALTIME_INTERVAL_SEC']}")
    output_lines.append(f"INDEXER_DELAY_SECONDS={env_vars['INDEXER_DELAY_SECONDS']}")
    output_lines.append(f"CURSOR_PATH={env_vars['CURSOR_PATH']}")
    output_lines.append("")
    
    # SSL Configuration
    output_lines.append("# SSL Configuration")
    output_lines.append("# WAZUH_API_VERIFY_SSL can be: true/false or path to cert file")
    output_lines.append(f"WAZUH_API_VERIFY_SSL={env_vars['WAZUH_API_VERIFY_SSL']}")
    output_lines.append("")
    
    # Wazuh Indexer Configuration
    output_lines.append("# Wazuh Indexer Configuration")
    output_lines.append(f"WAZUH_INDEXER_URL={env_vars['WAZUH_INDEXER_URL']}")
    output_lines.append(f"WAZUH_INDEXER_USER={env_vars['WAZUH_INDEXER_USER']}")
    output_lines.append(f"WAZUH_INDEXER_PASS={env_vars['WAZUH_INDEXER_PASS']}")
    output_lines.append("# WAZUH_INDEXER_VERIFY_SSL can be: true/false or path to cert file")
    output_lines.append("# Set to false to disable SSL verification (for testing)")
    output_lines.append(f"WAZUH_INDEXER_VERIFY_SSL={env_vars['WAZUH_INDEXER_VERIFY_SSL']}")
    output_lines.append(f"WAZUH_ALERTS_INDEX={env_vars['WAZUH_ALERTS_INDEX']}")
    output_lines.append("")
    
    # LLM Configuration
    output_lines.append("# LLM Configuration (optional)")
    output_lines.append(f"LLM_ENABLE={env_vars['LLM_ENABLE']}")
    output_lines.append("# Replace with your OpenAI API key (get from https://platform.openai.com/api-keys)")
    output_lines.append(f"OPENAI_API_KEY={env_vars['OPENAI_API_KEY']}")
    output_lines.append("# OpenAI API Base URL")
    output_lines.append("# Official OpenAI API: https://api.openai.com/v1")
    output_lines.append(f"OPENAI_API_BASE={env_vars['OPENAI_API_BASE']}")
    output_lines.append(f"LLM_MODEL={env_vars['LLM_MODEL']}")
    output_lines.append(f"LLM_MAX_TOKENS={env_vars['LLM_MAX_TOKENS']}")
    output_lines.append(f"LLM_TIMEOUT_SEC={env_vars['LLM_TIMEOUT_SEC']}")
    output_lines.append("")
    
    # Triage Configuration
    output_lines.append("# Triage Weights (must sum to 1.0)")
    output_lines.append(f"HEURISTIC_WEIGHT={env_vars['HEURISTIC_WEIGHT']}")
    output_lines.append(f"LLM_WEIGHT={env_vars['LLM_WEIGHT']}")
    output_lines.append(f"TRIAGE_THRESHOLD={env_vars['TRIAGE_THRESHOLD']}")
    output_lines.append("")
    
    # Telegram Bot Configuration
    output_lines.append("# Telegram Bot Configuration")
    output_lines.append("# Get bot token from @BotFather on Telegram: https://t.me/botfather")
    output_lines.append(f"TELEGRAM_BOT_TOKEN={env_vars['TELEGRAM_BOT_TOKEN']}")
    output_lines.append("# Get chat ID by messaging your bot and checking: https://api.telegram.org/bot<TOKEN>/getUpdates")
    output_lines.append(f"TELEGRAM_CHAT_ID={env_vars['TELEGRAM_CHAT_ID']}")
    output_lines.append("")
    
    # API Configuration
    output_lines.append("# API Configuration")
    output_lines.append(f"API_PORT={env_vars['API_PORT']}")
    output_lines.append("")
    
    # General Configuration
    output_lines.append("# General Configuration")
    output_lines.append(f"ENV_NAME={env_vars['ENV_NAME']}")
    output_lines.append(f"LOG_LEVEL={env_vars['LOG_LEVEL']}")
    output_lines.append(f"LOCAL_TIMEZONE={env_vars['LOCAL_TIMEZONE']}")
    output_lines.append("")
    
    # Correlation Configuration
    output_lines.append("# Correlation Configuration (group related alerts)")
    output_lines.append(f"CORRELATION_ENABLE={env_vars['CORRELATION_ENABLE']}")
    output_lines.append(f"CORRELATION_TIME_WINDOW_MINUTES={env_vars['CORRELATION_TIME_WINDOW_MINUTES']}")
    output_lines.append("")
    
    # Enrichment Configuration
    output_lines.append("# Enrichment Configuration (GeoIP, threat intelligence)")
    output_lines.append(f"ENRICHMENT_ENABLE={env_vars['ENRICHMENT_ENABLE']}")
    output_lines.append(f"GEOIP_ENABLE={env_vars['GEOIP_ENABLE']}")
    output_lines.append("")
    
    # LLM Cache Configuration
    output_lines.append("# LLM Cache Configuration (improve performance)")
    output_lines.append(f"LLM_CACHE_ENABLE={env_vars['LLM_CACHE_ENABLE']}")
    output_lines.append(f"LLM_CACHE_TTL_SECONDS={env_vars['LLM_CACHE_TTL_SECONDS']}")
    output_lines.append(f"LLM_CACHE_MAX_SIZE={env_vars['LLM_CACHE_MAX_SIZE']}")
    output_lines.append("")
    
    # Write to file
    with open(env_path, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines))
    
    print(f"[OK] Updated .env file: {env_path}")
    print("\n[INFO] Key changes:")
    print(f"   - WAZUH_INDEXER_VERIFY_SSL={env_vars['WAZUH_INDEXER_VERIFY_SSL']} (fix SSL error)")
    print(f"   - WAZUH_START_FROM_NOW={env_vars['WAZUH_START_FROM_NOW']} (fetch new alerts)")
    print(f"   - WAZUH_LOOKBACK_MINUTES={env_vars['WAZUH_LOOKBACK_MINUTES']} (avoid missing alerts)")
    print(f"   - INDEXER_DELAY_SECONDS={env_vars['INDEXER_DELAY_SECONDS']} (indexer delay compensation)")
    print("\n[OK] All existing values (like OPENAI_API_KEY) have been preserved!")
    print("\n[INFO] You can now run the pipeline:")
    print("   py -3 bin\\run_pipeline.py")

if __name__ == "__main__":
    update_env_file()

