#!/usr/bin/env python3
"""Quick script to check if Wazuh has alerts with level >= 7."""
import sys
import os

# Add project root to path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from src.common.config import WAZUH_MIN_LEVEL
from src.collector.wazuh_client import WazuhClient
from src.common.logging import setup_logging
import logging

setup_logging()
logger = logging.getLogger(__name__)

def main():
    """Check for alerts in Wazuh indexer."""
    logger.info(f"Checking for alerts with level >= {WAZUH_MIN_LEVEL}...")
    
    wazuh = WazuhClient()
    
    # Query without cursor to see all recent alerts
    from src.common.config import WAZUH_PAGE_LIMIT
    import json
    from requests.exceptions import RequestException, HTTPError
    
    payload = {
        "size": min(10, WAZUH_PAGE_LIMIT),  # Just check first 10
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"rule.level": {"gte": WAZUH_MIN_LEVEL}}}
                ]
            }
        }
    }
    
    search_url = f"{wazuh.indexer_url}/{wazuh.alerts_index.lstrip('/')}/_search"
    logger.info(f"Querying: {search_url}")
    
    try:
        response = wazuh.indexer_session.post(search_url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        hits = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {})
        
        if isinstance(total, dict):
            total_count = total.get("value", 0)
        else:
            total_count = total
        
        logger.info(f"Found {total_count} total alerts with level >= {WAZUH_MIN_LEVEL}")
        logger.info(f"Showing first {len(hits)} alerts:")
        
        if not hits:
            logger.warning("⚠️  NO ALERTS FOUND!")
            logger.info("This could mean:")
            logger.info("  1. No attacks have occurred yet")
            logger.info("  2. Wazuh rules are not configured to detect your test attacks")
            logger.info("  3. Alert levels are below the minimum threshold (level < 7)")
            logger.info("")
            logger.info("To generate test alerts, try:")
            logger.info("  - Failed login attempts (SSH brute force)")
            logger.info("  - Port scanning (nmap)")
            logger.info("  - Suspicious file modifications")
            logger.info("  - Or use Wazuh's test rules")
        else:
            for i, hit in enumerate(hits[:5], 1):
                source = hit.get("_source", {})
                rule = source.get("rule", {})
                logger.info(f"\n  Alert {i}:")
                logger.info(f"    Rule ID: {rule.get('id', 'N/A')}")
                logger.info(f"    Level: {rule.get('level', 'N/A')}")
                logger.info(f"    Description: {rule.get('description', 'N/A')[:80]}")
                logger.info(f"    Timestamp: {source.get('@timestamp', 'N/A')}")
                logger.info(f"    Agent: {source.get('agent', {}).get('name', 'N/A')}")
    
    except (RequestException, HTTPError) as e:
        logger.error(f"Error querying Wazuh: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response: {e.response.text}")

if __name__ == "__main__":
    main()

