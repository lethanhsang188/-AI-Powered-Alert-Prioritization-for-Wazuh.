#!/usr/bin/env python3
"""Main pipeline loop: collect -> analyze -> triage -> orchestrate."""
import sys
import os
import time
import logging

# Add src to path (works in both local and Docker)
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_dir = os.path.join(base_dir, "src")
sys.path.insert(0, src_dir)

from common.config import WAZUH_POLL_INTERVAL_SEC
from common.logging import setup_logging
from collector.wazuh_client import WazuhClient
from analyzer.triage import run as run_triage
from orchestrator.thehive_client import TheHiveClient
from orchestrator.notify import notify

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


def main():
    """Main pipeline loop."""
    logger.info("Starting security alert pipeline...")
    
    # Initialize clients
    wazuh = WazuhClient()
    thehive = TheHiveClient()
    
    logger.info("Pipeline initialized, starting main loop...")
    
    while True:
        try:
            # 1. Collect alerts
            alerts = wazuh.fetch_alerts()
            
            if not alerts:
                logger.debug("No new alerts, sleeping...")
                time.sleep(WAZUH_POLL_INTERVAL_SEC)
                continue
            
            logger.info(f"Processing {len(alerts)} alerts...")
            
            # 2. Process each alert
            for alert in alerts:
                try:
                    # 3. Analyze and triage
                    triage_result = run_triage(alert)
                    
                    logger.debug(
                        f"Alert {alert.get('rule', {}).get('id', 'unknown')} "
                        f"triaged with score {triage_result.get('score', 0.0):.2f}"
                    )
                    
                    # 4. Create or update case in TheHive
                    case_id, created = thehive.create_or_update(alert, triage_result)
                    
                    if case_id:
                        logger.info(
                            f"{'Created' if created else 'Updated'} case {case_id} "
                            f"for alert rule {alert.get('rule', {}).get('id', 'unknown')}"
                        )
                        
                        # 5. Notify (if high severity)
                        notify(alert, triage_result, case_id)
                    else:
                        logger.warning("Failed to create/update case in TheHive")
                
                except Exception as e:
                    logger.error(f"Error processing alert: {e}", exc_info=True)
                    continue
            
            logger.info(f"Finished processing {len(alerts)} alerts")
            
            # Sleep before next poll
            time.sleep(WAZUH_POLL_INTERVAL_SEC)
        
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
            break
        
        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)
            time.sleep(WAZUH_POLL_INTERVAL_SEC)


if __name__ == "__main__":
    main()

