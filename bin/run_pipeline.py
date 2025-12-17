#!/usr/bin/env python3
"""Main pipeline loop: collect -> analyze -> triage -> orchestrate."""
import sys
import os
import time
import logging

# Add project root to path so we can import the src package
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from src.common.config import (
    WAZUH_POLL_INTERVAL_SEC,
    WAZUH_REALTIME_MODE,
    WAZUH_REALTIME_INTERVAL_SEC,
    LOCAL_TIMEZONE,
    LLM_ENABLE,
    OPENAI_API_BASE,
    OPENAI_API_KEY,
    LLM_MODEL,
)
from src.common.logging import setup_logging
from src.collector.wazuh_client import WazuhClient
from src.analyzer.triage import run as run_triage
from src.orchestrator.notify import notify

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


def main():
    """Main pipeline loop."""
    logger.info(
        "SOC Pipeline Starting",
        extra={
            "component": "pipeline",
            "action": "startup",
            "status": "initializing"
        }
    )
    
    # Determine polling interval based on mode
    if WAZUH_REALTIME_MODE:
        poll_interval = WAZUH_REALTIME_INTERVAL_SEC
        logger.info(
            "Real-time mode ENABLED",
            extra={
                "component": "pipeline",
                "action": "config",
                "mode": "realtime",
                "poll_interval_sec": poll_interval,
                "timezone": LOCAL_TIMEZONE
            }
        )
    else:
        poll_interval = WAZUH_POLL_INTERVAL_SEC
        logger.info(
            "Standard polling mode",
            extra={
                "component": "pipeline",
                "action": "config",
                "mode": "standard",
                "poll_interval_sec": poll_interval,
                "timezone": LOCAL_TIMEZONE
            }
        )
    
    # Log LLM configuration status
    if LLM_ENABLE:
        api_key_status = "configured" if OPENAI_API_KEY else "not configured"
        api_key_preview = f"{OPENAI_API_KEY[:10]}..." if OPENAI_API_KEY else "none"
        logger.info(
            "LLM enabled",
            extra={
                "component": "llm",
                "action": "config",
                "status": "enabled",
                "api_base": OPENAI_API_BASE,
                "api_key_status": api_key_status,
                "api_key_preview": api_key_preview,
                "model": LLM_MODEL
            }
        )
    else:
        logger.info(
            "LLM disabled",
            extra={
                "component": "llm",
                "action": "config",
                "status": "disabled"
            }
        )
    
    # Initialize client
    wazuh = WazuhClient()
    logger.info(
        "Pipeline initialized, entering main processing loop",
        extra={
            "component": "pipeline",
            "action": "ready",
            "status": "operational"
        }
    )
    
    consecutive_empty_polls = 0
    max_empty_polls_before_sleep = 10  # Only sleep after 10 consecutive empty polls in real-time mode
    total_processed = 0
    total_created = 0
    total_updated = 0
    total_errors = 0
    
    while True:
        try:
            loop_start = time.time()
            
            # 1. Collect alerts
            alerts = wazuh.fetch_alerts()
            
            if not alerts:
                consecutive_empty_polls += 1
                
                # In real-time mode, only sleep after multiple empty polls
                # This allows for near real-time processing when alerts are available
                if WAZUH_REALTIME_MODE:
                    if consecutive_empty_polls >= max_empty_polls_before_sleep:
                        logger.debug(
                            "No new alerts, entering sleep cycle",
                            extra={
                                "component": "pipeline",
                                "action": "sleep",
                                "consecutive_empty_polls": consecutive_empty_polls,
                                "sleep_interval_sec": poll_interval
                            }
                        )
                        time.sleep(poll_interval)
                        consecutive_empty_polls = 0
                    else:
                        # Very short sleep to prevent CPU spinning
                        time.sleep(0.1)
                else:
                    logger.debug(
                        "No new alerts, sleeping",
                        extra={
                            "component": "pipeline",
                            "action": "sleep",
                            "sleep_interval_sec": poll_interval
                        }
                    )
                    time.sleep(poll_interval)
                    consecutive_empty_polls = 0
                continue
            
            # Reset counter when we have alerts
            consecutive_empty_polls = 0
            
            logger.info(
                "Alert batch received, starting processing",
                extra={
                    "component": "pipeline",
                    "action": "process_batch",
                    "alert_count": len(alerts)
                }
            )
            
            # 2. Process each alert
            batch_errors = 0
            
            for alert in alerts:
                alert_start = time.time()
                rule = alert.get("rule", {})
                agent = alert.get("agent", {})
                rule_id = rule.get("id", "unknown")
                rule_level = rule.get("level", 0)
                agent_name = agent.get("name", "unknown")
                agent_id = agent.get("id", "unknown")
                srcip = alert.get("srcip", "")
                user = alert.get("user", "")
                
                try:
                    # 3. Analyze and triage
                    triage_start = time.time()
                    triage_result = run_triage(alert)
                    triage_duration = (time.time() - triage_start) * 1000
                    
                    score = triage_result.get("score", 0.0)
                    threat_level = triage_result.get("threat_level", "unknown")
                    
                    logger.debug(
                        "Alert triaged",
                        extra={
                            "component": "triage",
                            "action": "complete",
                            "rule_id": rule_id,
                            "rule_level": rule_level,
                            "agent_name": agent_name,
                            "agent_id": agent_id,
                            "srcip": srcip,
                            "user": user,
                            "score": round(score, 3),
                            "threat_level": threat_level,
                            "duration_ms": round(triage_duration, 2)
                        }
                    )
                    
                    # 4. Notify (if high severity)
                    notify(alert, triage_result)

                    alert_duration = (time.time() - alert_start) * 1000
                    severity_map = {"none": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}
                    severity = severity_map.get(threat_level.lower(), 2)

                    logger.info(
                        "Alert processed",
                        extra={
                            "component": "pipeline",
                            "action": "alert_processed",
                            "rule_id": rule_id,
                            "rule_level": rule_level,
                            "agent_name": agent_name,
                            "agent_id": agent_id,
                            "srcip": srcip,
                            "user": user,
                            "threat_level": threat_level.upper(),
                            "severity": severity,
                            "score": round(score, 3),
                            "duration_ms": round(alert_duration, 2),
                        },
                    )
                
                except Exception as e:
                    batch_errors += 1
                    total_errors += 1
                    logger.error(
                        "Error processing alert",
                        extra={
                            "component": "pipeline",
                            "action": "alert_processing_error",
                            "rule_id": rule_id,
                            "rule_level": rule_level,
                            "agent_name": agent_name,
                            "srcip": srcip,
                            "error": str(e)
                        },
                        exc_info=True
                    )
                    continue
                
                total_processed += 1
            
            loop_duration = (time.time() - loop_start) * 1000
            logger.info(
                "Alert batch processing completed",
                extra={
                    "component": "pipeline",
                    "action": "batch_complete",
                    "alert_count": len(alerts),
                    "cases_created": 0,
                    "cases_updated": 0,
                    "errors": batch_errors,
                    "duration_ms": round(loop_duration, 2),
                    "avg_duration_ms": round(loop_duration / len(alerts), 2) if alerts else 0,
                    "total_processed": total_processed,
                    "total_created": total_created,
                    "total_updated": total_updated,
                    "total_errors": total_errors
                }
            )
            
            # In real-time mode, don't sleep if we just processed alerts
            # This allows immediate processing of the next batch
            if WAZUH_REALTIME_MODE:
                # Very short sleep to allow other processes
                time.sleep(0.1)
            else:
                # Standard mode: sleep before next poll
                time.sleep(poll_interval)
        
        except KeyboardInterrupt:
            logger.info(
                "Received interrupt signal, shutting down gracefully",
                extra={
                    "component": "pipeline",
                    "action": "shutdown",
                    "status": "interrupted",
                    "total_processed": total_processed,
                    "total_created": total_created,
                    "total_updated": total_updated,
                    "total_errors": total_errors
                }
            )
            break
        
        except Exception as e:
            logger.error(
                "Pipeline error occurred",
                extra={
                    "component": "pipeline",
                    "action": "pipeline_error",
                    "error": str(e),
                    "status": "error"
                },
                exc_info=True
            )
            time.sleep(poll_interval)


if __name__ == "__main__":
    main()

