#!/usr/bin/env python3
"""
CLI to test Active Response (dry-run or execute) against a management host.

Usage:
  python tools/test_active_response.py --target-ip 1.2.3.4 --management-host 192.168.10.1 --dry-run
  python tools/test_active_response.py --target-ip 1.2.3.4 --management-host 192.168.10.1 --execute

Notes:
 - This script imports the project's active_response.block_ip() and runs it.
 - It runs in the same Python environment as the project; ensure dependencies are installed.
 - Do NOT place private keys in the repository. Set ACTIVE_RESPONSE_SSH_KEY_PATH to the key path on the runner.
"""
import argparse
import json
import os
import sys

from typing import Any, Dict

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

try:
    from src.orchestrator.active_response import block_ip
except Exception as e:
    print("Failed to import active_response module. Make sure you run this from project root and have dependencies installed.")
    raise


def build_alert(target_ip: str) -> Dict[str, Any]:
    """Construct a minimal normalized alert for testing Active Response."""
    return {
        "srcip": target_ip,
        "rule": {"id": "test", "level": 13, "groups": ["test"]},
        "agent": {"name": "test-agent", "id": "test-agent-001"},
        "@timestamp": None,
    }


def build_triage(score: float = 0.99, threat_level: str = "critical") -> Dict[str, Any]:
    """Construct a minimal triage dict for testing."""
    return {
        "score": score,
        "threat_level": threat_level,
        "priority": "P1" if threat_level == "critical" else "P4",
        "llm_confidence": 0.9,
    }


def main():
    parser = argparse.ArgumentParser(description="Test Active Response (block_ip) in project")
    parser.add_argument("--target-ip", required=True, help="IP address to block (source IP)")
    parser.add_argument("--management-host", required=False, help="Management host to run block command on (overrides ACTIVE_RESPONSE_TARGET_HOSTS)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Run in dry-run mode (default safe)")
    group.add_argument("--execute", action="store_true", help="Execute non-dry-run (dangerous; ensure env set and keys deployed)")
    parser.add_argument("--ssh-user", required=False, help="SSH user to use (overrides ACTIVE_RESPONSE_SSH_USER)")
    parser.add_argument("--ssh-key-path", required=False, help="SSH private key path to use (overrides ACTIVE_RESPONSE_SSH_KEY_PATH)")

    args = parser.parse_args()

    dry_run = args.dry_run
    if args.execute:
        dry_run = False

    alert = build_alert(args.target_ip)
    triage = build_triage()

    # Respect overrides
    mgmt = args.management_host
    ssh_user = args.ssh_user
    ssh_key_path = args.ssh_key_path

    print("Active Response test parameters:")
    print(f"  target_ip: {args.target_ip}")
    print(f"  management_host: {mgmt or '(from config)'}")
    print(f"  dry_run: {dry_run}")
    if ssh_user:
        print(f"  ssh_user: {ssh_user} (override)")
    if ssh_key_path:
        print(f"  ssh_key_path: {ssh_key_path} (override)")

    # Execute
    audit = block_ip(alert, triage, management_host=mgmt, dry_run=dry_run)

    print("\nResult (audit):")
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()


