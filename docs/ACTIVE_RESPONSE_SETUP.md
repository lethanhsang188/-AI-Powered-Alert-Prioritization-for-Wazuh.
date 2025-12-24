# Active Response — Setup & Staging Checklist

This document explains how to safely set up and test Active Response (containment) for
the AI-Powered Alert Prioritization project. Follow the steps carefully; Active Response
can block traffic and must be tested on staging before enabling in production.

## Goals
- Provide safe, auditable containment for P1 (critical) alerts.  
- Start in dry-run mode; require manual confirmation initially.  
- Provide clear steps to move to staging non-dry-run and production after verification.

## Summary of components
- `src/orchestrator/active_response.py`: containment helpers (SSH default).  
- `src/common/config.py`: feature flags & params (`ENABLE_ACTIVE_RESPONSE`, `ACTIVE_RESPONSE_*`, `ESCALATION_*`).  
- `tools/test_active_response.py`: CLI to run dry-run or execute tests against a management host.

## Pre-requisites
- A management host (firewall/pfSense) reachable from the pipeline runner. Example: `192.168.10.1`.  
- An account on that host to run block commands (suggested: `ai_blocker`).  
- Public key for runner's deploy account added to `~ai_blocker/.ssh/authorized_keys` on management host.  
- Private key stored on runner machine (not in repo) and `ACTIVE_RESPONSE_SSH_KEY_PATH` set to that path.  
- Ensure project environment active and Python dependencies installed (`python -m pip install -r requirements.txt` if present).

## Add public key on management host (example)
1. On runner (generate key if needed):
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/ai_blocker_key -C "ai_blocker" 
   ```
2. Copy public key to management host (run as admin on firewall):
   Option A (recommended): copy the provided pubkey file from the repo and install it as the `ai_blocker` account's authorized key:
   ```bash
   # From the runner or operator machine:
   scp deploy/admin_pubkey.pub admin@192.168.10.1:/tmp/
   ssh admin@192.168.10.1 "mkdir -p /home/admin/.ssh && cat /tmp/admin_pubkey.pub >> /home/admin/.ssh/authorized_keys && chown -R admin:admin /home/admin/.ssh && chmod 700 /home/admin/.ssh && chmod 600 /home/admin/.ssh/authorized_keys"
   ```
   Option B: or use `ssh-copy-id` if available:
   ```bash
   ssh-copy-id -i ~/.ssh/admin_key.pub admin@192.168.10.1
   ```
   Option C: manually append the public key to `/home/ai_blocker/.ssh/authorized_keys`.

## Environment variables (example `.env` or export)
Set these on the machine running the pipeline (runner) — do NOT commit secrets to repo.

```
ENABLE_ACTIVE_RESPONSE=false
ACTIVE_RESPONSE_METHOD=ssh
ACTIVE_RESPONSE_TARGET_HOSTS=192.168.10.1
ACTIVE_RESPONSE_SSH_USER=ai_blocker
ACTIVE_RESPONSE_SSH_KEY_PATH=/home/runner/.ssh/ai_blocker_key
ACTIVE_RESPONSE_ALLOWLIST=10.0.0.0/8,192.168.0.0/16,127.0.0.1
ACTIVE_RESPONSE_REQUIRE_CONFIRM=true
ACTIVE_RESPONSE_AUTO_UNBLOCK_MINUTES=60
ESCALATION_HIGH_COUNT=3
ESCALATION_SCORE_HIGH=0.7
```

## Dry-run testing (recommended first)
1. Ensure `ENABLE_ACTIVE_RESPONSE=false` and `ACTIVE_RESPONSE_REQUIRE_CONFIRM=true` in env.  
2. From project root, run:
   ```bash
   python tools/test_active_response.py --target-ip 1.2.3.4 --management-host 192.168.10.1 --dry-run
   ```
3. Inspect output audit JSON — expect `dry_run` true and a prepared SSH command shown in `messages`.
4. Trigger a test alert (or simulate by calling triage + notify) and verify logs: `active_response_audit` appears in notify logs.

## Non-dry-run staging run (manual confirmation)
1. On runner, set:
   ```
   ENABLE_ACTIVE_RESPONSE=true
   ACTIVE_RESPONSE_REQUIRE_CONFIRM=true
   ```
2. Use the CLI to do a controlled execute (still requires confirm logic in policy, so if `REQUIRE_CONFIRM=true` the module will not run actual block; to test actual execution you must set `ACTIVE_RESPONSE_REQUIRE_CONFIRM=false` — do this only on staging and after approvals):
   ```bash
   # execute (dangerous) - only after you have confirmed key deployment & allowlist
   python tools/test_active_response.py --target-ip 1.2.3.4 --management-host 192.168.10.1 --execute
   ```
3. Inspect management host to verify pfSense/iptables shows rule added.
   - Note: the project uses a configurable pf table name (`ACTIVE_RESPONSE_PF_TABLE`, default `WAZUH_BLOCK`).
     Example verify command:
     ```bash
     ssh -i /path/to/key ai_blocker@192.168.10.1 "sudo pfctl -t WAZUH_BLOCK -T show"
     ```
4. Verify audit logs and Telegram notification show containment audit outcome.

## Fast-block (pfSense immediate containment)

For prioritized network sensors (e.g., pfSense agent `002`) you can enable a "fast-block" policy
that attempts containment immediately when clear indicators are present (signature ID, LLM tag,
suricata action 'allowed' with severity, or attacker user-agent like sqlmap). This is useful for
automatically blocking automated web scanners and exploit probes hitting your WAN interface.

WARNING: Fast-block can lead to false positives if misconfigured. Test in staging and use allowlist.

1. Example env variables (add to your runner `.env` or export):
```bash
FAST_BLOCK_RULE_IDS=20101
FAST_BLOCK_TAGS=sql_injection,web_attack
FAST_BLOCK_UA_TOOLS=sqlmap,nikto
FAST_BLOCK_REQUIRE_CONFIRM=false
FAST_BLOCK_SURICATA_SEVERITY=1
```

2. Behavior:
  - If alert originates from a prioritized agent (configured in `PRIORITY_AGENT_IDS`) and matches any fast-block criteria,
    the pipeline will attempt to block the source IP immediately (subject to `ENABLE_ACTIVE_RESPONSE` and dry-run flags).
  - If `FAST_BLOCK_REQUIRE_CONFIRM=true`, the fast-block will still be skipped pending manual confirmation.

3. Safety recommendations:
  - Keep `ACTIVE_RESPONSE_ALLOWLIST` populated with internal and monitoring IPs.
  - Start with `FAST_BLOCK_REQUIRE_CONFIRM=true` in staging, test, then set to `false` only when confident.
  - Use short auto-unblock windows (30–60 minutes) while tuning rules.

## Production rollout (after staging validation)
1. Keep `ACTIVE_RESPONSE_REQUIRE_CONFIRM=true` initially in prod to require manual confirmation.  
2. After 1–2 weeks of staging validation, consider `ACTIVE_RESPONSE_REQUIRE_CONFIRM=false` for automatic containment of P1 alerts only.  
3. Always keep robust allowlist entries and short auto-unblock windows (30–60min).

## Safety checklist (must be completed before enabling execute in any environment)
- [ ] Public key added to management host `ai_blocker` account.  
- [ ] Runner private key present and `ACTIVE_RESPONSE_SSH_KEY_PATH` set.  
- [ ] `ACTIVE_RESPONSE_ALLOWLIST` configured with all internal/jump/monitoring IPs.  
- [ ] Dry-run tests passed and audit logs reviewed.  
- [ ] Stakeholders notified and change control approved for staging execute.  
- [ ] Auto-unblock configured (recommended >= 30 minutes).

## Troubleshooting
- If SSH key fails: check `~/.ssh/authorized_keys` and permissions (`chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys`).  
- If SSH command fails in non-dry-run: check `ACTIVE_RESPONSE_SSH_USER` privileges and the management host block command compatibility.  
- Consider using `pfsense_api` method if your device supports API for cleaner integration.

## Next steps I can do for you
- Wire non-dry-run staging toggle script (helper) and a small audit log collector.  
- Implement `pfsense_api` method — requires API credentials and endpoint.  
- Add automated auto-unblock scheduler (cron/task) to remove rules after configured window.


