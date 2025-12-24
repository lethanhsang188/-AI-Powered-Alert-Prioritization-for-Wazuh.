# Project Overview — AI-Powered Alert Prioritization for Wazuh
# Tổng quan dự án — Hệ thống ưu tiên cảnh báo bằng AI cho Wazuh

English (top) / Vietnamese (bottom) are provided for SOC and dev audiences.

---

## 1. Core purpose / Mục đích chính

- English
  - This repository implements an AI-assisted SOC pipeline that ingests alerts (Wazuh → Elastic/Wazuh indexer), normalizes and enriches them, scores and summarizes them using a combination of heuristic rules and an LLM, and triggers downstream notifications and active containment (pfSense) when warranted.
  - The goal is to reduce analyst triage time, automatically contain high-confidence perimeter attacks, and keep noisy signals while labeling FP/low-priority items.

- Vietnamese
  - Repo này triển khai một pipeline SOC có trợ giúp AI: nhận alert từ Wazuh (qua indexer), chuẩn hóa và enrichment, chấm điểm và tóm tắt bằng kết hợp luật heuristic và LLM, rồi gửi thông báo và thực thi containment (pfSense) khi cần.
  - Mục tiêu giảm thời gian triage cho analyst, tự động ngăn chặn tấn công ngoại vi có độ tin cậy cao, đồng thời vẫn lưu các tín hiệu ồn cho audit và gắn nhãn FP/ưu tiên thấp.

---

## 2. High-level flow / Luồng tổng quát

- English
  1. Collector: fetch alerts from `wazuh-alerts-*` (indexer) and normalize fields (ensure source IP present).  
  2. Heuristic analyzer: rule-level scoring, static signals, signatures.  
  3. LLM analyzer: summary, tags, threat-level suggestion, confidence.  
  4. Triage: fuse heuristic + LLM scores → triage score (0–1), threat_level (none/low/medium/high/critical), numeric escalation for correlated events, map to priority P1–P4.  
  5. Notify: Telegram notifications (Markdown + fallback), audit logging.  
  6. Active Response: policy checks, confirmation, fast-block for prioritized agents (pfSense), execute SSH pfctl commands, schedule auto-unblock.

- Vietnamese
  1. Collector: lấy alert từ `wazuh-alerts-*` và chuẩn hóa trường (đảm bảo có source IP).  
  2. Heuristic: chấm điểm theo rule, dấu hiệu tĩnh, signature.  
  3. LLM: tóm tắt alert, gán tag, gợi ý threat level và confidence.  
  4. Triage: hợp nhất điểm heuristic + LLM → score (0–1), threat_level (none/low/medium/high/critical), áp numeric escalation khi nhiều alert tương quan, ánh xạ thành priority P1–P4.  
  5. Notify: gửi Telegram (Markdown và fallback plain), ghi audit.  
  6. Active Response: kiểm tra chính sách, xác nhận, fast-block cho agent ưu tiên (pfSense), thực thi lệnh `pfctl` qua SSH, lập lịch auto-unblock.

---

## 3. What the AI (LLM) does / Vai trò AI (LLM)

- English
  - Generates a concise human-readable summary of each alert (context + key evidence).  
  - Suggests tags (e.g., sql_injection, xss, web_attack) used by fast-block and reporting.  
  - Provides a soft threat-level recommendation and confidence score used in fusion with heuristics.  
  - Assists in false-positive reasoning by generating textual reasons that can be stored for analyst review.

- Vietnamese
  - Sinh tóm tắt ngắn gọn, dễ đọc cho mỗi alert (ngữ cảnh + bằng chứng chính).  
  - Gợi tag (ví dụ sql_injection, xss, web_attack) dùng cho fast-block và báo cáo.  
  - Đưa khuyến nghị threat-level và độ tin cậy để hợp nhất với heuristic.  
  - Hỗ trợ lý luận FP bằng văn bản để lưu lại cho analyst xem xét.

---

## 4. Key source files and responsibilities / Các file mã nguồn chính và chức năng

- `bin/run_pipeline.py`
  - Orchestrates pipeline execution and polling loop. (Entry point)

- `src/collector/wazuh_client.py`
  - Fetch + normalize Wazuh alerts. Ensures `srcip` extraction from multiple field paths (`srcip`, `data.srcip`, `data.flow.src_ip`).

- `src/analyzer/heuristic.py`
  - Rule-based scoring logic and deterministic indicators.

- `src/analyzer/llm.py`
  - LLM integration: prompt templates, API requests, timeout and cache handling.

- `src/analyzer/triage.py`
  - Fuses heuristic + LLM outputs, applies numeric escalation, computes `triage_score`, `threat_level`, `priority`.

- `src/orchestrator/notify.py`
  - Formats Telegram messages, handles Markdown fallback, and coordinates Active Response pre-call and audit. Contains suppression logic to avoid repeated spam.

- `src/orchestrator/active_response.py`
  - Attack confirmation logic, policy decision, SSH execution of `pfctl` on pfSense, retry without `sudo`, schedule auto-unblock, audit outputs for transparency.

- `src/common/config.py`
  - All runtime toggles and thresholds (TRIAGE_THRESHOLD, ENABLE_ACTIVE_RESPONSE, FAST_BLOCK_TAGS, AR_SUPPRESSION_WINDOW_SECONDS, AR_MAX_NOTIFICATIONS, etc.).

- `tools/test_active_response.py`
  - CLI tool to test AR against a management host (dry-run/execute).

---

## 5. Where this project sits: SIEM / IDS / IPS roles

- English
  - SIEM: This pipeline consumes Wazuh (which functions as the initial SIEM/agent manager) index alerts and enriches them. The pipeline acts as a triage and orchestration layer on top of SIEM — classifying, summarizing, and pushing notifications and cases.
  - IDS: Suricata (deployed on pfSense) is the IDS sensor that generates network intrusion alerts consumed by Wazuh → pipeline. Suricata provides signature/context (signature_id, severity, action).
  - IPS (active containment): The pipeline provides IPS-like behavior by instructing pfSense to add offending IPs into a runtime pf table (`WAZUH_BLOCK`) — this is an inline *containment* action (time-bound by auto-unblock or manual removal).

- Vietnamese
  - SIEM: Pipeline tiêu thụ alert từ Wazuh (vai trò SIEM) và làm lớp triage/orchestration phía trên — phân loại, tóm tắt và đẩy thông báo / case.  
  - IDS: Suricata (chạy trên pfSense) là sensor IDS tạo alert mạng, chứa signature_id, severity, action — dữ liệu này được pipeline dùng để xác nhận tấn công.  
  - IPS: Pipeline cung cấp hành vi giống IPS bằng cách yêu cầu pfSense chặn IP (thêm vào bảng `WAZUH_BLOCK`) — là containment theo thời gian (auto-unblock) hoặc thủ công.

---

## 6. How to apply in an SMB environment / Áp dụng cho doanh nghiệp vừa và nhỏ

- English
  - Architecture: Deploy Wazuh manager + Elastic (indexer) to collect host and Suricata logs; pfSense at the perimeter running Suricata; the pipeline runs on a small VM (4 vCPU / 8 GB recommended for testing).  
  - Operational model:
    - Keep `ENABLE_ACTIVE_RESPONSE=false` initially — monitor Telegram alerts and audits.  
    - Tune `FAST_BLOCK_TAGS` and `FAST_BLOCK_SURICATA_SEVERITY` to your environment; use `PRIORITY_AGENT_IDS=002` to limit AR to the perimeter sensor.  
    - Enable `AR_SUPPRESSION_WINDOW_SECONDS` and `AR_MAX_NOTIFICATIONS` to avoid repetitive automatic blocks.  
  - People/process: SOC analyst reviews Telegram messages, confirms blocks if REQUIRE_CONFIRM=true. Use `AR_MAX_NOTIFICATIONS=1` to only notify once per IP, then create a case in your ticketing system for follow-up.

- Vietnamese
  - Kiến trúc: Cài Wazuh manager + Elastic để thu thập host/Suricata logs; pfSense làm perimeter chạy Suricata; pipeline chạy trên VM nhỏ (ví dụ 4 vCPU / 8GB cho test).  
  - Vận hành:
    - Bắt đầu với `ENABLE_ACTIVE_RESPONSE=false` để chỉ quan sát.  
    - Tùy chỉnh `FAST_BLOCK_TAGS`, `FAST_BLOCK_SURICATA_SEVERITY`; đặt `PRIORITY_AGENT_IDS=002` để chỉ AR cho perimeter.  
    - Bật suppression (`AR_SUPPRESSION_WINDOW_SECONDS`, `AR_MAX_NOTIFICATIONS`) để tránh spam/loop.  
  - Con người/quy trình: SOC analyst xem Telegram, confirm block nếu `REQUIRE_CONFIRM=true`. Dùng `AR_MAX_NOTIFICATIONS=1` để chỉ gửi 1 thông báo AR cho mỗi IP, sau đó tạo case để điều tra.

---

## 7. Operational safety & audits / An toàn vận hành và audit

- English
  - Feature flags: `ENABLE_ACTIVE_RESPONSE`, `ACTIVE_RESPONSE_REQUIRE_CONFIRM` exist so ops can test in dry-run mode and require manual approval before executing blocks.  
  - Audit trail: Every AR attempt returns an `audit` dict with timestamp, result, messages, management_host and policy_decision. Telegram messages also carry summary.  
  - Allowlist: `ACTIVE_RESPONSE_ALLOWLIST` prevents blocking internal/trusted IPs. Improve by supporting CIDR-based allowlist via `ipaddress` module.

- Vietnamese
  - Cờ tính năng: `ENABLE_ACTIVE_RESPONSE`, `ACTIVE_RESPONSE_REQUIRE_CONFIRM` cho phép test dry-run và yêu cầu phê duyệt trước khi chặn.  
  - Audit: Mỗi lần AR trả về `audit` chứa timestamp, result, messages, management_host, policy_decision. Telegram cũng gửi tóm tắt.  
  - Allowlist: `ACTIVE_RESPONSE_ALLOWLIST` ngăn chặn chặn những IP tin cậy. Nên nâng cấp để hỗ trợ CIDR bằng module `ipaddress`.

---

## 8. Future enhancements (recommended) / Nâng cấp tương lai

- English
 1. VirusTotal enrichment: Query VT API for source IP / domains / file hashes found in alerts and add threat intel scores/tags. Use VT rate-limits and caching.  
 2. Deeper Suricata integration: Fetch Suricata EVE context or NIDS session stats to confirm payloads (e.g., extracted HTTP bodies, file MD5s) before fast-block.  
 3. pfSense persistence & API: Use pfSense API or a persistent alias for permanent blocks across reboots. Add rollback/unblock automation with cron or stateful scheduler.  
 4. CIDR allowlist support: Replace exact-match allowlist with CIDR checks.  
 5. Telemetry & dashboards: Add a small API to surface AR events and suppression stats for SOC dashboarding.  
 6. Unit tests & CI: Add unit tests for `trigger_active_response`, confirmation logic, and suppression behavior. Integrate with GitHub Actions.  

- Vietnamese
 1. VirusTotal: Gọi API VT cho IP/domain/hash trong alert để enrich IOC, gắn thẻ "known_malicious" nếu VT score cao; cache VT results để tránh rate-limit.  
 2. Tích hợp Suricata sâu hơn: Lấy nhiều ngữ cảnh EVE (extracted HTTP body, file MD5) để xác nhận payload trước khi fast-block.  
 3. pfSense persistence: Dùng pfSense API hoặc persistent alias để block tồn tại qua reboot; thêm cron hoặc scheduler bền vững cho auto-unblock.  
 4. Allowlist CIDR: Hỗ trợ CIDR thay vì exact-match.  
 5. Telemetry/dashboard: API nhỏ để báo cáo AR events và suppression stats cho SOC dashboard.  
 6. Unit tests & CI: Viết test cho `trigger_active_response`, confirm logic, suppression; tích hợp GitHub Actions.

---

## 9. Quick operational commands / Các lệnh hữu ích

- Show pf table:
  - ssh -i C:\Users\ADMIN\.ssh\id_ed25519 admin@192.168.10.1 "pfctl -t WAZUH_BLOCK -T show"

- Delete IP from table:
  - ssh -i C:\Users\ADMIN\.ssh\id_ed25519 admin@192.168.10.1 "pfctl -t WAZUH_BLOCK -T delete 172.16.69.175"

- Set env recommendations for safe auto-block:
  - ENABLE_ACTIVE_RESPONSE=true  
  - ACTIVE_RESPONSE_REQUIRE_CONFIRM=false  
  - AR_MAX_NOTIFICATIONS=2  
  - AR_SUPPRESSION_WINDOW_SECONDS=600

---

If you'd like, I can:
- generate a short `README.md` developer guide from this content, or  
- create unit test stubs for `trigger_active_response()` and suppression logic.  

If you want the README/test stubs, tell me which one (README/tests/both).  


