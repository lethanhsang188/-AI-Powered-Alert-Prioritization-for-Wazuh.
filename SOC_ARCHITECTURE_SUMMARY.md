## SOC Architecture Summary (AI-Powered Wazuh Pipeline)

Tài liệu này tóm tắt kiến trúc tổng thể ở mức cao, dùng cho đào tạo SOC và trình bày nhanh.

### 1. Sơ đồ kiến trúc mạng & pipeline AI (ASCII)

```
                 INTERNET / WAN
                        │
                 [ Attacker ]
                        │
                 172.16.69.176
                        │
                ┌──────────────────┐
                │   pfSense FW     │
                │  (NAT / VPN /    │
                │   IDS/IPS)       │
                └─────┬──────┬─────┘
                      │      │
                LAN   │      │   DMZ
          192.168.10.0/24    192.168.20.0/24
          ┌──────────────┐   ┌───────────────────────┐
          │  Wazuh       │   │   WebServer (DVWA)    │
          │  Server      │   │   192.168.20.125      │
          │  192.168.10.128  │   - Apache / PHP       │
          │  - Wazuh Mgr │   │   - Wazuh Agent 001   │
          │  - Wazuh API │   │   - Suricata IDS      │
          │  - Wazuh     │   │   - auditd            │
          │    Indexer   │   └─────────┬─────────────┘
          └────────┬─────┘             │
                   │ Wazuh Agent Logs  │
                   └─────────▲─────────┘
                             │
                  ┌──────────┴──────────┐
                  │  AI Pipeline (SOC)  │
                  │  (this project)     │
                  │  - Collector        │
                  │  - Correlation      │
                  │  - FP Filtering     │
                  │  - Heuristic+LLM    │
                  │  - Telegram Notify  │
                  └──────────┬──────────┘
                             │
                       HTTPS / API
                             │
                    ┌────────▼────────┐
                    │  Telegram Bot   │
                    │  / n8n / SOAR   │
                    └─────────────────┘
```

**Luồng chính (từ trên xuống dưới):**
- Tấn công từ **Internet → pfSense → DMZ/LAN**.
- **pfSense + Suricata + Wazuh Agents + auditd** gửi log về **Wazuh Manager / Indexer** (`wazuh-alerts-*`).
- **AI Pipeline** đọc alert từ Indexer, áp dụng **lọc SOC hai tầng → chuẩn hóa → tương quan → FP labeling → heuristic + LLM → notify**.
- **SOC Analyst** nhận thông báo trên **Telegram / SOAR**, bấm vào link Kibana/Discover để điều tra sâu.

---

### 2. Bảng mapping: Thành phần → Log → Vai trò SOC

| Thành phần              | Nguồn log/chức năng chính                                          | Vai trò SOC chính                                               |
|-------------------------|---------------------------------------------------------------------|------------------------------------------------------------------|
| **pfSense Firewall**    | Firewall logs, NAT, VPN, IPS/IDS (Suricata trên biên)              | Phòng tuyến đầu, phát hiện/chặn tấn công từ WAN, geo/IP block   |
| **Suricata (DMZ)**      | `suricata.eve` (alert, http, tls, dns, flow…)                      | Nhận diện tấn công mạng (SYN DoS, SQLi, XSS, bruteforce, v.v.)  |
| **WebServer (DVWA)**    | Apache/PHP logs, app logs                                          | Thể hiện hậu quả trên ứng dụng (500, SQL error, RCE, upload…)   |
| **Wazuh Agent 001/002** | Syslog, auth, process, file, OS events, app logs                   | Giám sát host/ứng dụng, phát hiện webshell, lateral movement    |
| **auditd**              | Process exec, file access, privilege escalation                    | Bằng chứng chi tiết về RCE, abuse quyền, persistence            |
| **Wazuh Manager**       | Điều phối agent, rule engine, decode log                           | Biến raw logs thành alert có `rule.id/level/groups/mitre`       |
| **Wazuh Indexer**       | `wazuh-alerts-*` (OpenSearch)                                      | Kho dữ liệu trung tâm cho phân tích, truy vấn, correlation      |
| **AI Pipeline**         | Collector, Correlation, FP Filtering, Heuristic, LLM, Notify       | Tự động triage, gắn nhãn FP, tương quan, ưu tiên hóa, cảnh báo  |
| **Telegram / SOAR**     | Nhận alert SOC‑grade, trigger playbook (block IP, ticket, v.v.)    | Giao diện vận hành & tự động hóa phản ứng                       |

---

### 3. Luồng xử lý chi tiết (tóm tắt)

1. **Ingestion (Collector – `src/collector/wazuh_client.py`)**
   - Poll index `wazuh-alerts-*` qua Wazuh Indexer.
   - Áp dụng **lọc SOC 2 tầng**:
     - Tầng 1: `MIN_LEVEL..MAX_LEVEL` + `INCLUDE_RULE_IDS`/`INCLUDE_RULE_ID_PREFIX`.
     - Tầng 2: luôn lấy `rule.level >= ALWAYS_REEVALUATE_LEVEL_GTE`.
   - Chuẩn hóa alert thành `AlertNormalized` với đầy đủ: identity, network, flow, HTTP, Suricata, tags, full_data, raw_json.

2. **Correlation & FP Labeling**
   - `correlate_alert` nhóm alert cùng nguồn/đích/attack‑type trong `LOOKBACK_MINUTES_CORRELATION`.
   - `analyze_fp_risk` gắn `fp_risk` + `fp_reason` + `noise_signals` (internal 404 scan, benign UA, high repetition,…).
   - **Không drop** FP – chỉ gắn nhãn để SOC/LLM tham chiếu.

3. **Triage (Heuristic + LLM – `src/analyzer/triage.py`)**
   - Heuristic score dựa trên rule.level, groups, MITRE, flow, HTTP status, action, correlation, fp_risk.
   - Gửi context đã redacted tới LLM:
     - Nhận lại JSON: `threat_level`, `confidence`, `summary`, `tags`, (có thể `evidence`, `mitre`).
     - Áp dụng **anti‑hallucination**: không bịa field/value; thiếu thì ghi “Not present/Unknown”.
   - Hợp nhất heuristic + LLM bằng **dynamic weighting + threat‑level adjustment** → `final_score`.

4. **Notification & Orchestration (`src/orchestrator/notify.py`)**
   - `should_notify_critical_attack`: override cho rule/attack cực kỳ nguy hiểm (SQLi, XSS, RCE, DoS lớn, bruteforce…).
   - `_format_telegram_message`: tạo message SOC‑grade (header, scores, identity, network, what happened, evidence, IOCs, correlation, actions, MITRE, query).
   - `_validate_telegram_message` + fallback plain text nếu lỗi Markdown → **không bao giờ bỏ sót alert vì lỗi format**.
   - (Tuỳ chọn) Gửi thêm webhook sang n8n/SOAR để tự động block IP, mở ticket, gửi email,…

---

### 4. Góc nhìn SOC khi vận hành

- **Trước khi triển khai**:
  - Xác định rule/id nào là critical (ví dụ: `100100` – SYN DoS, `31103/31105`, `100144`, `5715`,…).
  - Cấu hình `MIN_LEVEL/MAX_LEVEL/INCLUDE_RULE_IDS/ALWAYS_REEVALUATE_LEVEL_GTE` phù hợp risk appetite.
  - Thiết kế playbook SOAR (block IP, isolate host, forensics, thông báo CSIRT,…).

- **Khi đang bị tấn công (ví dụ: SYN DoS từ WAN vào DMZ)**:
  - Suricata/pfSense phát hiện lưu lượng SYN bất thường → alert `suricata.eve` (pkts_toserver cao, `signature_id` 1000001…).
  - Wazuh chuẩn hóa rule `100100` level 3, alert vẫn **lọt qua Tầng 1** nhờ `INCLUDE_RULE_IDS`.
  - Correlation nhận thấy `group_size` lớn cho cùng `src_ip + attack_type=dos`.
  - FP filtering có thể đánh dấu `fp_risk=LOW` (vì IP ngoài, pkts_toserver cao).
  - Heuristic + LLM đánh giá `threat_level=high/critical`, `confidence` cao, tags `["syn_flood","dos","network_attack"]`.
   - Notify gửi Telegram: hiển thị WAN IP, DMZ IP/port, flow stats, MITRE (T1498 – Network Denial of Service), khuyến nghị block IP tại pfSense, kiểm tra saturation, v.v.

- **Sau tấn công**:
  - SOC dùng `event_id`, `group_key`, `first_seen/last_seen`, `summary`, `evidence`, `MITRE` trong Telegram để:
    - Lập báo cáo sự cố.
    - Điều chỉnh rule/threshold hoặc `INCLUDE_RULE_IDS` để tối ưu FP/FN.

---

Tài liệu chi tiết hơn (logic, code và prompt LLM) xem thêm:
- `SOC_IMPLEMENTATION_GUIDE.md` – hướng dẫn triển khai chi tiết từng module.
- `SOC_ARCHITECTURE_DOCUMENTATION.md` – mô tả đầy đủ kiến trúc, data flow, và use case.

