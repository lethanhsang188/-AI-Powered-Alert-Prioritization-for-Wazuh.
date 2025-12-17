# SOC Pipeline Implementation Guide (Wazuh 4.12+)

Tài liệu này mô tả cách triển khai pipeline triage cảnh báo Wazuh theo chuẩn SOC: thu thập không bỏ sót (three-tier filtering), chuẩn hóa đầy đủ, attack type normalization, supply chain detection, gắn nhãn FP, tương quan, chấm điểm heuristics + LLM, và gửi cảnh báo Telegram giàu ngữ cảnh. Mọi bước đều tránh "silent drop".

## 1) Cấu hình chính (env)

- Ngưỡng lọc ba tầng: `MIN_LEVEL`, `MAX_LEVEL`, `INCLUDE_RULE_IDS`, `INCLUDE_RULE_ID_PREFIX`, và luôn lấy `ALWAYS_REEVALUATE_LEVEL_GTE`.
- Tier 3: Tự động detect attacks từ fields/content (category, signature, event_type) không phụ thuộc rule IDs.
- Tương quan & dedup: `LOOKBACK_MINUTES_CORRELATION`, `DEDUP_WINDOW_MINUTES`, `CORRELATION_TIME_WINDOW_MINUTES`.
- Nhịp kéo chỉ số: `WAZUH_POLL_INTERVAL_SEC`.
- Real-time mode: `WAZUH_START_FROM_NOW`, `WAZUH_REALTIME_MODE`.

```python
# src/common/config.py
SOC_MIN_LEVEL = get_env_int("MIN_LEVEL", 3)  # Minimum rule level to include (for custom rules)
SOC_MAX_LEVEL = get_env_int("MAX_LEVEL", 7)  # Maximum rule level for custom rule filtering
INCLUDE_RULE_IDS = [rid.strip() for rid in get_env("INCLUDE_RULE_IDS", "100100").split(",") if rid.strip()]
INCLUDE_RULE_ID_PREFIX = get_env("INCLUDE_RULE_ID_PREFIX", "1001")  # Optional prefix for rule IDs
ALWAYS_REEVALUATE_LEVEL_GTE = get_env_int("ALWAYS_REEVALUATE_LEVEL_GTE", 7)  # Always include and re-evaluate alerts with level >= this
LOOKBACK_MINUTES_CORRELATION = get_env_int("LOOKBACK_MINUTES_CORRELATION", 30)  # Lookback window for correlation
DEDUP_WINDOW_MINUTES = get_env_int("DEDUP_WINDOW_MINUTES", 10)  # Deduplication window in minutes
WAZUH_POLL_INTERVAL_SEC = get_env_int("WAZUH_POLL_INTERVAL_SEC", 8)  # Poll interval in seconds
CORRELATION_TIME_WINDOW_MINUTES = get_env_int("CORRELATION_TIME_WINDOW_MINUTES", 15)  # Time window for correlation groups
WAZUH_START_FROM_NOW = get_env_bool("WAZUH_START_FROM_NOW", True)  # Real-time mode: start from now
WAZUH_REALTIME_MODE = get_env_bool("WAZUH_REALTIME_MODE", True)  # Enable real-time processing
```

## 2) Luồng tổng thể

1. **Collector** (`wazuh_client.py`): Dựng truy vấn ba tầng (Tier 1: custom rules, Tier 2: high-level alerts, Tier 3: attack indicators từ fields), cân bằng agent, xử lý lookback động, chuẩn hóa AlertNormalized.
2. **Attack Type Normalization** (`attack_type_normalizer.py`): Normalize attack type từ nhiều nguồn (tags, signature, category, description) để đảm bảo cùng một loại tấn công được đánh giá giống nhau không phụ thuộc agent type hay rule IDs.
3. **Correlation & FP labeling**: `correlate_alert` (với source_campaign cho supply chain detection) + `analyze_fp_risk` → gắn nhãn `correlation`, `fp_filtering` (không loại bỏ).
4. **Triage**: Heuristic + LLM (dynamic weighting, threat-level adjustment), boost theo attack type, supply chain, tag/rule, dựng alert_card.
5. **Notify**: Kiểm tra override critical (bao gồm supply chain attacks), format Telegram SOC-grade, fallback không Markdown nếu lỗi parse.

## 3) Thu thập & lọc ba tầng (collector)

**Three-Tier Filtering Approach:**

- **Tier 1**: Level trong `[MIN_LEVEL..MAX_LEVEL]` và rule id khớp list/prefix (custom rules).
- **Tier 2**: Luôn lấy level >= `ALWAYS_REEVALUATE_LEVEL_GTE` (high-level alerts cho AI re-evaluation).
- **Tier 3**: Level >= `MIN_LEVEL` và có attack indicators trong fields (category, signature, event_type) - **NEW**: Không bỏ sót attacks thật dù không match rule IDs.

**Tier 3 Attack Indicators:**
- Attack categories: `Web Application Attack`, `Exploit`, `Malware`, `Trojan`, `Virus`, `Worm`, `DoS`, `Network Scan`, `Reconnaissance`, etc.
- Attack keywords in signature: `XSS`, `SQL Injection`, `Exploit`, `Command Injection`, `Path Traversal`, `RCE`, `File Upload`, `Brute Force`, etc.
- Suricata alerts: `data.event_type = "alert"` (IDS/IPS detections).

```python
# src/collector/wazuh_client.py (lines 627-750)
# SOC-GRADE FILTERING: Three-tier approach
# Tier 1: Include alerts with level [SOC_MIN_LEVEL..SOC_MAX_LEVEL] AND rule.id in INCLUDE_RULE_IDS or starts with INCLUDE_RULE_ID_PREFIX
# Tier 2: Always include alerts with level >= ALWAYS_REEVALUATE_LEVEL_GTE (for AI re-evaluation)
# Tier 3: Include alerts with attack indicators in fields (data.alert.category, data.alert.signature, etc.)
#         This ensures we don't miss real attacks even if they don't match rule IDs

tier_filters = [
    # Tier 1: Level 3-7 with custom rule IDs
    {
        "bool": {
            "must": [
                {"range": {"rule.level": {"gte": SOC_MIN_LEVEL, "lte": SOC_MAX_LEVEL}}},
                {
                    "bool": {
                        "should": rule_id_filters if rule_id_filters else [{"match_all": {}}],
                        "minimum_should_match": 1 if rule_id_filters else 0
                    }
                }
            ]
        }
    },
    # Tier 2: Level >= ALWAYS_REEVALUATE_LEVEL_GTE (always include)
    {"range": {"rule.level": {"gte": ALWAYS_REEVALUATE_LEVEL_GTE}}},
    # Tier 3: Attack indicators in fields (include even if rule ID doesn't match)
    {
        "bool": {
            "must": [
                {"range": {"rule.level": {"gte": SOC_MIN_LEVEL}}},  # At least MIN_LEVEL
                {
                    "bool": {
                        "should": attack_indicator_filters,
                        "minimum_should_match": 1
                    }
                }
            ]
        }
    }
]
```

**Lợi ích Tier 3:**
- ✅ Không bỏ sót attacks từ Agent 002 (pfSense/Suricata) dù rule ID không match
- ✅ Detect attacks từ fields/content, không chỉ dựa vào rule metadata
- ✅ Ví dụ: XSS attack từ rule 86601 (level 3) sẽ được include nhờ Tier 3 (category: "Web Application Attack", signature: "[L2-Exploit][XSS]")

**Agent Balancing:**
- Không còn must_not cho agent 002; sort theo thời gian và agent để tránh dồn tải.
- Cả Agent 001 và Agent 002 được query đồng đều với cùng field set.

## 4) Chuẩn hóa AlertNormalized

- Giữ nguyên `@timestamp` (UTC + local), `event_id`, `index`, `agent`/`rule`/`decoder`/`manager`, `location`.
- Trích xuất network (src/dest ip/port, proto, app_proto, direction, flow stats), `http`, `suricata_alert`, `tags`, `full_data`, `raw_json`.
- Mặc định None/{} nếu thiếu để tránh crash; lưu toàn bộ raw cho bằng chứng và LLM.

```python
# src/collector/wazuh_client.py (lines 520-611)
return {
    "@timestamp": timestamp,
    "@timestamp_local": localized_ts or "",
    "event_id": event_id,
    "index": index,
    "manager": {"name": manager_name} if manager_name else {},
    "decoder": {"name": decoder_name} if decoder_name else {},
    "location": location,
    "agent": raw.get("agent", {}),
    "rule": raw.get("rule", {}),
    "srcip": src_ip, "src_port": src_port,
    "dest_ip": dest_ip, "dest_port": dest_port,
    "proto": proto, "app_proto": app_proto,
    "flow": {...},
    "http": http_context if http_context else None,
    "suricata_alert": suricata_alert if suricata_alert else None,
    "full_data": full_data,
    "tags": tags,
    "raw": raw,
    "raw_json": raw_json,
}
```

## 5) Attack Type Normalization

**File:** `src/common/attack_type_normalizer.py`

**Mục đích:** Đảm bảo cùng một loại tấn công được đánh giá giống nhau không phụ thuộc vào agent type (WebServer vs pfSense) hay rule IDs khác nhau.

**Priority:**
1. Tags (đã được normalize từ signature/category)
2. Suricata signature keywords
3. Rule description keywords
4. Rule groups
5. Alert category

**Supported Attack Types:**
- `xss` - Cross-Site Scripting
- `sql_injection` - SQL Injection
- `command_injection` - Command Injection
- `path_traversal` - Path Traversal
- `csrf` - Cross-Site Request Forgery
- `web_attack` - Generic web attack

**Usage:**
```python
# src/analyzer/triage.py (line 67)
alert = normalize_attack_type_for_scoring(alert)
normalized_attack_type = alert.get("attack_type_normalized")
```

**Kết quả:**
- ✅ Cùng attack type từ Agent 001 và Agent 002 → cùng normalized type
- ✅ Heuristic scoring dựa trên attack type, không phụ thuộc rule ID
- ✅ LLM analysis nhận normalized attack type trong context

## 6) Correlation & FP labeling

**Correlation Types (Priority Order):**
1. **`source_campaign`** - **NEW**: Group tất cả attacks từ cùng source IP (cho supply chain detection)
2. `source_attack` - Same source IP + same attack type
3. `destination_attack` - Same destination + same attack type
4. `signature` - Same signature + time window
5. `rule_pattern` - Same rule pattern + time window

**Supply Chain Detection:**
- Auto-detect khi có 2+ attack types khác nhau từ cùng source trong time window
- Severity:
  - **High**: 3+ attack types hoặc critical combo (XSS+SQL, SQL+Command Injection)
  - **Medium**: 2 attack types (không phải critical combo)
  - **Low**: 2 attack types (fallback)

**Correlation Return:**
```python
# src/common/correlation.py
{
    "is_correlated": True,
    "group_key": "campaign:src:1.2.3.4",  # source_campaign
    "group_size": 30,
    "correlation_type": "source_campaign",
    "supply_chain": {
        "is_supply_chain": True,
        "attack_types": ["xss", "sql_injection"],
        "attack_type_counts": {"xss": 10, "sql_injection": 20},
        "severity": "high",
        "total_alerts": 30
    }
}
```

**FP Filtering:**
- Gắn nhãn FP nhưng không loại bỏ; xét internal IP + 404, benign signature/user-agent, lặp lại, cron pattern.
- Xuất `fp_risk`, `fp_reason`, `noise_signals`.

```python
# src/common/fp_filtering.py
def analyze_fp_risk(alert: Dict[str, Any], correlation_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if src_ip and _is_internal_ip(src_ip):
        if http_context and http_context.get("status") == "404":
            fp_reasons.append("Internal IP with HTTP 404 (likely internal scan)")
    ...
    if correlation_info and correlation_info.get("is_correlated"):
        group_size = correlation_info.get("group_size", 1)
        if group_size >= 10:
            fp_reasons.append(f"High repetition: {group_size} alerts from same source (possible noise)")
    ...
    return {"fp_risk": fp_risk, "fp_reason": fp_reasons, "allowlist_hit": allowlist_hit, "noise_signals": noise_signals}
```

```python
# src/analyzer/triage.py (lines 48-64)
if CORRELATION_ENABLE:
    correlation_info = correlate_alert(alert)
    alert["correlation"] = correlation_info
...
fp_result = analyze_fp_risk(alert, correlation_info)
alert["fp_filtering"] = fp_result

# Normalize attack type BEFORE scoring
alert = normalize_attack_type_for_scoring(alert)
normalized_attack_type = alert.get("attack_type_normalized")
```

## 7) Triage (heuristic + LLM)

**Heuristic Scoring:**
- Base score từ rule level (non-linear curve)
- **Attack type bonus** (NEW): Dựa trên normalized attack type, không phụ thuộc rule ID
- Attack tool detection (sqlmap, nmap, nikto, burp, metasploit, etc.): +0.15
- Correlation bonus: +0.10 (3+ alerts) hoặc +0.20 (5+ alerts)
- **Supply chain bonus** (NEW): +0.25 (high), +0.15 (medium), +0.10 (low)
- Group-based bonus, rule-specific multiplier

```python
# src/analyzer/heuristic.py
# Normalize attack type
attack_type = normalize_attack_type(alert)
attack_priority = get_attack_type_priority(attack_type)

# Attack type bonus (ensures same attack type gets similar score)
if attack_type:
    attack_bonus = attack_priority * 0.01  # 0.01-0.10 bonus
    base_score += attack_bonus

# Supply chain bonus
supply_chain = correlation.get("supply_chain")
if supply_chain and supply_chain.get("is_supply_chain"):
    severity = supply_chain.get("severity", "low")
    if severity == "high":
        base_score += 0.25
    elif severity == "medium":
        base_score += 0.15
    else:
        base_score += 0.10
```

**LLM Triage:**
- Heuristic score + LLM triage_llm; dynamic trọng số theo confidence.
- Điều chỉnh theo threat_level.
- Boost confidence khi LLM nhận đúng SQLi/XSS/command injection.
- LLM nhận normalized attack type trong context.

```python
# src/analyzer/triage.py (lines 245-270)
if llm_confidence < 0.3:
    effective_h_weight = min(HEURISTIC_WEIGHT + 0.2, 0.9)
...
fused_score = (effective_h_weight * h_score) + (effective_l_weight * llm_confidence)
threat_adjustment = THREAT_LEVEL_ADJUSTMENTS.get(threat_level, 0.0)
final_score = max(0.0, min(1.0, final_score))
```

## 8) Thông báo Telegram SOC-grade

**Override Critical Attacks:**
- Rule list (CRITICAL_ATTACK_RULES)
- Critical tags (sql_injection, xss, command_injection, etc.)
- High level (>= 12)
- Suricata severity (>= 3)
- Attack tools (sqlmap, nmap, nikto, burp, metasploit, etc.)
- Correlation campaign (group_size >= 5)
- **Supply chain attacks** (NEW): Always notify với message "🚨 SUPPLY CHAIN ATTACK DETECTED 🚨"

**Telegram Message Format:**
- Header: Rule ID, Level, Agent, Timestamp
- Threat Level & Score: LLM threat level, confidence, final score
- Attack Details: Description, category, signature
- Network Context: Source/Destination IP, ports, protocol
- HTTP Context: URL, method, user agent, status
- IOC: Source IP, destination IP, domain, URL
- **Correlation Section** (NEW):
  - Correlated count
  - **Supply chain info** (nếu có): Attack types, severity, breakdown
  - First seen, last seen
- Evidence: Full alert data cho investigation

**Supply Chain Notification:**
```
🚨 SUPPLY CHAIN ATTACK DETECTED 🚨
Multiple attack types from same source: xss (10 alerts), sql_injection (20 alerts)
Total alerts: 30, Severity: HIGH
```

**Telegram Message Section:**
```
*Correlation:*
Correlated Count: 30

🚨 SUPPLY CHAIN ATTACK 🚨
Attack Types: xss, sql_injection
Severity: HIGH
Total Campaign Alerts: 30
Breakdown: xss: 10, sql_injection: 20
```

**Helper Functions:**
- `_to_int`: Chuyển chuỗi số → int để tránh TypeError; dùng trong evidence/flow stats.
- `_validate_telegram_message`: Validate Markdown, fallback gửi plain text nếu parse lỗi để không mất cảnh báo.

```python
# src/orchestrator/notify.py
def _to_int(value: Any) -> Optional[int]:
    """Best-effort convert a value to int (handles numeric strings from JSON)."""
    if isinstance(value, str):
        s = value.strip()
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        return int(float(s))
    return None

def _validate_telegram_message(message: str) -> Tuple[bool, Optional[str]]:
    MAX_LENGTH = 4096
    if len(message) > MAX_LENGTH:
        return False, f"Message too long: {len(message)} characters (max {MAX_LENGTH})"
    asterisk_count = message.count('*')
    if asterisk_count % 2 != 0:
        return False, f"Unbalanced asterisks: {asterisk_count} (should be even for proper Markdown formatting)"
```

```python
# src/orchestrator/notify.py (lines 89-158)
def should_notify_critical_attack(alert: Dict[str, Any], triage: Dict[str, Any]) -> Tuple[bool, str]:
    # Supply chain attack override (highest priority)
    supply_chain = correlation.get("supply_chain")
    if supply_chain and supply_chain.get("is_supply_chain"):
        return True, "🚨 SUPPLY CHAIN ATTACK DETECTED 🚨"
    
    if rule_id in CRITICAL_ATTACK_RULES: return True, ...
    if critical_tags_found: return True, ...
    if rule_level >= 12: return True, ...
    if suricata_severity >= 3: return True, ...
    if attack_tools in user_agent: return True, ...
    if correlation.get("group_size") >= 5: return True, ...
```

## 9) Real-Time Processing

**Dynamic Lookback:**
- Real-time mode: Bỏ cursor, dùng dynamic lookback
- Lookback = `poll_interval + max_indexer_delay + safety_buffer`
- Ví dụ: 8s (poll) + 30s (indexer) + 10s (buffer) = 48s ≈ 1 minute

**Timeline:**
```
T+0s:   Attack xảy ra
T+1s:   Wazuh Manager phát hiện
T+2-5s: Wazuh Manager → Indexer
T+5-30s: Indexer index → OpenSearch (DELAY!)
T+30s:  Pipeline query → nhận alert
T+38s:  Pipeline process → notify (nếu poll interval = 8s)
```

**Delay:** 8-48 giây (chủ yếu do indexer, không phải pipeline)

**Supply Chain Detection:**
- ✅ Detect ngay khi có 2+ attack types từ cùng source
- ✅ Time window: 15 phút (configurable via `CORRELATION_TIME_WINDOW_MINUTES`)
- ✅ Real-time notification khi detect

## 10) Lưu ý vận hành

- **Agent 001/002**: Xử lý đồng nhất (không must_not); cân bằng qua sort và truy vấn theo agent.
- **Không drop cảnh báo**: Mọi FP chỉ được gắn nhãn `fp_risk`, vẫn qua LLM + Telegram.
- **Tier 3**: Đảm bảo không bỏ sót attacks thật từ fields/content.
- **Attack Type Normalization**: Đảm bảo cùng attack type được đánh giá giống nhau.
- **Supply Chain Detection**: Auto-detect multi-stage attacks, always notify.
- **Đảm bảo**: `TELEGRAM_BOT_TOKEN`/`CHAT_ID`, Wazuh API/indexer, và `OPENAI_API_KEY` được đặt trước khi chạy.

## 11) Cách chạy nhanh

- **Chạy pipeline**: `python bin/run_pipeline.py` (đảm bảo env đã set và indexer/API reachable).
- **Kiểm tra định dạng Telegram offline**: `python bin/test_telegram_message_formatting.py`.

## 12) Tính năng mới (2025-12-17)

### **Tier 3 Attack Detection**
- Detect attacks từ fields/content (category, signature, event_type)
- Không bỏ sót attacks thật dù không match rule IDs
- Ví dụ: XSS attack từ rule 86601 (level 3) được include nhờ Tier 3

### **Attack Type Normalization**
- Normalize attack type từ nhiều nguồn
- Đảm bảo cùng attack type được đánh giá giống nhau
- Heuristic scoring dựa trên attack type, không phụ thuộc rule ID

### **Supply Chain Attack Detection**
- Auto-detect multi-stage attacks (nhiều attack types từ cùng source)
- Severity: High/Medium/Low dựa trên số lượng và loại attack types
- Always notify với message "🚨 SUPPLY CHAIN ATTACK DETECTED 🚨"
- Score boost: +0.25 (high), +0.15 (medium), +0.10 (low)

### **Source Campaign Correlation**
- Correlation type mới: `source_campaign` (priority cao nhất)
- Group tất cả attacks từ cùng source IP, không phân biệt attack type
- Enable supply chain detection

## 13) Test Cases

### **Test Case 1: Tier 3 Detection**
- Alert: Rule 86601, Level 3, Category "Web Application Attack", Signature "[L2-Exploit][XSS]"
- Expected: ✅ Included nhờ Tier 3 (không match rule IDs nhưng có attack indicators)

### **Test Case 2: Attack Type Normalization**
- Agent 001: Rule 31105 "XSS attempt" → normalized: "xss"
- Agent 002: Rule 86601 "Suricata: Alert - [L2-Exploit][XSS]" → normalized: "xss"
- Expected: ✅ Cùng normalized type "xss", cùng attack type bonus

### **Test Case 3: Supply Chain Attack**
- T+0s: 10 XSS payloads từ 1.2.3.4
- T+60s: 20 SQL injection (sqlmap) từ 1.2.3.4
- Expected: ✅ Supply chain detected, attack_types=["xss", "sql_injection"], severity="high", always notify

---

**Version:** 2.0 (Updated 2025-12-17)  
**Author:** SOC Pipeline Team  
**Status:** ✅ Production Ready
