# 🏗️ SOC Pipeline Architecture - Detailed Technical Documentation

**Project:** AI-Powered Alert Prioritization for Wazuh  
**Version:** 1.0  
**Date:** 2025-01-XX  
**Perspective:** SOC Technical Architecture

---

## 📋 TABLE OF CONTENTS

1. [Executive Summary](#executive-summary)
2. [Pipeline Architecture Overview](#pipeline-architecture-overview)
3. [Module-by-Module Architecture](#module-by-module-architecture)
4. [Data Flow & State Management](#data-flow--state-management)
5. [Error Handling & Resilience](#error-handling--resilience)
6. [Performance & Scalability](#performance--scalability)
7. [Configuration Management](#configuration-management)
8. [Dependencies & Integration Points](#dependencies--integration-points)

---

## 🎯 EXECUTIVE SUMMARY

Pipeline này là một **single-threaded, event-driven loop** chạy trên một máy (có thể scale horizontal bằng cách chạy nhiều instance với cursor riêng). Pipeline được thiết kế để:

- **Không bỏ sót cảnh báo quan trọng**: SOC two-tier filtering + critical override
- **Resilient**: Retry logic, fallback messages, graceful degradation
- **Observable**: Structured logging với context (component, action, rule_id, agent_id)
- **Configurable**: Tất cả thresholds và behavior điều khiển qua environment variables

---

## 🔄 PIPELINE ARCHITECTURE OVERVIEW

### High-Level Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    MAIN LOOP (run_pipeline.py)                 │
│                                                                 │
│  while True:                                                    │
│    1. Poll Wazuh Indexer (fetch_alerts)                       │
│    2. For each alert:                                          │
│       a. Normalize → AlertNormalized                            │
│       b. Enrich (GeoIP, Threat Intel)                          │
│       c. Correlate (group related alerts)                      │
│       d. FP Filtering (label, don't drop)                     │
│       e. Triage (heuristic + LLM)                              │
│       f. Notify (Telegram if score >= threshold OR critical)   │
│    3. Save cursor state                                        │
│    4. Sleep (poll_interval)                                     │
└─────────────────────────────────────────────────────────────────┘
```

### Module Organization

```
src/
├── collector/          # Data ingestion layer
│   └── wazuh_client.py    # Wazuh Indexer client, SOC two-tier filtering, normalization
│
├── analyzer/           # Analysis layer
│   ├── heuristic.py       # Rule-based scoring (rule.level, groups, MITRE, flow stats)
│   ├── llm.py            # LLM-based analysis (OpenAI API, caching, anti-hallucination)
│   └── triage.py         # Fusion logic (heuristic + LLM, dynamic weighting, threat adjustment)
│
├── orchestrator/       # Orchestration layer
│   └── notify.py          # Telegram notification, critical override, message formatting
│
└── common/             # Shared utilities
    ├── config.py          # Environment variable loading & validation
    ├── correlation.py     # Alert correlation engine (in-memory groups)
    ├── dedup.py          # Deduplication key generation
    ├── enrichment.py     # GeoIP, Threat Intel enrichment
    ├── fp_filtering.py   # False positive labeling (no silent drops)
    ├── llm_cache.py      # LLM result caching (LRU, TTL)
    ├── logging.py        # Structured logging setup
    ├── redaction.py      # PII redaction for LLM
    ├── timezone.py       # Timezone handling
    └── web.py            # RetrySession (HTTP client with retry logic)
```

---

## 🧩 MODULE-BY-MODULE ARCHITECTURE

### 1. Collector Module (`src/collector/wazuh_client.py`)

**Responsibility**: Thu thập alerts từ Wazuh Indexer, áp dụng SOC two-tier filtering, chuẩn hóa thành AlertNormalized.

#### 1.1 Class: `WazuhClient`

**Initialization**:
```python
def __init__(self):
    # Setup API session (Wazuh Manager API - optional, mainly for token refresh)
    self.session = RetrySession()
    self._setup_api_session()  # Bearer token or Basic auth
    
    # Setup indexer session (OpenSearch/Wazuh Indexer - REQUIRED)
    self.indexer_session = RetrySession()
    self._setup_indexer_session()  # Basic auth (WAZUH_INDEXER_USER/PASS)
    
    # SSL verification: True/False or path to cert file
    # Logs warning if SSL disabled (security risk)
```

**Key Methods**:

- **`fetch_alerts()` → `List[Dict[str, Any]]`**
  - **Purpose**: Main entry point để lấy alerts từ indexer
  - **Logic**:
    1. Load cursor từ file (`CURSOR_PATH`, default `/app/state/cursor.json`)
    2. Tính toán lookback window:
       - **Realtime mode** (`WAZUH_DEMO_MODE` hoặc `WAZUH_START_FROM_NOW`):
         - Lookback = `WAZUH_POLL_INTERVAL_SEC + INDEXER_DELAY_SECONDS + buffer`
         - Cutoff = `now - lookback`
       - **Normal mode**:
         - Nếu có cursor: `max(cursor.timestamp - INDEXER_DELAY_SECONDS, now - 24h)`
         - Nếu không có cursor: `now - 24h - INDEXER_DELAY_SECONDS`
    3. **Agent-balanced fetching** (nếu `expected_agents` được set):
       - Loop qua từng agent (001, 002, ...)
       - Gọi `_fetch_alerts_for_agent(agent_id, cursor, page_size=100)`
       - Merge kết quả từ tất cả agents
    4. **SOC two-tier filtering** (trong `_build_indexer_query`):
       - **Tier 1**: `rule.level` trong [MIN_LEVEL..MAX_LEVEL] **AND** (`rule.id` trong INCLUDE_RULE_IDS **OR** `rule.id` bắt đầu với INCLUDE_RULE_ID_PREFIX)
       - **Tier 2**: `rule.level >= ALWAYS_REEVALUATE_LEVEL_GTE` (mặc định 7)
       - Query dùng `bool.should` với `minimum_should_match=1` → một trong hai tier pass là được
    5. Sort: `@timestamp ASC`, `agent.id ASC`, `_id ASC` (để phân phối đều agents)
    6. Pagination: `search_after` nếu có cursor.sort (chính xác hơn timestamp-based)
    7. Normalize từng alert: `_normalize_alert(hit["_source"])`
    8. Update cursor: `{"timestamp": last_alert_timestamp, "sort": [timestamp, agent_id, _id]}`
    9. Save cursor: `_save_cursor(cursor)`
  - **Returns**: List of AlertNormalized dictionaries
  - **Error Handling**: 
    - Nếu indexer không reachable → log error, return empty list (không crash pipeline)
    - Nếu query syntax error → log error, return empty list

- **`_normalize_alert(raw: Dict) → AlertNormalized`**
  - **Purpose**: Chuẩn hóa raw Wazuh alert thành cấu trúc thống nhất
  - **Input**: Raw `_source` từ OpenSearch hit
  - **Output**: AlertNormalized dict với các field:
    - **Timestamps**: `@timestamp` (UTC ISO), `@timestamp_local` (localized)
    - **Identity**: `event_id` (`_id`), `index`, `agent.{id,name,ip}`, `manager.name`, `decoder.name`, `location`
    - **Rule**: `rule.{id,level,description,groups,mitre,firedtimes}`
    - **Network**: `src_ip`, `dest_ip`, `src_port`, `dest_port`, `proto`, `app_proto`, `direction`, `in_iface`, `flow_id`, `tx_id`
    - **Flow stats**: `flow.{pkts_toserver,pkts_toclient,bytes_toserver,bytes_toclient,start}`
    - **HTTP context**: `http.{method,url,status,hostname,user_agent,referer,redirect}`, `http_anomaly_count`
    - **Suricata alert**: `suricata_alert.{signature_id,signature,category,action,severity}`
    - **Tags**: Derived từ `rule.groups`, `suricata.category`, signature keywords
    - **Raw data**: `full_data` (copy của `data.*`), `raw_json` (copy của toàn bộ `_source`)
  - **Extraction Logic**:
    - Network fields: Ưu tiên `data.source.ip` / `data.destination.ip`, fallback `srcip` / `agent.ip`
    - Flow stats: Từ `data.flow.*` hoặc `suricata.eve.flow.*`
    - HTTP: Từ `data.http.*` hoặc `suricata.eve.http.*`
    - Suricata: Từ `data.suricata.*` hoặc `suricata.eve.alert.*`
  - **Default Values**: Tất cả field không tồn tại → `None` hoặc `{}` (không crash)

- **`_build_indexer_query(cursor, agent_id=None) → Dict`**
  - **Purpose**: Xây dựng OpenSearch query với SOC two-tier filtering
  - **Query Structure**:
    ```json
    {
      "size": WAZUH_PAGE_LIMIT (default 200),
      "sort": [{"@timestamp": "asc"}, {"agent.id": "asc"}, {"_id": "asc"}],
      "query": {
        "bool": {
          "filter": [
            {
              "bool": {
                "should": [
                  {
                    "bool": {
                      "must": [
                        {"range": {"rule.level": {"gte": MIN_LEVEL, "lte": MAX_LEVEL}}},
                        {"bool": {"should": rule_id_filters, "minimum_should_match": 1}}
                      ]
                    }
                  },
                  {"range": {"rule.level": {"gte": ALWAYS_REEVALUATE_LEVEL_GTE}}}
                ],
                "minimum_should_match": 1
              }
            },
            {"range": {"@timestamp": {"gt": cutoff_iso}}},
            {"term": {"agent.id": agent_id}}  // Nếu agent_id được chỉ định
          ]
        }
      },
      "search_after": [timestamp, agent_id, _id]  // Nếu có cursor.sort
    }
    ```

#### 1.2 State Management

- **Cursor File** (`CURSOR_PATH`, default `/app/state/cursor.json`):
  - Format: `{"timestamp": "2025-01-XX...", "sort": [timestamp, agent_id, _id]}`
  - Purpose: Track last processed alert để tránh duplicate và đảm bảo sequential processing
  - Persistence: `_save_cursor()` ghi sau mỗi batch, `_load_cursor()` đọc khi khởi động

---

### 2. Analyzer Module (`src/analyzer/`)

#### 2.1 Heuristic Scoring (`src/analyzer/heuristic.py`)

**Function**: `score(alert: Dict) → float (0.0-1.0)`

**Scoring Formula**:
```
base_score = _calculate_base_score(rule_level)
  - Level 0: 0.0
  - Level 1-11: Linear (level / 15.0)
  - Level 12-14: Non-linear curve (0.80 + normalized * 0.15)
  - Level 15: 1.0

group_bonus = _calculate_group_bonus(rule_groups)
  - CRITICAL_GROUPS (sql_injection, attack): +0.15
  - HIGH_GROUPS (bruteforce, web_attack, ids): +0.10
  - MEDIUM_GROUPS (web, invalid_access): +0.05

multipliers:
  - SUCCESSFUL_ATTACK_RULES (31106): x1.2
  - XSS_RULES (31105, 31154): x1.15
  - FREQUENCY_BASED_RULES (31151-31163): x1.1

flow_bonus:
  - pkts_toserver > 100: +0.05 (DoS indicator)
  - bytes_toserver > 10000: +0.03

http_bonus:
  - HTTP 200 (successful attack): +0.10
  - HTTP 404 (scanning): +0.02

action_bonus:
  - suricata.action == "allowed" (attack passed firewall): +0.10

final_score = min((base_score + group_bonus) * multipliers + flow_bonus + http_bonus + action_bonus, 1.0)
```

**Key Constants**:
- `CRITICAL_GROUPS`: `{"sql_injection", "sqlinjection", "attack"}`
- `HIGH_GROUPS`: `{"authentication_failed", "bruteforce", "web_attack", "web_scan", "recon", "ids", "suricata"}`
- `SUCCESSFUL_ATTACK_RULES`: `{"31106"}` (Web attack returned 200)
- `XSS_RULES`: `{"31105", "31154"}`

#### 2.2 LLM Analysis (`src/analyzer/llm.py`)

**Function**: `triage_llm(alert_text: str, rule_context: Dict) → Dict`

**Input Processing**:
1. **Cache Check** (`LLM_CACHE_ENABLE=True`):
   - Key: `hash(alert_text + rule_context.id)`
   - TTL: `LLM_CACHE_TTL_SECONDS` (default 3600s)
   - Cache hit → return cached result (không gọi API)

2. **Prompt Construction**:
   - **System Prompt**: Role definition (SOC analyst), anti-hallucination rules
   - **Rule Context**: `rule.id`, `level`, `description`, `groups`, `mitre.ids`
   - **Rule-Specific Guidance**: 
     - Rule 31105 (XSS): "CRITICAL: XSS detection → threat_level: high/critical, tags: [xss, web_attack]"
     - Rule 31103/31104 (SQLi): "CRITICAL: SQL injection → threat_level: critical, tags: [sql_injection, web_attack]"
   - **Alert Text**: Redacted alert context (rule, HTTP, network, flow, Suricata, message, FP context, correlation)
   - **Output Schema**: JSON với `threat_level`, `confidence`, `summary`, `tags`, `evidence`, `mitre`

3. **API Call**:
   - Endpoint: `{OPENAI_API_BASE}/chat/completions`
   - Model: `LLM_MODEL` (default `gpt-4o-mini`)
   - Temperature: Dynamic dựa trên `rule_level`:
     - Level >= 12: 0.2 (very precise)
     - Level >= 9: 0.25
     - Level >= 7: 0.3
     - Level < 7: 0.35 (more flexible)
   - Max tokens: `LLM_MAX_TOKENS` (default 512)
   - Timeout: `LLM_TIMEOUT_SEC` (default 20s)

4. **Response Parsing**:
   - Parse JSON từ `response.choices[0].message.content`
   - Validate: `threat_level` trong `ALLOWED_THREAT_LEVELS`, `tags` trong `ALLOWED_TAGS`
   - Cache result nếu `LLM_CACHE_ENABLE=True`

5. **Error Handling**:
   - API timeout → return default `{"threat_level": "medium", "confidence": 0.0, "tags": []}`
   - JSON parse error → log warning, return default
   - Rate limit → log warning, return default

**Output Schema**:
```json
{
  "threat_level": "critical" | "high" | "medium" | "low" | "none",
  "confidence": 0.0-1.0,
  "summary": "Brief description of what happened, where, impact, evidence",
  "tags": ["sql_injection", "web_attack", ...],
  "evidence": ["field=value", ...],  // Optional
  "mitre": ["T1190", "T1059", ...]   // Optional
}
```

**Anti-Hallucination Rules** (enforced trong prompt):
- Không được "chế" field/value không có trong alert
- Nếu thiếu field → ghi `"Not present in alert"` hoặc `"Unknown"`
- Evidence phải là `field=value` với field thật sự tồn tại
- Nếu không chắc → giảm `confidence`, nhưng alert vẫn được chuyển sang notify

#### 2.3 Triage Fusion (`src/analyzer/triage.py`)

**Function**: `run(alert: Dict) → Dict`

**Pipeline Steps**:

1. **Enrichment** (`ENRICHMENT_ENABLE=True`):
   - `enrich_alert(alert)` → thêm `enrichment.{geoip, threat_intel}` vào alert
   - GeoIP: Country, region, city, ASN, org (từ ipapi.co, cached)
   - Threat Intel: (có thể mở rộng với VirusTotal, AbuseIPDB)

2. **Correlation** (`CORRELATION_ENABLE=True`):
   - `correlate_alert(alert)` → thêm `correlation.{is_correlated, group_key, group_size, first_seen, attack_pattern}` vào alert
   - Correlation engine (in-memory): Groups alerts theo `src_ip + attack_type`, `dst_ip + attack_type`, `signature_id`, `rule.id`
   - Time window: `LOOKBACK_MINUTES_CORRELATION` (default 30 minutes)

3. **FP Filtering**:
   - `analyze_fp_risk(alert, correlation_info)` → thêm `fp_filtering.{fp_risk, fp_reason, noise_signals}` vào alert
   - **Không drop**, chỉ label: `fp_risk` = LOW/MEDIUM/HIGH
   - Checks: Internal IP + 404, benign signatures, repetition, cron patterns

4. **Heuristic Score**:
   - `heuristic_score(alert)` → `h_score` (0.0-1.0)

5. **LLM Analysis**:
   - Build alert text (redacted) với rule context, HTTP, network, flow, Suricata, FP context, correlation
   - `triage_llm(alert_text, rule_context)` → `llm_result`
   - Extract: `threat_level`, `confidence`, `summary`, `tags`

6. **Confidence Boost** (nếu LLM nhận đúng):
   - Rule 31105 + tag "xss" → `confidence += 0.15`
   - Rule 31103/31104 + tag "sql_injection" → `confidence += 0.20`
   - Rule 100144/100145/100146 + tag "command_injection" → `confidence += 0.20`

7. **Dynamic Weighting**:
   - Nếu `llm_confidence < 0.3`: `effective_h_weight = min(HEURISTIC_WEIGHT + 0.2, 0.9)`, `effective_l_weight = max(LLM_WEIGHT - 0.2, 0.1)`
   - Nếu `llm_confidence > 0.8`: `effective_h_weight = max(HEURISTIC_WEIGHT - 0.1, 0.3)`, `effective_l_weight = min(LLM_WEIGHT + 0.1, 0.7)`
   - Ngược lại: dùng `HEURISTIC_WEIGHT` và `LLM_WEIGHT` mặc định

8. **Score Fusion**:
   ```
   fused_score = (effective_h_weight * h_score) + (effective_l_weight * llm_confidence)
   ```

9. **Threat Level Adjustment**:
   ```
   threat_adjustment = THREAT_LEVEL_ADJUSTMENTS[threat_level]
     - "critical": +0.10
     - "high": +0.05
     - "medium": 0.0
     - "low": -0.05
     - "none": -0.10
   
   final_score = fused_score + threat_adjustment
   final_score = clamp(final_score, 0.0, 1.0)
   ```

10. **Alert Card Formatting**:
    - `format_alert_card(alert, triage_result)` → `alert_card` (title, short summary, fields)

**Output**:
```python
{
    "title": "Alert title from alert_card",
    "score": final_score (0.0-1.0),
    "threat_level": threat_level,
    "summary": llm_result["summary"],
    "tags": llm_result["tags"],
    "heuristic_score": h_score,
    "llm_confidence": llm_confidence,
    "llm_threat_level": threat_level,
    "alert_card": alert_card,
    "alert_card_short": alert_card_short
}
```

---

### 3. Orchestrator Module (`src/orchestrator/notify.py`)

**Function**: `notify(alert: Dict, triage: Dict) → None`

**Pipeline Steps**:

1. **Critical Override Check** (`should_notify_critical_attack`):
   - **Rule-based**: `rule.id` trong `CRITICAL_ATTACK_RULES` → `override=True`
   - **Tag-based**: `tags` chứa `CRITICAL_ATTACK_TAGS` → `override=True`
   - **Level-based**: `rule.level >= 12` → `override=True`
   - **Suricata severity**: `suricata_severity >= 3` + `action == "allowed"` → `override=True`
   - **Attack tools**: User agent chứa `sqlmap`, `nmap`, `burp`, ... → `override=True`
   - **Correlation**: `correlation.group_size >= 5` → `override=True`
   - **Threat level**: `threat_level in ["critical", "high"]` + `confidence > 0.3` → `override=True`

2. **Score Threshold Check**:
   - Nếu `override=True` → luôn notify
   - Nếu `override=False` → chỉ notify nếu `triage.score >= TRIAGE_THRESHOLD` (default 0.70)

3. **Message Formatting** (`_format_telegram_message`):
   - **15 Sections**:
     1. **Header**: ENV name, timestamp (local), event_id, index
     2. **Scores**: Heuristic, LLM confidence, final score, threat level, FP risk
     3. **Identity**: Agent/host, user, process (nếu có)
     4. **Network Summary**: Src/dst IP/Port, proto, app_proto, direction (WAN/DMZ/LAN)
     5. **HTTP Context**: URL, method, status, hostname, user-agent, referer
     6. **Flow Statistics**: Packets/bytes to server/client
     7. **Suricata Alert**: Signature, category, action (allowed/blocked)
     8. **What Happened**: LLM summary
     9. **Evidence**: List `field=value` (dùng `_to_int` để convert số)
     10. **IOCs**: IPs, domains, hashes
     11. **Correlation**: Group size, first_seen/last_seen, attack pattern
     12. **Recommended Actions**: Block IP, isolate host, collect memory, check WAF
     13. **MITRE ATT&CK**: TTPs từ rule.mitre hoặc LLM
     14. **Kibana Query**: Link + query string để analyst xem log
     15. **Tags**: Từ triage.tags
   - **Markdown Formatting**: Bold (`*text*`), italic (`_text_`), code (`\`text\``)
   - **Escape Special Chars**: `_escape_markdown_content()` để tránh parse error

4. **Message Validation** (`_validate_telegram_message`):
   - Length check: Max 4096 chars (Telegram limit)
   - Balanced asterisks (Markdown formatting)
   - Unescaped parentheses/brackets check

5. **Send to Telegram**:
   - Endpoint: `https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage`
   - Payload: `{"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}`
   - **Retry Logic**: `RetrySession` (max 3 retries, exponential backoff)
   - **Fallback**: Nếu Markdown parse error → gửi lại với `parse_mode=None` (plain text)

6. **Error Handling**:
   - Format error → log error, gửi fallback message (simplified format)
   - Telegram API error → log error, retry (không crash pipeline)

**Helper Functions**:

- **`_to_int(value: Any) → Optional[int]`**:
  - Convert string/int/float → int
  - Handles: `"120"` → `120`, `120.5` → `120`, `None` → `None`
  - Used trong evidence/flow stats để tránh `TypeError: '>' not supported between 'str' and 'int'`

---

### 4. Common Utilities (`src/common/`)

#### 4.1 Correlation Engine (`src/common/correlation.py`)

**Class**: `AlertCorrelationEngine`

**State**:
- `self.alert_groups: Dict[str, List[Dict]]` - Group key → list of alerts
- `self.group_metadata: Dict[str, Dict]` - Group key → metadata (first_seen, last_seen, count, attack_pattern)
- `self.time_window_minutes: int` - Correlation window (default 15, configurable via `LOOKBACK_MINUTES_CORRELATION`)

**Methods**:

- **`correlate(alert) → Dict`**:
  - Generate group keys theo priority:
    1. `source_attack`: `src:{src_ip}:attack:{attack_type}`
    2. `destination_attack`: `dst:{dst_ip}:attack:{attack_type}`
    3. `signature`: `sig:{signature_id}`
    4. `rule_pattern`: `rule:{rule_id}`
  - Check time window: Nếu alert trong window của existing group → add vào group
  - Nếu không → create new group
  - Return: `{is_correlated, group_key, group_size, first_seen, last_seen, attack_pattern, correlation_type}`

- **`_cleanup_old_groups()`**:
  - Chạy mỗi 1 giờ (hoặc khi correlate được gọi)
  - Remove groups cũ hơn 2 giờ

**Global Instance**: `correlation_engine = AlertCorrelationEngine()` (singleton)

**Function**: `correlate_alert(alert) → Dict` (wrapper gọi `correlation_engine.correlate(alert)`)

#### 4.2 FP Filtering (`src/common/fp_filtering.py`)

**Function**: `analyze_fp_risk(alert, correlation_info) → Dict`

**Checks**:

1. **Internal IP + HTTP 404**:
   - `src_ip` là internal (RFC 1918) **AND** `http.status == "404"` → `fp_reason.append("Internal IP with HTTP 404")`, `noise_signals.append("internal_scan_404")`

2. **Benign Signatures**:
   - `suricata_alert.signature` chứa `"health-check"`, `"monitoring"`, `"keepalive"`, ... → `fp_reason.append("Benign signature pattern")`

3. **Benign User Agents**:
   - `http.user_agent` chứa `"healthcheck"`, `"monitoring"`, `"pingdom"`, ... → `fp_reason.append("Benign user agent")`

4. **Repetition**:
   - Nếu `correlation_info.group_size >= 10` → `fp_reason.append("High repetition")`, `fp_risk = HIGH`
   - Nếu `correlation_info.group_size >= 5` → `fp_reason.append("Moderate repetition")`, `fp_risk = MEDIUM`

5. **Cron/Job Patterns**:
   - `message` chứa `"cron"`, `"scheduled task"`, `"job"` → `fp_reason.append("Cron/job pattern")`

**FP Risk Calculation**:
- `fp_reasons >= 3` hoặc `high_repetition` → `fp_risk = HIGH`
- `fp_reasons >= 2` hoặc `moderate_repetition` → `fp_risk = MEDIUM`
- `fp_reasons >= 1` → `fp_risk = LOW`
- Ngược lại → `fp_risk = LOW`

**Output**:
```python
{
    "fp_risk": "LOW" | "MEDIUM" | "HIGH",
    "fp_reason": ["reason1", "reason2", ...],
    "allowlist_hit": False,  # Future: whitelist support
    "noise_signals": ["internal_scan_404", "benign_signature_health-check", ...]
}
```

#### 4.3 Enrichment (`src/common/enrichment.py`)

**Class**: `GeoIPEnricher`

**Methods**:

- **`enrich(ip: str) → Dict`**:
  - Skip private IPs → return `{is_internal: True, country: "Internal"}`
  - Check cache (TTL 1 hour)
  - Call `ipapi.co/{ip}/json/` (free, no API key)
  - Cache result
  - Return: `{country, country_code, region, city, latitude, longitude, asn, org, timezone, is_internal}`

**Function**: `enrich_alert(alert) → Dict` (wrapper gọi `GeoIPEnricher().enrich(src_ip)`)

#### 4.4 LLM Cache (`src/common/llm_cache.py`)

**Class**: `LLMCache`

**State**:
- `self._cache: Dict[str, Tuple[Dict, float]]` - Key → (result, cached_at timestamp)
- `self._max_size: int` - Max cache entries (default 1000)
- `self._ttl: int` - TTL seconds (default 3600)

**Methods**:

- **`get(alert_text, rule_context) → Optional[Dict]`**:
  - Key: `hash(alert_text + rule_context.id)`
  - Check TTL: Nếu `now - cached_at < ttl` → return cached result
  - Ngược lại → return None

- **`set(alert_text, rule_context, result)`**:
  - Key: `hash(alert_text + rule_context.id)`
  - Store: `(result, time.time())`
  - Evict oldest nếu `len(cache) > max_size`

**Global Instance**: `_llm_cache = LLMCache()` (singleton)

**Functions**: `get_llm_cache() → LLMCache`, `clear_llm_cache()`

#### 4.5 Retry Session (`src/common/web.py`)

**Class**: `RetrySession` (extends `requests.Session`)

**Configuration**:
- `max_retries: int` (default 3)
- `backoff_factor: float` (default 0.5)
- `timeout: int` (default 10s)

**Retry Logic**:
- Retry trên: `ConnectionError`, `Timeout`, `HTTPError` (5xx, 429)
- Exponential backoff: `sleep = backoff_factor * (2 ** retry_count)`
- Max retries: 3

**Usage**: Dùng cho tất cả HTTP calls (Wazuh API, Indexer, OpenAI API, Telegram API, GeoIP API)

#### 4.6 Redaction (`src/common/redaction.py`)

**Class**: `Redactor`

**Methods**:

- **`redact(text: str) → Tuple[str, List[str]]`**:
  - Redact PII: IPs (giữ 2 octets đầu), emails, credit cards, SSNs
  - Return: `(redacted_text, redacted_items)`

**Usage**: Redact alert text trước khi gửi cho LLM (privacy compliance)

#### 4.7 Deduplication (`src/common/dedup.py`)

**Function**: `dedup_key(alert) → str`

**Key Format**: `SHA256(rule_id:agent_id:srcip:YYYY-MM-DD)[:16]`

**Purpose**: Generate deterministic key để deduplicate alerts trong cùng ngày (local timezone)

**Usage**: (Hiện tại chưa được dùng trong pipeline chính, có thể tích hợp vào notify để tránh spam)

---

## 🔄 DATA FLOW & STATE MANAGEMENT

### Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Wazuh Indexer (OpenSearch)                   │
│                    Index: wazuh-alerts-*                        │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP POST /_search
                             │ Query: SOC two-tier filter + cursor
                             │
                ┌────────────▼────────────┐
                │   WazuhClient.fetch_alerts()                     │
                │   - Load cursor from file                        │
                │   - Build query (two-tier filter)                │
                │   - Fetch batch (page_size=200)                  │
                │   - Normalize each alert                        │
                │   - Update & save cursor                        │
                └────────────┬────────────┘
                             │ List[AlertNormalized]
                             │
                ┌────────────▼────────────┐
                │   For each alert:                                │
                │   1. enrich_alert()                             │
                │      → alert["enrichment"]                       │
                │   2. correlate_alert()                          │
                │      → alert["correlation"]                     │
                │   3. analyze_fp_risk()                          │
                │      → alert["fp_filtering"]                    │
                │   4. run_triage()                               │
                │      → triage_result                            │
                │   5. notify()                                   │
                │      → Telegram (if score >= threshold OR critical)
                └─────────────────────────────────────────────────┘
```

### State Management

#### 1. Cursor State (File-based)

**Location**: `CURSOR_PATH` (default `/app/state/cursor.json`)

**Format**:
```json
{
  "timestamp": "2025-01-XXT10:30:45.123Z",
  "sort": [1705312245123, "001", "abc123def456"]
}
```

**Lifecycle**:
- **Load**: Khi `WazuhClient.__init__()` hoặc `fetch_alerts()` được gọi lần đầu
- **Update**: Sau mỗi batch fetch, update với timestamp và sort values của alert cuối cùng
- **Save**: `_save_cursor()` ghi vào file (sync, blocking I/O)

**Purpose**:
- **Sequential Processing**: Đảm bảo alerts được xử lý theo thứ tự thời gian
- **No Duplicates**: `search_after` cursor đảm bảo không fetch lại alerts đã xử lý
- **Resume After Restart**: Pipeline có thể restart và tiếp tục từ cursor cuối cùng

**Edge Cases**:
- **No cursor file**: Fetch từ `now - 24h` (hoặc `WAZUH_LOOKBACK_MINUTES` trong realtime mode)
- **Corrupted cursor**: Log warning, fallback về time-based cutoff
- **Very old cursor**: Dùng `max(cursor.timestamp, now - 24h)` để tránh fetch quá nhiều alerts

#### 2. Correlation State (In-Memory)

**Storage**: `AlertCorrelationEngine.alert_groups` và `self.group_metadata`

**Lifecycle**:
- **Initialize**: Khi `correlation_engine = AlertCorrelationEngine()` được tạo (singleton, global)
- **Update**: Mỗi khi `correlate_alert()` được gọi
- **Cleanup**: Tự động cleanup groups cũ hơn 2 giờ (mỗi 1 giờ check một lần)

**Persistence**: **Không persist** (in-memory only)

**Impact**:
- **Restart**: Correlation groups bị mất khi pipeline restart
- **Scale**: Nếu chạy nhiều instance → mỗi instance có correlation state riêng (không share)

**Future Improvement**: Có thể persist vào Redis/DB để share giữa instances

#### 3. LLM Cache State (In-Memory)

**Storage**: `LLMCache._cache` (Dict)

**Lifecycle**:
- **Initialize**: Khi `_llm_cache = LLMCache()` được tạo (singleton)
- **Update**: Mỗi khi LLM API call thành công
- **Eviction**: LRU eviction khi `len(cache) > max_size` (default 1000)

**Persistence**: **Không persist** (in-memory only)

**Impact**:
- **Restart**: Cache bị mất khi pipeline restart
- **Memory**: Max memory = `max_size * avg_result_size` (~100KB nếu mỗi result ~100 bytes)

**Future Improvement**: Có thể persist vào Redis để share giữa instances và survive restarts

#### 4. Deduplication State (Not Currently Used)

**Storage**: (Chưa implement)

**Future**: Có thể dùng `dedup_key()` để track alerts đã notify trong `DEDUP_WINDOW_MINUTES` (default 10 minutes)

---

## 🛡️ ERROR HANDLING & RESILIENCE

### Error Handling Strategy

**Principle**: **Never crash pipeline, always log errors, graceful degradation**

#### 1. Collector Errors

- **Indexer Connection Error**:
  - Log error với context (component, action, error message)
  - Return empty list → pipeline tiếp tục (không crash)
  - Retry logic trong `RetrySession` (max 3 retries)

- **Query Syntax Error**:
  - Log error với query payload
  - Return empty list → pipeline tiếp tục

- **Normalization Error**:
  - Log error với alert `_id`
  - Skip alert (không normalize) → tiếp tục với alert tiếp theo
  - **Không crash pipeline**

#### 2. Analyzer Errors

- **Enrichment Error**:
  - Log debug (không log error vì enrichment là optional)
  - Set `alert["enrichment"] = {}` → tiếp tục

- **Correlation Error**:
  - Log debug
  - Set `alert["correlation"] = {"is_correlated": False, "group_size": 1}` → tiếp tục

- **FP Filtering Error**:
  - Log debug
  - Set `alert["fp_filtering"] = {"fp_risk": "LOW", "fp_reason": []}` → tiếp tục

- **Heuristic Score Error**:
  - Log error
  - Return `h_score = 0.0` → tiếp tục (alert vẫn được xử lý)

- **LLM API Error**:
  - **Timeout**: Log warning, return default `{"threat_level": "medium", "confidence": 0.0}`
  - **Rate Limit**: Log warning, return default
  - **JSON Parse Error**: Log warning, return default
  - **API Key Missing**: Log warning, return default
  - **Pipeline tiếp tục** (không crash)

#### 3. Orchestrator Errors

- **Message Formatting Error**:
  - Log error với exception traceback
  - **Fallback**: Gửi simplified message (không format Markdown) → **không mất cảnh báo**

- **Telegram API Error**:
  - **Markdown Parse Error**: Retry với `parse_mode=None` (plain text)
  - **Rate Limit**: Retry với exponential backoff (trong `RetrySession`)
  - **Connection Error**: Retry (max 3 lần)
  - **Nếu vẫn fail**: Log error → **không crash pipeline** (alert đã được xử lý, chỉ fail ở notification)

#### 4. State Persistence Errors

- **Cursor Save Error**:
  - Log error
  - **Pipeline tiếp tục** (cursor sẽ được save ở lần fetch tiếp theo)

- **Cursor Load Error**:
  - Log warning
  - Fallback về time-based cutoff → pipeline tiếp tục

### Resilience Mechanisms

1. **Retry Logic**: Tất cả HTTP calls dùng `RetrySession` với exponential backoff
2. **Fallback Messages**: Nếu formatting fail → gửi simplified message
3. **Graceful Degradation**: Nếu LLM/enrichment fail → pipeline vẫn chạy với heuristic score
4. **No Silent Drops**: Mọi alert đã qua filter đều được xử lý (không bị drop ở analyzer/orchestrator)

---

## ⚡ PERFORMANCE & SCALABILITY

### Performance Characteristics

**Single-Threaded**: Pipeline chạy trên một thread (không có concurrency)

**Bottlenecks**:
1. **LLM API Calls**: Mỗi alert → 1 API call (có thể mất 1-5s)
2. **GeoIP API Calls**: Mỗi unique IP → 1 API call (cached sau lần đầu)
3. **Indexer Query**: Mỗi poll → 1 query (có thể mất 100-500ms)

**Optimizations**:
1. **LLM Caching**: Cache kết quả LLM (TTL 1h) → giảm API calls cho duplicate alerts
2. **GeoIP Caching**: Cache GeoIP results (TTL 1h) → giảm API calls cho duplicate IPs
3. **Batch Processing**: Fetch nhiều alerts một lúc (page_size=200) → giảm số query
4. **Cursor Pagination**: Dùng `search_after` thay vì offset → nhanh hơn với large datasets

### Scalability

**Vertical Scaling**: Tăng `WAZUH_PAGE_LIMIT` và `WAZUH_MAX_BATCHES` để fetch nhiều alerts hơn mỗi poll

**Horizontal Scaling**: Chạy nhiều instance với:
- **Different agents**: Mỗi instance filter theo `agent.id` khác nhau
- **Different time windows**: Mỗi instance dùng cursor riêng (không conflict)
- **Shared state**: (Future) Dùng Redis cho correlation/LLM cache để share giữa instances

**Limitations**:
- **Correlation**: In-memory → không share giữa instances
- **LLM Cache**: In-memory → không share giữa instances
- **Single-threaded**: Không thể parallelize processing trong một instance

**Future Improvements**:
- **Async/Await**: Dùng `asyncio` để parallelize LLM calls (nếu có nhiều alerts)
- **Message Queue**: Dùng RabbitMQ/Kafka để decouple collector và analyzer
- **Distributed Correlation**: Dùng Redis để share correlation state

---

## ⚙️ CONFIGURATION MANAGEMENT

### Configuration Source

**Environment Variables** (loaded via `python-dotenv` từ `.env` file)

**Loading Order**:
1. `.env` file (nếu có)
2. System environment variables (override `.env`)

### Configuration Categories

#### 1. Wazuh Connection

- `WAZUH_API_URL`: Wazuh Manager API URL (default: `http://localhost:55000`)
- `WAZUH_API_USER`: API username (default: `wazuh`)
- `WAZUH_API_PASS`: API password
- `WAZUH_API_TOKEN`: Bearer token (preferred over user/pass)
- `WAZUH_API_VERIFY_SSL`: SSL verification (True/False or cert file path)
- `WAZUH_INDEXER_URL`: Wazuh Indexer URL (OpenSearch)
- `WAZUH_INDEXER_USER`: Indexer username
- `WAZUH_INDEXER_PASS`: Indexer password
- `WAZUH_INDEXER_VERIFY_SSL`: SSL verification
- `WAZUH_ALERTS_INDEX`: Index pattern (default: `wazuh-alerts-*`)

#### 2. SOC Filtering

- `MIN_LEVEL`: Minimum rule level for Tier 1 (default: 3)
- `MAX_LEVEL`: Maximum rule level for Tier 1 (default: 7)
- `INCLUDE_RULE_IDS`: Comma-separated rule IDs (default: `"100100"`)
- `INCLUDE_RULE_ID_PREFIX`: Rule ID prefix (default: `"1001"`)
- `ALWAYS_REEVALUATE_LEVEL_GTE`: Always include level >= this (default: 7)

#### 3. Polling & Timing

- `WAZUH_POLL_INTERVAL_SEC`: Poll interval in seconds (default: 8)
- `WAZUH_REALTIME_MODE`: Enable real-time mode (default: False)
- `WAZUH_REALTIME_INTERVAL_SEC`: Real-time poll interval (default: 1.0)
- `WAZUH_LOOKBACK_MINUTES`: Lookback window for real-time mode (default: 10)
- `WAZUH_DEMO_MODE`: Demo mode (ignore cursor, use lookback) (default: False)
- `WAZUH_START_FROM_NOW`: Start from now instead of cursor (default: False)
- `WAZUH_PAGE_LIMIT`: Page size for indexer query (default: 200)
- `WAZUH_MAX_BATCHES`: Max batches per poll (default: 5)

#### 4. Correlation & Dedup

- `CORRELATION_ENABLE`: Enable correlation (default: True)
- `LOOKBACK_MINUTES_CORRELATION`: Correlation time window (default: 30)
- `DEDUP_WINDOW_MINUTES`: Deduplication window (default: 10)

#### 5. Enrichment

- `ENRICHMENT_ENABLE`: Enable enrichment (default: True)
- `GEOIP_ENABLE`: Enable GeoIP (default: True)

#### 6. LLM

- `LLM_ENABLE`: Enable LLM analysis (default: False)
- `OPENAI_API_BASE`: OpenAI API base URL (default: `https://api.openai.com/v1`)
- `OPENAI_API_KEY`: OpenAI API key
- `LLM_MODEL`: Model name (default: `gpt-4o-mini`)
- `LLM_MAX_TOKENS`: Max tokens (default: 512)
- `LLM_TIMEOUT_SEC`: Timeout seconds (default: 20)
- `LLM_CACHE_ENABLE`: Enable LLM cache (default: True)
- `LLM_CACHE_TTL_SECONDS`: Cache TTL (default: 3600)
- `LLM_CACHE_MAX_SIZE`: Max cache entries (default: 1000)

#### 7. Triage

- `TRIAGE_THRESHOLD`: Score threshold for notification (default: 0.70)
- `HEURISTIC_WEIGHT`: Heuristic weight in fusion (default: 0.6)
- `LLM_WEIGHT`: LLM weight in fusion (default: 0.4)

#### 8. Notification

- `TELEGRAM_BOT_TOKEN`: Telegram bot token
- `TELEGRAM_CHAT_ID`: Telegram chat ID

#### 9. General

- `ENV_NAME`: Environment name (default: `dev`)
- `LOG_LEVEL`: Logging level (default: `INFO`)
- `LOCAL_TIMEZONE`: Local timezone (default: `Asia/Ho_Chi_Minh`)
- `CURSOR_PATH`: Cursor file path (default: `/app/state/cursor.json`)

### Configuration Validation

**At Startup**:
- Validate Wazuh auth: Either `WAZUH_API_TOKEN` or both `WAZUH_API_USER` and `WAZUH_API_PASS` must be set
- Validate Indexer auth: Both `WAZUH_INDEXER_USER` and `WAZUH_INDEXER_PASS` must be set
- Validate Triage weights: `HEURISTIC_WEIGHT + LLM_WEIGHT == 1.0` (allow small floating point errors)

**Runtime**:
- Log warnings nếu config không hợp lý (vd: `LLM_ENABLE=True` nhưng `OPENAI_API_KEY` không set)

---

## 🔗 DEPENDENCIES & INTEGRATION POINTS

### External Dependencies

1. **Wazuh Indexer (OpenSearch)**:
   - Protocol: HTTP/HTTPS
   - Endpoint: `{WAZUH_INDEXER_URL}/{WAZUH_ALERTS_INDEX}/_search`
   - Auth: HTTP Basic Auth
   - Purpose: Source of truth cho alerts

2. **Wazuh Manager API** (Optional):
   - Protocol: HTTP/HTTPS
   - Endpoint: `{WAZUH_API_URL}/security/user/authenticate`
   - Auth: Bearer token hoặc Basic Auth
   - Purpose: Token refresh (nếu dùng token auth)

3. **OpenAI API**:
   - Protocol: HTTPS
   - Endpoint: `{OPENAI_API_BASE}/chat/completions`
   - Auth: Bearer token (`Authorization: Bearer {OPENAI_API_KEY}`)
   - Purpose: LLM analysis

4. **Telegram Bot API**:
   - Protocol: HTTPS
   - Endpoint: `https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage`
   - Auth: Token trong URL
   - Purpose: Notification delivery

5. **GeoIP API (ipapi.co)**:
   - Protocol: HTTPS
   - Endpoint: `https://ipapi.co/{ip}/json/`
   - Auth: None (free tier)
   - Purpose: IP geolocation

### Internal Dependencies

**Module Dependencies**:
```
run_pipeline.py
  ├── wazuh_client (collector)
  │     └── RetrySession (common/web)
  ├── run_triage (analyzer/triage)
  │     ├── heuristic_score (analyzer/heuristic)
  │     ├── triage_llm (analyzer/llm)
  │     │     └── LLMCache (common/llm_cache)
  │     ├── enrich_alert (common/enrichment)
  │     │     └── RetrySession (common/web)
  │     ├── correlate_alert (common/correlation)
  │     ├── analyze_fp_risk (common/fp_filtering)
  │     └── Redactor (common/redaction)
  └── notify (orchestrator/notify)
        ├── format_alert_card (common/alert_formatter)
        └── RetrySession (common/web)
```

**Shared State**:
- `correlation_engine` (singleton trong `correlation.py`)
- `_llm_cache` (singleton trong `llm_cache.py`)
- `GeoIPEnricher` (instance trong `enrichment.py`, có internal cache)

---

## 📊 MONITORING & OBSERVABILITY

### Structured Logging

**Format**: JSON logs với context fields

**Context Fields**:
- `component`: Module name (vd: `"wazuh_client"`, `"triage"`, `"llm"`, `"notify"`)
- `action`: Action name (vd: `"fetch_alerts"`, `"correlate"`, `"llm_analysis"`, `"send_telegram"`)
- `rule_id`: Rule ID (nếu có)
- `agent_id`: Agent ID (nếu có)
- `agent_name`: Agent name (nếu có)
- `score`: Triage score (nếu có)
- `threat_level`: Threat level (nếu có)

**Log Levels**:
- `DEBUG`: Detailed information (correlation details, cache hits, etc.)
- `INFO`: Important events (pipeline start, alerts processed, notifications sent)
- `WARNING`: Non-critical errors (LLM API key missing, GeoIP lookup failed)
- `ERROR`: Critical errors (indexer connection failed, normalization error)

**Example Log Entry**:
```json
{
  "timestamp": "2025-01-XXT10:30:45.123Z",
  "level": "INFO",
  "component": "triage",
  "action": "analysis_complete",
  "rule_id": "31105",
  "rule_level": 7,
  "agent_name": "webserver-001",
  "agent_id": "001",
  "score": 0.85,
  "threat_level": "high",
  "heuristic_score": 0.75,
  "llm_confidence": 0.90,
  "llm_tags": ["xss", "web_attack"],
  "message": "Triage analysis completed"
}
```

### Metrics (Future)

**Potential Metrics**:
- Alerts processed per minute
- Average processing time per alert
- LLM API latency (p50, p95, p99)
- Telegram notification success rate
- Correlation group sizes
- FP risk distribution (LOW/MEDIUM/HIGH)

**Implementation**: Có thể tích hợp Prometheus metrics exporter

---

## 🎯 SUMMARY

Pipeline này là một **single-threaded, event-driven loop** với các đặc điểm:

1. **SOC-Grade Filtering**: Two-tier filtering đảm bảo không bỏ sót cảnh báo quan trọng
2. **Resilient**: Retry logic, fallback messages, graceful degradation
3. **Observable**: Structured logging với context
4. **Configurable**: Tất cả behavior điều khiển qua environment variables
5. **No Silent Drops**: Mọi alert đã qua filter đều được xử lý và notify nếu cần

**Architecture Highlights**:
- **Collector**: SOC two-tier filtering, normalization, agent-balanced fetching
- **Analyzer**: Heuristic + LLM fusion với dynamic weighting
- **Orchestrator**: Critical override, SOC-grade Telegram formatting
- **Common**: Correlation, FP labeling, enrichment, caching, retry logic

**Scalability**: Vertical scaling (tăng page size) hoặc horizontal scaling (nhiều instances với cursor riêng)

**Future Improvements**: Async processing, message queue, distributed state (Redis)

