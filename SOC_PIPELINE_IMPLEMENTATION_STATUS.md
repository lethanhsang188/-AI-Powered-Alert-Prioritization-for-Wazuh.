# 📊 SOC Pipeline Implementation Status

**Ngày:** 2025-12-15  
**Status:** 🔄 60% Complete

---

## ✅ ĐÃ HOÀN THÀNH (60%)

### 1. ✅ Config Mới (`src/common/config.py`)
**Status:** Hoàn thành

**Thêm các biến:**
```python
SOC_MIN_LEVEL = 3
SOC_MAX_LEVEL = 7
INCLUDE_RULE_IDS = ["100100"]
INCLUDE_RULE_ID_PREFIX = "1001"
ALWAYS_REEVALUATE_LEVEL_GTE = 7
LOOKBACK_MINUTES_CORRELATION = 30
DEDUP_WINDOW_MINUTES = 10
```

---

### 2. ✅ FP Filtering Module (`src/common/fp_filtering.py`)
**Status:** Hoàn thành

**Chức năng:**
- `analyze_fp_risk()` - Phân tích FP risk với labeling (không drop)
- Detect: internal IP + 404, benign signatures, repetition, cron patterns
- Output: `fp_risk` (LOW/MEDIUM/HIGH), `fp_reason`, `noise_signals`

**Usage:**
```python
from src.common.fp_filtering import analyze_fp_risk

fp_result = analyze_fp_risk(alert, correlation_info)
# Returns: {"fp_risk": "LOW", "fp_reason": [...], "allowlist_hit": False, "noise_signals": [...]}
```

---

### 3. ✅ Collector Query (`src/collector/wazuh_client.py`)
**Status:** Hoàn thành

**SOC-Grade Filtering Logic:**
```python
# Tier 1: Level 3-7 với custom rule IDs
# Tier 2: Level >= 7 (always include)
```

**Query Structure:**
- Include alerts nếu:
  1. `rule.level` trong [3..7] VÀ `rule.id` thuộc `INCLUDE_RULE_IDS` hoặc bắt đầu bằng `INCLUDE_RULE_ID_PREFIX`
  2. HOẶC `rule.level >= 7` (luôn include)

---

### 4. ✅ Normalization Module (`src/collector/wazuh_client.py`)
**Status:** Hoàn thành

**Đã thêm các fields:**
- ✅ `event_id` từ `_id`
- ✅ `index` từ `_index`
- ✅ `manager.name`
- ✅ `decoder.name`
- ✅ `location`
- ✅ `full_data` (toàn bộ `_source.data`)
- ✅ `tags` suy ra từ rule.groups, data.alert.category, signature
- ✅ `raw_json` (toàn bộ `_source`)

---

## ⏳ CẦN HOÀN THIỆN (40%)

### 5. ⏳ Correlation & Dedup
**Files:** `src/common/correlation.py`, `src/common/dedup.py`

**Cần cải thiện:**
- Correlation keys: (src_ip, dest_ip, signature_id) hoặc (rule.id, agent.id)
- Output: `correlated_count`, `first_seen`, `last_seen`, `distinct_agents`, `sample_event_ids`
- Dedup với `DEDUP_WINDOW_MINUTES`

**Code Example cần implement:**
```python
# In correlation.py
def correlate_alert_enhanced(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced correlation với lookback window.
    
    Returns:
    {
        "is_correlated": bool,
        "correlated_count": int,
        "first_seen": str,
        "last_seen": str,
        "distinct_agents": [str],
        "sample_event_ids": [str]  # Max 5
    }
    """
    # Implementation needed
    pass
```

---

### 6. ⏳ LLM Prompt Update (`src/analyzer/llm.py`)
**Status:** Cần update

**Schema mới cần implement:**
```json
{
  "soc_title": string,
  "severity_score": number (0.0-1.0),
  "severity_label": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": number (0.0-1.0),
  "attack_category": string,
  "mitre": [{"tactic":string,"technique_id":string,"technique":string}],
  "what_happened": string,
  "evidence": [string],  // Format: "field=value"
  "ioc": {
    "src_ip": string|null,
    "dest_ip": string|null,
    "domain": string|null,
    "url": string|null,
    "hash": string|null
  },
  "triage_decision": "IGNORE|MONITOR|INVESTIGATE|ESCALATE",
  "recommended_actions": [string],
  "missing_info": [string],
  "notes": string
}
```

**Anti-hallucination Rules:**
- Không được bịa user/process/CVE/exploit/payload nếu không có trong alert
- Evidence phải dạng "field=value"
- Không xác định được thì ghi "Unknown"

**Prompt Template cần update:**
```python
prompt = f"""
You are a senior SOC analyst. Analyze this alert STRICTLY based on provided fields.

CRITICAL RULES:
1. DO NOT invent fields that are not in the alert
2. Evidence MUST be in format "field=value" from actual alert data
3. If field is missing, use null or "Unknown"
4. DO NOT guess user names, process names, CVEs, exploits, or payloads

Alert Data:
{normalized_alert_fields}

Correlation Info:
{correlation_info}

FP Risk:
{fp_risk_info}

Raw JSON (truncated if > 8000 chars):
{raw_json_truncated}

Respond with STRICT JSON only:
{{
  "soc_title": "...",
  "severity_score": 0.0-1.0,
  "severity_label": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0.0-1.0,
  "attack_category": "...",
  "mitre": [...],
  "what_happened": "...",
  "evidence": ["field=value", ...],
  "ioc": {{...}},
  "triage_decision": "IGNORE|MONITOR|INVESTIGATE|ESCALATE",
  "recommended_actions": [...],
  "missing_info": [...],
  "notes": "..."
}}
"""
```

---

### 7. ⏳ Telegram Formatter (`src/orchestrator/notify.py`)
**Status:** Cần update

**Format SOC-Grade cần implement:**
```
🔴 SOC Alert - HIGH

*Title:* {soc_title}

*Scores:*
Severity: {severity_score} ({severity_label})
Confidence: {confidence}
FP Risk: {fp_risk}

*Identity:*
Time: {timestamp_local} ({timestamp_utc} UTC)
Agent: {agent_name} (ID: {agent_id}, IP: {agent_ip})
Rule: {rule_id} (Level {rule_level}) - {rule_description}
Index: {index}
Event ID: {event_id}

*Network:*
Source: {src_ip}:{src_port} -> Destination: {dest_ip}:{dest_port}
Protocol: {proto}/{app_proto}

*What Happened:*
{what_happened}

*Evidence:*
- {evidence[0]}
- {evidence[1]}
- {evidence[2]}
- {evidence[3]}
- {evidence[4]}

*Correlation:*
Correlated Count: {correlated_count}
First Seen: {first_seen}
Last Seen: {last_seen}
Impacted Agents: {distinct_agents}

*Recommended Actions:*
1. {recommended_actions[0]}
2. {recommended_actions[1]}
3. {recommended_actions[2]}
4. {recommended_actions[3]}
5. {recommended_actions[4]}

*Missing Info:*
{missing_info}

*Query:*
index={index} AND rule.id={rule_id} AND src_ip={src_ip}
```

---

### 8. ⏳ Message Mẫu
**Status:** Cần tạo

**Cần tạo:** Message Telegram mẫu từ alert sample đã cung cấp

---

## 🔄 INTEGRATION POINTS

### Tích hợp FP Filtering vào Triage:
```python
# In src/analyzer/triage.py
from src.common.fp_filtering import analyze_fp_risk

def run(alert: Dict[str, Any]) -> Dict[str, Any]:
    # ... existing code ...
    
    # FP Filtering
    fp_result = analyze_fp_risk(alert, correlation_info)
    alert["fp_filtering"] = fp_result
    
    # Pass FP context to LLM
    # ... rest of code ...
```

### Tích hợp vào Notify:
```python
# In src/orchestrator/notify.py
def notify(alert: Dict[str, Any], triage: Dict[str, Any]):
    # ... existing code ...
    
    fp_result = alert.get("fp_filtering", {})
    fp_risk = fp_result.get("fp_risk", "LOW")
    
    # Include FP risk in Telegram message
    # ... rest of code ...
```

---

## 📝 NEXT STEPS

1. ✅ Config - Done
2. ✅ FP Filtering - Done
3. ✅ Collector Query - Done
4. ✅ Normalization - Done
5. ⏳ Correlation & Dedup - Cần implement
6. ⏳ LLM Prompt - Cần update
7. ⏳ Telegram Formatter - Cần update
8. ⏳ Message Mẫu - Cần tạo

---

## 🎯 TESTING CHECKLIST

- [ ] Test query filter với rule level 3-7 + rule.id=100100
- [ ] Test query filter với rule level >= 7
- [ ] Test normalization với sample alert
- [ ] Test FP filtering với các scenarios
- [ ] Test LLM prompt với strict schema
- [ ] Test Telegram formatter với đầy đủ fields
- [ ] Test end-to-end pipeline

---

## 📚 FILES ĐÃ TẠO/SỬA

1. ✅ `src/common/config.py` - Thêm config mới
2. ✅ `src/common/fp_filtering.py` - Module mới
3. ✅ `src/collector/wazuh_client.py` - Update query + normalization
4. 📝 `SOC_PIPELINE_UPGRADE_PLAN.md` - Kế hoạch
5. 📝 `IMPLEMENTATION_SUMMARY.md` - Tóm tắt
6. 📝 `SOC_PIPELINE_IMPLEMENTATION_STATUS.md` - Status (file này)

---

## ⚠️ NOTES

- Pipeline KHÔNG được skip alerts đã chọn ✅
- Alert level 3-7 với rule.id=100100 phải được xử lý ✅
- Alert level >= 7 phải được AI đánh giá lại ⏳ (Cần update LLM)
- Telegram message không được hallucinate field ⏳ (Cần update formatter)
- False positives được kiểm soát bằng confidence + decision, không drop âm thầm ✅

