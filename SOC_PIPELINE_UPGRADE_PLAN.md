# 🎯 Kế Hoạch Nâng Cấp Pipeline SOC-Grade

**Ngày:** 2025-12-15  
**Mục tiêu:** Chuyển pipeline thành SOC-grade, nghiêm ngặt, giảm false positive tối đa nhưng không làm rơi alert quan trọng

---

## 📋 TỔNG QUAN THAY ĐỔI

### **1. Config Mới (✅ Đã hoàn thành)**

**File:** `src/common/config.py`

**Thêm các biến:**
- `SOC_MIN_LEVEL = 3` (MIN_LEVEL)
- `SOC_MAX_LEVEL = 7` (MAX_LEVEL)
- `INCLUDE_RULE_IDS = ["100100"]` (danh sách rule IDs)
- `INCLUDE_RULE_ID_PREFIX = "1001"` (prefix cho rule IDs)
- `ALWAYS_REEVALUATE_LEVEL_GTE = 7` (luôn include và re-evaluate)
- `LOOKBACK_MINUTES_CORRELATION = 30` (lookback cho correlation)
- `DEDUP_WINDOW_MINUTES = 10` (dedup window)

---

### **2. Collector Query Filtering (🔄 Đang làm)**

**File:** `src/collector/wazuh_client.py` - `_build_indexer_query()`

**Logic mới:**
```python
# Include alerts nếu:
# 1. rule.level trong [SOC_MIN_LEVEL..SOC_MAX_LEVEL] VÀ rule.id thuộc INCLUDE_RULE_IDS hoặc bắt đầu bằng INCLUDE_RULE_ID_PREFIX
# 2. HOẶC rule.level >= ALWAYS_REEVALUATE_LEVEL_GTE (luôn include)

filters = [
    {
        "bool": {
            "should": [
                # Condition 1: Level 3-7 với custom rules
                {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": SOC_MIN_LEVEL, "lte": SOC_MAX_LEVEL}}},
                            {
                                "bool": {
                                    "should": [
                                        {"terms": {"rule.id": INCLUDE_RULE_IDS}},
                                        {"prefix": {"rule.id": INCLUDE_RULE_ID_PREFIX}}
                                    ],
                                    "minimum_should_match": 1
                                }
                            }
                        ]
                    }
                },
                # Condition 2: Level >= 7 (luôn include)
                {"range": {"rule.level": {"gte": ALWAYS_REEVALUATE_LEVEL_GTE}}}
            ],
            "minimum_should_match": 1
        }
    }
]
```

---

### **3. Normalization Module (⏳ Chưa làm)**

**File:** `src/collector/wazuh_client.py` - `_normalize_alert()`

**Cải thiện:**
- Thêm `event_id` từ `_id`
- Thêm `index` từ `_index`
- Thêm `manager.name`
- Thêm `decoder.name`
- Thêm `location`
- Thêm `full_data` (toàn bộ `_source.data`)
- Chuẩn hóa network fields tốt hơn
- Thêm `tags` suy ra từ rule.groups, data.alert.category, etc.
- Giữ `raw_json` (toàn bộ `_source`)

---

### **4. FP Filtering Module (✅ Đã hoàn thành)**

**File:** `src/common/fp_filtering.py`

**Chức năng:**
- Phân tích FP risk (LOW/MEDIUM/HIGH)
- Gắn nhãn với lý do
- Không drop alerts (chỉ label)
- Detect: internal IP + 404, benign signatures, repetition, cron patterns

---

### **5. Correlation & Dedup (⏳ Chưa làm)**

**Files:** `src/common/correlation.py`, `src/common/dedup.py`

**Cải thiện:**
- Correlation keys: (src_ip, dest_ip, signature_id) hoặc (rule.id, agent.id)
- Output: correlated_count, first_seen, last_seen, distinct_agents, sample_event_ids
- Dedup với DEDUP_WINDOW_MINUTES
- Group thành incidents

---

### **6. LLM Prompt Update (⏳ Chưa làm)**

**File:** `src/analyzer/llm.py`

**Schema mới:**
```json
{
  "soc_title": string,
  "severity_score": number (0.0-1.0),
  "severity_label": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": number (0.0-1.0),
  "attack_category": string,
  "mitre": [{"tactic":string,"technique_id":string,"technique":string}],
  "what_happened": string,
  "evidence": [string],
  "ioc": {"src_ip":string|null,"dest_ip":string|null,"domain":string|null,"url":string|null,"hash":string|null},
  "triage_decision": "IGNORE|MONITOR|INVESTIGATE|ESCALATE",
  "recommended_actions": [string],
  "missing_info": [string],
  "notes": string
}
```

**Anti-hallucination rules:**
- Không được bịa user/process/CVE/exploit/payload nếu không có trong alert
- Evidence phải dạng "field=value"
- Không xác định được thì ghi "Unknown"

---

### **7. Telegram Formatter (⏳ Chưa làm)**

**File:** `src/orchestrator/notify.py`

**Format mới:**
- Header với emoji severity (🔴 HIGH, 🟠 MEDIUM, 🟡 LOW, 🟢 INFO)
- Title (soc_title)
- Scores (severity_score, confidence, fp_risk)
- Identity (time, agent, rule, index, event_id)
- Network summary (src -> dest, port, proto)
- What happened (tóm tắt factual)
- Evidence bullets (top 5)
- Correlation (correlated_count, first_seen, last_seen, impacted agents)
- Recommended actions (top 5)
- Missing info (nếu có)
- Query Discover/Kibana (nếu có)

---

## 🔄 WORKFLOW MỚI

```
1. Fetch từ Indexer
   ↓ (Query filter: level 3-7 + rule IDs OR level >= 7)
   
2. Normalize Alert
   ↓ (Extract tất cả fields, giữ raw_json)
   
3. FP Filtering
   ↓ (Label FP risk, không drop)
   
4. Correlation
   ↓ (Group related alerts)
   
5. Dedup
   ↓ (Tránh spam Telegram)
   
6. Triage (Heuristic + LLM)
   ↓ (LLM với strict schema, anti-hallucination)
   
7. Format Telegram
   ↓ (SOC-grade format)
   
8. Notify
```

---

## ✅ CHECKLIST

- [x] Thêm config mới
- [x] Tạo fp_filtering module
- [ ] Sửa collector query
- [ ] Cải thiện normalization
- [ ] Cải thiện correlation + dedup
- [ ] Update LLM prompt
- [ ] Update Telegram formatter
- [ ] Tạo message mẫu

---

## 📝 NOTES

- Pipeline KHÔNG được skip alerts đã chọn
- Alert level 3-7 với rule.id=100100 phải được xử lý
- Alert level >= 7 phải được AI đánh giá lại
- Telegram message không được hallucinate field
- False positives được kiểm soát bằng confidence + decision, không drop âm thầm

