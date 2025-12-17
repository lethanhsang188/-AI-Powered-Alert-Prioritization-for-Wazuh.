# 📋 Tóm Tắt Implementation: SOC-Grade Pipeline Upgrade

**Status:** 🔄 Đang triển khai  
**Ngày:** 2025-12-15

---

## ✅ ĐÃ HOÀN THÀNH

### 1. Config Mới (`src/common/config.py`)
- ✅ `SOC_MIN_LEVEL = 3`
- ✅ `SOC_MAX_LEVEL = 7`
- ✅ `INCLUDE_RULE_IDS = ["100100"]`
- ✅ `INCLUDE_RULE_ID_PREFIX = "1001"`
- ✅ `ALWAYS_REEVALUATE_LEVEL_GTE = 7`
- ✅ `LOOKBACK_MINUTES_CORRELATION = 30`
- ✅ `DEDUP_WINDOW_MINUTES = 10`

### 2. FP Filtering Module (`src/common/fp_filtering.py`)
- ✅ Module `analyze_fp_risk()` với labeling (không drop)
- ✅ Detect: internal IP + 404, benign signatures, repetition, cron patterns
- ✅ Output: fp_risk (LOW/MEDIUM/HIGH), fp_reason, noise_signals

### 3. Collector Query (`src/collector/wazuh_client.py`)
- ✅ SOC-grade filtering với 2 tiers:
  - Tier 1: Level 3-7 + rule IDs match
  - Tier 2: Level >= 7 (always include)
- ✅ Import config mới

---

## 🔄 ĐANG LÀM

### 4. Normalization Module
**File:** `src/collector/wazuh_client.py` - `_normalize_alert()`

**Cần thêm:**
- `event_id` từ `_id`
- `index` từ `_index`
- `manager.name`
- `decoder.name`
- `location`
- `full_data` (toàn bộ `_source.data`)
- `tags` suy ra từ rule.groups, data.alert.category
- `raw_json` (toàn bộ `_source`)

---

## ⏳ CHƯA LÀM

### 5. Correlation & Dedup
**Files:** `src/common/correlation.py`, `src/common/dedup.py`

**Cần cải thiện:**
- Correlation keys: (src_ip, dest_ip, signature_id) hoặc (rule.id, agent.id)
- Output: correlated_count, first_seen, last_seen, distinct_agents, sample_event_ids
- Dedup với DEDUP_WINDOW_MINUTES

### 6. LLM Prompt Update
**File:** `src/analyzer/llm.py`

**Cần:**
- Schema mới với đầy đủ fields
- Anti-hallucination rules
- Strict JSON validation

### 7. Telegram Formatter
**File:** `src/orchestrator/notify.py`

**Cần:**
- Format SOC-grade với đầy đủ fields
- Emoji severity
- Evidence bullets
- Correlation info
- Missing info

### 8. Message Mẫu
**Cần tạo:** Message Telegram mẫu từ alert giả lập

---

## 📝 NEXT STEPS

1. Hoàn thiện normalization module
2. Update LLM prompt với schema mới
3. Update Telegram formatter
4. Tạo message mẫu
5. Test end-to-end

---

## 🎯 KEY REQUIREMENTS

- ✅ Pipeline không skip alerts đã chọn
- ✅ Alert level 3-7 với rule.id=100100 phải được xử lý
- ✅ Alert level >= 7 phải được AI đánh giá lại
- ⏳ Telegram message không được hallucinate field
- ✅ False positives được kiểm soát bằng confidence + decision, không drop âm thầm

