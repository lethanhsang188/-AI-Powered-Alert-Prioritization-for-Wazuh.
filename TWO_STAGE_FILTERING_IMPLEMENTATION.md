# ✅ Implementation: Two-Stage Filtering

**Ngày:** 2025-12-15  
**Status:** ✅ Implemented  
**Mục đích:** Phân loại theo rule level, sau đó lọc lại theo field names trong JSON

---

## 🎯 ĐÃ IMPLEMENT

### **1. Classification Stage**

**Code:**
```python
def _classify_alert_by_level(self, alert: Dict[str, Any]) -> str:
    """
    Classify alert by rule level for different filtering strategies.
    
    Returns: "high" (>= 7), "medium" (5-6), or "low" (3-4)
    """
    rule_level = alert.get("rule", {}).get("level", 0)
    
    if rule_level >= 7:
        return "high"
    elif rule_level >= 5:
        return "medium"
    else:
        return "low"
```

**Kết quả:**
- ✅ Phân loại alerts thành 3 categories: high, medium, low
- ✅ Dựa trên rule level từ Wazuh JSON

---

### **2. Level-Specific Filtering**

**Code:**
```python
def _apply_level_specific_filter(self, alert: Dict[str, Any], level_class: str) -> Tuple[bool, str]:
    """
    Apply level-specific field-based filtering.
    
    - High: Check false positive indicators (Internal IP + HTTP 404)
    - Medium: Check important indicators (Suricata severity, HTTP context, rule groups)
    - Low: Strict filtering - require multiple indicators (at least 2)
    """
```

**Strategies:**

**High Level (>= 7):**
- ✅ Always process
- ✅ Filter obvious false positives: Internal IP + HTTP 404

**Medium Level (5-6):**
- ✅ Must have at least 1 indicator:
  - Suricata severity >= 2
  - HTTP context (URL exists)
  - Important rule groups (suricata, web_attack, ids, attack, web_scan, recon)

**Low Level (3-4):**
- ✅ Must have at least 2 indicators:
  - Suricata severity >= 2
  - HTTP context
  - Flow context
  - Important rule groups

---

### **3. Field-Based Filtering**

**Code:**
```python
def _apply_field_based_filter(self, alert: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Apply general field-based filtering after normalization.
    
    Checks:
    - Internal IP + HTTP 404 = False positive
    - Suricata blocked = Already mitigated
    - Attack indicators in low-level alerts
    """
```

**Filters:**
1. ✅ Internal IP + HTTP 404 → Filter (false positive)
2. ✅ Suricata blocked → Process (but note mitigated)
3. ✅ Low-level alerts without attack indicators → Filter

---

### **4. Integration vào Pipeline**

**Code:**
```python
# wazuh_client.py - _fetch_alerts_for_agent
normalized = [
    self._normalize_alert(hit.get("_source", {})) for hit in hits
]

# TWO-STAGE FILTERING
filtered_alerts = []
for alert in normalized:
    # Stage 1: Basic spam filter
    if agent_id_alert == "002" and rule_id == "100100":
        continue
    
    # Stage 2: Classification
    level_class = self._classify_alert_by_level(alert)
    
    # Stage 3: Level-specific filter
    should_process, filter_reason = self._apply_level_specific_filter(alert, level_class)
    if not should_process:
        continue
    
    # Stage 4: Field-based filter
    should_process, filter_reason = self._apply_field_based_filter(alert)
    if not should_process:
        continue
    
    # Add classification info
    alert["classification"] = {
        "level_class": level_class,
        "filter_reason": filter_reason
    }
    
    filtered_alerts.append(alert)
```

---

## 📊 WORKFLOW

```
┌─────────────────────────────────────┐
│ 1. Fetch from Indexer               │
│    - Query filter (rule level)      │
│    - Field existence checks          │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ 2. Normalize Alerts                 │
│    - Extract all fields from JSON    │
│    - Normalize to common format     │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ 3. Classification                    │
│    - High (>= 7)                     │
│    - Medium (5-6)                    │
│    - Low (3-4)                       │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ 4. Level-Specific Filtering          │
│    - High: Check false positives    │
│    - Medium: Check indicators       │
│    - Low: Require multiple indicators│
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ 5. Field-Based Filtering             │
│    - Check all field indicators     │
│    - Apply general rules             │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ 6. Triage & Analysis                │
│    - Heuristic scoring              │
│    - LLM analysis                   │
└─────────────────────────────────────┘
```

---

## 🎯 TỪ GÓC NHÌN SOC

### **Lợi ích:**

1. ✅ **Phân loại rõ ràng:**
   - High/Medium/Low levels
   - Mỗi level có filtering strategy riêng

2. ✅ **Lọc lại theo field names:**
   - Check `data.alert.severity`
   - Check `data.http.url`
   - Check `data.flow.src_ip`
   - Check rule groups
   - Check nội dung JSON

3. ✅ **Giảm False Positives:**
   - High-level alerts được lọc lại
   - Internal IP + HTTP 404 → Filter
   - Low-level alerts cần multiple indicators

4. ✅ **Transparent:**
   - Log filter reason
   - Classification info trong alert

### **Ví dụ:**

**Before:**
```
Alert: Rule 31171, Level 7, Internal IP, HTTP 404
→ High level → Include ngay
→ Process → Notify
→ SOC: False positive! (internal scan)
```

**After:**
```
Alert: Rule 31171, Level 7, Internal IP, HTTP 404
→ Classification: "high"
→ Level-specific filter: Internal IP + HTTP 404 → Filter
→ Result: Filtered (false positive)
→ SOC: ✅ Không nhận false positive
```

---

## 📝 SUMMARY

**Đã implement:**
- ✅ Classification stage (high/medium/low)
- ✅ Level-specific filtering
- ✅ Field-based filtering
- ✅ Integration vào pipeline

**Lợi ích:**
- ✅ Phân loại theo rule level
- ✅ Lọc lại theo field names trong JSON
- ✅ Giảm false positives
- ✅ Transparent filtering

**Status:**
- ✅ Ready for testing
- ✅ Ready for production (sau khi test)

