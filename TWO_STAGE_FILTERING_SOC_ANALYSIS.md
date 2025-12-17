# 🔍 Phân Tích: Two-Stage Filtering - Góc Nhìn SOC

**Ngày:** 2025-12-15  
**Câu hỏi:** Pipeline có thể phân loại theo rule level, sau đó lọc lại theo field name trong wazuh-alerts-* và nội dung JSON không?  
**Mục đích:** Đề xuất giải pháp 2-stage filtering cho SOC

---

## 🎯 YÊU CẦU TỪ SOC

### **Workflow mong muốn:**

```
Stage 1: Phân loại theo Rule Level
  ↓
  High Level (>= 7) → Process ngay
  Medium Level (5-6) → Check indicators
  Low Level (3-4) → Check indicators
  
Stage 2: Lọc lại theo Field Names trong JSON
  ↓
  Check: data.alert.severity, data.http.url, data.flow.src_ip, etc.
  Check: Rule groups, Suricata signatures, HTTP context
  Check: Correlation indicators
  
Stage 3: Final Decision
  ↓
  Process / Notify / Suppress
```

---

## 📊 PHÂN TÍCH PIPELINE HIỆN TẠI

### **1. Query Filter (Stage 1 - Trong Indexer Query)**

**Code hiện tại:**
```python
# wazuh_client.py line 388-435
if WAZUH_MIN_LEVEL >= 7:
    filters = [{
        "bool": {
            "should": [
                # High level alerts (>= MIN_LEVEL) - always include
                {"range": {"rule.level": {"gte": WAZUH_MIN_LEVEL}}},
                # Low level alerts (3-6) but with important indicators
                {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": 3, "lt": WAZUH_MIN_LEVEL}}},
                            {
                                "bool": {
                                    "should": [
                                        # Field-based filters
                                        {"exists": {"field": "data.alert.severity"}},
                                        {"range": {"data.alert.severity": {"gte": 2}}},
                                        {"terms": {"rule.groups": ["suricata", "web_attack", ...]}},
                                        {"exists": {"field": "data.http.url"}},
                                        {"exists": {"field": "data.flow.src_ip"}}
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }]
```

**Phân tích:**
- ✅ **Đã có 2-stage filtering trong query:**
  - Stage 1: Rule level filter (>= 7 hoặc 3-6)
  - Stage 2: Field-based filter (trong query)
- ⚠️ **Nhưng:** Field-based filter chỉ áp dụng cho low-level alerts (3-6)
- ⚠️ **Vấn đề:** High-level alerts (>= 7) không được lọc lại theo field names

---

### **2. Post-Fetch Filtering (Stage 2 - Sau khi Fetch)**

**Code hiện tại:**
```python
# wazuh_client.py line 616-630
filtered_alerts = []
for alert in normalized:
    rule_id = alert.get("rule", {}).get("id")
    event_type = alert.get("event_type", "")
    agent_id_alert = alert.get("agent", {}).get("id", "")
    
    # Skip rule 100100 CHỈ cho pfSense (raw signature spam)
    if agent_id_alert == "002" and rule_id == "100100":
        continue
    
    # For pfSense (002), only accept Suricata alerts with event_type="alert"
    if agent_id_alert == "002" and event_type and event_type != "alert":
        continue
    
    filtered_alerts.append(alert)
```

**Phân tích:**
- ✅ **Đã có post-fetch filtering:**
  - Filter theo rule_id và agent_id
  - Filter theo event_type
- ⚠️ **Nhưng:** Chỉ filter spam, không filter theo field-based indicators
- ⚠️ **Thiếu:** Field-based filtering sau khi normalize

---

### **3. Triage Analysis (Stage 3 - Analysis)**

**Code hiện tại:**
```python
# triage.py line 25-313
def run(alert: Dict[str, Any]) -> Dict[str, Any]:
    # Enrich alert
    # Correlate alert
    # Extract all fields from alert
    # Heuristic score (field-based)
    # LLM analysis (field-based)
    # Fuse scores
```

**Phân tích:**
- ✅ **Đã có field-based analysis:**
  - Extract tất cả fields từ alert JSON
  - Heuristic scoring dựa trên nhiều fields
  - LLM analysis dựa trên field context
- ✅ **Đã normalize alerts:**
  - Extract từ raw JSON
  - Normalize thành common format
  - Preserve raw JSON

---

## 🚨 VẤN ĐỀ TỪ GÓC NHÌN SOC

### **1. High-Level Alerts Không Được Lọc Lại**

**Vấn đề:**
- High-level alerts (>= 7) được include ngay, không check field-based indicators
- Có thể có false positives từ high-level alerts
- SOC muốn lọc lại ngay cả high-level alerts

**Ví dụ:**
```
Alert: Rule 31171, Level 7, SQL Injection
→ High level → Include ngay
→ Nhưng: Source IP là internal, HTTP status 404, không có payload
→ Thực tế: False positive (internal scan)
→ SOC muốn: Lọc lại theo field indicators
```

---

### **2. Thiếu Post-Fetch Field-Based Filtering**

**Vấn đề:**
- Field-based filter chỉ trong query (trước khi fetch)
- Sau khi fetch và normalize, không có field-based filtering
- SOC muốn lọc lại sau khi có đầy đủ field context

**Ví dụ:**
```
Alert fetched: Rule 100100, Level 3, Suricata severity 3
→ Passed query filter (có severity >= 2)
→ Normalized: Có đầy đủ fields
→ Nhưng: HTTP status 404, no attack pattern in URL
→ Thực tế: False positive
→ SOC muốn: Lọc lại sau khi normalize
```

---

### **3. Không Có Classification Stage**

**Vấn đề:**
- Pipeline không có explicit classification stage
- SOC muốn phân loại alerts theo rule level, sau đó apply different filters

**Ví dụ:**
```
High Level (>= 7):
  → Always process
  → But check: Is source IP internal? Is HTTP status 404?
  
Medium Level (5-6):
  → Check: Suricata severity, HTTP context, rule groups
  
Low Level (3-4):
  → Check: All indicators, correlation
```

---

## ✅ ĐỀ XUẤT: TWO-STAGE FILTERING

### **Architecture:**

```
┌─────────────────────────────────────┐
│ Stage 1: Query Filter (Indexer)    │
│ - Rule level filter                 │
│ - Basic field existence checks      │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ Stage 2: Normalize & Extract        │
│ - Extract all fields from JSON      │
│ - Normalize to common format        │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ Stage 3: Classification             │
│ - Classify by rule level            │
│ - Apply level-specific filters      │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ Stage 4: Field-Based Filtering      │
│ - Check field indicators            │
│ - Apply field-based rules           │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ Stage 5: Triage & Analysis          │
│ - Heuristic scoring                 │
│ - LLM analysis                      │
└─────────────────────────────────────┘
```

---

## 🔧 IMPLEMENTATION

### **1. Thêm Classification Stage**

**Code:**
```python
# wazuh_client.py - Add after normalization
def _classify_alert_by_level(alert: Dict[str, Any]) -> str:
    """
    Classify alert by rule level for different filtering strategies.
    
    Returns: "high", "medium", "low"
    """
    rule_level = alert.get("rule", {}).get("level", 0)
    
    if rule_level >= 7:
        return "high"
    elif rule_level >= 5:
        return "medium"
    else:
        return "low"

def _apply_level_specific_filter(alert: Dict[str, Any], level_class: str) -> bool:
    """
    Apply level-specific field-based filtering.
    
    Returns: True if alert should be processed, False if should be filtered
    """
    if level_class == "high":
        # High level: Check for false positive indicators
        http_context = alert.get("http", {})
        source = alert.get("source", {})
        src_ip = source.get("ip", "") or alert.get("srcip", "")
        
        # Filter if: Internal IP + HTTP 404 (likely false positive)
        if _is_internal_ip(src_ip):
            if http_context and http_context.get("status") == "404":
                return False  # Internal scan, likely false positive
        
        # Always process high-level alerts (but can filter false positives)
        return True
    
    elif level_class == "medium":
        # Medium level: Check for important indicators
        suricata_alert = alert.get("suricata_alert", {})
        http_context = alert.get("http", {})
        rule_groups = alert.get("rule", {}).get("groups", [])
        
        # Must have at least one indicator
        has_indicators = (
            (suricata_alert and suricata_alert.get("severity", 0) >= 2) or
            (http_context and http_context.get("url")) or
            any(group in rule_groups for group in ["suricata", "web_attack", "ids", "attack"])
        )
        
        return has_indicators
    
    else:  # low
        # Low level: Strict filtering - must have multiple indicators
        suricata_alert = alert.get("suricata_alert", {})
        http_context = alert.get("http", {})
        flow = alert.get("flow", {})
        rule_groups = alert.get("rule", {}).get("groups", [])
        
        indicator_count = 0
        
        # Suricata severity >= 2
        if suricata_alert and suricata_alert.get("severity", 0) >= 2:
            indicator_count += 1
        
        # HTTP context
        if http_context and http_context.get("url"):
            indicator_count += 1
        
        # Flow context
        if flow and flow.get("src_ip"):
            indicator_count += 1
        
        # Important rule groups
        if any(group in rule_groups for group in ["suricata", "web_attack", "ids", "attack"]):
            indicator_count += 1
        
        # Need at least 2 indicators for low-level alerts
        return indicator_count >= 2
```

---

### **2. Thêm Field-Based Filtering Stage**

**Code:**
```python
# wazuh_client.py - Add after classification
def _apply_field_based_filter(alert: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Apply field-based filtering after normalization.
    
    Returns: (should_process, reason)
    """
    # Extract fields
    http_context = alert.get("http", {})
    suricata_alert = alert.get("suricata_alert", {})
    flow = alert.get("flow", {})
    source = alert.get("source", {})
    src_ip = source.get("ip", "") or alert.get("srcip", "")
    
    # Filter 1: Internal IP + HTTP 404 = Likely false positive
    if _is_internal_ip(src_ip):
        if http_context and http_context.get("status") == "404":
            return False, "Internal IP with HTTP 404 (likely false positive)"
    
    # Filter 2: No attack indicators = Likely noise
    has_attack_indicators = (
        (suricata_alert and suricata_alert.get("severity", 0) >= 2) or
        (http_context and http_context.get("url") and any(pattern in http_context.get("url", "").lower() for pattern in ["sqli", "xss", "union", "select"])) or
        (http_context and http_context.get("user_agent") and any(tool in http_context.get("user_agent", "").lower() for tool in ["sqlmap", "nmap", "nikto"]))
    )
    
    if not has_attack_indicators:
        rule_level = alert.get("rule", {}).get("level", 0)
        if rule_level < 7:
            return False, "Low-level alert without attack indicators"
    
    # Filter 3: Suricata action = "blocked" = Already mitigated
    if suricata_alert and suricata_alert.get("action") == "blocked":
        # Still process but mark as mitigated
        return True, "Suricata blocked (already mitigated)"
    
    return True, "Passed field-based filter"
```

---

### **3. Integration vào Pipeline**

**Code:**
```python
# wazuh_client.py - _fetch_alerts_for_agent
normalized = [
    self._normalize_alert(hit.get("_source", {})) for hit in hits
]

# NEW: Two-stage filtering
filtered_alerts = []
for alert in normalized:
    # Stage 1: Basic spam filter (existing)
    rule_id = alert.get("rule", {}).get("id")
    agent_id_alert = alert.get("agent", {}).get("id", "")
    
    if agent_id_alert == "002" and rule_id == "100100":
        continue
    
    # NEW: Stage 2: Classification
    level_class = _classify_alert_by_level(alert)
    
    # NEW: Stage 3: Level-specific filter
    if not _apply_level_specific_filter(alert, level_class):
        logger.debug(
            "Alert filtered by level-specific filter",
            extra={
                "rule_id": rule_id,
                "rule_level": alert.get("rule", {}).get("level", 0),
                "level_class": level_class
            }
        )
        continue
    
    # NEW: Stage 4: Field-based filter
    should_process, reason = _apply_field_based_filter(alert)
    if not should_process:
        logger.debug(
            "Alert filtered by field-based filter",
            extra={
                "rule_id": rule_id,
                "reason": reason
            }
        )
        continue
    
    # Add classification info to alert
    alert["classification"] = {
        "level_class": level_class,
        "filter_reason": reason
    }
    
    filtered_alerts.append(alert)
```

---

## 📊 KẾT QUẢ MONG ĐỢI

### **Before (Single-Stage):**
```
Alert: Rule 31171, Level 7, Internal IP, HTTP 404
→ High level → Include ngay
→ Process → Score 0.6 → Notify
→ SOC: False positive! (internal scan)
```

### **After (Two-Stage):**
```
Alert: Rule 31171, Level 7, Internal IP, HTTP 404
→ High level → Classification: "high"
→ Level-specific filter: Check indicators
  → Internal IP + HTTP 404 → Filter out
→ Result: Filtered (false positive)
→ SOC: ✅ Không nhận false positive
```

---

## 🎯 TỪ GÓC NHÌN SOC

### **Lợi ích:**
1. ✅ **Giảm False Positives:**
   - High-level alerts được lọc lại
   - Field-based filtering sau khi normalize
   
2. ✅ **Tăng Precision:**
   - Level-specific filtering strategies
   - Multiple indicators required for low-level alerts
   
3. ✅ **Flexible:**
   - Có thể tune filters cho từng level
   - Có thể add/remove filter rules dễ dàng

4. ✅ **Transparent:**
   - Log filter reason
   - SOC biết tại sao alert bị filter

### **Considerations:**
1. ⚠️ **Performance:**
   - Additional filtering stages
   - Cần monitor performance impact
   
2. ⚠️ **False Negatives:**
   - Strict filtering có thể miss real attacks
   - Cần tune carefully

---

## 📝 SUMMARY

**Pipeline hiện tại:**
- ✅ Đã có field-based filtering trong query
- ✅ Đã có post-fetch filtering (spam)
- ⚠️ Thiếu classification stage
- ⚠️ Thiếu field-based filtering sau normalize

**Đề xuất:**
- ✅ Thêm classification stage (high/medium/low)
- ✅ Thêm level-specific filtering
- ✅ Thêm field-based filtering sau normalize
- ✅ Log filter reasons

**Status:**
- 📋 Ready for implementation
- 📋 Cần test và tune

