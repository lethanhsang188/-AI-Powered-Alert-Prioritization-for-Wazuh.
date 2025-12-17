# ✅ Implementation: Field-Based Analysis

**Ngày:** 2025-12-15  
**Status:** ✅ Completed  
**Mục đích:** Chuyển từ rule-based filtering sang field-based analysis để giảm false negatives

---

## 🎯 CÁC THAY ĐỔI ĐÃ IMPLEMENT

### **1. Cải Thiện Query Filter (wazuh_client.py)**

**Thay đổi:**
- ✅ Thêm multi-condition filter khi `WAZUH_MIN_LEVEL >= 7`
- ✅ Include alerts có level thấp (3-6) nhưng có indicators quan trọng:
  - Suricata alerts với severity >= 2
  - Alerts với rule groups quan trọng (suricata, web_attack, ids, attack, web_scan, recon)
  - HTTP alerts (có context)
  - Flow alerts (có network context)

**Code:**
```python
# Line 384-420 in wazuh_client.py
if WAZUH_MIN_LEVEL >= 7:
    # Multi-condition filter: Include high-level alerts OR low-level alerts with important indicators
    filters = [{
        "bool": {
            "should": [
                {"range": {"rule.level": {"gte": WAZUH_MIN_LEVEL}}},  # High level
                {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": 3, "lt": WAZUH_MIN_LEVEL}}},  # Low level
                            {
                                "bool": {
                                    "should": [
                                        # Suricata severity >= 2
                                        {"exists": {"field": "data.alert.severity"}},
                                        {"range": {"data.alert.severity": {"gte": 2}}},
                                        # Important rule groups
                                        {"terms": {"rule.groups": ["suricata", "web_attack", "ids", "attack", "web_scan", "recon"]}},
                                        # HTTP context
                                        {"exists": {"field": "data.http.url"}},
                                        # Flow context
                                        {"exists": {"field": "data.flow.src_ip"}}
                                    ],
                                    "minimum_should_match": 1
                                }
                            }
                        ]
                    }
                }
            ],
            "minimum_should_match": 1
        }
    }]
```

**Lợi ích:**
- ✅ Không miss Suricata alerts quan trọng có level thấp
- ✅ Không miss web attacks có HTTP context
- ✅ Không miss network attacks có flow context

---

### **2. Field-Based Heuristic Scoring (heuristic.py)**

**Thay đổi:**
- ✅ Thêm Suricata severity bonus (independent of rule level)
- ✅ Thêm HTTP context bonuses:
  - Attack tool detection (sqlmap, nmap, etc.)
  - Suspicious status codes (200, 5xx)
  - Attack patterns in URL
- ✅ Thêm network flow bonuses:
  - Large response (data exfiltration)
  - Large request (exploitation)
- ✅ Thêm correlation bonus (attack campaigns)

**Code:**
```python
# Line 132-220 in heuristic.py

# 1. Suricata severity bonus
if suricata_alert:
    suricata_severity = suricata_alert.get("severity", 0)
    if suricata_severity >= 3:
        base_score += 0.15  # High severity
    elif suricata_severity >= 2:
        base_score += 0.10  # Medium severity
    
    if alert_action == "allowed":
        base_score += 0.10  # Attack passed firewall

# 2. HTTP context bonus
if http_context:
    # Attack tools
    if any(tool in user_agent for tool in attack_tools):
        base_score += 0.15
    
    # Status codes
    if status == "200":
        base_score += 0.10
    
    # Attack patterns in URL
    if any(pattern in url for pattern in attack_patterns):
        base_score += 0.15

# 3. Network flow bonus
if flow:
    if bytes_toclient > 10000:
        base_score += 0.10  # Large response
    
    if bytes_toserver > 5000:
        base_score += 0.05  # Large request

# 4. Correlation bonus
if correlation.get("is_correlated"):
    if group_size >= 5:
        base_score += 0.20  # Large campaign
    elif group_size >= 3:
        base_score += 0.10  # Multiple attacks
```

**Lợi ích:**
- ✅ Alerts có level thấp nhưng có indicators nguy hiểm → score cao
- ✅ Suricata alerts với severity cao → được prioritize
- ✅ Attack tools detected → bonus cao
- ✅ Attack campaigns → correlation bonus

---

### **3. Enhanced Critical Attack Detection (notify.py)**

**Thay đổi:**
- ✅ Thêm Suricata severity override
- ✅ Thêm attack tool detection override
- ✅ Thêm correlation override (attack campaigns)

**Code:**
```python
# Line 80-120 in notify.py

# NEW: Suricata severity override
if suricata_alert:
    if suricata_severity >= 3:
        if alert_action == "allowed":
            return True, "High Suricata severity with action 'allowed'"

# NEW: Attack tool detection override
if http_context:
    detected_tools = [tool for tool in attack_tools if tool in user_agent]
    if detected_tools:
        return True, f"Attack tool detected: {', '.join(detected_tools)}"

# NEW: Correlation override
if correlation.get("is_correlated") and group_size >= 5:
    return True, f"Large attack campaign: {group_size} alerts"
```

**Lợi ích:**
- ✅ Detect critical attacks dựa trên nhiều indicators
- ✅ Override threshold cho attacks có indicators nguy hiểm
- ✅ Không chỉ dựa vào rule level

---

## 📊 KẾT QUẢ MONG ĐỢI

### **Before (Rule-Based Only):**
```
Alert: Rule 100100, Level 3, Suricata severity 3, sqlmap user agent
→ Filtered out (level < 7)
→ Score: N/A
→ Notification: None
```

### **After (Field-Based):**
```
Alert: Rule 100100, Level 3, Suricata severity 3, sqlmap user agent
→ Included (Suricata severity >= 2)
→ Score: 0.75 (base 0.2 + Suricata 0.15 + tool 0.15 + group 0.10 + multiplier)
→ Critical Override: Yes (attack tool detected)
→ Notification: ✅ SENT
```

---

## 🔧 CONFIGURATION

### **Option 1: Giảm WAZUH_MIN_LEVEL (Simple)**

**`.env` file:**
```bash
WAZUH_MIN_LEVEL=3  # Include all alerts from level 3+
```

**Lợi ích:**
- ✅ Đơn giản, dễ config
- ✅ Include tất cả alerts từ level 3+

**Nhược điểm:**
- ⚠️ Có thể tăng số lượng alerts (noise)
- ⚠️ Cần improve scoring để filter noise

---

### **Option 2: Giữ WAZUH_MIN_LEVEL cao, dùng Multi-Condition Filter (Recommended)**

**`.env` file:**
```bash
WAZUH_MIN_LEVEL=7  # High level alerts
# Multi-condition filter sẽ tự động include low-level alerts với indicators
```

**Lợi ích:**
- ✅ Giữ filter strict cho high-level alerts
- ✅ Tự động include low-level alerts có indicators quan trọng
- ✅ Balance giữa false negatives và false positives

**Nhược điểm:**
- ⚠️ Query phức tạp hơn (có thể chậm hơn một chút)

---

## ⚠️ MONITORING & TUNING

### **Metrics cần monitor:**
1. **Query Performance:**
   - Thời gian query (nên < 1s)
   - Số lượng alerts fetched mỗi batch

2. **Scoring Distribution:**
   - Score của alerts có level thấp
   - Score của alerts có indicators cao

3. **False Positives/Negatives:**
   - Alerts được notify nhưng không phải attack
   - Alerts bị bỏ qua nhưng là attack thật

### **Tuning Parameters:**
- `WAZUH_MIN_LEVEL`: Điều chỉnh threshold
- Field-based bonuses: Điều chỉnh weights trong `heuristic.py`
- Critical override thresholds: Điều chỉnh trong `notify.py`

---

## 🎯 NEXT STEPS

1. ✅ **Test với real alerts:**
   - Test với alerts có level thấp nhưng có indicators cao
   - Verify scoring và notification logic

2. ✅ **Monitor performance:**
   - Query performance
   - Scoring distribution
   - False positives/negatives

3. ✅ **Tune parameters:**
   - Điều chỉnh weights dựa trên kết quả thực tế
   - Fine-tune thresholds

4. ✅ **Documentation:**
   - Update user guide
   - Document configuration options

---

## 📝 SUMMARY

**Đã implement:**
- ✅ Multi-condition query filter
- ✅ Field-based heuristic scoring
- ✅ Enhanced critical attack detection

**Lợi ích:**
- ✅ Giảm false negatives
- ✅ Detect attacks sớm hơn
- ✅ Phân tích dựa trên nhiều indicators (SOC perspective)

**Configuration:**
- ✅ Flexible: Có thể dùng `WAZUH_MIN_LEVEL=3` hoặc giữ `WAZUH_MIN_LEVEL=7` với multi-condition filter

**Status:**
- ✅ Ready for testing
- ✅ Ready for production (sau khi test và tune)

