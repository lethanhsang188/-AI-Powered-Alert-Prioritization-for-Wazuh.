# 🔍 Đề Xuất: Field-Based Analysis Thay Vì Rule-Based Filtering

**Ngày:** 2025-12-15  
**Vấn đề:** Pipeline filter theo `rule.level >= 7` quá strict, bỏ qua các alerts quan trọng có level thấp  
**Mục tiêu:** Phân tích dựa trên nhiều field indicators thay vì chỉ rule_id và rule_level

---

## 🚨 VẤN ĐỀ HIỆN TẠI

### **1. Rule Level Filter Quá Strict**

**Code hiện tại:**
```python
# wazuh_client.py line 384-386
filters: List[Dict[str, Any]] = [
    {"range": {"rule.level": {"gte": WAZUH_MIN_LEVEL}}}  # Default: 7
]
```

**Vấn đề:**
- ❌ Alerts có `rule.level < 7` bị **bỏ qua hoàn toàn**
- ❌ Một số tấn công có level thấp nhưng **thực tế rất nguy hiểm**:
  - Rule 100100 (Level 3): Suricata raw signature - có thể là attack quan trọng
  - Rule với level 5-6: Có thể là reconnaissance hoặc early-stage attacks
  - Multiple low-level alerts từ cùng source = **attack campaign**

**Ví dụ False Negative:**
```
Alert 1: Rule 100100, Level 3, Suricata signature "HTTP Response excessive header"
Alert 2: Rule 100100, Level 3, Suricata signature "Suspicious User-Agent"
Alert 3: Rule 100100, Level 3, Suricata signature "SQL Injection Pattern"

→ Pipeline BỎ QUA tất cả vì level < 7
→ Nhưng thực tế: 3 alerts từ cùng IP = Attack campaign!
```

---

## 🎯 GIẢI PHÁP: FIELD-BASED ANALYSIS

### **Từ Góc Nhìn SOC:**

SOC không chỉ nhìn vào **rule level**, mà phân tích dựa trên **nhiều indicators**:

1. **Network Flow Patterns:**
   - Bytes/packets to server vs client
   - Direction (inbound/outbound)
   - Flow statistics anomalies

2. **HTTP Context:**
   - Status codes (200 = success, 302 = redirect, 4xx/5xx = errors)
   - User agents (sqlmap, nmap, etc.)
   - URL patterns (sqli, xss, etc.)
   - Redirect patterns

3. **Suricata Alert Context:**
   - Signature severity (khác với rule level!)
   - Alert action (allowed vs blocked)
   - Signature category

4. **Correlation Indicators:**
   - Multiple alerts từ cùng source IP
   - Same attack pattern trong time window
   - Frequency-based detection

5. **Rule Groups:**
   - `suricata`, `web_attack`, `ids` groups
   - `attack`, `sql_injection` groups

---

## 📋 ĐỀ XUẤT THAY ĐỔI

### **1. Giảm Strict Filter - Thêm Field-Based Filters**

**Thay đổi query filter:**

```python
# THAY VÌ:
filters = [{"range": {"rule.level": {"gte": 7}}}]

# NÊN LÀ:
filters = [
    # Option 1: Giảm threshold xuống 3 (bao gồm Suricata alerts)
    {"range": {"rule.level": {"gte": 3}}},
    
    # HOẶC Option 2: Multi-condition filter (RECOMMENDED)
    {
        "bool": {
            "should": [
                # High level alerts (>= 7) - luôn include
                {"range": {"rule.level": {"gte": 7}}},
                
                # Low level alerts (3-6) nhưng có indicators quan trọng
                {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": 3, "lt": 7}}},
                            {
                                "bool": {
                                    "should": [
                                        # Suricata alerts với severity >= 2
                                        {
                                            "bool": {
                                                "must": [
                                                    {"exists": {"field": "data.alert.severity"}},
                                                    {"range": {"data.alert.severity": {"gte": 2}}}
                                                ]
                                            }
                                        },
                                        # Rule groups quan trọng
                                        {"terms": {"rule.groups": ["suricata", "web_attack", "ids", "attack"]}},
                                        # HTTP alerts (có context)
                                        {"exists": {"field": "data.http.url"}},
                                        # Flow alerts (có network context)
                                        {"exists": {"field": "data.flow.src_ip"}}
                                    ]
                                }
                            }
                        ]
                    }
                }
            ],
            "minimum_should_match": 1
        }
    }
]
```

**Lợi ích:**
- ✅ Include high-level alerts (>= 7) như cũ
- ✅ Include low-level alerts (3-6) nhưng có indicators quan trọng
- ✅ Không miss Suricata alerts quan trọng
- ✅ Không miss web attacks có HTTP context

---

### **2. Cải Thiện Heuristic Scoring - Field-Based**

**Thêm field-based scoring:**

```python
def score(alert: Dict[str, Any]) -> float:
    """
    Calculate heuristic score based on MULTIPLE indicators.
    """
    rule = alert.get("rule", {})
    rule_level = rule.get("level", 0)
    rule_id = str(rule.get("id", ""))
    rule_groups = rule.get("groups", [])
    
    # Base score từ rule level
    base_score = _calculate_base_score(rule_level)
    
    # Field-based bonuses
    
    # 1. Suricata severity bonus (nếu có)
    suricata_alert = alert.get("suricata_alert", {})
    if suricata_alert:
        suricata_severity = suricata_alert.get("severity", 0)
        if suricata_severity >= 3:
            base_score += 0.15  # High severity Suricata alert
        elif suricata_severity >= 2:
            base_score += 0.10  # Medium severity
    
    # 2. Alert action bonus (allowed = more dangerous)
    alert_action = suricata_alert.get("action", "")
    if alert_action == "allowed":
        base_score += 0.10  # Attack passed through firewall
    
    # 3. HTTP context bonus
    http_context = alert.get("http", {})
    if http_context:
        # Suspicious user agents
        user_agent = http_context.get("user_agent", "").lower()
        if any(tool in user_agent for tool in ["sqlmap", "nmap", "nikto", "burp"]):
            base_score += 0.15  # Attack tool detected
        
        # Suspicious status codes
        status = http_context.get("status", "")
        if status == "200":
            base_score += 0.10  # Successful request (possible exploitation)
        
        # Suspicious URL patterns
        url = http_context.get("url", "").lower()
        if any(pattern in url for pattern in ["sqli", "xss", "union", "select", "exec"]):
            base_score += 0.15  # Attack pattern in URL
    
    # 4. Network flow bonus
    flow = alert.get("flow", {})
    if flow:
        # High bytes/packets = potential data exfiltration
        bytes_toclient = flow.get("bytes_toclient", 0)
        if isinstance(bytes_toclient, (int, float)) and bytes_toclient > 10000:
            base_score += 0.10  # Large response (possible data exfiltration)
    
    # 5. Correlation bonus (nếu có)
    correlation = alert.get("correlation", {})
    if correlation.get("is_correlated"):
        group_size = correlation.get("group_size", 1)
        if group_size >= 5:
            base_score += 0.20  # Large attack campaign
        elif group_size >= 3:
            base_score += 0.10  # Multiple attacks from same source
    
    # Group-based bonus (existing)
    group_bonus = _calculate_group_bonus(rule_groups)
    base_score = min(base_score + group_bonus, 1.0)
    
    # Rule-specific multiplier (existing)
    multiplier = _calculate_rule_specific_multiplier(rule_id, rule_level)
    final_score = min(base_score * multiplier, 1.0)
    
    return final_score
```

**Lợi ích:**
- ✅ Alerts có level thấp nhưng có indicators nguy hiểm → score cao
- ✅ Suricata alerts với severity cao → được prioritize
- ✅ Attacks từ cùng source → correlation bonus
- ✅ Attack tools detected → bonus cao

---

### **3. Thêm Field-Based Critical Attack Detection**

**Cải thiện `should_notify_critical_attack()`:**

```python
def should_notify_critical_attack(
    alert: Dict[str, Any], triage: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Check if alert represents a critical attack based on MULTIPLE indicators.
    """
    rule = alert.get("rule", {})
    rule_id = str(rule.get("id", ""))
    rule_level = rule.get("level", 0)
    
    tags = triage.get("tags", [])
    threat_level = triage.get("threat_level", "").lower()
    
    # 1. Rule-based override (existing)
    if rule_id in CRITICAL_ATTACK_RULES:
        return True, f"Critical attack rule {rule_id} (level {rule_level})"
    
    # 2. Tag-based override (existing)
    critical_tags_found = [tag for tag in tags if tag in CRITICAL_ATTACK_TAGS]
    if critical_tags_found:
        return True, f"Critical attack tags detected: {critical_tags_found}"
    
    # 3. Rule level override (existing)
    if rule_level >= 12:
        return True, f"High rule level {rule_level} indicates critical threat"
    
    # 4. NEW: Suricata severity override
    suricata_alert = alert.get("suricata_alert", {})
    if suricata_alert:
        suricata_severity = suricata_alert.get("severity", 0)
        alert_action = suricata_alert.get("action", "")
        if suricata_severity >= 3 and alert_action == "allowed":
            return True, f"High Suricata severity {suricata_severity} with action 'allowed'"
    
    # 5. NEW: Attack tool detection override
    http_context = alert.get("http", {})
    if http_context:
        user_agent = http_context.get("user_agent", "").lower()
        if any(tool in user_agent for tool in ["sqlmap", "nmap", "nikto", "burp", "metasploit"]):
            return True, f"Attack tool detected in user agent: {user_agent[:50]}"
    
    # 6. NEW: Correlation override
    correlation = alert.get("correlation", {})
    if correlation.get("is_correlated"):
        group_size = correlation.get("group_size", 1)
        if group_size >= 5:
            return True, f"Large attack campaign detected: {group_size} alerts from same source"
    
    # 7. Threat level override (existing)
    if threat_level in ["critical", "high"]:
        llm_confidence = triage.get("llm_confidence", 0.0)
        if llm_confidence > 0.3:
            return True, f"High threat level '{threat_level}' with confidence {llm_confidence:.2f}"
    
    return False, None
```

**Lợi ích:**
- ✅ Detect critical attacks dựa trên nhiều indicators
- ✅ Không chỉ dựa vào rule level
- ✅ Override threshold cho attacks có indicators nguy hiểm

---

## 🔧 IMPLEMENTATION PLAN

### **Phase 1: Giảm Strict Filter (IMMEDIATE)**

1. ✅ Thay đổi `WAZUH_MIN_LEVEL` default từ 7 → 3
2. ✅ Hoặc implement multi-condition filter (recommended)

### **Phase 2: Field-Based Scoring (SHORT TERM)**

1. ✅ Cải thiện `heuristic.py` với field-based bonuses
2. ✅ Test với alerts có level thấp nhưng có indicators cao

### **Phase 3: Enhanced Critical Detection (SHORT TERM)**

1. ✅ Cải thiện `should_notify_critical_attack()` với field-based checks
2. ✅ Test với Suricata alerts và attack tools

### **Phase 4: Correlation Enhancement (MEDIUM TERM)**

1. ✅ Improve correlation engine để detect attack campaigns
2. ✅ Add correlation-based scoring

---

## 📊 EXPECTED RESULTS

### **Before (Rule-Based Only):**
```
Alert: Rule 100100, Level 3, Suricata severity 3, sqlmap user agent
→ Filtered out (level < 7)
→ Score: N/A (not processed)
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

## ⚠️ CONSIDERATIONS

### **Performance:**
- Multi-condition filter có thể chậm hơn
- Cần monitor query performance
- Có thể cần optimize với proper indexes

### **False Positives:**
- Include nhiều alerts hơn → có thể tăng false positives
- Cần improve scoring và filtering logic
- Cần monitor và tune thresholds

### **Configuration:**
- Cho phép user config `WAZUH_MIN_LEVEL`
- Cho phép user config field-based thresholds
- Cho phép user enable/disable field-based analysis

---

## 🎯 KẾT LUẬN

**Từ góc nhìn SOC:**
- ✅ **Không chỉ nhìn vào rule level** - cần phân tích nhiều indicators
- ✅ **Field-based analysis** giúp detect attacks sớm hơn
- ✅ **Correlation** giúp detect attack campaigns
- ✅ **Giảm false negatives** quan trọng hơn false positives

**Recommendation:**
- ✅ Implement multi-condition filter (Phase 1)
- ✅ Implement field-based scoring (Phase 2)
- ✅ Monitor và tune dựa trên kết quả thực tế

