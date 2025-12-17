# 🔍 Ví Dụ: SYN DoS Attack với Rule Level 3 - Pipeline Processing

**Ngày:** 2025-12-15  
**Scenario:** SYN DoS attack với rule level 3  
**Mục đích:** Giải thích chi tiết cách pipeline xử lý attack có level thấp

---

## 🎯 SCENARIO: SYN DoS Attack

### **Attack Details:**
- **Attack Type:** SYN Flood (TCP SYN DoS)
- **Rule ID:** 100142 (hoặc rule tương tự)
- **Rule Level:** 3 (LOW)
- **Source IP:** 203.0.113.50 (External attacker)
- **Destination IP:** 192.168.20.125 (WebServer)
- **Protocol:** TCP
- **Port:** 80

---

## 📊 WAZUH ALERT JSON (Raw từ wazuh-alerts-*)

### **Alert JSON Structure:**

```json
{
  "@timestamp": "2025-12-15T10:30:15.123Z",
  "agent": {
    "id": "001",
    "name": "WebServer",
    "ip": "192.168.20.125"
  },
  "rule": {
    "id": "100142",
    "level": 3,
    "description": "Suricata: Multiple SYN packets from same source (possible SYN flood)",
    "groups": ["attack", "invalid_access", "suricata"]
  },
  "data": {
    "src_ip": "203.0.113.50",
    "src_port": 54321,
    "dest_ip": "192.168.20.125",
    "dest_port": 80,
    "proto": "TCP",
    "app_proto": "http",
    "direction": "to_server",
    "flow": {
      "src_ip": "203.0.113.50",
      "src_port": 54321,
      "dest_ip": "192.168.20.125",
      "dest_port": 80,
      "pkts_toserver": 1000,
      "pkts_toclient": 0,
      "bytes_toserver": 60000,
      "bytes_toclient": 0,
      "direction": "to_server"
    },
    "alert": {
      "action": "allowed",
      "gid": 1,
      "signature_id": 2200004,
      "signature": "ET POLICY Possible SYN flood",
      "category": "Potential Corporate Privacy Violation",
      "severity": 3
    },
    "event_type": "alert"
  },
  "location": "/var/log/suricata/eve.json",
  "message": "Suricata: Multiple SYN packets from same source (possible SYN flood)"
}
```

---

## 🔄 PIPELINE PROCESSING WORKFLOW

### **Stage 1: Query Filter (Indexer Query)**

**Code:** `wazuh_client.py` - `_build_indexer_query()`

**Query Logic:**
```python
# WAZUH_MIN_LEVEL = 7 (default)
if WAZUH_MIN_LEVEL >= 7:
    filters = [{
        "bool": {
            "should": [
                # High level alerts (>= 7) - NOT MATCH (rule level = 3)
                {"range": {"rule.level": {"gte": 7}}},
                
                # Low level alerts (3-6) but with important indicators
                {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": 3, "lt": 7}}},  # ✅ MATCH (3 >= 3 and 3 < 7)
                            {
                                "bool": {
                                    "should": [
                                        # Suricata alerts with severity >= 2
                                        {
                                            "bool": {
                                                "must": [
                                                    {"exists": {"field": "data.alert.severity"}},  # ✅ EXISTS
                                                    {"range": {"data.alert.severity": {"gte": 2}}}  # ✅ MATCH (3 >= 2)
                                                ]
                                            }
                                        },
                                        # Important rule groups
                                        {"terms": {"rule.groups": ["suricata", "web_attack", "ids", "attack", ...]}},  # ✅ MATCH ("attack" in groups)
                                        # HTTP alerts
                                        {"exists": {"field": "data.http.url"}},  # ❌ NOT EXISTS
                                        # Flow alerts
                                        {"exists": {"field": "data.flow.src_ip"}}  # ✅ EXISTS
                                    ],
                                    "minimum_should_match": 1  # ✅ MATCH (3 indicators match)
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }]
```

**Kết quả:**
- ✅ **Alert được FETCH** vì:
  - Rule level 3 nằm trong range [3, 7)
  - Có `data.alert.severity` = 3 (>= 2) ✅
  - Rule groups chứa "attack" ✅
  - Có `data.flow.src_ip` ✅
  - **Minimum 1 indicator match** → ✅ PASS

---

### **Stage 2: Normalize Alert**

**Code:** `wazuh_client.py` - `_normalize_alert()`

**Normalized Alert:**
```python
{
    "@timestamp": "2025-12-15T10:30:15.123Z",
    "@timestamp_local": "2025-12-15T17:30:15.123+07:00",
    
    "agent": {
        "id": "001",
        "name": "WebServer",
        "ip": "192.168.20.125"
    },
    
    "rule": {
        "id": "100142",
        "level": 3,
        "description": "Suricata: Multiple SYN packets from same source (possible SYN flood)",
        "groups": ["attack", "invalid_access", "suricata"]
    },
    
    # Network fields
    "src_ip": "203.0.113.50",
    "src_port": 54321,
    "dest_ip": "192.168.20.125",
    "dest_port": 80,
    "proto": "TCP",
    "app_proto": "http",
    "direction": "to_server",
    
    # Flow context
    "flow": {
        "src_ip": "203.0.113.50",
        "src_port": 54321,
        "dest_ip": "192.168.20.125",
        "dest_port": 80,
        "pkts_toserver": 1000,  # HIGH - indicates flood
        "pkts_toclient": 0,
        "bytes_toserver": 60000,  # HIGH
        "bytes_toclient": 0,
        "direction": "to_server"
    },
    
    # Suricata alert
    "suricata_alert": {
        "action": "allowed",  # ⚠️ Attack passed firewall!
        "signature_id": 2200004,
        "signature": "ET POLICY Possible SYN flood",
        "category": "Potential Corporate Privacy Violation",
        "severity": 3  # HIGH severity
    },
    
    "event_type": "alert",
    "srcip": "203.0.113.50",  # Normalized srcip
    
    # Raw JSON preserved
    "raw": { ... }
}
```

**Kết quả:**
- ✅ **Alert được normalize** với đầy đủ fields
- ✅ **Flow statistics** extracted (pkts_toserver = 1000 - HIGH!)
- ✅ **Suricata alert** extracted (severity = 3, action = "allowed")

---

### **Stage 3: Basic Spam Filter**

**Code:** `wazuh_client.py` - `_fetch_alerts_for_agent()`

**Filter Logic:**
```python
# Stage 1: Basic spam filter
rule_id = "100142"
agent_id_alert = "001"

# Skip rule 100100 CHỈ cho pfSense (agent 002)
if agent_id_alert == "002" and rule_id == "100100":
    continue  # ❌ NOT MATCH (agent 001, rule 100142)

# For pfSense (002), only accept Suricata alerts with event_type="alert"
if agent_id_alert == "002" and event_type and event_type != "alert":
    continue  # ❌ NOT MATCH (agent 001)
```

**Kết quả:**
- ✅ **Alert PASS** spam filter (không phải pfSense spam)

---

### **Stage 4: Classification by Rule Level**

**Code:** `wazuh_client.py` - `_classify_alert_by_level()`

**Classification Logic:**
```python
rule_level = 3

if rule_level >= 7:
    return "high"  # ❌ NOT MATCH
elif rule_level >= 5:
    return "medium"  # ❌ NOT MATCH
else:
    return "low"  # ✅ MATCH
```

**Kết quả:**
- ✅ **Classification: "low"** (rule level 3 < 5)

---

### **Stage 5: Level-Specific Filtering**

**Code:** `wazuh_client.py` - `_apply_level_specific_filter()`

**Filter Logic (Low Level):**
```python
level_class = "low"

# Low level: Strict filtering - must have multiple indicators
suricata_alert = {
    "severity": 3  # ✅ Indicator 1
}
http_context = None  # ❌ No HTTP context
flow = {
    "src_ip": "203.0.113.50"  # ✅ Indicator 2
}
rule_groups = ["attack", "invalid_access", "suricata"]  # ✅ Indicator 3 ("attack" in groups)

indicator_count = 0

# Suricata severity >= 2
if suricata_alert.get("severity", 0) >= 2:
    indicator_count += 1  # = 1 ✅

# HTTP context
if http_context and http_context.get("url"):
    indicator_count += 1  # = 1 (no change)

# Flow context
if flow and flow.get("src_ip"):
    indicator_count += 1  # = 2 ✅

# Important rule groups
if any(group in rule_groups for group in ["suricata", "web_attack", "ids", "attack", ...]):
    indicator_count += 1  # = 3 ✅

# Need at least 2 indicators for low-level alerts
if indicator_count >= 2:  # ✅ 3 >= 2
    return True, f"Low-level alert with {indicator_count} indicators"
```

**Kết quả:**
- ✅ **Alert PASS** level-specific filter
- ✅ **Reason:** "Low-level alert with 3 indicators"
  - Indicator 1: Suricata severity 3 (>= 2) ✅
  - Indicator 2: Flow context (src_ip exists) ✅
  - Indicator 3: Rule groups contain "attack" ✅

---

### **Stage 6: Field-Based Filtering**

**Code:** `wazuh_client.py` - `_apply_field_based_filter()`

**Filter Logic:**
```python
# Extract fields
http_context = None
suricata_alert = {
    "action": "allowed",
    "severity": 3
}
src_ip = "203.0.113.50"

# Filter 1: Internal IP + HTTP 404 = Likely false positive
if src_ip and self._is_internal_ip(src_ip):
    if http_context and http_context.get("status") == "404":
        return False, "Internal IP with HTTP 404"
# ❌ NOT MATCH (external IP, no HTTP context)

# Filter 2: Suricata action = "blocked" = Already mitigated
if suricata_alert and suricata_alert.get("action") == "blocked":
    return True, "Suricata blocked"
# ❌ NOT MATCH (action = "allowed")

# Filter 3: Check for attack indicators in low-level alerts
rule_level = 3
if rule_level < 7:
    has_attack_indicators = (
        (suricata_alert.get("severity", 0) >= 2) or  # ✅ TRUE (3 >= 2)
        (http_context and http_context.get("url") and ...) or  # ❌ FALSE
        (http_context and http_context.get("user_agent") and ...)  # ❌ FALSE
    )
    # ✅ has_attack_indicators = True (Suricata severity >= 2)
    
    if not has_attack_indicators:
        return False, "Low-level alert without attack indicators"
    # ✅ NOT REACHED (has_attack_indicators = True)

return True, "Passed field-based filter"
```

**Kết quả:**
- ✅ **Alert PASS** field-based filter
- ✅ **Reason:** "Passed field-based filter"
  - External IP (not internal) ✅
  - Suricata severity 3 >= 2 (attack indicator) ✅

---

### **Stage 7: Add Classification Info**

**Code:** `wazuh_client.py` - `_fetch_alerts_for_agent()`

**Add Info:**
```python
alert["classification"] = {
    "level_class": "low",
    "filter_reason": "Passed field-based filter"
}

filtered_alerts.append(alert)
```

**Kết quả:**
- ✅ **Alert được thêm vào filtered_alerts**
- ✅ **Classification info** được thêm vào alert

---

### **Stage 8: Triage Analysis**

**Code:** `triage.py` - `run()`

**Analysis Steps:**

#### **8.1. Enrichment (GeoIP, Threat Intel)**
```python
enrichment_data = enrich_alert(alert)
# Source IP: 203.0.113.50
# GeoIP: United States, California
# Threat Intel: Not in blacklist (new attacker)
```

#### **8.2. Correlation**
```python
correlation_info = correlate_alert(alert)
# Check for other alerts from same source IP
# If multiple SYN flood alerts → Attack campaign
```

#### **8.3. Heuristic Scoring**
**Code:** `heuristic.py` - `score()`

**Scoring Logic:**
```python
rule_level = 3
rule_id = "100142"
rule_groups = ["attack", "invalid_access", "suricata"]

# Base score from rule level
base_score = _calculate_base_score(3)  # = 3/15 = 0.2

# Field-based bonuses
suricata_alert = {
    "severity": 3,
    "action": "allowed"
}

# Suricata severity bonus
if suricata_alert.get("severity", 0) >= 3:
    base_score += 0.15  # = 0.2 + 0.15 = 0.35 ✅

# Alert action bonus (allowed = more dangerous)
if suricata_alert.get("action") == "allowed":
    base_score += 0.10  # = 0.35 + 0.10 = 0.45 ✅

# Network flow bonus
flow = {
    "pkts_toserver": 1000,  # HIGH - flood pattern
    "bytes_toserver": 60000
}
if flow.get("pkts_toserver", 0) > 100:  # 1000 > 100
    base_score += 0.10  # = 0.45 + 0.10 = 0.55 ✅

# Correlation bonus (if multiple alerts)
if correlation.get("is_correlated") and correlation.get("group_size", 1) >= 3:
    base_score += 0.10  # = 0.55 + 0.10 = 0.65 ✅

# Group-based bonus
group_bonus = _calculate_group_bonus(["attack", "invalid_access", "suricata"])
# "attack" in CRITICAL_GROUPS → bonus = 0.15
base_score += 0.15  # = 0.65 + 0.15 = 0.80 ✅

# Rule-specific multiplier
multiplier = _calculate_rule_specific_multiplier("100142", 3)
# Not in special rules → multiplier = 1.0

final_score = min(base_score * multiplier, 1.0)  # = min(0.80 * 1.0, 1.0) = 0.80
```

**Kết quả:**
- ✅ **Heuristic Score: 0.80** (HIGH!)
  - Base: 0.20 (rule level 3)
  - Suricata severity: +0.15
  - Action allowed: +0.10
  - Flow flood pattern: +0.10
  - Correlation: +0.10 (if multiple alerts)
  - Group bonus: +0.15
  - **Total: 0.80**

#### **8.4. LLM Analysis**
**Code:** `llm.py` - `triage_llm()`

**LLM Input:**
```
Rule ID: 100142, Level: 3, Groups: ['attack', 'invalid_access', 'suricata'],
Description: Suricata: Multiple SYN packets from same source (possible SYN flood),
Suricata Signature ID: 2200004, Suricata Signature: ET POLICY Possible SYN flood,
Suricata Category: Potential Corporate Privacy Violation,
Suricata Severity: 3, Suricata Action: allowed,
Network Src IP: 203.0.113.50, Network Dest IP: 192.168.20.125,
Network Src Port: 54321, Network Dest Port: 80,
Network Protocol: TCP, Network Direction: to_server,
Flow Bytes to Server: 60000, Flow Packets to Server: 1000,
Flow Bytes to Client: 0, Flow Packets to Client: 0,
Message: Suricata: Multiple SYN packets from same source (possible SYN flood),
Agent: WebServer, Src IP: 203.0.113.50
```

**LLM Output:**
```python
{
    "threat_level": "high",  # LLM recognizes SYN flood as high threat
    "confidence": 0.85,  # High confidence
    "tags": ["dos", "syn_flood", "network_attack", "wazuh_rule_medium"],
    "summary": "Suricata detected a potential SYN flood attack from external IP 203.0.113.50 targeting WebServer on port 80. The attack shows 1000 packets to server with 0 responses, indicating a classic SYN flood pattern. The attack was allowed by Suricata (not blocked), suggesting it may have passed through firewall. This is a denial-of-service attack that can exhaust server resources."
}
```

**Kết quả:**
- ✅ **Threat Level: "high"**
- ✅ **LLM Confidence: 0.85**
- ✅ **Tags: ["dos", "syn_flood", "network_attack"]**
- ✅ **Summary:** Mô tả chi tiết SYN flood attack

#### **8.5. Fuse Scores**
**Code:** `triage.py` - `run()`

**Fusion Logic:**
```python
heuristic_score = 0.80
llm_confidence = 0.85
threat_level = "high"

# Dynamic weighting (LLM confidence > 0.8 → increase LLM weight)
effective_h_weight = 0.5  # Reduced from 0.6
effective_l_weight = 0.5  # Increased from 0.4

# Fuse scores
fused_score = (0.5 * 0.80) + (0.5 * 0.85)  # = 0.40 + 0.425 = 0.825

# Threat level adjustment
threat_adjustment = THREAT_LEVEL_ADJUSTMENTS.get("high", 0.05)  # = 0.05
final_score = fused_score + threat_adjustment  # = 0.825 + 0.05 = 0.875

# Clamp to [0, 1]
final_score = min(0.875, 1.0)  # = 0.875
```

**Kết quả:**
- ✅ **Final Score: 0.875** (VERY HIGH!)
- ✅ **Threat Level: "high"**

---

### **Stage 9: Critical Attack Override Check**

**Code:** `notify.py` - `should_notify_critical_attack()`

**Override Logic:**
```python
rule_id = "100142"
rule_level = 3
tags = ["dos", "syn_flood", "network_attack"]
threat_level = "high"
suricata_alert = {
    "severity": 3,
    "action": "allowed"
}

# Rule-based override
if rule_id in CRITICAL_ATTACK_RULES:
    return True, "Critical attack rule"
# ❌ NOT MATCH (100142 not in list)

# Tag-based override
critical_tags_found = [tag for tag in tags if tag in CRITICAL_ATTACK_TAGS]
# ❌ NOT MATCH (no tags in CRITICAL_ATTACK_TAGS)

# Rule level override
if rule_level >= 12:
    return True, "High rule level"
# ❌ NOT MATCH (3 < 12)

# Suricata severity override
if suricata_alert.get("severity", 0) >= 3:
    if suricata_alert.get("action") == "allowed":
        return True, "High Suricata severity 3 with action 'allowed' (attack passed firewall)"  # ✅ MATCH!
```

**Kết quả:**
- ✅ **Critical Override: TRUE**
- ✅ **Reason:** "High Suricata severity 3 with action 'allowed' (attack passed firewall)"
- ✅ **Threat Level:** Override to "HIGH" (thay vì "MEDIUM")

---

### **Stage 10: Notification Decision**

**Code:** `notify.py` - `notify()`

**Decision Logic:**
```python
score = 0.875
TRIAGE_THRESHOLD = 0.70
is_critical_override = True

# Check threshold
if score < TRIAGE_THRESHOLD:  # 0.875 >= 0.70
    # Not reached
else:
    # Score is above threshold - normal notification
    if is_critical_override:
        logger.info("Critical attack detected (score above threshold)")
        # Continue to notify
```

**Kết quả:**
- ✅ **Score 0.875 >= 0.70** → **NOTIFY**
- ✅ **Critical Override:** TRUE → **NOTIFY với HIGH priority**

---

### **Stage 11: Format Telegram Message**

**Code:** `notify.py` - `_format_telegram_message()`

**Message Format:**
```
🚨 *CRITICAL ATTACK OVERRIDE* 🚨
*Reason:* High Suricata severity 3 with action 'allowed' (attack passed firewall)
*Score:* 0.875 (above threshold 0.7, critical attack)

🟠 *SOC Alert - HIGH*

*Title:* SYN Flood attack on WebServer

*Score:* 0.875
*Rule ID:* 100142 (Level 3)
*Agent:* WebServer

*Tags:* dos, syn_flood, network_attack, wazuh_rule_medium

*Summary:*
Suricata detected a potential SYN flood attack from external IP 203.0.113.50 targeting WebServer on port 80. The attack shows 1000 packets to server with 0 responses, indicating a classic SYN flood pattern. The attack was allowed by Suricata (not blocked), suggesting it may have passed through firewall. This is a denial-of-service attack that can exhaust server resources.

*Network Information:*
Source IP: 203.0.113.50:54321 (United States, California)
Destination IP: 192.168.20.125:80 (WebServer)
Protocol: TCP
Direction: to_server

*Flow Statistics:*
Packets to Server: 1000 (HIGH - flood pattern)
Bytes to Server: 60000
Packets to Client: 0 (no responses - SYN flood pattern)

*Suricata Alert:*
Signature: ET POLICY Possible SYN flood
Severity: 3 (HIGH)
Action: allowed ⚠️ (attack passed firewall)
Category: Potential Corporate Privacy Violation

*Recommended Actions:*
1. Review alert details in Wazuh dashboard
2. Investigate source IP: 203.0.113.50
3. Check for related alerts from same source
4. Consider blocking source IP 203.0.113.50 at firewall
5. Monitor server resources (CPU, memory, connection pool)
6. Check for other SYN flood alerts in time window
```

**Kết quả:**
- ✅ **Message được format** với đầy đủ thông tin
- ✅ **Critical Override** được highlight
- ✅ **Flow statistics** được hiển thị (1000 packets - flood pattern)
- ✅ **Suricata action "allowed"** được warning

---

## ✅ KẾT QUẢ CUỐI CÙNG

### **Pipeline Processing Summary:**

| Stage | Status | Reason |
|-------|--------|--------|
| **1. Query Filter** | ✅ PASS | Rule level 3 + Suricata severity 3 + rule groups "attack" + flow context |
| **2. Normalize** | ✅ PASS | All fields extracted successfully |
| **3. Spam Filter** | ✅ PASS | Not pfSense spam |
| **4. Classification** | ✅ LOW | Rule level 3 < 5 |
| **5. Level-Specific Filter** | ✅ PASS | 3 indicators (severity, flow, rule groups) |
| **6. Field-Based Filter** | ✅ PASS | External IP + Suricata severity >= 2 |
| **7. Triage Analysis** | ✅ PASS | Score 0.875, Threat "high" |
| **8. Critical Override** | ✅ YES | Suricata severity 3 + action "allowed" |
| **9. Notification** | ✅ SENT | Score 0.875 >= 0.70 + Critical override |

---

## 🎯 TỪ GÓC NHÌN SOC

### **Pipeline CÓ THỂ phát hiện SYN DoS với Rule Level 3 vì:**

1. ✅ **Query Filter:**
   - Không chỉ filter theo rule level
   - Check field indicators: Suricata severity, rule groups, flow context
   - Rule level 3 + indicators → **ĐƯỢC FETCH**

2. ✅ **Two-Stage Filtering:**
   - Classification: "low" level
   - Level-specific filter: Require multiple indicators
   - Field-based filter: Check attack indicators
   - **3 indicators match** → **PASS**

3. ✅ **Field-Based Scoring:**
   - Suricata severity 3 → +0.15 bonus
   - Action "allowed" → +0.10 bonus
   - Flow flood pattern (1000 packets) → +0.10 bonus
   - Rule groups "attack" → +0.15 bonus
   - **Final score: 0.875** (HIGH!)

4. ✅ **Critical Override:**
   - Suricata severity 3 + action "allowed" → **Critical override**
   - Threat level → **HIGH**
   - **NOTIFY** regardless of threshold

---

## 📊 SO SÁNH: Before vs After

### **Before (Chỉ filter theo rule level):**
```
Alert: Rule 100142, Level 3, SYN Flood
→ Query: rule.level >= 7? NO (3 < 7)
→ Result: ❌ NOT FETCHED
→ SOC: ❌ Không biết có SYN flood attack!
```

### **After (Field-based + Two-stage filtering):**
```
Alert: Rule 100142, Level 3, SYN Flood
→ Query: rule.level 3-6 AND indicators? YES ✅
  - Suricata severity 3 >= 2 ✅
  - Rule groups contain "attack" ✅
  - Flow context exists ✅
→ Fetch: ✅ INCLUDED
→ Classification: "low"
→ Level-specific filter: 3 indicators → ✅ PASS
→ Field-based filter: External IP + severity >= 2 → ✅ PASS
→ Triage: Score 0.875, Threat "high" → ✅ HIGH
→ Critical Override: Suricata severity 3 + "allowed" → ✅ YES
→ Notification: ✅ SENT với HIGH priority
→ SOC: ✅ Biết có SYN flood attack ngay lập tức!
```

---

## 🎯 KẾT LUẬN

### **Pipeline CÓ THỂ phát hiện SYN DoS với Rule Level 3 vì:**

1. ✅ **Field-based query filter** - Không chỉ dựa vào rule level
2. ✅ **Two-stage filtering** - Classification + field-based filtering
3. ✅ **Field-based scoring** - Bonuses cho indicators quan trọng
4. ✅ **Critical override** - Suricata severity + action override

### **Key Indicators cho SYN DoS:**

- ✅ **Suricata severity >= 2** (trong case này = 3)
- ✅ **Rule groups contain "attack"**
- ✅ **Flow context** (pkts_toserver HIGH, pkts_toclient = 0)
- ✅ **Suricata action = "allowed"** (attack passed firewall)

### **SOC Perspective:**

- ✅ **Pipeline phát hiện được** SYN DoS với rule level 3
- ✅ **Score cao** (0.875) do field-based bonuses
- ✅ **Critical override** → Notify với HIGH priority
- ✅ **Đầy đủ thông tin** để investigate (Source IP, flow stats, Suricata details)

---

## 📝 SUMMARY

**Câu trả lời:** ✅ **CÓ**, pipeline sau khi chỉnh sửa **CÓ THỂ phát hiện** SYN DoS attack với rule level 3 thông qua:

1. Field-based query filtering
2. Two-stage filtering (classification + field-based)
3. Field-based scoring với bonuses
4. Critical override logic

**Pipeline không bỏ sót** SYN DoS attack chỉ vì rule level thấp!

