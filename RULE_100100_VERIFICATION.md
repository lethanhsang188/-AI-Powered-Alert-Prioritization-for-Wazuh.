# ✅ Verification: Rule 100100 Fetching Status

**Ngày:** 2025-12-15  
**Mục đích:** Verify xem pipeline có đang lấy alerts rule 100100 không

---

## 🔍 PHÂN TÍCH CODE

### **1. Query Filter (wazuh_client.py line 511-516)**

```python
# Filter pfSense spam: exclude rule 100100 (raw signature) ONLY for pfSense (agent 002)
must_not_filters: List[Dict[str, Any]] = []
# CHỈ suppress raw signature spam cho pfSense (002)
if agent_id == "002":
    must_not_filters.append({"term": {"rule.id": "100100"}})
```

**Phân tích:**
- ✅ **pfSense (agent 002):** Rule 100100 bị filter trong query (must_not)
- ✅ **WebServer (agent 001):** Rule 100100 **KHÔNG bị filter** → **ĐƯỢC FETCH** ✅
- ✅ **Other agents:** Rule 100100 **KHÔNG bị filter** → **ĐƯỢC FETCH** ✅

---

### **2. Post-Fetch Filter (wazuh_client.py line 614-616)**

```python
# Filter pfSense spam: exclude rule 100100 ONLY for pfSense (002), require event_type="alert" for Suricata
filtered_alerts = []
for alert in normalized:
    rule_id = alert.get("rule", {}).get("id")
    event_type = alert.get("event_type", "")
    agent_id_alert = alert.get("agent", {}).get("id", "")

    # Skip rule 100100 CHỈ cho pfSense (raw signature spam)
    if agent_id_alert == "002" and rule_id == "100100":
        continue
```

**Phân tích:**
- ✅ **pfSense (agent 002):** Rule 100100 bị skip sau khi fetch
- ✅ **WebServer (agent 001):** Rule 100100 **KHÔNG bị skip** → **ĐƯỢC PROCESS** ✅
- ✅ **Other agents:** Rule 100100 **KHÔNG bị skip** → **ĐƯỢC PROCESS** ✅

---

### **3. Field-Based Filter (wazuh_client.py line 388-435)**

**Multi-condition filter khi WAZUH_MIN_LEVEL >= 7:**
```python
if WAZUH_MIN_LEVEL >= 7:
    filters = [{
        "bool": {
            "should": [
                # High level alerts (>= MIN_LEVEL)
                {"range": {"rule.level": {"gte": WAZUH_MIN_LEVEL}}},
                # Low level alerts (3-6) but with important indicators
                {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": 3, "lt": WAZUH_MIN_LEVEL}}},
                            {
                                "bool": {
                                    "should": [
                                        # Suricata alerts with severity >= 2
                                        {"exists": {"field": "data.alert.severity"}},
                                        {"range": {"data.alert.severity": {"gte": 2}}},
                                        # Important rule groups
                                        {"terms": {"rule.groups": ["suricata", "web_attack", "ids", "attack", "web_scan", "recon"]}},
                                        # HTTP alerts (has context)
                                        {"exists": {"field": "data.http.url"}},
                                        # Flow alerts (has network context)
                                        {"exists": {"field": "data.flow.src_ip"}}
                                    ],
                                    "minimum_should_match": 1
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }]
```

**Phân tích cho Rule 100100:**
- Rule 100100 thường có:
  - `rule.level = 3` (low level)
  - `rule.groups = ["suricata", "raw"]` → **MATCH** "suricata" group ✅
  - `data.alert.severity` thường >= 2 → **MATCH** severity >= 2 ✅
  - `data.http.url` thường có → **MATCH** HTTP context ✅

**Kết luận:**
- ✅ Rule 100100 **ĐƯỢC FETCH** vì match với field-based filter (suricata group, severity, HTTP context)

---

## 📊 TEST CASES

### **Test Case 1: WebServer (agent 001) - Rule 100100**

```
Alert:
- Rule ID: 100100
- Rule Level: 3
- Agent ID: 001 (WebServer)
- Rule Groups: ["suricata", "raw"]
- Suricata Severity: 3
- HTTP URL: "/dvwa/vulnerabilities/sqli/..."

Query Filter:
- rule.level >= 7? NO (level 3)
- rule.level 3-6 AND indicators? YES ✅
  - rule.groups contains "suricata"? YES ✅
  - data.alert.severity >= 2? YES ✅
  - data.http.url exists? YES ✅
- agent_id == "002"? NO (agent 001)
- must_not rule.id == "100100"? NO (only for agent 002)

Result: ✅ INCLUDED in query

Post-Fetch Filter:
- agent_id_alert == "002" AND rule_id == "100100"? NO (agent 001)

Result: ✅ NOT SKIPPED → PROCESSED ✅
```

---

### **Test Case 2: pfSense (agent 002) - Rule 100100**

```
Alert:
- Rule ID: 100100
- Rule Level: 3
- Agent ID: 002 (pfSense)
- Rule Groups: ["suricata", "raw"]

Query Filter:
- rule.level >= 7? NO (level 3)
- rule.level 3-6 AND indicators? YES ✅
- agent_id == "002"? YES
- must_not rule.id == "100100"? YES ❌ (for agent 002)

Result: ❌ EXCLUDED in query (spam prevention)

Post-Fetch Filter:
- (Not reached - already filtered in query)

Result: ❌ NOT FETCHED (by design - spam prevention) ✅
```

---

### **Test Case 3: Other Agent (agent 003) - Rule 100100**

```
Alert:
- Rule ID: 100100
- Rule Level: 3
- Agent ID: 003
- Rule Groups: ["suricata", "raw"]
- Suricata Severity: 3
- HTTP URL: "/test/..."

Query Filter:
- rule.level >= 7? NO (level 3)
- rule.level 3-6 AND indicators? YES ✅
- agent_id == "002"? NO (agent 003)
- must_not rule.id == "100100"? NO (only for agent 002)

Result: ✅ INCLUDED in query

Post-Fetch Filter:
- agent_id_alert == "002" AND rule_id == "100100"? NO (agent 003)

Result: ✅ NOT SKIPPED → PROCESSED ✅
```

---

## ✅ KẾT LUẬN

### **Rule 100100 Fetching Status:**

| Agent | Rule 100100 Status | Reason |
|-------|-------------------|--------|
| **WebServer (001)** | ✅ **ĐƯỢC FETCH** | Không bị filter, match field-based indicators |
| **pfSense (002)** | ❌ **KHÔNG FETCH** | Bị filter để tránh spam (by design) |
| **Other Agents** | ✅ **ĐƯỢC FETCH** | Không bị filter, match field-based indicators |

### **Field-Based Filter Support:**

- ✅ Rule 100100 **ĐƯỢC FETCH** cho WebServer vì:
  - Match `rule.groups` contains "suricata" ✅
  - Match `data.alert.severity >= 2` ✅
  - Match `data.http.url` exists ✅

### **Summary:**

- ✅ **Pipeline ĐANG lấy alerts rule 100100** cho WebServer và agents khác
- ✅ Chỉ filter rule 100100 cho pfSense (agent 002) để tránh spam
- ✅ Field-based filter đảm bảo rule 100100 được include nếu có indicators quan trọng

