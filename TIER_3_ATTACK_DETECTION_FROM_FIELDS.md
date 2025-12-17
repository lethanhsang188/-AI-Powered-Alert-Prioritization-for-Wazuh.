# Tier 3: Attack Detection Từ Fields/Content

## 🎯 Mục Tiêu

**Vấn đề:** Pipeline bỏ sót alerts quan trọng (như XSS attack từ Agent 002) vì:
- Alert có `rule.id = 86601` không match với `INCLUDE_RULE_IDS = ["100100"]`
- Alert có `rule.level = 3` < `ALWAYS_REEVALUATE_LEVEL_GTE = 7`
- Nhưng alert **THỰC SỰ là tấn công** (XSS exploit)

**Giải pháp:** Thêm **Tier 3** vào query để detect attacks từ **fields/content**, không chỉ dựa vào rule IDs.

## 📊 Cấu Trúc Three-Tier Filtering

### **Tier 1: Custom Rules (Existing)**
- Level 3-7 **VÀ** rule.id trong `INCLUDE_RULE_IDS` hoặc bắt đầu với `INCLUDE_RULE_ID_PREFIX`
- Mục đích: Include custom rules đã được định nghĩa

### **Tier 2: High-Level Alerts (Existing)**
- Level >= `ALWAYS_REEVALUATE_LEVEL_GTE` (default: 7)
- Mục đích: Luôn include và re-evaluate alerts có level cao

### **Tier 3: Attack Indicators from Fields (NEW)**
- Level >= `MIN_LEVEL` (default: 3) **VÀ** có attack indicators trong fields:
  - `data.alert.category` chứa attack categories
  - `data.alert.signature` chứa attack keywords
  - `data.event_type = "alert"` (Suricata alerts)
- Mục đích: **Không bỏ sót attacks thật** dù không match rule IDs

## 🔍 Attack Indicators Được Detect

### **1. Attack Categories (data.alert.category)**

```python
attack_categories = [
    "Web Application Attack",      # ✅ XSS, SQL Injection, etc.
    "Attempted Information Leak",
    "Attempted User Privilege Gain",
    "Attempted Administrator Privilege Gain",
    "Exploit",                     # ✅ Exploits
    "Malware",
    "Trojan",
    "Virus",
    "Worm",
    "Denial of Service",
    "Network Scan",
    "Reconnaissance",
]
```

**Ví dụ Alert Agent 002:**
```json
{
  "data.alert.category": "Web Application Attack",  // ✅ Match Tier 3
  "rule.id": "86601",
  "rule.level": 3
}
```

### **2. Attack Keywords in Signature (data.alert.signature)**

```python
attack_signature_keywords = [
    "*XSS*", "*xss*", "*Cross-Site*", "*cross-site*",
    "*SQL*", "*sqli*", "*SQL Injection*", "*sql injection*",
    "*Exploit*", "*exploit*", "*L2-Exploit*",
    "*Command Injection*", "*command injection*",
    "*Path Traversal*", "*path traversal*",
    "*Remote Code Execution*", "*RCE*",
    "*File Upload*", "*file upload*",
    "*Brute Force*", "*brute force*",
    "*DoS*", "*DDoS*",
]
```

**Ví dụ Alert Agent 002:**
```json
{
  "data.alert.signature": "[L2-Exploit][XSS] DVWA xss_r/xss_d payload in URI",
  // ✅ Match "*XSS*" và "*Exploit*" → Tier 3
  "rule.id": "86601",
  "rule.level": 3
}
```

### **3. Suricata Alerts (data.event_type)**

```python
# Suricata alerts (event_type = "alert" indicates IDS/IPS detection)
attack_indicator_filters.append({
    "term": {"data.event_type": "alert"}
})
```

**Ví dụ Alert Agent 002:**
```json
{
  "data.event_type": "alert",  // ✅ Match Tier 3
  "rule.id": "86601",
  "rule.level": 3
}
```

## ✅ Kết Quả

### **Trước Khi Có Tier 3:**

```
Alert Agent 002:
- rule.id = 86601 ❌ (không match INCLUDE_RULE_IDS)
- rule.level = 3 ❌ (< ALWAYS_REEVALUATE_LEVEL_GTE = 7)
- data.alert.category = "Web Application Attack" ✅
- data.alert.signature = "[L2-Exploit][XSS] ..." ✅
- data.event_type = "alert" ✅

→ BỊ FILTER ở query → Không được fetch
```

### **Sau Khi Có Tier 3:**

```
Alert Agent 002:
- rule.id = 86601 ❌ (không match Tier 1)
- rule.level = 3 ❌ (< Tier 2 threshold)
- data.alert.category = "Web Application Attack" ✅ → Tier 3 PASS
- data.alert.signature = "[L2-Exploit][XSS] ..." ✅ → Tier 3 PASS
- data.event_type = "alert" ✅ → Tier 3 PASS

→ TIER 3 PASS → Được fetch và xử lý
```

## 📝 Query Logic

```python
# Three-tier filter
filters = [
    {
        "bool": {
            "should": [
                # Tier 1: Level 3-7 với custom rule IDs
                {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": 3, "lte": 7}}},
                            {"bool": {
                                "should": rule_id_filters,  # INCLUDE_RULE_IDS hoặc prefix
                                "minimum_should_match": 1
                            }}
                        ]
                    }
                },
                # Tier 2: Level >= 7 (always include)
                {"range": {"rule.level": {"gte": 7}}},
                # Tier 3: Attack indicators từ fields
                {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": 3}}},  # At least MIN_LEVEL
                            {
                                "bool": {
                                    "should": [
                                        {"terms": {"data.alert.category": attack_categories}},
                                        {"wildcard": {"data.alert.signature": "*XSS*"}},
                                        {"wildcard": {"data.alert.signature": "*SQL*"}},
                                        # ... more attack keywords
                                        {"term": {"data.event_type": "alert"}}
                                    ],
                                    "minimum_should_match": 1
                                }
                            }
                        ]
                    }
                }
            ],
            "minimum_should_match": 1  # Pass nếu match ít nhất 1 tier
        }
    }
]
```

## 🎯 Lợi Ích

1. **Không Bỏ Sót Attacks Thật:**
   - XSS, SQL Injection, Exploits được detect từ fields
   - Không phụ thuộc vào rule IDs cụ thể

2. **Linh Hoạt:**
   - Có thể detect attacks mới chưa có rule IDs trong config
   - Dựa trên content/signature, không chỉ rule metadata

3. **SOC-Grade:**
   - Phân tích dựa trên nhiều indicators (category, signature, event_type)
   - Giống cách SOC analyst phân tích alerts

4. **Cân Bằng:**
   - Vẫn giữ Tier 1 và Tier 2 cho custom rules và high-level alerts
   - Tier 3 chỉ bổ sung, không thay thế

## ⚠️ Lưu Ý

1. **Performance:**
   - Wildcard queries có thể chậm hơn exact match
   - Nên monitor query performance

2. **False Positives:**
   - Có thể include một số alerts không phải attacks
   - Nhưng sẽ được filter lại ở post-fetch filtering và FP filtering

3. **Maintenance:**
   - Cần cập nhật attack keywords khi có attack patterns mới
   - Có thể config qua env variables trong tương lai

## 🔧 Cấu Hình (Tương Lai)

Có thể thêm config options:

```bash
# Enable Tier 3 attack detection
TIER_3_ATTACK_DETECTION_ENABLE=true

# Custom attack categories (comma-separated)
TIER_3_ATTACK_CATEGORIES=Web Application Attack,Exploit,Malware

# Custom attack keywords (comma-separated)
TIER_3_ATTACK_KEYWORDS=XSS,SQL Injection,Exploit,RCE
```

## ✅ Kết Luận

**Tier 3** đảm bảo pipeline **không bỏ sót attacks thật** dù:
- Rule ID không match với config
- Rule level thấp (< 7)
- Nhưng có attack indicators rõ ràng trong fields

**Ví dụ:** Alert Agent 002 (XSS attack, rule 86601, level 3) giờ sẽ được fetch và xử lý nhờ Tier 3.

