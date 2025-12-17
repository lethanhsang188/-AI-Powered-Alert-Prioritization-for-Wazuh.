# CSRF Detection Analysis

## 📊 Phân Tích Log

**Từ log được cung cấp:**
- Pipeline đang chạy real-time mode
- Cả Agent 001 và Agent 002 đều được query
- **Không có alerts nào được tìm thấy** trong khoảng thời gian này (`raw_hits_count: 0`)
- Pipeline đã xử lý **17 alerts** trước đó (`total_processed: 17`)

**Kết luận:** Log hiện tại không hiển thị CSRF attacks vì không có alerts mới trong khoảng thời gian này.

---

## ✅ CSRF Detection Status

### **1. CSRF Support trong Code**

**Đã có:**
- ✅ CSRF trong `attack_type_normalizer.py` (tags, priority: 6)
- ✅ CSRF rules trong `CRITICAL_ATTACK_RULES`: `31110`, `31111`, `100133`, `100143`
- ✅ CSRF trong LLM analysis (rule 100133/100143)
- ✅ CSRF trong alert formatter

**Thiếu:**
- ❌ CSRF **KHÔNG có** trong Tier 3 attack signature keywords
- ❌ CSRF patterns **KHÔNG có** trong attack type normalizer (signature, URL, description)

---

## 🔧 Cải Thiện Đã Thực Hiện

### **1. Thêm CSRF vào Tier 3 Attack Detection**

**File:** `src/collector/wazuh_client.py`

**Thay đổi:**
```python
attack_signature_keywords = [
    "*XSS*", "*xss*", "*Cross-Site*", "*cross-site*",
    "*SQL*", "*sqli*", "*SQL Injection*", "*sql injection*",
    "*CSRF*", "*csrf*", "*Cross-Site Request Forgery*", "*cross-site request forgery*",  # NEW
    ...
]
```

**Kết quả:**
- ✅ CSRF attacks sẽ được detect bởi Tier 3 ngay cả khi rule ID không match
- ✅ Ví dụ: Alert với signature "CSRF attempt detected" sẽ được include

---

### **2. Thêm CSRF Patterns vào Attack Type Normalizer**

**File:** `src/common/attack_type_normalizer.py`

**Thay đổi:**

**a) Signature Patterns:**
```python
# CSRF patterns
csrf_patterns = [
    r"csrf", r"cross-site.*request.*forgery", r"cross site.*request.*forgery",
    r"unauthorized.*state.*change", r"missing.*referer", r"origin.*mismatch"
]
if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in csrf_patterns):
    return "csrf"
```

**b) URL Patterns:**
```python
# CSRF in URL (less common, but possible)
if any(pattern in http_url for pattern in ["csrf", "cross-site"]):
    return "csrf"
```

**c) Description Patterns:**
```python
# CSRF
if any(keyword in rule_description for keyword in ["csrf", "cross-site request forgery", "cross site request forgery"]):
    return "csrf"
```

**Kết quả:**
- ✅ CSRF được normalize từ nhiều nguồn (signature, URL, description)
- ✅ Cùng CSRF attack từ Agent 001 và Agent 002 → cùng normalized type "csrf"

---

## 🔍 Cách Kiểm Tra CSRF Attacks

### **1. Kiểm Tra Logs**

**Tìm CSRF trong logs:**
```bash
# Tìm CSRF trong logs
grep -i "csrf" logs/*.log

# Tìm rule 31110, 31111, 100133, 100143
grep -E "(31110|31111|100133|100143)" logs/*.log

# Tìm attack_type_normalized: csrf
grep "attack_type_normalized.*csrf" logs/*.log
```

### **2. Kiểm Tra Wazuh Indexer**

**Query CSRF alerts:**
```json
{
  "query": {
    "bool": {
      "should": [
        {"term": {"rule.id": "31110"}},
        {"term": {"rule.id": "31111"}},
        {"term": {"rule.id": "100133"}},
        {"term": {"rule.id": "100143"}},
        {"wildcard": {"data.alert.signature": "*CSRF*"}},
        {"wildcard": {"data.alert.signature": "*csrf*"}},
        {"wildcard": {"data.alert.signature": "*Cross-Site Request Forgery*"}}
      ]
    }
  }
}
```

### **3. Kiểm Tra Pipeline Output**

**Khi có CSRF alert, sẽ thấy:**
```json
{
  "rule_id": "100133",
  "attack_type_normalized": "csrf",
  "correlation": {
    "is_correlated": true,
    "supply_chain": {
      "attack_types": ["csrf", "xss"]  // Nếu có multi-stage attack
    }
  }
}
```

---

## 📋 CSRF Rules Được Support

### **Wazuh Rules:**
- **31110**: CSRF (Apache accesslog)
- **31111**: CSRF (Apache accesslog)

### **Suricata Rules:**
- **100133**: CSRF Detection
- **100143**: CSRF Detection

**Tất cả đều trong `CRITICAL_ATTACK_RULES` → Always notify!**

---

## 🎯 Kết Luận

### **Trước Cải Thiện:**
- ❌ CSRF không được detect bởi Tier 3
- ❌ CSRF patterns không có trong attack type normalizer
- ⚠️ Chỉ detect CSRF nếu rule ID match (31110, 31111, 100133, 100143)

### **Sau Cải Thiện:**
- ✅ CSRF được detect bởi Tier 3 (signature keywords)
- ✅ CSRF patterns có trong attack type normalizer (signature, URL, description)
- ✅ CSRF được normalize từ nhiều nguồn
- ✅ CSRF có thể được detect ngay cả khi rule ID không match

### **Kiểm Tra Logs:**
- Log hiện tại không có CSRF attacks (không có alerts mới)
- Để kiểm tra CSRF, cần:
  1. Query Wazuh indexer với CSRF rules/signatures
  2. Chờ alerts mới và xem logs
  3. Kiểm tra `attack_type_normalized: "csrf"` trong pipeline output

---

## 📝 Test Case

### **Scenario: CSRF Attack**

**Alert mẫu:**
```json
{
  "rule": {
    "id": "100133",
    "level": 5,
    "description": "CSRF attempt detected"
  },
  "data": {
    "alert": {
      "signature": "Cross-Site Request Forgery attempt",
      "category": "Web Application Attack"
    }
  }
}
```

**Expected Result:**
- ✅ Included nhờ Tier 3 (signature: "*Cross-Site Request Forgery*")
- ✅ Normalized: `attack_type_normalized: "csrf"`
- ✅ Always notify (rule 100133 trong CRITICAL_ATTACK_RULES)
- ✅ Heuristic score: Base + CSRF bonus (priority 6 = +0.06)

---

**Status:** ✅ CSRF Detection đã được cải thiện và sẵn sàng!

