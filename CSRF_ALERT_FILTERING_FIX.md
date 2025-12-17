`Q# CSRF Alert Filtering Fix

## 🚨 Vấn Đề

**Alert CSRF bị filter bởi field filtering:**
- Alert đã được fetch từ indexer: `raw_hits_count: 1`
- Nhưng bị filter: `field_filtered: 1`
- Kết quả: `filtered_alerts: 0`

**Alert Details:**
- Rule ID: 86601
- Rule Level: 3 (< 7 → phải check attack indicators)
- Category: "Web Application Attack"
- Signature: "[L2-Exploit][CSRF] DVWA csrf password change params (WAN pre-NAT)"
- Severity: "2" (STRING, không phải int/float)
- Event Type: "alert"
- URL: "/dvwa/vulnerabilities/csrf/?password_new=hacked123&password_conf=hacked123&Change=Change"

---

## ❌ Nguyên Nhân

### **Field Filtering Logic (Trước Fix):**

```python
if rule_level < 7:
    has_attack_indicators = (
        (suricata_alert and isinstance(suricata_alert.get("severity"), (int, float)) and suricata_alert.get("severity", 0) >= 2) or
        (http_context and http_context.get("url") and any(pattern in http_context.get("url", "").lower() for pattern in ["sqli", "xss", "union", "select", "exec", "cmd", "shell"])) or
        (http_context and http_context.get("user_agent") and any(tool in http_context.get("user_agent", "").lower() for tool in ["sqlmap", "nmap", "nikto", "burp", "metasploit"]))
    )
```

**Vấn đề:**

1. **Severity là string "2":**
   - `isinstance(suricata_alert.get("severity"), (int, float))` → **False**
   - Severity check → **False**

2. **URL không có patterns:**
   - URL: "/dvwa/vulnerabilities/csrf/..."
   - Patterns: `["sqli", "xss", "union", "select", "exec", "cmd", "shell"]`
   - **Không có "csrf"** → **False**

3. **User agent không có attack tools:**
   - User agent: "curl/8.15.0"
   - Tools: `["sqlmap", "nmap", "nikto", "burp", "metasploit"]`
   - **Không có tools** → **False**

4. **Thiếu checks:**
   - ❌ Không check category ("Web Application Attack")
   - ❌ Không check signature ("CSRF")
   - ❌ Không check event_type ("alert")

**Kết quả:** `has_attack_indicators = False` → Alert bị filter!

---

## ✅ Giải Pháp

### **Field Filtering Logic (Sau Fix):**

```python
# Helper to convert severity to int (handles string "2" -> int 2)
def _to_int_safe(value):
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except (ValueError, AttributeError):
            return 0
    return 0

# Check Suricata severity (convert string to int if needed)
suricata_severity = 0
if suricata_alert:
    severity_raw = suricata_alert.get("severity")
    suricata_severity = _to_int_safe(severity_raw)

# Check Suricata category
suricata_category = ""
if suricata_alert:
    suricata_category = (suricata_alert.get("category", "") or "").lower()

# Check Suricata signature
suricata_signature = ""
if suricata_alert:
    suricata_signature = (suricata_alert.get("signature", "") or "").lower()

# Check event_type
event_type = alert.get("event_type", "").lower()

# Check URL patterns (expanded to include CSRF and other attacks)
url_patterns = ["sqli", "xss", "union", "select", "exec", "cmd", "shell", "csrf", "cross-site", "path", "traversal", "rce", "injection"]
url_has_pattern = False
if http_context and http_context.get("url"):
    url_lower = http_context.get("url", "").lower()
    url_has_pattern = any(pattern in url_lower for pattern in url_patterns)

# Attack indicators: severity >= 2, attack category, attack signature, event_type=alert, URL patterns, or attack tools
has_attack_indicators = (
    (suricata_severity >= 2) or
    (suricata_category and any(cat in suricata_category for cat in ["web application attack", "exploit", "malware", "trojan", "virus", "worm", "dos", "network scan", "reconnaissance"])) or
    (suricata_signature and any(pattern in suricata_signature for pattern in ["xss", "sql", "sqli", "csrf", "exploit", "injection", "traversal", "rce", "command", "brute", "dos"])) or
    (event_type == "alert") or
    url_has_pattern or
    user_agent_has_tool
)
```

---

## ✅ Kết Quả

### **CSRF Alert Bây Giờ Pass:**

**Alert:**
- Severity: "2" → Converted to int 2 → `>= 2` → ✅ **True**
- Category: "Web Application Attack" → Contains "web application attack" → ✅ **True**
- Signature: "[L2-Exploit][CSRF]..." → Contains "csrf" → ✅ **True**
- Event Type: "alert" → `== "alert"` → ✅ **True**
- URL: "/dvwa/vulnerabilities/csrf/..." → Contains "csrf" → ✅ **True**

**Kết quả:** `has_attack_indicators = True` → Alert **KHÔNG bị filter**!

---

## 📊 So Sánh: Trước vs Sau

### **Trước Fix:**

```
CSRF Alert:
- Severity check: False (string "2" không phải int/float)
- URL check: False (không có "csrf" trong patterns)
- User agent check: False (không có attack tools)
- Category check: ❌ Không có
- Signature check: ❌ Không có
- Event type check: ❌ Không có
→ has_attack_indicators = False → BỊ FILTER ❌
```

### **Sau Fix:**

```
CSRF Alert:
- Severity check: True (string "2" → int 2 >= 2)
- URL check: True (URL chứa "csrf")
- Category check: True ("Web Application Attack")
- Signature check: True (chứa "csrf")
- Event type check: True ("alert")
→ has_attack_indicators = True → KHÔNG BỊ FILTER ✅
```

---

## 🔍 Test Case

### **CSRF Alert:**

```json
{
  "rule": {
    "id": "86601",
    "level": 3
  },
  "data": {
    "alert": {
      "severity": "2",
      "category": "Web Application Attack",
      "signature": "[L2-Exploit][CSRF] DVWA csrf password change params"
    },
    "event_type": "alert",
    "http": {
      "url": "/dvwa/vulnerabilities/csrf/?password_new=hacked123"
    }
  }
}
```

**Expected:**
- ✅ Severity: "2" → int 2 >= 2 → **Pass**
- ✅ Category: "Web Application Attack" → **Pass**
- ✅ Signature: Contains "csrf" → **Pass**
- ✅ Event Type: "alert" → **Pass**
- ✅ URL: Contains "csrf" → **Pass**
- ✅ **Alert KHÔNG bị filter**

---

## 📝 Cải Thiện

### **1. Severity Conversion**
- ✅ Convert string "2" → int 2
- ✅ Handle cả int, float, và string

### **2. Expanded URL Patterns**
- ✅ Thêm "csrf", "cross-site", "path", "traversal", "rce", "injection"
- ✅ Detect nhiều loại attacks hơn

### **3. Category Check**
- ✅ Check "Web Application Attack", "Exploit", "Malware", etc.
- ✅ Detect attacks từ category

### **4. Signature Check**
- ✅ Check "xss", "sql", "sqli", "csrf", "exploit", "injection", etc.
- ✅ Detect attacks từ signature

### **5. Event Type Check**
- ✅ Check `event_type == "alert"` (Suricata alerts)
- ✅ Detect IDS/IPS detections

---

## ✅ Kết Luận

**Đã fix:**
- ✅ CSRF alerts sẽ không bị filter nữa
- ✅ Field filtering giờ check đầy đủ: severity, category, signature, event_type, URL, user_agent
- ✅ Support cả string và int/float cho severity
- ✅ Expanded attack patterns (CSRF, path traversal, RCE, etc.)

**Status:** ✅ CSRF Alert Filtering đã được fix!

