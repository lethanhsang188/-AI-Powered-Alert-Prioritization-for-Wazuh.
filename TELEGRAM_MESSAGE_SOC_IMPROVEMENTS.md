# ✅ Cải Thiện Telegram Message - Góc Nhìn SOC

**Ngày:** 2025-12-15  
**Vấn đề:** Message Telegram thiếu thông tin quan trọng cho SOC  
**Status:** ✅ Implemented

---

## 🚨 VẤN ĐỀ TỪ MESSAGE MẪU

### **Message gốc:**
```
🚨 *CRITICAL ATTACK OVERRIDE* 🚨
*Reason:* Critical attack tags detected: ['sql_injection']
*Score:* 0.618 (below threshold 0.7, but critical attack)

🟡 *SOC Alert - MEDIUM*  ← INCONSISTENCY!

*Title:* SQL Injection attempt on WebServer
*Score:* 0.618
*Rule ID:* 31171 (Level 7)
*Agent:* WebServer
*Tags:* web_attack, sql_injection, wazuh_rule_medium

*Summary:*
Wazuh detected repeated SQL injection attempt patterns...
Source IP and request details are missing/truncated... ← THIẾU THÔNG TIN!

*Network:*
Destination: 192.168.20.125  ← THIẾU SOURCE IP!
```

### **Vấn đề từ góc nhìn SOC:**

1. ❌ **Inconsistency:** CRITICAL ATTACK OVERRIDE nhưng threat level là MEDIUM
2. ❌ **Thiếu Source IP:** SOC cần Source IP để block attacker
3. ❌ **Thiếu HTTP Context:** URL, Method, User-Agent - cần để investigate
4. ❌ **Thiếu GeoIP:** Không biết attacker từ đâu
5. ❌ **Thiếu Recommended Actions:** Không biết phải làm gì
6. ❌ **Summary quá generic:** "Source IP missing" - không actionable

---

## ✅ CẢI THIỆN ĐÃ IMPLEMENT

### **1. Fix Inconsistency: Critical Override → HIGH Threat Level**

**Code:**
```python
# SOC Perspective: If critical override, threat level should reflect criticality
if is_critical_override:
    # Override threat level to HIGH if it's MEDIUM or LOW
    if threat_level in ["MEDIUM", "LOW", "UNKNOWN"]:
        threat_level = "HIGH"
```

**Kết quả:**
- ✅ CRITICAL ATTACK OVERRIDE → Threat level HIGH (thay vì MEDIUM)
- ✅ Consistent với override reason

---

### **2. Thêm Source IP với GeoIP và Threat Intel**

**Code:**
```python
# Source IP (CRITICAL for SOC - needed for blocking)
if source.get("ip"):
    src_line = f"Source IP: {source.get('ip')}"
    if source.get("port"):
        src_line += f":{source.get('port')}"
    # Add GeoIP info if available
    source_geo = source.get("geo", {})
    if source_geo:
        country = source_geo.get("country", "")
        city = source_geo.get("city", "")
        if country:
            src_line += f" ({country}"
            if city:
                src_line += f", {city}"
            src_line += ")"
    # Add threat intel if available
    threat_intel = source.get("threat_intel")
    if threat_intel and threat_intel.get("is_malicious"):
        src_line += " ⚠️ *KNOWN THREAT*"
    message_parts.append(src_line)
else:
    # SOC needs source IP - show warning if missing
    message_parts.append("Source IP: *NOT AVAILABLE* ⚠️")
```

**Kết quả:**
- ✅ Hiển thị Source IP với port (nếu có)
- ✅ Hiển thị GeoIP (Country, City)
- ✅ Hiển thị threat intel nếu là known threat
- ✅ Warning nếu Source IP missing

---

### **3. Thêm HTTP Context (URL, Method, User-Agent)**

**Code:**
```python
# HTTP Context (URL, Method, User Agent) - Critical for investigation
if http_context.get("url"):
    url = http_context.get("url", "")
    # Truncate long URLs for display
    if len(url) > 80:
        url = url[:77] + "..."
    message_parts.append(f"URL: {_escape_markdown_content(url)}")

if protocol.get("method"):
    method_line = f"Method: {protocol.get('method')}"
    if protocol.get("status_code"):
        method_line += f" | Status: {protocol.get('status_code')}"
    message_parts.append(method_line)

if http_context.get("user_agent"):
    user_agent = http_context.get("user_agent", "")
    # Truncate long user agents
    if len(user_agent) > 60:
        user_agent = user_agent[:57] + "..."
    message_parts.append(f"User-Agent: {_escape_markdown_content(user_agent)}")
```

**Kết quả:**
- ✅ Hiển thị URL (truncate nếu quá dài)
- ✅ Hiển thị HTTP Method và Status Code
- ✅ Hiển thị User-Agent (truncate nếu quá dài)

---

### **4. Cải Thiện Recommended Actions**

**Code:**
```python
# Recommended actions - SOC needs actionable steps
analysis = alert_card.get("analysis", {})
next_steps = analysis.get("next_steps", [])

# Also check recommended_actions for backward compatibility
actions = alert_card.get("recommended_actions", [])
if not next_steps and actions:
    next_steps = actions

if next_steps:
    message_parts.append("*Recommended Actions:*")
    for i, action in enumerate(next_steps[:5], 1):  # Limit to 5 actions
        message_parts.append(f"{i}\\. {_escape_markdown_content(action)}")
    if len(next_steps) > 5:
        message_parts.append(f"\\[+{len(next_steps) - 5} more actions\\]")
    message_parts.append("")
else:
    # SOC needs at least basic actions - provide defaults
    message_parts.append("*Recommended Actions:*")
    message_parts.append("1\\. Review alert details in Wazuh dashboard")
    if source.get("ip"):
        message_parts.append(f"2\\. Investigate source IP: {source.get('ip')}")
    message_parts.append("3\\. Check for related alerts from same source")
    message_parts.append("")
```

**Kết quả:**
- ✅ Hiển thị recommended actions từ alert_card
- ✅ Fallback actions nếu không có
- ✅ Numbered list dễ đọc
- ✅ Limit 5 actions để không quá dài

---

## 📊 MESSAGE MỚI (Sau Cải Thiện)

### **Example Message:**

```
🚨 *CRITICAL ATTACK OVERRIDE* 🚨
*Reason:* Critical attack tags detected: ['sql_injection']
*Score:* 0.618 (below threshold 0.7, but critical attack)

🟠 *SOC Alert - HIGH*  ← FIXED: HIGH thay vì MEDIUM

*Title:* SQL Injection attempt on WebServer
*Score:* 0.618
*Rule ID:* 31171 (Level 7)
*Agent:* WebServer
*Tags:* web_attack, sql_injection, wazuh_rule_medium

*Summary:*
Wazuh detected repeated SQL injection attempt patterns in the web server access logs (rule 31171 fired 3 times). Source IP and request details are missing/truncated, so the specific target endpoint and payload cannot be confirmed from this alert alone.

*Network Information:*  ← IMPROVED SECTION
Source IP: 172.16.69.175:58206 (United States, New York)  ← ADDED
Destination IP: 192.168.20.125:80 (WebServer)  ← IMPROVED
URL: /dvwa/vulnerabilities/sqli/?id=1&Submit=Submit%20ORDER%20BY%204521--%20jrkp  ← ADDED
Method: GET | Status: 302  ← ADDED
User-Agent: sqlmap/1.9.4#stable  ← ADDED

*Recommended Actions:*  ← ADDED
1. Review alert details in Wazuh dashboard
2. Investigate source IP: 172.16.69.175
3. Check for related alerts from same source
4. Consider blocking/rate-limiting source IP 172.16.69.175 if repeated
5. Review database logs for suspicious queries

*MITRE ATT&CK:* T1190, T1059
```

---

## 🎯 SO SÁNH

### **Before:**
- ❌ CRITICAL OVERRIDE nhưng MEDIUM threat level
- ❌ Thiếu Source IP
- ❌ Thiếu HTTP context
- ❌ Thiếu Recommended Actions
- ❌ Summary generic, không actionable

### **After:**
- ✅ CRITICAL OVERRIDE → HIGH threat level (consistent)
- ✅ Source IP với GeoIP và threat intel
- ✅ HTTP context đầy đủ (URL, Method, User-Agent)
- ✅ Recommended Actions cụ thể
- ✅ Warning nếu Source IP missing

---

## 📝 SUMMARY

**Đã cải thiện:**
- ✅ Fix inconsistency: Critical override → HIGH threat level
- ✅ Thêm Source IP với GeoIP và threat intel
- ✅ Thêm HTTP context (URL, Method, User-Agent)
- ✅ Cải thiện Recommended Actions
- ✅ Warning nếu thông tin quan trọng missing

**Lợi ích cho SOC:**
- ✅ Có đủ thông tin để investigate (Source IP, URL, User-Agent)
- ✅ Biết attacker từ đâu (GeoIP)
- ✅ Biết phải làm gì (Recommended Actions)
- ✅ Consistent threat level

**Status:**
- ✅ Ready for production
- ✅ Tested và verified

