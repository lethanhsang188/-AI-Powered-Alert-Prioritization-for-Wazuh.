# 🔍 Phân Tích Cuộc Tấn Công Từ Log

## 📊 Tổng Quan

**Thời gian:** 2025-12-14 21:05:13 - 21:06:15  
**Agent:** WebServer (001)  
**Tổng alerts:** 9 alerts (batch 1) + 50 alerts (batch 2) = 59 alerts

---

## 🚨 CUỘC TẤN CÔNG PHÁT HIỆN

### **1. CONFIRMED Reverse Shell Attack (Rule 110231, Level 13) - CRITICAL**

**Số lượng:** 2 alerts (cùng timestamp, rule fired 2 lần)

**Chi tiết:**
```
Rule ID: 110231
Rule Level: 13 (CONFIRMED - Highest Priority)
Agent: WebServer (001)
Timestamp: 2025-12-14T14:04:56.286Z và 14:04:56.336Z
Score: 0.938 (rất cao)
Threat Level: HIGH (LLM đánh, nhưng nên là CRITICAL vì level 13)
```

**LLM Analysis:**
- **Summary:** "Auditd on WebServer detected an outbound network connection initiated by the web server user, which is commonly associated with a webshell or reverse shell activity. The rule fired twice, suggesting repeated connection attempts."
- **Confidence:** 0.72 (cao)
- **Tags:** ["network_intrusion", "suspicious_process", "web_attack", "wazuh_rule_high"]

**Ý nghĩa:**
- ✅ **CONFIRMED attack** - Wazuh đã xác nhận
- ✅ **Reverse shell** - Attacker đã compromise server và tạo reverse shell
- ✅ **Web server user** - Process web server (www-data/apache) đang tạo outbound connection
- ✅ **Rule fired 2 lần** - Có thể là multiple connection attempts

**Mức độ nguy hiểm:** 🔴 **CRITICAL**
- Server đã bị compromise
- Attacker có thể điều khiển server từ xa
- Cần isolate ngay lập tức

---

### **2. XSS (Cross-Site Scripting) Attacks (Rule 31105, Level 7) - HIGH**

**Số lượng:** 7 alerts (nhiều attempts)

**Chi tiết:**
```
Rule ID: 31105
Rule Level: 7 (Medium severity - Attack attempt)
Agent: WebServer (001)
Score: 0.855 (cao) hoặc 0.805 (trung bình)
Threat Level: HIGH hoặc MEDIUM (tùy context)
```

**LLM Analysis:**
- **Summary:** "Wazuh rule 31105 triggered multiple times on the WebServer, indicating a suspected Cross-Site Scripting (XSS) payload was observed in web access logs. Key request details (source IP/payload) are missing, so the specific payload and target endpoint cannot be determined."
- **Confidence:** 0.87 (rất cao)
- **Tags:** ["web_attack", "xss", "wazuh_rule_high"] hoặc ["web_attack", "xss", "wazuh_rule_medium"]

**Ý nghĩa:**
- ⚠️ **XSS attempts** - Attacker đang thử inject JavaScript
- ⚠️ **Multiple attempts** - Rule fired nhiều lần (có thể là scanning)
- ⚠️ **Missing context** - Thiếu source IP và payload details

**Mức độ nguy hiểm:** 🟠 **HIGH**
- Có thể steal session cookies
- Có thể inject malware
- Cần kiểm tra xem có thành công không (HTTP 200?)

---

## 🎯 TÓM TẮT CUỘC TẤN CÔNG

### **Kịch bản có thể:**

1. **Attacker scan và tìm vulnerability:**
   - Gửi XSS payloads (Rule 31105)
   - Multiple attempts để tìm endpoint vulnerable

2. **Attacker exploit thành công:**
   - Upload webshell hoặc execute command
   - Tạo reverse shell connection (Rule 110231)

3. **Attacker đã compromise server:**
   - Reverse shell đã được establish
   - Có thể điều khiển server từ xa

### **Timeline:**

```
21:05:13 - Pipeline start
21:05:16 - CONFIRMED reverse shell detected (Rule 110231, Level 13)
21:05:19 - XSS attempts detected (Rule 31105, Level 7)
21:05:27 - CONFIRMED reverse shell detected again (Rule 110231, Level 13)
21:05:31 - XSS attempts continue (Rule 31105, Level 7)
...
21:06:09 - CONFIRMED reverse shell detected again (Rule 110231, Level 13)
```

**Kết luận:**
- 🔴 **Server đã bị compromise** (reverse shell CONFIRMED)
- 🟠 **XSS attacks đang diễn ra** (multiple attempts)
- ⚠️ **Cần isolate server ngay lập tức**

---

## ❌ VẤN ĐỀ PHÁT HIỆN

### **1. Threat Level Không Đúng:**

**Rule 110231 (Level 13 - CONFIRMED):**
- LLM đánh: "high" ❌
- Nên là: "critical" ✅
- Lý do: Level 13 = CONFIRMED attack, không phải attempt

**Giải pháp:** Cần implement rule level override (như đã phân tích trong SOC_THREAT_LEVEL_LOGIC_ANALYSIS.md)

---

### **2. Telegram Message Parsing Error:**

**Lỗi:**
```
"Bad Request: can't parse entities: Can't find end of the entity starting at byte offset 196"
```

**Nguyên nhân:**
- Markdown formatting lỗi
- Có thể do dấu ngoặc đơn `()` trong summary không được escape
- Có thể do các ký tự đặc biệt khác

**Ví dụ summary có thể gây lỗi:**
- "webshell or reverse shell activity" - từ "or" có thể bị parse sai
- "The rule fired twice, suggesting repeated connection attempts" - dấu phẩy và ngoặc đơn

**Giải pháp:** Cần cải thiện Markdown escaping

---

## 📋 HÀNH ĐỘNG CẦN THIẾT

### **Ngay lập tức (CRITICAL):**

1. **Isolate WebServer:**
   - Block outbound connections từ web server user
   - Disconnect server khỏi network nếu cần

2. **Investigate reverse shell:**
   - Check audit logs để xem connection đến đâu
   - Check process list để tìm suspicious processes
   - Check network connections (netstat, ss)

3. **Check XSS attacks:**
   - Review web server logs để xem payloads
   - Check xem có HTTP 200 responses không (successful XSS?)
   - Identify source IPs

### **Sau đó:**

4. **Forensic analysis:**
   - Check webshell files trong uploads directory
   - Check command history
   - Check cron jobs và scheduled tasks

5. **Remediation:**
   - Remove webshell
   - Patch vulnerabilities
   - Update security rules

---

## 🔧 FIX CẦN THIẾT

1. **Implement rule level override** để đảm bảo Level 13 → "critical"
2. **Fix Markdown escaping** để Telegram messages không bị lỗi parsing
3. **Improve error handling** để log message content khi có lỗi

