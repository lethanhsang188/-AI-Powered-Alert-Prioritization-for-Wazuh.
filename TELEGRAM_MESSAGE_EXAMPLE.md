# Ví dụ Message Telegram Bot

## Ví dụ 1: Critical Attack (Reverse Shell - Level 13)

Dựa trên alert rule 110231 từ log của bạn:

```
🚨 *CRITICAL ATTACK OVERRIDE* 🚨
*Reason:* Critical attack rule 110231 (level 13)
*Score:* 0.962 (below threshold 0.7, but critical attack)

🔴 *SOC Alert - HIGH*

*Title:* CONFIRMED: Network connect by web server user (possible reverse shell) (auditd key=webshell_net_connect)
*Score:* 0.962
*Rule ID:* 110231 (Level 13)
*Agent:* WebServer
*Tags:* wazuh_rule_high, network_intrusion, suspicious_process, web_attack

*Summary:*
Auditd on WebServer detected an outbound network connection initiated by the web server user, which is commonly associated with a webshell spawning a reverse shell. This behavior is unusual for a web server process and indicates potential compromise.

*Network:*
Source: 192.168.20.125
Destination: 172.16.69.175:4444
URI: /dvwa/vulnerabilities/exec/

*Recommended Actions:*
• Check if request succeeded (HTTP 200/302?)
• Search for follow-up events (RCE/file upload) trong 5–10 phút sau
• Block/Rate-limit src_ip (nếu external)
• Open case nếu cùng src_ip quét nhiều endpoint
• Isolate affected host immediately
• Review audit logs for command execution

*MITRE ATT&CK:* T1059
```

---

## Ví dụ 2: High Severity Alert (XSS Attack - Level 7)

Dựa trên alert rule 31105 từ log:

```
🟠 *SOC Alert - HIGH*

*Title:* Cross-Site Scripting (XSS) attempt detected in web access logs
*Score:* 0.855
*Rule ID:* 31105 (Level 7)
*Agent:* WebServer
*Tags:* web_attack, xss, wazuh_rule_high

*Summary:*
Wazuh rule 31105 triggered on the WebServer, indicating a potential Cross-Site Scripting (XSS) attempt observed in web access logs. The alert lacks request details (message/src IP/user), so the specific payload and target endpoint cannot be determined from this event alone.

*Network:*
Source: 172.16.69.175
Destination: 192.168.20.125:80
URI: /dvwa/vulnerabilities/xss/?name=<script>alert('XSS')</script>

*Recommended Actions:*
• Check if request succeeded (HTTP 200/302?)
• Search for follow-up events (RCE/file upload) trong 5–10 phút sau
• Block/Rate-limit src_ip (nếu external)
• Review web server logs for successful XSS execution
• Check for session hijacking attempts

*MITRE ATT&CK:* T1190
```

---

## Ví dụ 3: Medium Severity Alert (Normal Threshold)

```
🟡 *SOC Alert - MEDIUM*

*Title:* Suspicious package installation detected
*Score:* 0.724
*Rule ID:* 2902 (Level 7)
*Agent:* WebServer
*Tags:* suspicious_config_change, wazuh_rule_medium

*Summary:*
Wazuh detected that a new Debian package was installed via dpkg on the WebServer host. The alert lacks package name, user, and source IP, so the change cannot be attributed from this event alone.

*Network:*
Source: N/A
Destination: N/A

*Recommended Actions:*
• Verify package installation was authorized
• Check package source and integrity
• Review system logs for unauthorized changes
```

---

## Cấu trúc Message

### 1. Critical Override Section (nếu có)
- Chỉ hiển thị khi `score < 0.7` nhưng là critical attack (rule level >= 12)
- Cảnh báo đỏ 🚨
- Lý do override

### 2. Header
- Emoji theo threat level:
  - 🔴 CRITICAL
  - 🟠 HIGH  
  - 🟡 MEDIUM
  - 🔵 LOW
- Threat level text

### 3. Alert Information
- **Title**: Mô tả ngắn gọn alert
- **Score**: Điểm AI (0.0 - 1.0)
- **Rule ID**: ID rule Wazuh + Level
- **Agent**: Tên agent phát hiện
- **Tags**: Các tag phân loại

### 4. Summary
- Tóm tắt chi tiết từ AI analysis
- Tối đa 500 ký tự (tự động truncate nếu dài hơn)

### 5. Network Information (nếu có)
- Source IP:Port
- Destination IP:Port  
- URI/Path

### 6. Recommended Actions
- Danh sách hành động đề xuất từ alert card
- Format: bullet points (•)

### 7. MITRE ATT&CK (nếu có)
- Các technique IDs liên quan
- Ví dụ: T1190, T1059

---

## Lưu ý

1. **Message Length**: Tự động truncate nếu > 4096 ký tự (Telegram limit)
2. **Markdown Formatting**: Sử dụng Markdown mode, tự động escape ký tự đặc biệt
3. **Critical Override**: Alerts với rule level >= 12 sẽ luôn được gửi, kể cả khi score < 0.7
4. **Empty Fields**: Các field không có dữ liệu sẽ không hiển thị

