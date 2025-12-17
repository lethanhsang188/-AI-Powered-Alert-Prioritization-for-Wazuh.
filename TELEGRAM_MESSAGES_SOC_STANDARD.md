# 📱 Telegram Messages - SOC Standard Format

**Ngày:** 2025-12-15  
**Mục đích:** Message mẫu cho các loại tấn công theo chuẩn SOC

---

## 🎯 CÁC LOẠI TẤN CÔNG

1. SQL Injection
2. XSS (Cross-Site Scripting)
3. Command Injection
4. LFI (Local File Inclusion)
5. CSRF (Cross-Site Request Forgery)
6. HTTP DoS
7. SYN DoS
8. File Upload

---

## 1. 🔴 SQL INJECTION ATTACK

```
🟠 SOC Alert - HIGH

*Title:* SQL Injection attempt on WebServer /dvwa/vulnerabilities/sqli/

*Scores:*
Severity: 0.85 (HIGH)
Confidence: 0.82
FP Risk: LOW

*Identity:*
Time: 2025-12-14 16:18:02 +07:00 (2025-12-14 09:18:02 UTC)
Agent: WebServer (ID: 001, IP: 192.168.20.125)
Rule: 100100 (Level 3) - Suricata: Alert (raw signature)
Index: wazuh-alerts-4.x-2025.12.14
Event ID: 1765703886.15560605
Manager: wazuh-server
Decoder: json
Location: /var/log/suricata/eve.json

*Network:*
Source: 172.16.69.175:58206
Destination: 192.168.20.125:80
Protocol: TCP/HTTP
Direction: to_client

*HTTP Context:*
URL: /dvwa/vulnerabilities/sqli/?id=1&Submit=Submit%20ORDER%20BY%204521--%20jrkp
Method: GET | Status: 302
User-Agent: sqlmap/1.9.4#stable (https://sqlmap.org)

*Suricata Alert:*
Signature: SURICATA HTTP Response excessive header repetition
Signature ID: 2221036
Severity: 3
Action: allowed ⚠️ (attack passed firewall)
Category: Generic Protocol Command Decode

*What Happened:*
Suricata detected a SQL injection attempt from external IP 172.16.69.175 targeting WebServer on port 80. The attack used sqlmap tool (User-Agent: sqlmap/1.9.4#stable) and targeted the /dvwa/vulnerabilities/sqli/ endpoint with SQL injection payload "ORDER BY 4521--". The request returned HTTP 302 (redirect), indicating potential successful exploitation or application-level redirect.

*Evidence:*
1. data.http.url=/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit%20ORDER%20BY%204521--%20jrkp
2. data.http.http_user_agent=sqlmap/1.9.4#stable (https://sqlmap.org)
3. data.http.status=302
4. data.alert.signature_id=2221036
5. data.alert.action=allowed

*IOC:*
- Source IP: 172.16.69.175
- Destination IP: 192.168.20.125
- Domain: 172.16.69.176
- URL: 172.16.69.176/dvwa/vulnerabilities/sqli/

*Correlation:*
Correlated Count: 1
First Seen: 2025-12-14 09:18:02 UTC
Last Seen: 2025-12-14 09:18:02 UTC

*Recommended Actions:*
1. Review alert details in Wazuh dashboard
2. Investigate source IP: 172.16.69.175 (check for other alerts from same source)
3. Check web server logs for successful SQL injection exploitation
4. Verify if SQL injection payload executed successfully (check database logs)
5. Consider blocking source IP 172.16.69.175 if repeated attacks detected

*MITRE ATT&CK:* T1190, T1059

*Query:*
`index=wazuh-alerts-4.x-2025.12.14 AND rule.id=100100 AND data.flow.src_ip=172.16.69.175`

*Tags:* sql_injection, web_attack, suricata
```

---

## 2. 🔴 XSS (CROSS-SITE SCRIPTING) ATTACK

```
🟠 SOC Alert - HIGH

*Title:* XSS attempt on WebServer /dvwa/vulnerabilities/xss/

*Scores:*
Severity: 0.88 (HIGH)
Confidence: 0.85
FP Risk: LOW

*Identity:*
Time: 2025-12-14 16:20:15 +07:00 (2025-12-14 09:20:15 UTC)
Agent: WebServer (ID: 001, IP: 192.168.20.125)
Rule: 31105 (Level 7) - XSS (Cross-Site Scripting)
Index: wazuh-alerts-4.x-2025.12.14
Event ID: 1765703890.15560610

*Network:*
Source: 172.16.69.175:58210
Destination: 192.168.20.125:80
Protocol: TCP/HTTP

*HTTP Context:*
URL: /dvwa/vulnerabilities/xss/?name=<script>alert('XSS')</script>
Method: GET | Status: 200
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36

*What Happened:*
Wazuh detected a Cross-Site Scripting (XSS) attack attempt from external IP 172.16.69.175 targeting WebServer. The attack payload contains JavaScript code `<script>alert('XSS')</script>` in the name parameter. The request returned HTTP 200 (success), indicating the payload may have been executed or stored.

*Evidence:*
1. data.http.url=/dvwa/vulnerabilities/xss/?name=<script>alert('XSS')</script>
2. data.http.status=200
3. rule.id=31105
4. rule.level=7
5. rule.groups=web_attack, xss

*IOC:*
- Source IP: 172.16.69.175
- Destination IP: 192.168.20.125
- URL: /dvwa/vulnerabilities/xss/

*Recommended Actions:*
1. Review alert details in Wazuh dashboard
2. Check web application logs for XSS payload execution
3. Verify if XSS payload was stored in database or reflected in response
4. Check for session hijacking or credential theft attempts
5. Consider blocking source IP 172.16.69.175 if repeated attacks

*MITRE ATT&CK:* T1059.007, T1059.001

*Query:*
`index=wazuh-alerts-4.x-2025.12.14 AND rule.id=31105 AND data.flow.src_ip=172.16.69.175`

*Tags:* xss, web_attack
```

---

## 3. 🔴 COMMAND INJECTION ATTACK

```
🔴 SOC Alert - CRITICAL

*Title:* Command Injection attempt on WebServer /dvwa/vulnerabilities/exec/

*Scores:*
Severity: 0.92 (CRITICAL)
Confidence: 0.90
FP Risk: LOW

*Identity:*
Time: 2025-12-14 16:22:30 +07:00 (2025-12-14 09:22:30 UTC)
Agent: WebServer (ID: 001, IP: 192.168.20.125)
Rule: 100130 (Level 10) - Command Injection Attempt
Index: wazuh-alerts-4.x-2025.12.14
Event ID: 1765703895.15560615

*Network:*
Source: 172.16.69.175:58215
Destination: 192.168.20.125:80
Protocol: TCP/HTTP

*HTTP Context:*
URL: /dvwa/vulnerabilities/exec/?ip=127.0.0.1;cat /etc/passwd
Method: GET | Status: 200
User-Agent: curl/7.68.0

*What Happened:*
Wazuh detected a Command Injection attack attempt from external IP 172.16.69.175 targeting WebServer. The attack payload contains command injection pattern "127.0.0.1;cat /etc/passwd" attempting to execute shell commands. The request returned HTTP 200 (success), indicating potential successful command execution.

*Evidence:*
1. data.http.url=/dvwa/vulnerabilities/exec/?ip=127.0.0.1;cat /etc/passwd
2. data.http.status=200
3. rule.id=100130
4. rule.level=10
5. data.alert.action=allowed

*IOC:*
- Source IP: 172.16.69.175
- Destination IP: 192.168.20.125
- URL: /dvwa/vulnerabilities/exec/

*Recommended Actions:*
1. IMMEDIATE: Check for reverse shell connections or outbound traffic from WebServer
2. Review web server logs for command execution evidence
3. Check system logs (auditd, syslog) for command execution by web server user
4. Verify if /etc/passwd was accessed or exfiltrated
5. Consider blocking source IP 172.16.69.175 immediately

*MITRE ATT&CK:* T1059, T1059.004

*Query:*
`index=wazuh-alerts-4.x-2025.12.14 AND rule.id=100130 AND data.flow.src_ip=172.16.69.175`

*Tags:* command_injection, web_attack
```

---

## 4. 🟠 LFI (LOCAL FILE INCLUSION) ATTACK

```
🟠 SOC Alert - HIGH

*Title:* Local File Inclusion attempt on WebServer /dvwa/vulnerabilities/fi/

*Scores:*
Severity: 0.80 (HIGH)
Confidence: 0.75
FP Risk: LOW

*Identity:*
Time: 2025-12-14 16:25:45 +07:00 (2025-12-14 09:25:45 UTC)
Agent: WebServer (ID: 001, IP: 192.168.20.125)
Rule: 100150 (Level 8) - Local File Inclusion Attempt
Index: wazuh-alerts-4.x-2025.12.14
Event ID: 1765703900.15560620

*Network:*
Source: 172.16.69.175:58220
Destination: 192.168.20.125:80
Protocol: TCP/HTTP

*HTTP Context:*
URL: /dvwa/vulnerabilities/fi/?page=../../../../etc/passwd
Method: GET | Status: 200
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36

*What Happened:*
Wazuh detected a Local File Inclusion (LFI) attack attempt from external IP 172.16.69.175 targeting WebServer. The attack payload contains path traversal pattern "../../../../etc/passwd" attempting to access sensitive system files. The request returned HTTP 200 (success), indicating potential successful file access.

*Evidence:*
1. data.http.url=/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd
2. data.http.status=200
3. rule.id=100150
4. rule.level=8
5. rule.groups=path_traversal, web_attack

*IOC:*
- Source IP: 172.16.69.175
- Destination IP: 192.168.20.125
- URL: /dvwa/vulnerabilities/fi/

*Recommended Actions:*
1. Check web server logs for file access evidence
2. Verify if /etc/passwd was accessed or exfiltrated
3. Check for other sensitive file access attempts (config files, credentials)
4. Review file system access logs
5. Consider blocking source IP 172.16.69.175 if repeated attacks

*MITRE ATT&CK:* T1083, T1552.001

*Query:*
`index=wazuh-alerts-4.x-2025.12.14 AND rule.id=100150 AND data.flow.src_ip=172.16.69.175`

*Tags:* path_traversal, web_attack
```

---

## 5. 🟡 CSRF (CROSS-SITE REQUEST FORGERY) ATTACK

```
🟡 SOC Alert - MEDIUM

*Title:* CSRF attempt on WebServer /dvwa/vulnerabilities/csrf/

*Scores:*
Severity: 0.65 (MEDIUM)
Confidence: 0.70
FP Risk: LOW

*Identity:*
Time: 2025-12-14 16:28:10 +07:00 (2025-12-14 09:28:10 UTC)
Agent: WebServer (ID: 001, IP: 192.168.20.125)
Rule: 100133 (Level 6) - CSRF Detection
Index: wazuh-alerts-4.x-2025.12.14
Event ID: 1765703905.15560625

*Network:*
Source: 172.16.69.175:58225
Destination: 192.168.20.125:80
Protocol: TCP/HTTP

*HTTP Context:*
URL: /dvwa/vulnerabilities/csrf/?password_new=NewPass123&password_conf=NewPass123&Change=Change
Method: GET | Status: 302
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Referer: http://evil.com/csrf.html

*What Happened:*
Wazuh detected a Cross-Site Request Forgery (CSRF) attack attempt from external IP 172.16.69.175 targeting WebServer. The attack attempts to change password without proper CSRF token validation. The request has suspicious referer "http://evil.com/csrf.html" indicating cross-origin request. The request returned HTTP 302 (redirect), indicating potential successful state change.

*Evidence:*
1. data.http.url=/dvwa/vulnerabilities/csrf/?password_new=NewPass123&password_conf=NewPass123&Change=Change
2. data.http.status=302
3. data.http.referer=http://evil.com/csrf.html
4. rule.id=100133
5. rule.level=6

*IOC:*
- Source IP: 172.16.69.175
- Destination IP: 192.168.20.125
- Referer Domain: evil.com

*Recommended Actions:*
1. Verify if password change was successful
2. Check for unauthorized state changes in application
3. Review CSRF token validation mechanism
4. Check for other CSRF attempts from same source
5. Consider blocking source IP 172.16.69.175 if repeated attacks

*MITRE ATT&CK:* T1059.007

*Query:*
`index=wazuh-alerts-4.x-2025.12.14 AND rule.id=100133 AND data.flow.src_ip=172.16.69.175`

*Tags:* csrf, web_attack
```

---

## 6. 🔴 HTTP DoS ATTACK

```
🔴 SOC Alert - CRITICAL

*Title:* HTTP DoS attack on WebServer

*Scores:*
Severity: 0.90 (CRITICAL)
Confidence: 0.88
FP Risk: LOW

*Identity:*
Time: 2025-12-14 16:30:00 +07:00 (2025-12-14 09:30:00 UTC)
Agent: WebServer (ID: 001, IP: 192.168.20.125)
Rule: 100139 (Level 10) - HTTP DoS detected
Index: wazuh-alerts-4.x-2025.12.14
Event ID: 1765703910.15560630

*Network:*
Source: 203.0.113.50:54321
Destination: 192.168.20.125:80
Protocol: TCP/HTTP

*HTTP Context:*
URL: /dvwa/vulnerabilities/brute/
Method: GET | Status: 200
User-Agent: python-requests/2.28.1

*Flow Statistics:*
Packets to Server: 10000
Packets to Client: 500
Bytes to Server: 500000
Bytes to Client: 25000

*Suricata Alert:*
Signature: HTTP flood
Signature ID: 2200001
Severity: 3
Action: allowed ⚠️ (attack passed firewall)
Category: Potential Corporate Privacy Violation

*What Happened:*
Suricata detected an HTTP DoS (Denial of Service) attack from external IP 203.0.113.50 targeting WebServer on port 80. The attack shows 10000 packets to server with only 500 responses, indicating a flood pattern. The attack was allowed by Suricata (not blocked), suggesting it may have passed through firewall. This is a denial-of-service attack that can exhaust server resources.

*Evidence:*
1. data.flow.pkts_toserver=10000 (DoS indicator)
2. data.flow.bytes_toserver=500000
3. data.alert.signature=HTTP flood
4. data.alert.action=allowed
5. data.alert.severity=3

*IOC:*
- Source IP: 203.0.113.50
- Destination IP: 192.168.20.125

*Correlation:*
Correlated Count: 15
First Seen: 2025-12-14 09:25:00 UTC
Last Seen: 2025-12-14 09:30:00 UTC

*Recommended Actions:*
1. IMMEDIATE: Check server resources (CPU, memory, connection pool)
2. Review rate limiting and DDoS protection mechanisms
3. Consider blocking source IP 203.0.113.50 at firewall level
4. Check for other HTTP DoS alerts in time window
5. Monitor server performance metrics

*MITRE ATT&CK:* T1499, T1499.004

*Query:*
`index=wazuh-alerts-4.x-2025.12.14 AND rule.id=100139 AND data.flow.src_ip=203.0.113.50`

*Tags:* dos, web_attack, network_intrusion
```

---

## 7. 🔴 SYN DoS ATTACK

```
🔴 SOC Alert - CRITICAL

*Title:* SYN Flood attack on WebServer

*Scores:*
Severity: 0.88 (CRITICAL)
Confidence: 0.85
FP Risk: LOW

*Identity:*
Time: 2025-12-14 16:32:15 +07:00 (2025-12-14 09:32:15 UTC)
Agent: WebServer (ID: 001, IP: 192.168.20.125)
Rule: 100142 (Level 3) - Multiple SYN packets from same source (possible SYN flood)
Index: wazuh-alerts-4.x-2025.12.14
Event ID: 1765703915.15560635

*Network:*
Source: 203.0.113.50:54321
Destination: 192.168.20.125:80
Protocol: TCP

*Flow Statistics:*
Packets to Server: 1000
Packets to Client: 0
Bytes to Server: 60000
Bytes to Client: 0

*Suricata Alert:*
Signature: ET POLICY Possible SYN flood
Signature ID: 2200004
Severity: 3
Action: allowed ⚠️ (attack passed firewall)
Category: Potential Corporate Privacy Violation

*What Happened:*
Suricata detected a potential SYN flood attack from external IP 203.0.113.50 targeting WebServer on port 80. The attack shows 1000 packets to server with 0 responses, indicating a classic SYN flood pattern. The attack was allowed by Suricata (not blocked), suggesting it may have passed through firewall. This is a denial-of-service attack that can exhaust server connection resources.

*Evidence:*
1. data.flow.pkts_toserver=1000 (DoS indicator)
2. data.flow.pkts_toclient=0 (SYN flood pattern)
3. data.alert.signature=ET POLICY Possible SYN flood
4. data.alert.action=allowed
5. data.alert.severity=3

*IOC:*
- Source IP: 203.0.113.50
- Destination IP: 192.168.20.125

*Correlation:*
Correlated Count: 8
First Seen: 2025-12-14 09:30:00 UTC
Last Seen: 2025-12-14 09:32:15 UTC

*Recommended Actions:*
1. IMMEDIATE: Check server connection pool status
2. Review SYN flood protection mechanisms (SYN cookies, rate limiting)
3. Consider blocking source IP 203.0.113.50 at firewall level
4. Monitor server resources (CPU, memory, connection count)
5. Check for other SYN flood alerts in time window

*MITRE ATT&CK:* T1499, T1499.001

*Query:*
`index=wazuh-alerts-4.x-2025.12.14 AND rule.id=100142 AND data.flow.src_ip=203.0.113.50`

*Tags:* dos, syn_flood, network_intrusion
```

---

## 8. 🟠 FILE UPLOAD ATTACK

```
🟠 SOC Alert - HIGH

*Title:* Suspicious file upload attempt on WebServer /dvwa/vulnerabilities/upload/

*Scores:*
Severity: 0.82 (HIGH)
Confidence: 0.80
FP Risk: LOW

*Identity:*
Time: 2025-12-14 16:35:30 +07:00 (2025-12-14 09:35:30 UTC)
Agent: WebServer (ID: 001, IP: 192.168.20.125)
Rule: 100140 (Level 10) - Suspicious Upload (PHP/webshell)
Index: wazuh-alerts-4.x-2025.12.14
Event ID: 1765703920.15560640

*Network:*
Source: 172.16.69.175:58230
Destination: 192.168.20.125:80
Protocol: TCP/HTTP

*HTTP Context:*
URL: /dvwa/vulnerabilities/upload/
Method: POST | Status: 200
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: multipart/form-data

*Suricata Alert:*
Signature: Suspicious file upload detected
Signature ID: 2200005
Severity: 3
Action: allowed ⚠️ (attack passed firewall)
Category: File Upload

*What Happened:*
Wazuh detected a suspicious file upload attempt from external IP 172.16.69.175 targeting WebServer. The upload contains PHP webshell indicators (eval, base64_decode, system functions). The request returned HTTP 200 (success), indicating the file may have been successfully uploaded. This could lead to remote code execution and server compromise.

*Evidence:*
1. data.http.url=/dvwa/vulnerabilities/upload/
2. data.http.method=POST
3. data.http.status=200
4. rule.id=100140
5. data.alert.signature=Suspicious file upload detected

*IOC:*
- Source IP: 172.16.69.175
- Destination IP: 192.168.20.125
- URL: /dvwa/vulnerabilities/upload/

*Recommended Actions:*
1. IMMEDIATE: Check uploaded file location and content
2. Verify if webshell was successfully uploaded
3. Check for reverse shell connections or outbound traffic
4. Review file system for suspicious PHP files
5. Consider blocking source IP 172.16.69.175 immediately

*MITRE ATT&CK:* T1105, T1505.003

*Query:*
`index=wazuh-alerts-4.x-2025.12.14 AND rule.id=100140 AND data.flow.src_ip=172.16.69.175`

*Tags:* file_upload, webshell, web_attack
```

---

## 📝 NOTES

### Format Guidelines:
- ✅ Emoji severity: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW
- ✅ Evidence format: "field=value" (không hallucinate)
- ✅ IOC chỉ dùng fields có trong alert
- ✅ Query có thể dùng trong Kibana/Discover
- ✅ Recommended Actions cụ thể và actionable
- ✅ Correlation info khi có
- ✅ Missing info được ghi rõ nếu thiếu

### Key Sections:
1. **Header** - Severity emoji + threat level
2. **Scores** - Severity, Confidence, FP Risk
3. **Identity** - Time, Agent, Rule, Index, Event ID, Manager, Decoder, Location
4. **Network** - Source, Destination, Protocol, Direction
5. **HTTP Context** - URL, Method, Status, User-Agent (nếu có)
6. **Flow Statistics** - Packets/Bytes (cho DoS attacks)
7. **Suricata Alert** - Signature, ID, Severity, Action, Category
8. **What Happened** - Tóm tắt factual
9. **Evidence** - Top 5 evidence items (field=value format)
10. **IOC** - Source IP, Destination IP, Domain, URL
11. **Correlation** - Correlated count, First/Last seen (nếu có)
12. **Recommended Actions** - Top 5 actionable steps
13. **MITRE ATT&CK** - Technique IDs (nếu có)
14. **Query** - Kibana/Discover query
15. **Tags** - Attack tags

---

## ✅ CHECKLIST

- [x] Format chuẩn SOC với đầy đủ sections
- [x] Không hallucinate fields
- [x] Evidence format "field=value"
- [x] IOC chỉ dùng fields có thật
- [x] Query có thể dùng trong Kibana/Discover
- [x] Recommended Actions cụ thể và actionable
- [x] Emoji severity rõ ràng
- [x] Correlation info khi có

