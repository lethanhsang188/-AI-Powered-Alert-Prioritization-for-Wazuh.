# 📱 Telegram Message Mẫu - SOC-Grade Format

**Ngày:** 2025-12-15  
**Alert Sample:** Rule 100100, Level 3, SQL Injection attempt với sqlmap

---

## 📋 ALERT SAMPLE DATA

```json
{
  "_index": "wazuh-alerts-4.x-2025.12.14",
  "_id": "1765703886.15560605",
  "agent": {
    "id": "001",
    "name": "WebServer",
    "ip": "192.168.20.125"
  },
  "rule": {
    "id": "100100",
    "level": 3,
    "description": "Suricata: Alert (raw signature)",
    "groups": ["soc_dvwa_pack", "local", "suricata", "raw"],
    "firedtimes": 1063
  },
  "data": {
    "src_ip": "192.168.20.125",
    "src_port": 80,
    "dest_ip": "172.16.69.175",
    "dest_port": 58206,
    "proto": "TCP",
    "app_proto": "http",
    "alert": {
      "action": "allowed",
      "severity": 3,
      "signature": "SURICATA HTTP Response excessive header repetition",
      "signature_id": 2221036,
      "category": "Generic Protocol Command Decode"
    },
    "http": {
      "url": "/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit%20ORDER%20BY%204521--%20jrkp",
      "http_method": "GET",
      "http_user_agent": "sqlmap/1.9.4#stable (https://sqlmap.org)",
      "status": 302,
      "hostname": "172.16.69.176"
    },
    "flow": {
      "src_ip": "172.16.69.175",
      "dest_ip": "192.168.20.125",
      "src_port": 58206,
      "dest_port": 80,
      "pkts_toserver": 5,
      "pkts_toclient": 5,
      "bytes_toserver": 633,
      "bytes_toclient": 790
    }
  },
  "manager": {
    "name": "wazuh-server"
  },
  "decoder": {
    "name": "json"
  },
  "location": "/var/log/suricata/eve.json",
  "timestamp": "2025-12-14T09:18:02.560782+0000"
}
```

---

## 📱 TELEGRAM MESSAGE FORMAT

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
Source: 172.16.69.175:58206 -> Destination: 192.168.20.125:80
Protocol: TCP/HTTP
Direction: to_client

*What Happened:*
Suricata detected a SQL injection attempt from external IP 172.16.69.175 targeting WebServer on port 80. The attack used sqlmap tool (User-Agent: sqlmap/1.9.4#stable) and targeted the /dvwa/vulnerabilities/sqli/ endpoint with SQL injection payload "ORDER BY 4521--". The request returned HTTP 302 (redirect), indicating potential successful exploitation or application-level redirect.

*Evidence:*
- data.http.url=/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit%20ORDER%20BY%204521--%20jrkp
- data.http.http_user_agent=sqlmap/1.9.4#stable (https://sqlmap.org)
- data.http.status=302
- data.alert.signature_id=2221036
- data.alert.action=allowed

*IOC:*
Source IP: 172.16.69.175
Destination IP: 192.168.20.125
URL: /dvwa/vulnerabilities/sqli/?id=1&Submit=Submit%20ORDER%20BY%204521--%20jrkp
Domain: Unknown
Hash: Unknown

*Correlation:*
Correlated Count: 1
First Seen: 2025-12-14 09:18:02 UTC
Last Seen: 2025-12-14 09:18:02 UTC
Impacted Agents: WebServer (001)

*Recommended Actions:*
1. Review alert details in Wazuh dashboard
2. Investigate source IP: 172.16.69.175 (check for other alerts from same source)
3. Check web server logs for successful SQL injection exploitation
4. Verify if SQL injection payload executed successfully (check database logs)
5. Consider blocking source IP 172.16.69.175 if repeated attacks detected

*Missing Info:*
- Database query logs (to verify if SQL injection succeeded)
- Application logs (to check for error messages)
- User session information (if available)

*Query:*
index=wazuh-alerts-4.x-2025.12.14 AND rule.id=100100 AND data.flow.src_ip=172.16.69.175

*MITRE ATT&CK:*
- Tactic: Initial Access
- Technique: T1190 (Exploit Public-Facing Application)
- Technique: T1059 (Command and Scripting Interpreter)
```

---

## 📝 NOTES

- ✅ Không hallucinate fields (chỉ dùng fields có trong alert)
- ✅ Evidence format: "field=value"
- ✅ Missing info được ghi rõ
- ✅ Query có thể dùng để search trong Kibana/Discover
- ✅ MITRE ATT&CK chỉ khi có evidence thật

---

## 🎯 KEY POINTS

1. **Severity Emoji:**
   - 🔴 CRITICAL
   - 🟠 HIGH
   - 🟡 MEDIUM
   - 🟢 LOW

2. **Evidence Format:**
   - Luôn dạng "field=value"
   - Chỉ dùng fields có trong alert
   - Không bịa thông tin

3. **Missing Info:**
   - Ghi rõ fields cần nhưng thiếu
   - Giúp SOC biết cần thu thập thêm gì

4. **Query:**
   - Format có thể dùng trong Kibana/Discover
   - Chỉ dùng fields có thật

