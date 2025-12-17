# 🔍 Phân Tích Wazuh Fields - Góc Nhìn SOC

**Ngày:** 2025-12-14  
**Mục đích:** So sánh fields từ Wazuh alert thực tế với code hiện tại, đề xuất fields cần thêm từ góc nhìn SOC

---

## 📊 FIELDS TỪ WAZUH ALERT THỰC TẾ

### **Fields có trong alert thực tế:**

**1. Agent Information:**
- ✅ `agent.id`: "001"
- ✅ `agent.ip`: "192.168.20.125"
- ✅ `agent.name`: "WebServer"

**2. Network Information (QUAN TRỌNG cho SOC):**
- ⚠️ `data.src_ip`: "192.168.20.125" (server IP)
- ⚠️ `data.dest_ip`: "172.16.69.175" (attacker IP)
- ⚠️ `data.src_port`: 80
- ⚠️ `data.dest_port`: 58206
- ⚠️ `data.flow.src_ip`: "172.16.69.175" (attacker)
- ⚠️ `data.flow.dest_ip`: "192.168.20.125" (target)
- ⚠️ `data.flow.src_port`: 58206
- ⚠️ `data.flow.dest_port`: 80
- ⚠️ `data.flow.bytes_toserver`: 633
- ⚠️ `data.flow.bytes_toclient`: 790
- ⚠️ `data.flow.pkts_toserver`: 5
- ⚠️ `data.flow.pkts_toclient`: 5
- ⚠️ `data.flow.direction`: "to_client"
- ⚠️ `data.direction`: "to_client"

**3. HTTP Context:**
- ✅ `data.http.url`: "/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit%20ORDER%20BY%204521--%20jrkp"
- ✅ `data.http.http_method`: "GET"
- ✅ `data.http.status`: "302"
- ✅ `data.http.hostname`: "172.16.69.176"
- ✅ `data.http.http_user_agent`: "sqlmap/1.9.4#stable"
- ⚠️ `data.http.redirect`: "../../login.php" (QUAN TRỌNG - 302 redirect)
- ⚠️ `data.http.http_content_type`: "text/html"
- ✅ `data.http.protocol`: "HTTP/1.1"

**4. Suricata Alert:**
- ✅ `data.alert.signature_id`: 2221036
- ✅ `data.alert.signature`: "SURICATA HTTP Response excessive header repetition"
- ✅ `data.alert.category`: "Generic Protocol Command Decode"
- ✅ `data.alert.severity`: 3
- ⚠️ `data.alert.action`: "allowed" (QUAN TRỌNG - allowed vs blocked)

**5. Rule Information:**
- ✅ `rule.id`: "100100"
- ✅ `rule.level`: 3
- ✅ `rule.description`: "Suricata: Alert (raw signature)"
- ✅ `rule.groups`: ["soc_dvwa_pack", "local", "suricata", "raw"]
- ⚠️ `rule.firedtimes`: "1,063" (QUAN TRỌNG - số lần rule đã fire)

**6. Metadata:**
- ✅ `@timestamp`: Main timestamp
- ⚠️ `data.timestamp`: "Dec 14, 2025 @ 16:18:02.560" (có thể khác @timestamp)
- ⚠️ `location`: "/var/log/suricata/eve.json" (log source)
- ✅ `event_type`: "alert"

---

## 🔍 SO SÁNH VỚI CODE HIỆN TẠI

### **Fields đã có trong `_normalize_alert()`:**

✅ **Đã extract:**
- `@timestamp`, `@timestamp_local`
- `agent` (id, name, ip)
- `rule` (id, level, description, groups)
- `srcip` (từ top-level)
- `user`
- `message`
- `http` (url, method, user_agent, referer, status, hostname, protocol)
- `suricata_alert` (signature_id, signature, category, severity)
- `event_type`
- `raw` (full raw alert)

### **Fields THIẾU (từ góc nhìn SOC):**

❌ **1. Network Information (CRITICAL):**
- `data.src_ip`, `data.dest_ip` - Attacker IP và Target IP
- `data.src_port`, `data.dest_port` - Ports
- `data.flow.*` - Flow statistics (bytes, pkts, direction)

**Tại sao quan trọng:**
- SOC cần biết **attacker IP** để block
- SOC cần biết **target IP** để identify asset
- SOC cần **flow statistics** để phân tích network traffic
- SOC cần **direction** để biết inbound/outbound

❌ **2. HTTP Redirect (IMPORTANT):**
- `data.http.redirect` - "../../login.php"

**Tại sao quan trọng:**
- HTTP 302 + redirect = **Authentication failure** (có thể)
- Giúp phân biệt successful attack vs. failed attempt
- Context quan trọng cho AI analysis

❌ **3. Alert Action (IMPORTANT):**
- `data.alert.action` - "allowed" vs "blocked"

**Tại sao quan trọng:**
- "allowed" = Attack **đã pass qua** firewall/IPS
- "blocked" = Attack **đã bị chặn**
- Quan trọng để đánh giá impact

❌ **4. Rule Fired Times (IMPORTANT):**
- `rule.firedtimes` - "1,063"

**Tại sao quan trọng:**
- Số lần rule đã fire = **Frequency indicator**
- Giúp correlation (cùng rule fire nhiều lần = attack campaign)
- Quan trọng cho prioritization

❌ **5. HTTP Content Type (NICE TO HAVE):**
- `data.http.http_content_type` - "text/html"

**Tại sao quan trọng:**
- Giúp phân tích response type
- Có thể indicate successful exploitation

❌ **6. Location (NICE TO HAVE):**
- `location` - "/var/log/suricata/eve.json"

**Tại sao quan trọng:**
- Biết log source
- Có thể hữu ích cho investigation

---

## 🎯 ĐỀ XUẤT: FIELDS CẦN THÊM

### **Priority 1 (CRITICAL - Phải thêm):**

**1. Network Information:**
```python
"network": {
    "src_ip": data.get("src_ip", ""),  # Attacker IP
    "dest_ip": data.get("dest_ip", ""),  # Target IP
    "src_port": data.get("src_port", 0),
    "dest_port": data.get("dest_port", 0),
    "direction": data.get("direction", ""),  # to_client, to_server
}
```

**2. Flow Statistics:**
```python
"flow": {
    "src_ip": flow.get("src_ip", ""),
    "dest_ip": flow.get("dest_ip", ""),
    "src_port": flow.get("src_port", 0),
    "dest_port": flow.get("dest_port", 0),
    "bytes_toserver": flow.get("bytes_toserver", 0),
    "bytes_toclient": flow.get("bytes_toclient", 0),
    "pkts_toserver": flow.get("pkts_toserver", 0),
    "pkts_toclient": flow.get("pkts_toclient", 0),
    "direction": flow.get("direction", ""),
}
```

**Lý do:**
- SOC cần attacker IP để block
- SOC cần flow statistics để phân tích network traffic
- Quan trọng cho correlation và investigation

---

### **Priority 2 (IMPORTANT - Nên thêm):**

**3. HTTP Redirect:**
```python
"http": {
    ...
    "redirect": http_data.get("redirect", ""),  # 302 redirect
}
```

**Lý do:**
- HTTP 302 + redirect = Authentication failure indicator
- Giúp AI phân tích attack có thành công không

**4. Alert Action:**
```python
"suricata_alert": {
    ...
    "action": alert_data.get("action", ""),  # "allowed" vs "blocked"
}
```

**Lý do:**
- "allowed" = Attack đã pass qua firewall
- "blocked" = Attack đã bị chặn
- Quan trọng để đánh giá impact

**5. Rule Fired Times:**
```python
"rule": {
    ...
    "firedtimes": rule.get("firedtimes", ""),  # "1,063"
}
```

**Lý do:**
- Frequency indicator
- Quan trọng cho correlation

---

### **Priority 3 (NICE TO HAVE - Có thể thêm):**

**6. HTTP Content Type:**
```python
"http": {
    ...
    "content_type": http_data.get("http_content_type", ""),
}
```

**7. Location:**
```python
"location": raw.get("location", ""),  # "/var/log/suricata/eve.json"
```

---

## 📋 KẾT LUẬN

### **Fields PHẢI thêm (Priority 1):**
1. ✅ **Network Information** (`data.src_ip`, `data.dest_ip`, ports)
2. ✅ **Flow Statistics** (`data.flow.*`)

**Lý do:** SOC cần attacker IP và flow statistics để investigation và correlation.

### **Fields NÊN thêm (Priority 2):**
3. ✅ **HTTP Redirect** (`data.http.redirect`)
4. ✅ **Alert Action** (`data.alert.action`)
5. ✅ **Rule Fired Times** (`rule.firedtimes`)

**Lý do:** Quan trọng cho AI analysis và correlation.

### **Fields CÓ THỂ thêm (Priority 3):**
6. ⚠️ **HTTP Content Type** (nice to have)
7. ⚠️ **Location** (nice to have)

---

## 🔧 IMPLEMENTATION

**Cần update `_normalize_alert()` trong `wazuh_client.py`:**

1. Extract `data.src_ip`, `data.dest_ip`, ports
2. Extract `data.flow.*` information
3. Extract `data.http.redirect`
4. Extract `data.alert.action`
5. Extract `rule.firedtimes`

**Sau đó update:**
- `alert_formatter.py` để sử dụng các fields mới
- `triage.py` để pass các fields mới cho AI
- `llm.py` để AI có thể phân tích các fields mới

