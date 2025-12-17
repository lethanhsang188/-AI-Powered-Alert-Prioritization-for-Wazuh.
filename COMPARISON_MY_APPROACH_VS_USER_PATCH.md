# 🔍 So Sánh: Cách Của Tôi vs Cách Của User

**Ngày:** 2025-12-14  
**Mục đích:** So sánh và đánh giá 2 cách tiếp cận, đưa ra nhận xét từ góc nhìn SOC

---

## 📊 SO SÁNH CHI TIẾT

### **1. Rule 100100 Suppression**

#### **Cách của tôi:**
```python
# Suppress global cho tất cả agents
must_not_filters.append({"term": {"rule.id": "100100"}})

# Và filter lần 2 cũng drop global
if rule_id == "100100":
    continue
```

**Vấn đề:**
- ❌ **Suppress rule 100100 cho CẢ WebServer (001)** → WebServer không thể triage raw Suricata alerts
- ❌ **Mất thông tin** cho SOC analyst khi cần investigate raw signatures từ WebServer
- ❌ **Không linh hoạt** - không phân biệt agent

#### **Cách của user (Patch 1-2):**
```python
# CHỈ suppress cho pfSense (002)
if agent_id == "002":
    must_not_filters.append({"term": {"rule.id": "100100"}})

# Filter lần 2 cũng chỉ drop cho pfSense
if agent_id_alert == "002" and rule_id == "100100":
    continue
```

**Ưu điểm:**
- ✅ **WebServer (001) vẫn nhận được rule 100100** → SOC có thể triage raw Suricata
- ✅ **pfSense (002) vẫn chống flood** → Không bị spam
- ✅ **Linh hoạt** - phân biệt agent

**Kết luận:** ✅ **Cách của user HỢP LÝ HƠN**

---

### **2. Normalize Alert - Field Extraction**

#### **Cách của tôi:**
```python
# Extract network với fallback logic phức tạp
src_ip = data_section.get("src_ip") or (data_section.get("flow", {}).get("src_ip") if isinstance(data_section.get("flow"), dict) else None)
dest_ip = data_section.get("dest_ip") or (data_section.get("flow", {}).get("dest_ip") if isinstance(data_section.get("flow"), dict) else None)

# Extract HTTP chỉ 7 fields
http_context = {
    "url": http_data.get("url", ""),
    "method": http_data.get("http_method", ""),
    # ... chỉ 7 fields
}

# Extract Suricata chỉ 4 fields
suricata_alert = {
    "signature_id": alert_data.get("signature_id"),
    "signature": alert_data.get("signature"),
    "category": alert_data.get("category"),
    "severity": alert_data.get("severity"),
}
```

**Vấn đề:**
- ⚠️ **Fallback logic phức tạp** → Khó maintain
- ⚠️ **Thiếu nhiều fields** từ data sample:
  - HTTP: thiếu `redirect`, `length`, `content_type`
  - Suricata: thiếu `action`, `gid`, `rev`
  - Network: thiếu `proto`, `app_proto`, `direction`, `in_iface`, `flow_id`, `tx_id`
  - Flow: thiếu `pkts_toserver`, `pkts_toclient`, `bytes_toserver`, `bytes_toclient`, `start`
  - Metadata: thiếu `http_anomaly_count`
- ⚠️ **srcip vẫn có thể rỗng** vì fallback không đủ

#### **Cách của user (Patch 3):**
```python
# Extract trực tiếp từ data section, rõ ràng
src_ip = data_section.get("src_ip", "") or ""
src_port = data_section.get("src_port", "") or ""
dest_ip = data_section.get("dest_ip", "") or ""
dest_port = data_section.get("dest_port", "") or ""
proto = data_section.get("proto", "") or ""
app_proto = data_section.get("app_proto", "") or ""
direction = data_section.get("direction", "") or ""
in_iface = data_section.get("in_iface", "") or ""
flow_id = data_section.get("flow_id", "") or ""
tx_id = data_section.get("tx_id", "") or ""

# Extract flow đầy đủ
flow = data_section.get("flow", {}) if isinstance(data_section.get("flow", {}), dict) else {}
flow_src_ip = flow.get("src_ip", "") or ""
flow_pkts_toserver = flow.get("pkts_toserver", "")
flow_bytes_toserver = flow.get("bytes_toserver", "")
# ... đầy đủ flow fields

# Extract HTTP đầy đủ (10 fields)
http_context = {
    "url": http_data.get("url", ""),
    "method": http_data.get("http_method", ""),
    # ... 7 fields cơ bản
    "redirect": http_data.get("redirect", ""),  # ✅ Thêm
    "content_type": http_data.get("http_content_type", ""),  # ✅ Thêm
    "length": http_data.get("length", ""),  # ✅ Thêm
}

# Extract Suricata đầy đủ (7 fields)
suricata_alert = {
    "action": alert_data.get("action", ""),  # ✅ Thêm
    "gid": alert_data.get("gid", ""),  # ✅ Thêm
    "signature_id": alert_data.get("signature_id"),
    "rev": alert_data.get("rev", ""),  # ✅ Thêm
    "signature": alert_data.get("signature"),
    "category": alert_data.get("category"),
    "severity": alert_data.get("severity"),
}

# Extract metadata
http_anomaly_count = flowints.get("http.anomaly.count")

# srcip với fallback rõ ràng
normalized_srcip = flow_src_ip or src_ip or raw.get("srcip", "")
```

**Ưu điểm:**
- ✅ **Extract đầy đủ fields** từ data sample → SOC có đủ context
- ✅ **Logic rõ ràng** - không có fallback phức tạp
- ✅ **Map trực tiếp** từ data section → Dễ maintain
- ✅ **srcip luôn có giá trị** (flow_src_ip → src_ip → raw.srcip)

**Kết luận:** ✅ **Cách của user HỢP LÝ HƠN**

---

### **3. Output Structure**

#### **Cách của tôi:**
```python
return {
    "@timestamp": timestamp,
    "@timestamp_local": localized_ts or "",
    "agent": raw.get("agent", {}),
    "rule": raw.get("rule", {}),
    "srcip": raw.get("srcip", ""),  # ⚠️ Có thể rỗng
    "user": raw.get("user", ""),
    "message": raw.get("message", ""),
    "http": http_context if http_context else None,
    "suricata_alert": suricata_alert if suricata_alert else None,
    "network": network_info if network_info else None,  # ⚠️ Có thể None
    "flow": flow_info if flow_info else None,  # ⚠️ Có thể None
    "event_type": event_type,
    "location": raw.get("location", ""),
    "raw": raw,
}
```

**Vấn đề:**
- ⚠️ **Nested structure** (network, flow) → Phải check None
- ⚠️ **Thiếu fields** ở top-level (proto, app_proto, direction, etc.)
- ⚠️ **srcip có thể rỗng**

#### **Cách của user:**
```python
return {
    "@timestamp": timestamp,
    "@timestamp_local": localized_ts or "",
    "agent": raw.get("agent", {}),
    "rule": raw.get("rule", {}),
    "srcip": normalized_srcip,  # ✅ Luôn có giá trị
    "user": raw.get("user", ""),
    "message": raw.get("message", ""),
    
    # ✅ Top-level fields (dễ access)
    "src_ip": src_ip, "src_port": src_port,
    "dest_ip": dest_ip, "dest_port": dest_port,
    "proto": proto, "app_proto": app_proto,
    "direction": direction, "in_iface": in_iface,
    "flow_id": flow_id, "tx_id": tx_id,
    
    # ✅ Flow structure đầy đủ
    "flow": {
        "src_ip": flow_src_ip, "src_port": flow_src_port,
        "dest_ip": flow_dest_ip, "dest_port": flow_dest_port,
        "pkts_toserver": flow_pkts_toserver, "pkts_toclient": flow_pkts_toclient,
        "bytes_toserver": flow_bytes_toserver, "bytes_toclient": flow_bytes_toclient,
        "start": flow_start,
    },
    
    "http_anomaly_count": http_anomaly_count,  # ✅ Thêm
    
    "http": http_context if http_context else None,
    "suricata_alert": suricata_alert if suricata_alert else None,
    "event_type": event_type,
    "raw": raw,
}
```

**Ưu điểm:**
- ✅ **Top-level fields** → Dễ access (không cần check nested)
- ✅ **Flow structure đầy đủ** → SOC có đủ context
- ✅ **srcip luôn có giá trị** → Không còn rỗng
- ✅ **Thêm http_anomaly_count** → Quan trọng cho SOC

**Kết luận:** ✅ **Cách của user HỢP LÝ HƠN**

---

## 🎯 TỔNG KẾT

### **Cách của tôi:**
- ✅ Đã thêm network, flow, http.redirect, suricata_alert.action
- ❌ **Suppress rule 100100 global** → Mất thông tin cho WebServer
- ⚠️ **Thiếu nhiều fields** từ data sample
- ⚠️ **Fallback logic phức tạp** → Khó maintain
- ⚠️ **srcip vẫn có thể rỗng**

### **Cách của user:**
- ✅ **Chỉ suppress rule 100100 cho pfSense** → WebServer vẫn nhận được
- ✅ **Extract đầy đủ fields** từ data sample
- ✅ **Logic rõ ràng** - map trực tiếp từ data section
- ✅ **srcip luôn có giá trị** (flow_src_ip → src_ip → raw.srcip)
- ✅ **Top-level fields** → Dễ access

---

## 📋 KẾT LUẬN

### **Cách của user HỢP LÝ HƠN vì:**

1. **Rule 100100 suppression:**
   - ✅ Chỉ suppress cho pfSense → WebServer vẫn nhận được raw Suricata
   - ✅ Linh hoạt hơn - phân biệt agent

2. **Field extraction:**
   - ✅ Extract đầy đủ fields từ data sample
   - ✅ Logic rõ ràng - không có fallback phức tạp
   - ✅ Map trực tiếp từ data section → Dễ maintain

3. **Output structure:**
   - ✅ Top-level fields → Dễ access
   - ✅ Flow structure đầy đủ → SOC có đủ context
   - ✅ srcip luôn có giá trị → Không còn rỗng

### **Nên áp dụng cách của user:**
- ✅ **Patch 1-2:** Chỉ suppress rule 100100 cho pfSense
- ✅ **Patch 3:** Nâng cấp `_normalize_alert()` với đầy đủ fields

---

## 🔧 RECOMMENDATION

**Nên áp dụng cách của user vì:**
1. **Đúng với yêu cầu SOC** - không mất thông tin
2. **Đầy đủ fields** - SOC có đủ context để triage
3. **Logic rõ ràng** - dễ maintain
4. **srcip luôn có giá trị** - không còn rỗng

**Cách của tôi có điểm tốt:**
- Đã thêm network, flow, http.redirect, suricata_alert.action
- Nhưng thiếu nhiều fields và logic suppress rule 100100 không đúng

**Kết luận:** ✅ **Nên áp dụng cách của user**

