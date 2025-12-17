# 🔍 Phân Tích Pipeline Delay - Góc Nhìn SOC

**Ngày:** 2025-12-15  
**Vấn đề:** Pipeline delay so với Wazuh, cần bỏ cursor nhưng không miss alerts  
**Mục tiêu:** Real-time processing, không miss alerts, verify rule 100100

---

## 🚨 VẤN ĐỀ HIỆN TẠI

### **1. Pipeline Delay So Với Wazuh**

**Timeline thực tế:**
```
T+0s:   Attack xảy ra
T+1s:   Wazuh Manager phát hiện, tạo alert
T+2-5s: Wazuh Manager → Indexer
T+5-30s: Indexer index → OpenSearch (DELAY!)
T+30s:  Pipeline query → mới thấy alert
```

**Nguyên nhân:**
- ⚠️ **Indexer delay:** 5-30 giây
- ⚠️ **Cursor logic:** Có thể skip alerts mới nếu indexer delay
- ⚠️ **Poll interval:** 8 giây (WAZUH_POLL_INTERVAL_SEC)

**Kết quả:**
- Pipeline delay **30-40 giây** so với Wazuh
- Có thể miss alerts nếu indexer delay > poll interval

---

### **2. Cursor Logic Gây Delay**

**Code hiện tại:**
```python
# wazuh_client.py line 461-497
if cursor:
    timestamp = cursor.get("timestamp")
    if timestamp:
        cursor_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        cursor_with_delay = cursor_dt - timedelta(seconds=INDEXER_DELAY_SECONDS)
        effective_timestamp = max(cursor_with_delay, cutoff_iso)
        filters.append({"range": {"@timestamp": {"gt": effective_timestamp}}})
```

**Vấn đề:**
- ❌ Cursor lưu timestamp của alert cuối cùng đã fetch
- ❌ Query chỉ fetch alerts **sau** cursor timestamp
- ❌ Nếu alert mới chưa được index → **miss**
- ❌ Nếu cursor cũ → fetch lại alerts cũ

**Ví dụ:**
```
Cursor: 2025-12-15T10:00:00Z
Alert mới: 2025-12-15T10:00:05Z (nhưng chưa được index)
Query: @timestamp > 2025-12-15T10:00:00Z
→ Không thấy alert vì chưa được index
→ Next poll: Alert đã được index nhưng cursor đã move → MISS!
```

---

### **3. Rule 100100 Filtering**

**Code hiện tại:**
```python
# Line 511-516: wazuh_client.py
# Filter pfSense spam: exclude rule 100100 (raw signature) ONLY for pfSense (agent 002)
must_not_filters: List[Dict[str, Any]] = []
if agent_id == "002":
    must_not_filters.append({"term": {"rule.id": "100100"}})

# Line 614-616: _fetch_alerts_for_agent
# Skip rule 100100 CHỈ cho pfSense (raw signature spam)
if agent_id_alert == "002" and rule_id == "100100":
    continue
```

**Phân tích:**
- ✅ **pfSense (agent 002):** Rule 100100 bị filter (spam)
- ✅ **WebServer (agent 001):** Rule 100100 **KHÔNG bị filter** → **VẪN được fetch** ✅
- ✅ **Other agents:** Rule 100100 **KHÔNG bị filter** → **VẪN được fetch** ✅

**Kết luận:**
- ✅ Pipeline **ĐANG lấy alerts rule 100100** cho WebServer và các agents khác
- ✅ Chỉ filter rule 100100 cho pfSense (agent 002) để tránh spam

---

## 🎯 GIẢI PHÁP: BỎ CURSOR, KHÔNG MISS ALERTS

### **Strategy: Time Window với Lookback**

**Thay vì dùng cursor:**
- ✅ Dùng time window với lookback đủ lớn
- ✅ Lookback = poll_interval + indexer_delay + buffer
- ✅ Mỗi poll: fetch alerts từ (now - lookback) đến now
- ✅ Deduplication bằng alert ID hoặc hash

**Lợi ích:**
- ✅ Không miss alerts (lookback đủ lớn)
- ✅ Không fetch alerts cũ (time window gần)
- ✅ Real-time hơn (không phụ thuộc cursor)

---

## 🔧 IMPLEMENTATION

### **Option 1: Sử dụng WAZUH_START_FROM_NOW (Recommended)**

**Code hiện tại đã có:**
```python
# Line 661-680: wazuh_client.py
if WAZUH_START_FROM_NOW:
    lookback_minutes = max(WAZUH_LOOKBACK_MINUTES, 5)
    now_with_delay = datetime.utcnow() - timedelta(minutes=lookback_minutes)
    cursor_state = {
        "timestamp": now_with_delay.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    }
```

**Vấn đề:**
- ⚠️ Vẫn tạo cursor_state (nhưng không load từ file)
- ⚠️ Lookback cố định (minutes), không dynamic

**Cải thiện:**
- ✅ Bỏ cursor hoàn toàn
- ✅ Dynamic lookback = poll_interval + indexer_delay + buffer
- ✅ Deduplication trong memory

---

### **Option 2: Real-time Mode (No Cursor)**

**Thay đổi:**
1. Bỏ cursor logic hoàn toàn
2. Dùng time window với dynamic lookback
3. Deduplication bằng alert ID

**Code:**
```python
# Dynamic lookback = poll_interval + indexer_delay + buffer
POLL_INTERVAL_SEC = WAZUH_POLL_INTERVAL_SEC  # 8 seconds
INDEXER_DELAY_SEC = 30  # Max indexer delay
BUFFER_SEC = 10  # Safety buffer
lookback_seconds = POLL_INTERVAL_SEC + INDEXER_DELAY_SEC + BUFFER_SEC
lookback_minutes = max(lookback_seconds / 60, 1)  # At least 1 minute

cutoff_time = datetime.utcnow() - timedelta(minutes=lookback_minutes)
cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

filters.append({"range": {"@timestamp": {"gt": cutoff_iso}}})
```

---

## 📊 VERIFICATION: Rule 100100

### **Test Case 1: WebServer (agent 001)**
```
Alert: Rule 100100, Level 3, Agent 001 (WebServer)
→ Filter check: agent_id != "002" → NOT filtered ✅
→ Query: rule.level >= 3 OR (rule.level 3-6 AND indicators) ✅
→ Result: INCLUDED ✅
```

### **Test Case 2: pfSense (agent 002)**
```
Alert: Rule 100100, Level 3, Agent 002 (pfSense)
→ Filter check: agent_id == "002" → FILTERED ❌
→ Query: must_not rule.id == "100100" for agent 002 ❌
→ Result: EXCLUDED (spam prevention) ✅
```

### **Test Case 3: Other Agents**
```
Alert: Rule 100100, Level 3, Agent 003
→ Filter check: agent_id != "002" → NOT filtered ✅
→ Query: rule.level >= 3 OR (rule.level 3-6 AND indicators) ✅
→ Result: INCLUDED ✅
```

**Kết luận:**
- ✅ Pipeline **ĐANG lấy alerts rule 100100** cho WebServer và agents khác
- ✅ Chỉ filter cho pfSense (agent 002) để tránh spam

---

## 🎯 RECOMMENDED SOLUTION

### **1. Enable WAZUH_START_FROM_NOW**

**`.env` file:**
```bash
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=1  # 1 minute lookback (8s poll + 30s indexer + buffer)
```

**Hoặc dynamic lookback:**
```bash
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=0  # 0 = auto-calculate from poll_interval
```

### **2. Cải Thiện Code để Dynamic Lookback**

**Thay đổi:**
- Calculate lookback từ poll_interval + indexer_delay + buffer
- Không dùng cursor file
- Deduplication trong memory

---

## 📝 SUMMARY

**Vấn đề:**
- ⚠️ Pipeline delay 30-40s so với Wazuh
- ⚠️ Cursor logic có thể miss alerts
- ⚠️ Indexer delay 5-30s

**Rule 100100:**
- ✅ **ĐANG được fetch** cho WebServer và agents khác
- ✅ Chỉ filter cho pfSense (agent 002)

**Giải pháp:**
- ✅ Bỏ cursor, dùng time window với dynamic lookback
- ✅ Enable WAZUH_START_FROM_NOW
- ✅ Deduplication trong memory

