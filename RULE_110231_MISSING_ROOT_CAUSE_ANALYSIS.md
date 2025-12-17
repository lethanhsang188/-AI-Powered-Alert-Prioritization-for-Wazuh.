# 🔍 Phân Tích Nguyên Nhân: Rule 110231 (Level 13) Bị Bỏ Sót

**Ngày:** 2025-12-14  
**Thời gian phân tích:** 16:03:17 - 16:05:09  
**Mục đích:** Tìm nguyên nhân tại sao Rule 110231 (Level 13) bị missing

---

## 📊 TIMELINE PHÂN TÍCH

### **1. Pipeline Start Time:**

```
Pipeline Start: 2025-12-14T16:03:17 (UTC+7)
              = 2025-12-14T09:03:17 UTC
```

### **2. Alert Timestamp từ Wazuh:**

```
Rule 110231: "Dec 14, 2025 @ 16:03:30" (local time)
           = 2025-12-14T09:03:30 UTC
```

### **3. Cursor State:**

```
Old Cursor: 2025-12-13T09:03:10.002Z
New Cursor: 2025-12-13T09:03:17.020Z (sau khi adjust)
Time Window: 24 hours
Cutoff Time: 2025-12-13T09:03:17.020Z (24h trước pipeline start)
```

---

## 🔍 NGUYÊN NHÂN PHÂN TÍCH

### **Vấn đề 1: Indexer Delay (MOST LIKELY)**

**Timeline:**
```
16:03:17 (local) = 09:03:17 UTC: Pipeline START, fetch alerts
16:03:30 (local) = 09:03:30 UTC: Alert Rule 110231 xảy ra (SAU khi fetch)
```

**Phân tích:**
- ✅ Pipeline fetch lúc **09:03:17 UTC**
- ✅ Alert xảy ra lúc **09:03:30 UTC** (13 giây SAU khi fetch)
- ❌ **Alert chưa được index vào OpenSearch** vào thời điểm fetch
- ❌ **Indexer delay:** Wazuh → Indexer thường có delay 5-30 giây

**Kết luận:** Alert xảy ra **SAU** khi pipeline đã fetch, nên không có trong kết quả.

---

### **Vấn đề 2: Cursor Logic**

**Code logic:**
```python
# Line 346-352: wazuh_client.py
timestamp = cursor.get("timestamp")
if isinstance(timestamp, str) and timestamp:
    # Use max of cursor timestamp or cutoff time
    effective_timestamp = max(timestamp, cutoff_iso)
    filters.append(
        {"range": {"@timestamp": {"gt": effective_timestamp}}}
    )
```

**Phân tích:**
- ✅ Cursor: `2025-12-13T09:03:10.002Z`
- ✅ Cutoff: `2025-12-13T09:03:17.020Z` (24h trước)
- ✅ Effective: `max(cursor, cutoff)` = `2025-12-13T09:03:17.020Z`
- ✅ Query: `@timestamp > 2025-12-13T09:03:17.020Z`

**Nếu alert có timestamp:**
- Alert: `2025-12-14T09:03:30 UTC`
- Query filter: `@timestamp > 2025-12-13T09:03:17.020Z`
- ✅ **Alert PHẢI được fetch** (vì 09:03:30 > 09:03:17)

**Kết luận:** Cursor logic **ĐÚNG**, không phải nguyên nhân.

---

### **Vấn đề 3: Query Filter**

**Code:**
```python
# Line 316-318: wazuh_client.py
filters: List[Dict[str, Any]] = [
    {"range": {"rule.level": {"gte": WAZUH_MIN_LEVEL}}}
]
# WAZUH_MIN_LEVEL = 7 (default)
```

**Phân tích:**
- ✅ Rule 110231 có Level **13**
- ✅ Query filter: `rule.level >= 7`
- ✅ **13 >= 7** → Alert PHẢI được fetch

**Kết luận:** Query filter **ĐÚNG**, không phải nguyên nhân.

---

### **Vấn đề 4: Rule 100100 Filter**

**Code:**
```python
# Line 384-386: wazuh_client.py
must_not_filters: List[Dict[str, Any]] = []
must_not_filters.append({"term": {"rule.id": "100100"}})
```

**Phân tích:**
- ✅ Rule 110231 có ID **"110231"**
- ✅ Filter chỉ exclude rule **"100100"**
- ✅ **110231 != 100100** → Alert KHÔNG bị filter

**Kết luận:** Rule filter **ĐÚNG**, không phải nguyên nhân.

---

### **Vấn đề 5: Agent Filter**

**Code:**
```python
# Line 378-380: wazuh_client.py
if agent_id:
    filters.append({"term": {"agent.id": agent_id}})
```

**Phân tích:**
- ✅ Alert từ Agent **"001"** (WebServer)
- ✅ Pipeline fetch từ agent **"001"** và **"002"**
- ✅ Alert PHẢI được fetch từ agent "001"

**Kết luận:** Agent filter **ĐÚNG**, không phải nguyên nhân.

---

### **Vấn đề 6: Batch Size Limit**

**Code:**
```python
# Line 536-537: wazuh_client.py
base_per_agent_size = 50  # Base size for adaptive balancing
per_agent_size = base_per_agent_size  # Start with base size
```

**Log:**
```
Fetched batch 1/5: 70 alerts from agents ['001', '002']
├─ Agent 001: 50 alerts
├─ Agent 002: 20 alerts
└─ Total: 70 alerts
```

**Phân tích:**
- ✅ Fetch 50 alerts từ agent "001"
- ✅ Alert Rule 110231 có thể nằm **ngoài 50 alerts đầu tiên**
- ⚠️ **Nếu có > 50 alerts từ agent "001"**, alert có thể bị skip

**Kết luận:** Có thể là nguyên nhân nếu có nhiều alerts từ agent "001".

---

## 🎯 KẾT LUẬN

### **Nguyên nhân chính (MOST LIKELY):**

**1. Indexer Delay (90% khả năng):**
- Alert xảy ra **SAU** khi pipeline đã fetch (13 giây)
- Alert chưa được index vào OpenSearch
- **Giải pháp:** Wait thêm vài giây hoặc fetch lại

**2. Batch Size Limit (10% khả năng):**
- Nếu có > 50 alerts từ agent "001", alert có thể nằm ngoài batch đầu tiên
- **Giải pháp:** Tăng `per_agent_size` hoặc fetch nhiều batches hơn

---

## 🔧 GIẢI PHÁP

### **1. Thêm Indexer Delay Wait:**

```python
# Trong wazuh_client.py
import time

def fetch_alerts(self, max_batches: Optional[int] = None) -> List[Dict[str, Any]]:
    # Wait for indexer to catch up (5-10 seconds)
    time.sleep(5)  # Wait for indexer delay
    # ... rest of code
```

### **2. Tăng Batch Size:**

```python
# Trong wazuh_client.py
base_per_agent_size = 100  # Tăng từ 50 lên 100
```

### **3. Fetch Nhiều Batches Hơn:**

```python
# Trong config.py
WAZUH_MAX_BATCHES = 10  # Tăng từ 5 lên 10
```

### **4. Thêm Logging để Debug:**

```python
# Log alerts có level >= 12
if rule_level >= 12:
    logger.warning(
        "CRITICAL ALERT FETCHED",
        extra={
            "rule_id": rule_id,
            "rule_level": rule_level,
            "timestamp": timestamp,
            "agent_id": agent_id
        }
    )
```

---

## 📋 RECOMMENDATION

**Immediate Fix:**
1. ✅ Thêm logging cho alerts có level >= 12
2. ✅ Tăng `per_agent_size` từ 50 lên 100
3. ✅ Tăng `WAZUH_MAX_BATCHES` từ 5 lên 10

**Long-term Fix:**
1. ✅ Thêm indexer delay wait (5-10 giây)
2. ✅ Implement retry logic cho critical alerts
3. ✅ Monitor indexer delay và adjust accordingly

---

## 🎯 TESTING

**Test case:**
1. Trigger Rule 110231 (Level 13) alert
2. Wait 10 giây
3. Run pipeline
4. Verify alert được fetch và process

**Expected result:**
- ✅ Alert Rule 110231 được fetch
- ✅ Alert được process với threat level "critical"
- ✅ Alert được notify (override threshold)

