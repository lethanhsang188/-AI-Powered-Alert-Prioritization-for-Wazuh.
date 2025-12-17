# 🔍 Phân Tích Vấn Đề Real-Time Processing

**Ngày:** 2025-12-14  
**Vấn đề:** Pipeline không theo được thời gian thực - khi chạy SQL injection attack, pipeline vẫn chỉ hiển thị alerts cũ về XSS

---

## 🔍 NGUYÊN NHÂN PHÂN TÍCH

### **1. Indexer Delay (CRITICAL)**

**Vấn đề:**
- Wazuh Indexer (OpenSearch) có **delay 5-30 giây** để index alerts từ Wazuh Manager
- Khi alert xảy ra, nó phải:
  1. Wazuh Manager phát hiện → tạo alert
  2. Wazuh Manager gửi alert → Indexer
  3. Indexer index alert → OpenSearch
  4. Pipeline query OpenSearch → nhận alert

**Timeline thực tế:**
```
T+0s:   SQL injection attack xảy ra
T+1s:   Wazuh Manager phát hiện, tạo alert
T+2-5s: Wazuh Manager gửi alert → Indexer
T+5-30s: Indexer index alert → OpenSearch (DELAY!)
T+30s:  Pipeline query → mới thấy alert
```

**Kết luận:** ⚠️ **Indexer delay là nguyên nhân chính**

---

### **2. Cursor Logic (ISSUE)**

**Code hiện tại:**
```python
# wazuh_client.py line 405-419
if cursor:
    timestamp = cursor.get("timestamp")
    if isinstance(timestamp, str) and timestamp:
        effective_timestamp = max(timestamp, cutoff_iso)
        filters.append({"range": {"@timestamp": {"gt": effective_timestamp}}})
```

**Vấn đề:**
- Cursor lưu timestamp của alert **cuối cùng đã fetch**
- Query chỉ fetch alerts **sau** cursor timestamp
- Nếu cursor cũ → có thể skip alerts mới

**Ví dụ:**
```
Cursor: 2025-12-14T09:00:00Z
Alert mới: 2025-12-14T09:05:00Z (nhưng chưa được index)
Query: @timestamp > 2025-12-14T09:00:00Z
→ Không thấy alert mới vì chưa được index
```

**Kết luận:** ⚠️ **Cursor có thể skip alerts mới nếu indexer delay**

---

### **3. Time Window (ISSUE)**

**Code hiện tại:**
```python
# wazuh_client.py line 401-403
time_window_hours = 24
cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
```

**Vấn đề:**
- Time window 24h → OK
- Nhưng nếu cursor cũ hơn 24h → dùng cutoff time
- Cutoff time = **24h trước** → có thể skip alerts mới

**Kết luận:** ⚠️ **Time window có thể skip alerts mới**

---

### **4. DEMO_MODE (SOLUTION)**

**Code hiện tại:**
```python
# config.py line 65
WAZUH_DEMO_MODE = get_env_bool("WAZUH_DEMO_MODE", False)

# wazuh_client.py line 388-398
if WAZUH_DEMO_MODE:
    time_window_minutes = WAZUH_LOOKBACK_MINUTES
    cutoff_time = datetime.utcnow() - timedelta(minutes=time_window_minutes)
    filters.append({"range": {"@timestamp": {"gt": cutoff_iso}}})
```

**Giải pháp:**
- Enable `WAZUH_DEMO_MODE=true`
- Set `WAZUH_LOOKBACK_MINUTES=5` (chỉ fetch 5 phút gần nhất)
- **Bỏ qua cursor** → luôn fetch alerts mới nhất trong 5 phút

**Kết luận:** ✅ **DEMO_MODE là giải pháp tốt cho real-time**

---

### **5. Polling Interval (ISSUE)**

**Code hiện tại:**
```python
# config.py line 59
WAZUH_POLL_INTERVAL_SEC = get_env_int("WAZUH_POLL_INTERVAL_SEC", 8)
```

**Vấn đề:**
- Polling interval = 8 giây → có thể quá lâu
- Nếu indexer delay = 10 giây → pipeline có thể miss alerts

**Giải pháp:**
- Giảm polling interval xuống 2-3 giây
- Hoặc enable `WAZUH_REALTIME_MODE=true` với `WAZUH_REALTIME_INTERVAL_SEC=1.0`

**Kết luận:** ⚠️ **Polling interval có thể quá lâu**

---

## 🔧 GIẢI PHÁP

### **Giải pháp 1: Enable DEMO_MODE (RECOMMENDED)**

**Cấu hình:**
```bash
WAZUH_DEMO_MODE=true
WAZUH_LOOKBACK_MINUTES=5
```

**Ưu điểm:**
- ✅ Bỏ qua cursor → luôn fetch alerts mới nhất
- ✅ Chỉ fetch 5 phút gần nhất → giảm load
- ✅ Real-time hơn

**Nhược điểm:**
- ⚠️ Có thể miss alerts cũ hơn 5 phút
- ⚠️ Không dùng cursor → không track position

---

### **Giải pháp 2: Giảm Polling Interval**

**Cấu hình:**
```bash
WAZUH_POLL_INTERVAL_SEC=2
```

**Hoặc enable real-time mode:**
```bash
WAZUH_REALTIME_MODE=true
WAZUH_REALTIME_INTERVAL_SEC=1.0
```

**Ưu điểm:**
- ✅ Fetch thường xuyên hơn
- ✅ Giảm thời gian miss alerts

**Nhược điểm:**
- ⚠️ Tăng load lên Wazuh Indexer
- ⚠️ Vẫn có thể miss alerts nếu indexer delay > polling interval

---

### **Giải pháp 3: Thêm Indexer Delay Compensation**

**Code mới:**
```python
# Trong _build_indexer_query()
# Thêm delay compensation để chờ indexer
indexer_delay_seconds = 5  # Assume 5s delay
cutoff_time = datetime.utcnow() - timedelta(seconds=indexer_delay_seconds)
cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
```

**Ưu điểm:**
- ✅ Compensate cho indexer delay
- ✅ Không cần thay đổi cấu hình

**Nhược điểm:**
- ⚠️ Vẫn có thể miss alerts nếu delay > compensation

---

### **Giải pháp 4: Query với Time Range Gần Hơn**

**Code mới:**
```python
# Thêm option để query alerts trong 1 phút gần nhất
if cursor:
    # Use cursor
    pass
else:
    # No cursor: query last 1 minute for real-time
    cutoff_time = datetime.utcnow() - timedelta(minutes=1)
    cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    filters.append({"range": {"@timestamp": {"gt": cutoff_iso}}})
```

**Ưu điểm:**
- ✅ Fetch alerts mới nhất trong 1 phút
- ✅ Real-time hơn

**Nhược điểm:**
- ⚠️ Có thể miss alerts cũ hơn 1 phút

---

## 🎯 KHUYẾN NGHỊ

### **Cho Real-Time Processing:**

1. ✅ **Enable DEMO_MODE:**
   ```bash
   WAZUH_DEMO_MODE=true
   WAZUH_LOOKBACK_MINUTES=5
   ```

2. ✅ **Giảm Polling Interval:**
   ```bash
   WAZUH_POLL_INTERVAL_SEC=2
   ```

3. ✅ **Hoặc enable Real-Time Mode:**
   ```bash
   WAZUH_REALTIME_MODE=true
   WAZUH_REALTIME_INTERVAL_SEC=1.0
   ```

4. ✅ **Thêm Indexer Delay Compensation:**
   - Thêm 5-10 giây delay vào query để chờ indexer

---

## 📋 IMPLEMENTATION

**Cần update:**
1. `src/collector/wazuh_client.py` - Thêm indexer delay compensation
2. `env.template` - Thêm hướng dẫn về DEMO_MODE
3. `README.md` - Thêm hướng dẫn về real-time configuration

