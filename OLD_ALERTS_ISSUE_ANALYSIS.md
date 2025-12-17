# 🔍 Phân Tích: Tại Sao Pipeline Hiển Thị Alerts Cũ

**Ngày:** 2025-12-14  
**Vấn đề:** Khi chạy pipeline, log hiển thị alerts cũ về XSS, nhưng lúc đó không có tấn công gì cả

---

## 🔍 NGUYÊN NHÂN

### **1. Cursor Logic (ROOT CAUSE)**

**Timeline:**
```
Lần chạy trước: 2025-12-14T10:13:19Z
  → Pipeline fetch alerts XSS
  → Save cursor: 2025-12-14T10:13:19.970Z

Lần chạy hiện tại: 2025-12-14T17:13:21Z
  → Load cursor: 2025-12-14T10:13:19.970Z (CŨ!)
  → Query: @timestamp > 2025-12-14T10:13:19.970Z
  → Fetch alerts từ 10:13:19 đến 17:13:21
  → → Bao gồm alerts XSS CŨ từ trước đó!
```

**Code hiện tại:**
```python
# wazuh_client.py line 609
cursor_state = self._load_cursor()  # Load cursor CŨ

# Line 411-429
if cursor:
    timestamp = cursor.get("timestamp")  # 2025-12-14T10:13:19.970Z
    effective_timestamp = max(timestamp, cutoff_iso)
    filters.append({"range": {"@timestamp": {"gt": effective_timestamp}}})
    # → Fetch alerts SAU cursor timestamp → Bao gồm alerts CŨ!
```

**Vấn đề:**
- ✅ Cursor lưu timestamp của alert **cuối cùng đã fetch**
- ❌ Khi pipeline start lại → fetch alerts **từ cursor đến now**
- ❌ Alerts cũ (XSS) vẫn nằm trong khoảng này → được fetch lại

**Kết luận:** ⚠️ **Cursor đang fetch lại alerts cũ từ lần chạy trước**

---

### **2. Time Window (CONTRIBUTING FACTOR)**

**Code hiện tại:**
```python
# wazuh_client.py line 401-403
time_window_hours = 24
cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
```

**Vấn đề:**
- Time window = 24h → có thể fetch alerts từ 24h trước
- Nếu cursor cũ hơn 24h → dùng cutoff time (24h trước)
- → Vẫn fetch alerts cũ trong 24h

**Kết luận:** ⚠️ **Time window 24h quá rộng → fetch alerts cũ**

---

## 🔧 GIẢI PHÁP

### **Giải pháp 1: Reset Cursor về "Now" (RECOMMENDED)**

**Cách 1: Dùng script reset_cursor.py**
```bash
# Reset cursor về 1 phút trước (chỉ fetch alerts mới)
py -3 bin\reset_cursor.py --hours 0.016  # 0.016 hours = 1 minute

# Hoặc xóa cursor hoàn toàn (fetch từ đầu)
py -3 bin\reset_cursor.py --hours 0
```

**Cách 2: Thêm option vào pipeline**
```python
# Thêm --start-from-now option
# Khi start pipeline, set cursor về "now" thay vì load cursor cũ
```

**Ưu điểm:**
- ✅ Chỉ fetch alerts mới từ khi start pipeline
- ✅ Không fetch alerts cũ

**Nhược điểm:**
- ⚠️ Có thể miss alerts nếu indexer delay

---

### **Giải pháp 2: Enable DEMO_MODE (RECOMMENDED)**

**Cấu hình:**
```bash
WAZUH_DEMO_MODE=true
WAZUH_LOOKBACK_MINUTES=1  # Chỉ fetch 1 phút gần nhất
```

**Ưu điểm:**
- ✅ Bỏ qua cursor → luôn fetch alerts mới nhất
- ✅ Chỉ fetch 1 phút gần nhất → không fetch alerts cũ
- ✅ Real-time hơn

**Nhược điểm:**
- ⚠️ Có thể miss alerts cũ hơn 1 phút

---

### **Giải pháp 3: Thêm "Start from Now" Logic**

**Code mới:**
```python
# Trong fetch_alerts()
# Nếu có env var WAZUH_START_FROM_NOW=true
# → Set cursor về "now" thay vì load cursor cũ

if os.getenv("WAZUH_START_FROM_NOW", "false").lower() == "true":
    # Set cursor về 1 phút trước (để chờ indexer delay)
    now_with_delay = datetime.utcnow() - timedelta(minutes=1)
    cursor_state = {"timestamp": now_with_delay.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"}
    logger.info("Starting from now (ignoring old cursor)")
else:
    cursor_state = self._load_cursor()
```

**Ưu điểm:**
- ✅ Có option để start từ "now"
- ✅ Không cần reset cursor thủ công

**Nhược điểm:**
- ⚠️ Cần thêm env var

---

## 🎯 KHUYẾN NGHỊ

### **Cho Testing/Demo:**

**Option 1: Reset cursor**
```bash
# Reset cursor về 1 phút trước
py -3 bin\reset_cursor.py --hours 0.016

# Sau đó chạy pipeline
py -3 bin\run_pipeline.py
```

**Option 2: Enable DEMO_MODE**
```bash
# Trong .env file
WAZUH_DEMO_MODE=true
WAZUH_LOOKBACK_MINUTES=1

# Chạy pipeline
py -3 bin\run_pipeline.py
```

---

## 📋 IMPLEMENTATION

**Cần thêm:**
1. Option `--start-from-now` vào `run_pipeline.py`
2. Hoặc env var `WAZUH_START_FROM_NOW=true`
3. Logic để set cursor về "now" khi start pipeline

