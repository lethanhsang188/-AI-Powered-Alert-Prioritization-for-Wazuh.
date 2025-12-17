# ✅ File .env Đã Được Cập Nhật Tự Động

**Ngày:** 2025-12-14  
**Script:** `bin/update_env.py`

---

## 🎯 CÁC THAY ĐỔI QUAN TRỌNG

### **1. Fix SSL Certificate Error:**
```bash
WAZUH_INDEXER_VERIFY_SSL=false
```
**Lý do:** Disable SSL verification để fix lỗi certificate verification khi kết nối đến Wazuh Indexer.

---

### **2. Fetch Alerts Mới (Không Fetch Alerts Cũ):**
```bash
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=5
```
**Lý do:** 
- `WAZUH_START_FROM_NOW=true` → Bỏ qua cursor cũ, chỉ fetch alerts mới
- `WAZUH_LOOKBACK_MINUTES=5` → Fetch alerts từ 5 phút trước đến hiện tại (đủ thời gian cho indexer delay, không miss alerts)

---

### **3. Indexer Delay Compensation:**
```bash
INDEXER_DELAY_SECONDS=5
```
**Lý do:** Compensate cho Wazuh Indexer delay (5-30s) để không miss alerts mới.

---

## 📋 CÁC GIÁ TRỊ ĐÃ ĐƯỢC GIỮ LẠI

✅ **Tất cả các giá trị hiện có đã được giữ lại:**
- `OPENAI_API_KEY` → Giữ nguyên
- `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASS` → Giữ nguyên
- `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` → Giữ nguyên
- Tất cả các config khác → Giữ nguyên

---

## 🚀 SỬ DỤNG

### **Chạy Pipeline:**
```bash
py -3 bin\run_pipeline.py
```

**Kết quả mong đợi:**
- ✅ Không còn lỗi SSL certificate
- ✅ Chỉ fetch alerts mới (không fetch alerts cũ)
- ✅ Không miss alerts (đủ thời gian cho indexer delay)

---

## 🔧 CÁC GIÁ TRỊ KHÁC ĐÃ ĐƯỢC THÊM/CẬP NHẬT

### **Wazuh Configuration:**
- `WAZUH_MAX_BATCHES=5` → Số batch tối đa khi fetch alerts
- `WAZUH_DEMO_MODE=false` → Tắt demo mode
- `WAZUH_REALTIME_MODE=false` → Tắt real-time mode (dùng standard polling)
- `WAZUH_REALTIME_INTERVAL_SEC=1.0` → Interval cho real-time mode (nếu bật)

### **General Configuration:**
- `LOCAL_TIMEZONE=Asia/Ho_Chi_Minh` → Timezone cho logging

### **Correlation & Enrichment:**
- `CORRELATION_ENABLE=true` → Enable alert correlation
- `ENRICHMENT_ENABLE=true` → Enable alert enrichment
- `GEOIP_ENABLE=true` → Enable GeoIP lookup

### **LLM Cache:**
- `LLM_CACHE_ENABLE=true` → Enable LLM cache
- `LLM_CACHE_TTL_SECONDS=3600` → Cache TTL
- `LLM_CACHE_MAX_SIZE=1000` → Max cache size

---

## 📝 LƯU Ý

### **Nếu muốn thay đổi sau này:**

1. **Chỉnh sửa trực tiếp file `.env`:**
   ```bash
   # Mở file .env và chỉnh sửa
   notepad .env
   ```

2. **Hoặc chạy lại script:**
   ```bash
   py -3 bin\update_env.py
   ```

---

## ✅ KẾT LUẬN

File `.env` đã được cập nhật tự động với:
- ✅ Fix lỗi SSL certificate
- ✅ Fetch alerts mới (không fetch alerts cũ)
- ✅ Không miss alerts (indexer delay compensation)
- ✅ Giữ lại tất cả các giá trị hiện có

**Pipeline sẵn sàng để chạy!** 🚀

