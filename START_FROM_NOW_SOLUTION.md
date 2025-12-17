# 🔧 Giải Pháp: Start From Now - Không Miss Alerts

**Ngày:** 2025-12-14  
**Mục đích:** Bỏ qua cursor cũ, fetch alerts mới nhất, nhưng KHÔNG bị miss alerts

---

## 🎯 YÊU CẦU

1. ✅ **Bỏ qua cursor cũ** → Không fetch alerts cũ (XSS từ trước)
2. ✅ **Fetch alerts mới nhất** → Chỉ fetch alerts từ khi start pipeline
3. ✅ **KHÔNG miss alerts** → Phải fetch đủ alerts mới (kể cả alerts đang được index)

---

## 🔍 VẤN ĐỀ VỚI GIẢI PHÁP CŨ

### **Giải pháp cũ (1 phút):**
```python
now_with_delay = datetime.utcnow() - timedelta(minutes=1)
```

**Vấn đề:**
- ⚠️ Chỉ fetch 1 phút gần nhất
- ⚠️ Nếu indexer delay > 1 phút → **miss alerts**
- ⚠️ Nếu alert xảy ra 2 phút trước nhưng chưa được index → **miss**

---

## ✅ GIẢI PHÁP MỚI

### **Sử dụng `WAZUH_LOOKBACK_MINUTES`:**

```python
# Sử dụng LOOKBACK_MINUTES để xác định khoảng thời gian fetch
# Đảm bảo đủ thời gian để chờ indexer delay
lookback_minutes = max(WAZUH_LOOKBACK_MINUTES, 5)  # Tối thiểu 5 phút
now_with_delay = datetime.utcnow() - timedelta(minutes=lookback_minutes)
```

**Ưu điểm:**
- ✅ **Có thể config** → User set `WAZUH_LOOKBACK_MINUTES` theo nhu cầu
- ✅ **Tối thiểu 5 phút** → Đủ thời gian để chờ indexer delay (5-30s)
- ✅ **Không miss alerts** → Fetch đủ alerts mới trong khoảng thời gian này
- ✅ **Không fetch alerts cũ** → Chỉ fetch trong khoảng thời gian gần nhất

---

## 📋 CẤU HÌNH

### **Option 1: Start From Now với Lookback 5 phút (RECOMMENDED)**

**`.env` file:**
```bash
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=5
```

**Kết quả:**
- ✅ Bỏ qua cursor cũ
- ✅ Fetch alerts từ 5 phút trước đến hiện tại
- ✅ Đủ thời gian để chờ indexer delay
- ✅ Không miss alerts mới

---

### **Option 2: Start From Now với Lookback 10 phút (SAFER)**

**`.env` file:**
```bash
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=10
```

**Kết quả:**
- ✅ Bỏ qua cursor cũ
- ✅ Fetch alerts từ 10 phút trước đến hiện tại
- ✅ An toàn hơn (nếu indexer delay lớn)
- ✅ Vẫn không fetch alerts cũ (chỉ 10 phút gần nhất)

---

### **Option 3: DEMO_MODE (ALTERNATIVE)**

**`.env` file:**
```bash
WAZUH_DEMO_MODE=true
WAZUH_LOOKBACK_MINUTES=5
```

**Kết quả:**
- ✅ Bỏ qua cursor (luôn fetch từ LOOKBACK_MINUTES)
- ✅ Fetch alerts từ 5 phút trước đến hiện tại
- ✅ Real-time hơn (không dùng cursor)

---

## 🔍 SO SÁNH

### **Start From Now (1 phút) - CŨ:**
- ❌ Có thể miss alerts nếu indexer delay > 1 phút
- ✅ Chỉ fetch 1 phút gần nhất

### **Start From Now (5-10 phút) - MỚI:**
- ✅ Không miss alerts (đủ thời gian cho indexer delay)
- ✅ Chỉ fetch 5-10 phút gần nhất (không fetch alerts cũ)
- ✅ Có thể config theo nhu cầu

---

## 🎯 KHUYẾN NGHỊ

### **Cho Testing/Demo:**
```bash
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=5
```

**Lý do:**
- 5 phút đủ để chờ indexer delay (5-30s)
- Không fetch alerts cũ (chỉ 5 phút gần nhất)
- Phù hợp cho testing

### **Cho Production (nếu cần an toàn hơn):**
```bash
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=10
```

**Lý do:**
- 10 phút an toàn hơn (nếu indexer delay lớn)
- Vẫn không fetch alerts cũ (chỉ 10 phút gần nhất)

---

## 📊 TIMELINE

### **Với `WAZUH_START_FROM_NOW=true` và `WAZUH_LOOKBACK_MINUTES=5`:**

```
Pipeline Start: 2025-12-14T17:13:21Z
Lookback: 5 phút
Fetch From: 2025-12-14T17:08:21Z (5 phút trước)

Timeline:
17:08:21Z - 17:13:21Z: Fetch alerts trong khoảng này
  → Bao gồm alerts mới từ 5 phút trước
  → Đủ thời gian để chờ indexer delay
  → Không fetch alerts cũ (trước 17:08:21Z)
```

**Kết quả:**
- ✅ Fetch alerts mới (từ 5 phút trước)
- ✅ Không miss alerts (đủ thời gian cho indexer delay)
- ✅ Không fetch alerts cũ (chỉ 5 phút gần nhất)

---

## 🔧 IMPLEMENTATION

**Code đã được cập nhật:**
- ✅ Sử dụng `WAZUH_LOOKBACK_MINUTES` thay vì hardcode 1 phút
- ✅ Tối thiểu 5 phút để đảm bảo không miss alerts
- ✅ Có thể config theo nhu cầu

**Cách sử dụng:**
1. Set `WAZUH_START_FROM_NOW=true` trong `.env`
2. Set `WAZUH_LOOKBACK_MINUTES=5` (hoặc 10 cho an toàn hơn)
3. Chạy pipeline → Chỉ fetch alerts mới, không miss alerts

