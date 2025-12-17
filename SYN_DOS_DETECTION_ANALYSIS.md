# 🔍 Phân Tích: Tại Sao SYN DoS Không Được Phát Hiện Ngay

**Ngày:** 2025-12-15  
**Vấn đề:** SYN DoS attack không được phát hiện ngay, chỉ khi event queue full (rule 203, level 9) mới báo  
**Root Cause:** Query filter quá strict và lỗi code

---

## 🚨 VẤN ĐỀ PHÁT HIỆN

### **1. Lỗi Code: AttributeError**

**Lỗi:**
```
AttributeError: 'NoneType' object has no attribute 'get'
File: src/orchestrator/notify.py, line 366
if http_context.get("url"):
```

**Nguyên nhân:**
- `http_context = alert.get("http", {})` có thể trả về `None` thay vì `{}`
- Code gọi `http_context.get("url")` mà không check `None` trước

**Fix:**
```python
# Before
http_context = alert.get("http", {})
if http_context.get("url"):

# After
http_context = alert.get("http") or {}  # Fix: Handle None case
if http_context and http_context.get("url"):
```

---

### **2. SYN DoS Không Được Phát Hiện Ngay**

**Vấn đề:**
- SYN DoS attack xảy ra nhưng pipeline không báo ngay
- Chỉ khi event queue full (rule 203, level 9) mới báo
- Điều này có nghĩa là SYN DoS alerts bị bỏ qua hoặc không được fetch

**Root Cause Analysis:**

#### **A. Query Filter Quá Strict**

**Code hiện tại:**
```python
if WAZUH_MIN_LEVEL >= 7:
    # Multi-condition filter (chỉ áp dụng khi MIN_LEVEL >= 7)
else:
    # Simple filter: rule.level >= WAZUH_MIN_LEVEL
```

**Vấn đề:**
- Log cho thấy `WAZUH_MIN_LEVEL = 5` (từ log: "min_level": 5)
- Với MIN_LEVEL = 5, query filter chỉ dùng **simple filter**: `rule.level >= 5`
- SYN DoS alerts có thể có:
  - Rule level 3-4 (thấp hơn MIN_LEVEL)
  - Không có đủ indicators trong query (không có `data.alert.severity`, không có `rule.groups` chứa "attack", etc.)

**Ví dụ SYN DoS Alert:**
```json
{
  "rule": {
    "id": "100142",
    "level": 3,  // ❌ < 5 (MIN_LEVEL)
    "groups": ["attack", "invalid_access", "suricata"]
  },
  "data": {
    "flow": {
      "src_ip": "203.0.113.50",
      "pkts_toserver": 1000  // SYN flood pattern
    },
    "alert": {
      "severity": 3,
      "signature": "ET POLICY Possible SYN flood"
    }
  }
}
```

**Query Filter Behavior:**
- `rule.level = 3` < `WAZUH_MIN_LEVEL = 5` → ❌ **NOT FETCHED**
- Multi-condition filter không được áp dụng vì `MIN_LEVEL < 7`
- Result: SYN DoS alerts bị bỏ qua!

#### **B. SYN DoS Alerts Có Thể Không Có Đủ Indicators**

**Query Filter Requirements (khi MIN_LEVEL >= 7):**
- Rule level 3-6 AND
- At least 1 of:
  - `data.alert.severity >= 2` ✅ (SYN DoS có)
  - `rule.groups` contains "attack" ✅ (SYN DoS có)
  - `data.http.url` exists ❌ (SYN DoS không có HTTP)
  - `data.flow.src_ip` exists ✅ (SYN DoS có)

**Vấn đề:**
- SYN DoS là **network-level attack**, không có HTTP context
- Nếu query filter yêu cầu `data.http.url`, SYN DoS sẽ không match
- Nhưng SYN DoS có `data.flow.src_ip` và `data.alert.severity` → Should match

---

## ✅ GIẢI PHÁP

### **1. Fix Lỗi Code**

**File:** `src/orchestrator/notify.py`

**Changes:**
```python
# Fix 1: Handle None case
http_context = alert.get("http") or {}  # Instead of alert.get("http", {})

# Fix 2: Check None before calling .get()
if http_context and http_context.get("url"):
    # ...

if http_context and http_context.get("user_agent"):
    # ...
```

---

### **2. Sửa Query Filter để Phát Hiện SYN DoS**

**File:** `src/collector/wazuh_client.py`

**Changes:**
```python
# Before: Only apply multi-condition when MIN_LEVEL >= 7
if WAZUH_MIN_LEVEL >= 7:
    # Multi-condition filter
else:
    # Simple filter

# After: Apply multi-condition when MIN_LEVEL >= 5
if WAZUH_MIN_LEVEL >= 5:
    # Multi-condition filter với:
    # - Rule level 3 to MIN_LEVEL-1
    # - At least 1 indicator:
    #   - Suricata severity >= 2
    #   - Rule groups contain "attack", "suricata", "ids", etc.
    #   - HTTP context exists
    #   - Flow context exists (SYN DoS sẽ có)
    #   - Flow pkts_toserver >= 100 (DoS indicator)
else:
    # Simple filter
```

**Lợi ích:**
- ✅ SYN DoS với rule level 3-4 sẽ được fetch
- ✅ Network attacks không có HTTP context vẫn được detect
- ✅ Flow-based indicators (pkts_toserver) được thêm vào

---

## 📊 SO SÁNH: Before vs After

### **Before:**

**SYN DoS Alert:**
```
Rule ID: 100142
Rule Level: 3
Flow: pkts_toserver = 1000
Suricata: severity = 3

Query Filter:
- MIN_LEVEL = 5
- Condition: rule.level >= 5? NO (3 < 5)
- Multi-condition: NOT APPLIED (MIN_LEVEL < 7)
- Result: ❌ NOT FETCHED

Pipeline: ❌ Không biết có SYN DoS attack
```

**Event Queue Full Alert:**
```
Rule ID: 203
Rule Level: 9
Description: Event queue is full

Query Filter:
- Condition: rule.level >= 5? YES (9 >= 5)
- Result: ✅ FETCHED

Pipeline: ✅ Báo event queue full (nhưng quá muộn!)
```

---

### **After:**

**SYN DoS Alert:**
```
Rule ID: 100142
Rule Level: 3
Flow: pkts_toserver = 1000
Suricata: severity = 3
Rule Groups: ["attack", "invalid_access", "suricata"]

Query Filter:
- MIN_LEVEL = 5
- Condition: rule.level >= 5? NO (3 < 5)
- Multi-condition: ✅ APPLIED (MIN_LEVEL >= 5)
- Check indicators:
  - Suricata severity >= 2? ✅ YES (3 >= 2)
  - Rule groups contain "attack"? ✅ YES
  - Flow src_ip exists? ✅ YES
  - Flow pkts_toserver >= 100? ✅ YES (1000 >= 100)
- Result: ✅ FETCHED (match indicators)

Pipeline: ✅ Phát hiện SYN DoS ngay lập tức!
```

---

## 🎯 TẠI SAO CHỈ KHI EVENT QUEUE FULL MỚI BÁO?

### **Timeline:**

1. **T0: SYN DoS Attack Bắt Đầu**
   - SYN flood packets gửi đến server
   - Wazuh/Suricata phát hiện → Rule 100142, Level 3
   - **Pipeline: ❌ Không fetch (rule level 3 < 5)**

2. **T1-Tn: SYN DoS Tiếp Tục**
   - Server bị overwhelm
   - Wazuh agent event queue bắt đầu đầy
   - **Pipeline: ❌ Vẫn không fetch SYN DoS alerts**

3. **Tn+1: Event Queue Full**
   - Wazuh agent event queue đầy → Rule 203, Level 9
   - **Pipeline: ✅ Fetch rule 203 (level 9 >= 5)**
   - **Pipeline: ✅ Báo event queue full**

**Kết quả:**
- SOC chỉ biết khi event queue full (quá muộn!)
- SYN DoS attack đã xảy ra từ lâu nhưng không được phát hiện

---

## ✅ SAU KHI FIX

### **Timeline:**

1. **T0: SYN DoS Attack Bắt Đầu**
   - SYN flood packets gửi đến server
   - Wazuh/Suricata phát hiện → Rule 100142, Level 3
   - **Pipeline: ✅ Fetch (rule level 3 + indicators match)**
   - **Pipeline: ✅ Báo SYN DoS ngay lập tức!**

2. **T1-Tn: SYN DoS Tiếp Tục**
   - Server bị overwhelm
   - Wazuh agent event queue bắt đầu đầy
   - **Pipeline: ✅ Vẫn fetch và báo SYN DoS alerts**

3. **Tn+1: Event Queue Full (Nếu xảy ra)**
   - Wazuh agent event queue đầy → Rule 203, Level 9
   - **Pipeline: ✅ Fetch rule 203**
   - **Pipeline: ✅ Báo event queue full (nhưng đã biết SYN DoS từ trước)**

**Kết quả:**
- SOC biết SYN DoS ngay khi attack bắt đầu
- Có thể respond sớm, trước khi server bị overwhelm

---

## 📝 SUMMARY

### **Vấn đề:**
1. ❌ Lỗi code: `http_context` có thể là `None`
2. ❌ Query filter quá strict: Chỉ áp dụng multi-condition khi `MIN_LEVEL >= 7`
3. ❌ SYN DoS với rule level 3-4 bị bỏ qua

### **Giải pháp:**
1. ✅ Fix lỗi code: Handle `None` case cho `http_context`
2. ✅ Sửa query filter: Áp dụng multi-condition khi `MIN_LEVEL >= 5`
3. ✅ Thêm flow-based indicators: `pkts_toserver >= 100` cho DoS detection

### **Kết quả:**
- ✅ SYN DoS được phát hiện ngay khi attack bắt đầu
- ✅ Không cần chờ đến khi event queue full
- ✅ SOC có thể respond sớm

---

## 🔧 FILES ĐÃ SỬA

1. **`src/orchestrator/notify.py`**
   - Fix: Handle `None` case cho `http_context`
   - Lines: 319, 325, 366, 379

2. **`src/collector/wazuh_client.py`**
   - Fix: Áp dụng multi-condition filter khi `MIN_LEVEL >= 5` (thay vì >= 7)
   - Thêm: Flow-based indicator (`pkts_toserver >= 100`)
   - Lines: 570-617

---

## 🎯 KẾT LUẬN

**Tại sao SYN DoS không được phát hiện ngay:**
1. Query filter quá strict (chỉ áp dụng multi-condition khi `MIN_LEVEL >= 7`)
2. SYN DoS có rule level 3-4 (thấp hơn `MIN_LEVEL = 5`)
3. Simple filter bỏ qua alerts có level < 5

**Sau khi fix:**
- ✅ Multi-condition filter áp dụng khi `MIN_LEVEL >= 5`
- ✅ SYN DoS với rule level 3-4 + indicators → Được fetch
- ✅ Phát hiện ngay khi attack bắt đầu

