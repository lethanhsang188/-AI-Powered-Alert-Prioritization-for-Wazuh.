# 📊 Phân Tích Log Chi Tiết - SQL Injection Attack Run

**Ngày:** 2025-12-14  
**Thời gian:** 17:27:58 - 17:28:52  
**Duration:** ~54 giây  
**Tổng alerts processed:** 22 alerts

---

## 🔍 PHÂN TÍCH TỪNG GIAI ĐOẠN

### **1. Pipeline Initialization (17:27:58)**

```
✅ SOC Pipeline Starting
✅ Standard polling mode (poll_interval_sec: 8)
✅ LLM enabled (model: gpt-5.2)
✅ Wazuh client initialized
   - API URL: https://192.168.10.128:55000
   - Indexer URL: https://192.168.10.128:9200
   - Min level: 5
```

**Status:** ✅ Khởi động thành công

---

### **2. Fetch Alerts (17:27:58)**

```
✅ Fetched batch 1/5: 50 alerts from agents ['001']
   - Agent 001 (WebServer): 50 alerts
   - Agent 002 (pfSense): 0 alerts
```

**Chi tiết fetch:**
```
✅ Alerts fetched and normalized successfully
   - Total alerts: 50
   - Batches fetched: 1
   - Critical alerts count: 28 ⚠️ (CÓ 28 alerts level >= 12!)
   - Min rule level: 7
   - Max rule level: 13 ⚠️ (CÓ Rule 110231 Level 13!)
   - Avg rule level: 10.48
   - Agent distribution:
     * 001:WebServer: 50 alerts
   - Cursor timestamp: 2025-12-14T09:17:50.533Z
```

**⚠️ CRITICAL ALERTS FOUND:**
```
WARNING: CRITICAL ALERTS (level >= 12) found during fetch
   - Critical count: 28
   - All are Rule 110231 (Level 13) - CONFIRMED: Network connect (reverse shell)
   - Timestamp: 2025-12-14T09:17:50.263Z - 2025-12-14T09:17:50.533Z
   - Agent: 001 (WebServer)
```

**Phân tích:**
- ✅ **Có 28 critical alerts** (Rule 110231, Level 13) → Đây là alerts CŨ từ 09:17:50 (8 giờ trước!)
- ✅ **Max rule level: 13** → Có CONFIRMED attacks
- ⚠️ **Chỉ có agent 001** → pfSense (002) không có alerts mới
- ⚠️ **Cursor: 2025-12-14T09:17:50.533Z** → Đây là cursor CŨ từ lần chạy trước

**Kết luận:** Pipeline đang fetch alerts CŨ (từ 8 giờ trước) thay vì alerts mới!

---

### **3. Processing Alerts (17:28:01 - 17:28:52)**

**Alerts được process:**

#### **A. Rule 31103 (Level 7) - SQL Injection:**
- **Count:** 11 alerts
- **Threat Level:** CRITICAL
- **Score:** 0.908 (trên threshold 0.70)
- **LLM Confidence:** 1.0 (100% - rất cao!)
- **LLM Tags:** ["web_attack", "sql_injection", "wazuh_rule_high"]
- **LLM Summary:** "Wazuh rule 31103 triggered repeatedly on the WebServer, indicating a suspected SQL injection attempt against a web application endpoint (MITRE T1190). The alert fired 11 times, suggesting repeated probing or exploitation attempts."
- **Threat Adjustment:** +0.1 (vì critical)
- **Severity:** 4 (CRITICAL)

**Phân tích:**
- ✅ **LLM nhận diện đúng** SQL injection (confidence 1.0)
- ✅ **Score cao** (0.908) → Sẽ được notify
- ✅ **MITRE T1190** được identify
- ⚠️ **"fired 11 times"** → LLM đang đếm số lần rule fire (có thể từ correlation)

---

#### **B. Rule 31152 (Level 10) - SQL Injection (Multiple attempts):**
- **Count:** 2 alerts
- **Threat Level:** HIGH
- **Score:** 0.877 (trên threshold 0.70)
- **LLM Confidence:** 0.72
- **LLM Tags:** ["wazuh_rule_high", "web_attack", "sql_injection", "web_scanning"]
- **LLM Summary:** "Wazuh detected multiple SQL injection attempt patterns in the web access logs from the same source IP against the WebServer agent. This indicates repeated probing/exploitation attempts targeting a web application."
- **Threat Adjustment:** +0.05 (vì high)
- **Severity:** 3 (HIGH)

**Phân tích:**
- ✅ **LLM nhận diện đúng** SQL injection + web_scanning
- ✅ **Score cao** (0.877) → Sẽ được notify
- ✅ **Nhận diện "same source IP"** → Correlation tốt

---

#### **C. Rule 31171 (Level 7) - SQL Injection (Pattern):**
- **Count:** 9 alerts
- **Threat Level:** MEDIUM/HIGH (thay đổi)
- **Score:** 0.618-0.708 (một số dưới threshold 0.70)
- **LLM Confidence:** 0.62-0.72
- **LLM Tags:** ["web_attack", "sql_injection", "wazuh_rule_medium"]
- **LLM Summary:** "Wazuh detected repeated SQL injection patterns in the web server access logs, triggering rule 31171 multiple times (21-28 times). This suggests an external client attempted to manipulate backend queries via crafted inputs."
- **Threat Adjustment:** 0.0 hoặc +0.05
- **Severity:** 2-3 (MEDIUM/HIGH)

**Phân tích:**
- ✅ **LLM nhận diện đúng** SQL injection
- ⚠️ **Score thấp hơn** (0.618) → Một số có thể không được notify
- ✅ **Nhận diện "automated probing"** → Context tốt

---

## 📊 STATISTICS

### **Fetch Statistics:**
- Total fetched: 50 alerts
- Agents: 1 (001: 50, 002: 0)
- Rule levels: 7-13 (min: 7, max: 13, avg: 10.48)
- **Critical alerts: 28** (Rule 110231, Level 13)

### **Processing Statistics:**
- Total processed: 22 alerts (44% của fetched)
- Processing time: ~54 giây
- Average processing time: ~2.5 giây/alert
- Rules processed:
  * Rule 31103: 11 alerts (50%) - SQL Injection (CRITICAL)
  * Rule 31152: 2 alerts (9%) - SQL Injection Multiple (HIGH)
  * Rule 31171: 9 alerts (41%) - SQL Injection Pattern (MEDIUM/HIGH)

### **AI Analysis Statistics:**
- LLM enabled: ✅ Yes
- Average LLM confidence: 0.62-1.0
- Threat levels:
  * CRITICAL: 11 alerts (50%)
  * HIGH: 3 alerts (13.6%)
  * MEDIUM: 8 alerts (36.4%)
  * LOW: 0 alerts

---

## ⚠️ VẤN ĐỀ PHÁT HIỆN

### **1. Fetch Alerts CŨ (8 giờ trước)**

**Timeline:**
```
Pipeline Start: 2025-12-14T17:27:58 (local) = 2025-12-14T10:27:58 UTC
Cursor: 2025-12-14T09:17:50.533Z (CŨ - từ 8 giờ trước!)
Alerts fetched: 2025-12-14T09:17:50.263Z - 2025-12-14T09:17:50.533Z
```

**Vấn đề:**
- ❌ **Cursor cũ** → Fetch alerts từ 8 giờ trước
- ❌ **Không có alerts mới** → Chỉ có alerts cũ (SQL injection từ trước)
- ❌ **28 critical alerts (Rule 110231)** → Đây là alerts CŨ từ 09:17:50

**Nguyên nhân:**
- Cursor đang lưu timestamp cũ từ lần chạy trước
- Pipeline fetch alerts từ cursor cũ đến hiện tại
- → Bao gồm alerts cũ (SQL injection từ 8 giờ trước)

**Giải pháp:**
- Set `WAZUH_START_FROM_NOW=true` trong `.env`
- Hoặc reset cursor: `py -3 bin\reset_cursor.py --hours 0.016`

---

### **2. Chỉ Process 22/50 Alerts (44%)**

**Vấn đề:**
- Fetched: 50 alerts
- Processed: 22 alerts
- Missing: 28 alerts (56% không được process!)

**Nguyên nhân:**
- Pipeline bị interrupt (Ctrl+C) sau 22 alerts
- Còn 28 alerts chưa kịp process

**Kết luận:** Đây KHÔNG phải bug, mà là do user stop pipeline sớm.

---

### **3. 28 Critical Alerts (Rule 110231) Không Được Process**

**Vấn đề:**
- Fetch: 28 critical alerts (Rule 110231, Level 13)
- Processed: 0 alerts Rule 110231
- Chỉ process: Rule 31103, 31152, 31171 (SQL injection)

**Nguyên nhân:**
- 28 alerts Rule 110231 nằm trong batch fetched
- Nhưng pipeline chỉ process 22 alerts đầu tiên
- 28 alerts Rule 110231 có thể nằm sau trong batch
- → Chưa kịp process vì pipeline bị interrupt

**Kết luận:** Cần để pipeline chạy đủ thời gian để process hết 50 alerts.

---

## ✅ ĐIỂM TÍCH CỰC

### **1. AI Phân Tích Tốt:**
- ✅ **LLM nhận diện đúng** SQL injection (confidence 1.0)
- ✅ **Score cao** (0.908) → Đúng với mức độ nguy hiểm
- ✅ **MITRE T1190** được identify
- ✅ **Context tốt** → "repeated probing", "same source IP"

### **2. Critical Alerts Detection:**
- ✅ **28 critical alerts** được detect trong fetch
- ✅ **Logging tốt** → Có warning về critical alerts
- ✅ **Rule 110231 (Level 13)** được fetch

### **3. Threat Level Assessment:**
- ✅ **CRITICAL** cho Rule 31103 (SQL injection) → Đúng
- ✅ **HIGH** cho Rule 31152 (Multiple attempts) → Đúng
- ✅ **MEDIUM/HIGH** cho Rule 31171 (Pattern) → Đúng

---

## 🎯 KẾT LUẬN

### **✅ Hoạt động tốt:**
1. ✅ Pipeline khởi động thành công
2. ✅ AI phân tích tốt (LLM confidence 1.0, nhận diện đúng SQL injection)
3. ✅ Critical alerts được detect (28 alerts Rule 110231)
4. ✅ Score cao (0.908) → Đúng với mức độ nguy hiểm

### **⚠️ Vấn đề:**
1. ⚠️ **Fetch alerts CŨ** (từ 8 giờ trước) thay vì alerts mới
   - **Nguyên nhân:** Cursor cũ
   - **Giải pháp:** Set `WAZUH_START_FROM_NOW=true`

2. ⚠️ **Chỉ process 22/50 alerts** (44%)
   - **Nguyên nhân:** Pipeline bị interrupt (Ctrl+C)
   - **Giải pháp:** Để pipeline chạy đủ thời gian

3. ⚠️ **28 critical alerts không được process**
   - **Nguyên nhân:** Nằm sau trong batch, chưa kịp process
   - **Giải pháp:** Để pipeline chạy đủ thời gian

---

## 📋 RECOMMENDATIONS

### **Để chỉ fetch alerts mới:**
```bash
# Thêm vào .env
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=5
```

### **Để process hết alerts:**
- Để pipeline chạy đủ thời gian (không nhấn Ctrl+C sớm)
- 50 alerts cần ~125 giây (2 phút) để process

### **Để test real-time:**
1. Set `WAZUH_START_FROM_NOW=true`
2. Chạy pipeline
3. Sau đó mới tấn công SQL injection
4. Pipeline sẽ fetch alerts mới (không fetch alerts cũ)

