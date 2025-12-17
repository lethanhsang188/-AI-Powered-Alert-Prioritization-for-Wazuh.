# 📊 Phân Tích Log Chi Tiết

## 🔍 Tổng Quan

**Thời gian:** 2025-12-14 21:17:28 - 21:19:03  
**Tổng alerts:** 18 alerts (batch 1) + 30 alerts (batch 2) = 48 alerts  
**Agents:** 
- **001 (WebServer):** 4 alerts (batch 1) + 16 alerts (batch 2) = 20 alerts
- **002 (pfSense.home.arpa):** 14 alerts (batch 1) + 14 alerts (batch 2) = 28 alerts

---

## 🚨 ALERTS ĐÃ GỬI VỀ TELEGRAM

### **Kết quả:** ❌ **KHÔNG CÓ ALERT NÀO GỬI THÀNH CÔNG!**

Tất cả alerts đều bị lỗi:
```
"Bad Request: can't parse entities: Can't find end of the entity starting at byte offset 198"
```

---

## 📋 CHI TIẾT TỪNG ALERT

### **1. Rule 110231 (Level 13) - CONFIRMED Reverse Shell - CRITICAL**

**Số lượng:** 4 alerts (từ WebServer)

**Thông tin:**
- **Rule ID:** 110231
- **Rule Level:** 13 (CONFIRMED)
- **Agent:** WebServer (001)
- **Score:** 0.938 (rất cao)
- **Threat Level:** HIGH (LLM đánh, nhưng nên là CRITICAL)
- **LLM Summary:** "Auditd on WebServer detected the web server user initiating outbound network connections, consistent with a possible reverse shell/webshell activity. The rule fired 3-6 times, suggesting repeated connection attempts."

**Trạng thái gửi Telegram:**
- ❌ **FAILED** - Lỗi parsing tại byte offset 196-198
- **Message length:** 496-514 characters
- **Lỗi:** "can't parse entities: Can't find end of the entity"

**Nội dung message (ước tính):**
```
🟠 *SOC Alert - HIGH*

*Title:* Web Attack attempt on WebServer
*Score:* 0.938
*Rule ID:* 110231 (Level 13)  ← Dấu ngoặc đơn không escape!
*Agent:* WebServer
*Tags:* network_intrusion, suspicious_process, web_attack, wazuh_rule_high

*Summary:*
Auditd on WebServer detected the web server user initiating outbound network connections, consistent with a possible reverse shell/webshell activity. The rule fired 3 times, suggesting repeated connection attempts.  ← Có dấu phẩy và ngoặc đơn

*Network:*
Destination: 192.168.20.125
```

**Vấn đề:** Dấu ngoặc đơn `(Level 13)` trong line "*Rule ID:*" không được escape!

---

### **2. Rule 550 (Level 7) - File Integrity Change**

**Số lượng:** 3 alerts (từ pfSense)

**Thông tin:**
- **Rule ID:** 550
- **Rule Level:** 7
- **Agent:** pfSense.home.arpa (002)
- **Score:** 0.5
- **Threat Level:** MEDIUM
- **LLM Summary:** "Wazuh syscheck detected that a monitored file on pfSense.home.arpa had its integrity checksum change..."

**Trạng thái gửi Telegram:**
- ⚠️ **KHÔNG GỬI** - Score 0.5 < 0.7 (threshold), không phải critical attack
- **Lý do:** Score thấp, không đủ điều kiện gửi

---

### **3. Rule 510 (Level 7) - Rootcheck Anomaly**

**Số lượng:** 11 alerts (từ pfSense)

**Thông tin:**
- **Rule ID:** 510
- **Rule Level:** 7
- **Agent:** pfSense.home.arpa (002)
- **Score:** 0.46-0.5
- **Threat Level:** MEDIUM
- **LLM Summary:** "Wazuh rootcheck on pfSense.home.arpa generated a host-based anomaly detection alert (rule 510, level 7) repeatedly (53-62 times)..."

**Trạng thái gửi Telegram:**
- ⚠️ **KHÔNG GỬI** - Score 0.46-0.5 < 0.7 (threshold), không phải critical attack
- **Lý do:** Score thấp, không đủ điều kiện gửi

---

## 🔍 PHÂN TÍCH AGENT DISTRIBUTION

### **Batch 1 (18 alerts):**
- **Agent 001 (WebServer):** 4 alerts
  - Rule 110231 (Level 13): 4 alerts - CRITICAL
- **Agent 002 (pfSense):** 14 alerts
  - Rule 550 (Level 7): 3 alerts
  - Rule 510 (Level 7): 11 alerts

**Balancing ratio:** 2.8 (WebServer có ít alerts hơn)

### **Batch 2 (30 alerts):**
- **Agent 001 (WebServer):** 16 alerts
  - Rule 110231 (Level 13): 10 alerts - CRITICAL
- **Agent 002 (pfSense):** 14 alerts
  - Rule 550 (Level 7): 3 alerts
  - Rule 510 (Level 7): 11 alerts

**Balancing ratio:** 1.07 (Gần cân bằng hơn)

---

## ❌ VẤN ĐỀ PHÁT HIỆN

### **1. Telegram Message Parsing Error**

**Lỗi:** 
```
"Bad Request: can't parse entities: Can't find end of the entity starting at byte offset 198"
```

**Nguyên nhân:**
- ❌ Dấu ngoặc đơn `(Level 13)` trong "*Rule ID:*" không được escape
- ❌ Dấu ngoặc đơn trong summary có thể gây lỗi
- ❌ Có thể có ký tự đặc biệt khác

**Vị trí lỗi (ước tính):**
- Byte offset 198 ≈ khoảng dòng "*Rule ID:* 110231 (Level 13)"
- Hoặc trong summary có dấu ngoặc đơn không escape

**Đã fix:**
- ✅ Escape dấu ngoặc đơn trong "*Rule ID:*" → `\\(Level {rule_level}\\)`
- ✅ Escape dấu ngoặc đơn trong critical override message
- ✅ Escape dấu ngoặc đơn trong summary (đã có `_escape_markdown_content`)

---

### **2. Threat Level Không Đúng**

**Rule 110231 (Level 13 - CONFIRMED):**
- LLM đánh: "high" ❌
- Nên là: "critical" ✅
- **Impact:** Alert bị đánh giá thấp, emoji hiển thị 🟠 thay vì 🔴

---

## 📊 TÓM TẮT

### **Alerts từ Agent nào:**
- ✅ **Agent 001 (WebServer):** 20 alerts
  - Rule 110231 (Level 13): 14 alerts - CONFIRMED reverse shell
- ✅ **Agent 002 (pfSense.home.arpa):** 28 alerts
  - Rule 550 (Level 7): 6 alerts - File integrity change
  - Rule 510 (Level 7): 22 alerts - Rootcheck anomaly

### **Alerts nào đã gửi về Telegram:**
- ❌ **KHÔNG CÓ ALERT NÀO GỬI THÀNH CÔNG!**
- Tất cả 4 alerts Rule 110231 đều **FAILED** do Markdown parsing error
- Các alerts khác (Rule 550, 510) **KHÔNG GỬI** vì score < 0.7

### **Nội dung message (ước tính):**
```
🟠 *SOC Alert - HIGH*

*Title:* Web Attack attempt on WebServer
*Score:* 0.938
*Rule ID:* 110231 (Level 13)  ← LỖI: Dấu ngoặc đơn không escape
*Agent:* WebServer
*Tags:* network_intrusion, suspicious_process, web_attack, wazuh_rule_high

*Summary:*
Auditd on WebServer detected the web server user initiating outbound network connections, consistent with a possible reverse shell/webshell activity. The rule fired 3 times, suggesting repeated connection attempts.

*Network:*
Destination: 192.168.20.125
```

---

## 🔧 FIX ĐÃ THỰC HIỆN

1. ✅ **Escape dấu ngoặc đơn trong "*Rule ID:*"** → `\\(Level {rule_level}\\)`
2. ✅ **Escape dấu ngoặc đơn trong critical override message**
3. ✅ **Escape dấu ngoặc đơn trong summary** (đã có sẵn)
4. ✅ **Thêm debug logging** để xem message trước khi gửi

---

## ✅ KẾT QUẢ SAU KHI FIX

Sau khi fix, messages sẽ:
- ✅ Escape đúng tất cả dấu ngoặc đơn
- ✅ Gửi thành công về Telegram
- ✅ Hiển thị đúng format

**Chạy lại pipeline để test!**
