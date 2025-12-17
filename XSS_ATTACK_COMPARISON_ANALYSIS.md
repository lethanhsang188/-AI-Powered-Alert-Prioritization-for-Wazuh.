# 🔍 So Sánh: Wazuh Alerts vs Pipeline Log - XSS Attack

**Ngày:** 2025-12-14  
**Thời gian:** 16:03:17 - 16:05:09  
**Mục đích:** So sánh alerts từ Wazuh với log pipeline khi tấn công XSS

---

## 📊 PHÂN TÍCH WAZUH ALERTS (Từ Image)

### **Alerts từ Wazuh Dashboard:**

**1. XSS Attacks (Rule 31105, Level 7):**
- ✅ Nhiều alerts: "XSS (Cross Site Scripting) attempt"
- ✅ Timestamp: 16:03:30 - 16:03:42
- ✅ Agent: WebServer
- ✅ Rule Level: 7

**2. Suricata Raw Signatures (Rule 100100, Level 3):**
- ✅ 2 alerts: "Suricata: Alert (raw signature)"
- ✅ Timestamp: 16:03:36, 16:03:38
- ✅ Agent: WebServer
- ✅ Rule Level: 3

**3. CONFIRMED Reverse Shell (Rule 110231, Level 13):**
- ⚠️ **2 alerts: "CONFIRMED(13): Network connect by web server user (possible reverse shell)"**
- ⚠️ Timestamp: 16:03:30
- ⚠️ Agent: WebServer
- ⚠️ Rule Level: **13** (CRITICAL)

---

## 📊 PHÂN TÍCH PIPELINE LOG

### **1. Fetch Phase:**

```
Fetched batch 1/5: 70 alerts from agents ['001', '002']
├─ Agent 001 (WebServer): 50 alerts
├─ Agent 002 (pfSense): 20 alerts
├─ min_rule_level: 5
├─ max_rule_level: 7  ⚠️ (KHÔNG có Level 13!)
├─ avg_rule_level: 6.8
└─ balancing_ratio: 2.38
```

**Vấn đề phát hiện:**
- ❌ **Rule 110231 (Level 13) KHÔNG có trong fetch!**
- ❌ max_rule_level chỉ là 7, nhưng Wazuh có Level 13
- ✅ Rule 100100 (Level 3) bị filter (đúng, vì là spam)

---

### **2. Processing Phase:**

**XSS Alerts (Rule 31105) - Đã xử lý:**

```
Rule 31105 (XSS):
├─ Count: 7 alerts processed
├─ Score: 0.855 (cao)
├─ Threat Level: HIGH
├─ LLM Confidence: 0.87 (rất chắc chắn)
├─ LLM Tags: ["web_attack", "xss", "wazuh_rule_high"]
├─ LLM Summary: "Wazuh rule 31105 triggered on the WebServer, indicating a potential Cross-Site Scripting (XSS) attempt..."
└─ Status: ✅ Xử lý thành công
```

**Other Alerts:**
- Rule 2904 (Level 7): dpkg half-configured - Score 0.478, Threat LOW
- Rule 2902 (Level 7): dpkg package install - Score 0.5, Threat MEDIUM
- Rule 510 (Level 7): rootcheck anomaly - Score 0.42-0.46, Threat MEDIUM

**Total Processed:** 36 alerts (từ 70 alerts fetched)

---

## ⚠️ VẤN ĐỀ PHÁT HIỆN

### **1. Missing Critical Alert: Rule 110231 (Level 13)**

**Wazuh có:**
- ✅ Rule 110231 (Level 13): "CONFIRMED: Network connect (reverse shell)"
- ✅ Timestamp: 16:03:30
- ✅ Agent: WebServer

**Pipeline KHÔNG có:**
- ❌ Rule 110231 KHÔNG xuất hiện trong fetch log
- ❌ max_rule_level chỉ là 7 (không có Level 13)
- ❌ Không có alert nào được process với Level 13

**Nguyên nhân có thể:**
1. **Time window issue:** Alert Level 13 có timestamp 16:03:30, nhưng cursor có thể đã skip
2. **Query filter:** Có thể query không fetch được Level 13
3. **Indexer delay:** Alert Level 13 có thể chưa được index vào thời điểm fetch

---

### **2. Rule 100100 (Level 3) - Đã filter đúng**

**Wazuh có:**
- ✅ Rule 100100 (Level 3): "Suricata: Alert (raw signature)"
- ✅ 2 alerts

**Pipeline:**
- ✅ **Đã filter đúng** (code có logic skip rule 100100)
- ✅ Không xuất hiện trong processed alerts

---

## ✅ ĐIỂM TÍCH CỰC

### **1. XSS Detection hoạt động tốt:**

```
Rule 31105 (XSS):
├─ AI đã nhận ra: ✅ XSS attack
├─ Threat Level: ✅ HIGH (đúng)
├─ Confidence: ✅ 0.87 (rất chắc chắn)
├─ Tags: ✅ ["web_attack", "xss", "wazuh_rule_high"]
├─ Score: ✅ 0.855 (cao, trên threshold 0.70)
└─ Summary: ✅ "XSS attempt observed in web access logs"
```

**Kết luận:** AI đã phân tích đúng XSS attacks, đánh giá threat level cao, và tạo summary phù hợp.

---

### **2. Agent Distribution hoạt động:**

```
Agent Distribution:
├─ Agent 001 (WebServer): 50 alerts
├─ Agent 002 (pfSense): 20 alerts
├─ Balancing Ratio: 2.38 (có imbalance, nhưng đã fetch từ cả 2 agents)
└─ Status: ✅ Đã fetch từ cả 2 agents
```

---

## 🔧 KHUYẾN NGHỊ

### **1. Kiểm tra Rule 110231 (Level 13) bị missing:**

**Cần kiểm tra:**
- ✅ Query có filter theo `rule.level` không?
- ✅ Time window có đủ rộng không?
- ✅ Indexer có delay không?
- ✅ Cursor có skip alerts không?

**Giải pháp:**
```python
# Kiểm tra query trong wazuh_client.py
# Đảm bảo không filter theo rule level (chỉ filter theo min_level)
# Đảm bảo time window đủ rộng để capture Level 13 alerts
```

---

### **2. Logging cải thiện:**

**Thêm logging:**
- ✅ Log rule IDs và levels của alerts bị skip
- ✅ Log alerts có level >= 12 (critical)
- ✅ Log alerts có rule_id trong CRITICAL_ATTACK_RULES

---

## 📋 TÓM TẮT

### **✅ Đã xử lý đúng:**
1. ✅ XSS attacks (Rule 31105) - 7 alerts, score 0.855, threat HIGH
2. ✅ Filter rule 100100 (spam) - đúng
3. ✅ Agent distribution - đã fetch từ cả 2 agents
4. ✅ AI analysis - đánh giá đúng threat level và tạo summary

### **⚠️ Vấn đề:**
1. ⚠️ **Rule 110231 (Level 13) - CONFIRMED reverse shell BỊ MISSING!**
   - Wazuh có 2 alerts Level 13
   - Pipeline không fetch được
   - Cần kiểm tra query và time window

### **🎯 Kết luận:**
- Pipeline xử lý XSS attacks **TỐT**
- AI phân tích XSS **CHÍNH XÁC** (confidence 0.87, threat HIGH)
- **NHƯNG** missing critical alerts Level 13 cần được fix ngay

---

## 🔍 NEXT STEPS

1. **Kiểm tra query:** Đảm bảo không filter Level 13 alerts
2. **Kiểm tra time window:** Đảm bảo đủ rộng để capture Level 13
3. **Thêm logging:** Log alerts có level >= 12 để debug
4. **Test lại:** Chạy pipeline và verify Level 13 alerts được fetch

