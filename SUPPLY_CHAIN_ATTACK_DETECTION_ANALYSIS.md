# Phân Tích: Supply Chain Attack Detection

## 🎯 Câu Hỏi

**Pipeline có thể nhận ra supply chain attack không?**
- Ví dụ: Xả 1 tràng XSS payload → sau đó xả 1 tràng SQL injection (sqlmap)
- Có thể hiển thị alerts theo real-time không?

---

## 📊 Phân Tích Hiện Tại

### 1. **Correlation Engine - Vấn Đề**

**Code hiện tại:** `src/common/correlation.py`

**Correlation types:**
```python
correlation_types = ["source_attack", "destination_attack", "signature", "rule_pattern"]
```

**Vấn đề:**
- `source_attack` = `src:{srcip}:attack:{attack_type}`
  - XSS: `src:1.2.3.4:attack:xss`
  - SQL injection: `src:1.2.3.4:attack:sql_injection`
  - → **Khác group keys → Không group lại được!**

**Kết quả:**
- ❌ XSS và SQL injection từ cùng source IP → **KHÔNG được group**
- ❌ Không detect được supply chain attack (multi-stage attack)

---

### 2. **Real-Time Processing - Status**

**Poll interval:** 8 giây (`WAZUH_POLL_INTERVAL_SEC`)

**Lookback window:** 48 giây
- Poll interval: 8s
- Max indexer delay: 30s
- Safety buffer: 10s
- **Total: 48s ≈ 1 minute**

**Timeline:**
```
T+0s:   Attack xảy ra
T+1s:   Wazuh Manager phát hiện
T+2-5s: Wazuh Manager → Indexer
T+5-30s: Indexer index → OpenSearch (DELAY!)
T+30s:  Pipeline query → nhận alert
T+38s:  Pipeline process → notify (nếu poll interval = 8s)
```

**Kết luận:**
- ✅ **Có thể hiển thị real-time** nhưng có delay **8-48 giây**
- ✅ Delay chủ yếu do indexer (5-30s), không phải pipeline

---

### 3. **Attack Tool Detection - Status**

**Code:** `src/analyzer/heuristic.py:200-204`

**Detected tools:**
```python
attack_tools = ["sqlmap", "nmap", "nikto", "burp", "metasploit", "w3af", "acunetix"]
```

**Bonus:**
- Attack tool detected: +0.15 score
- Large campaign (>=5 alerts): +0.20 score

**Kết luận:**
- ✅ **Có thể detect sqlmap** từ user agent
- ✅ Có bonus cho attack tools và campaigns

---

## ❌ Vấn Đề: Supply Chain Attack Detection

### **Scenario: Supply Chain Attack**

**Timeline:**
```
T+0s:   Attacker xả 10 XSS payloads từ 1.2.3.4
T+30s:  Pipeline nhận XSS alerts → Group: src:1.2.3.4:attack:xss (10 alerts)
T+60s:  Attacker chuyển sang SQL injection (sqlmap) từ 1.2.3.4
T+90s:  Pipeline nhận SQL injection alerts → Group: src:1.2.3.4:attack:sql_injection (20 alerts)
```

**Vấn đề:**
- ❌ XSS group: `src:1.2.3.4:attack:xss` (10 alerts)
- ❌ SQL injection group: `src:1.2.3.4:attack:sql_injection` (20 alerts)
- ❌ **Không có cách nào link 2 groups lại** → Không detect được supply chain attack!

**Kết quả:**
- SOC analyst thấy 2 campaigns riêng biệt
- Không biết đây là **cùng 1 attacker** đang thực hiện multi-stage attack

---

## ✅ Giải Pháp Đề Xuất

### 1. **Thêm Correlation Type: `source_campaign`**

**Mục đích:** Group tất cả attacks từ cùng source IP, không phân biệt attack type

**Implementation:**
```python
# Thêm vào correlation_types
correlation_types = [
    "source_campaign",  # NEW: Group all attacks from same source
    "source_attack",    # Existing: Group same attack type from same source
    "destination_attack",
    "signature",
    "rule_pattern"
]

# Thêm vào _generate_group_key
elif correlation_type == "source_campaign":
    if srcip:
        return f"campaign:src:{srcip}"  # No attack_type!
```

**Kết quả:**
- ✅ XSS và SQL injection từ cùng source → **Cùng campaign group**
- ✅ Detect được supply chain attack

---

### 2. **Supply Chain Attack Detection**

**Logic:**
```python
def detect_supply_chain_attack(campaign_group: List[Dict]) -> Dict[str, Any]:
    """
    Detect supply chain attack: Multiple attack types from same source
    in short time window.
    """
    attack_types = set()
    for alert in campaign_group:
        attack_type = normalize_attack_type(alert)
        if attack_type:
            attack_types.add(attack_type)
    
    # Supply chain = 2+ different attack types from same source
    if len(attack_types) >= 2:
        return {
            "is_supply_chain": True,
            "attack_types": list(attack_types),
            "count": len(campaign_group),
            "severity": "high" if len(attack_types) >= 3 else "medium"
        }
    
    return {"is_supply_chain": False}
```

**Ví dụ:**
- Campaign: `campaign:src:1.2.3.4`
  - 10 XSS alerts
  - 20 SQL injection alerts
  - → **Supply chain detected:** `["xss", "sql_injection"]`

---

### 3. **Enhanced Notification**

**Thêm vào Telegram message:**
```
🚨 SUPPLY CHAIN ATTACK DETECTED 🚨

Source IP: 1.2.3.4
Attack Types: XSS → SQL Injection
Total Alerts: 30
Time Span: 2 minutes

This indicates a coordinated multi-stage attack!
```

**Priority boost:**
- Supply chain attack → **Always notify** (override thresholds)
- Threat level: **Critical**

---

## 📊 So Sánh: Trước vs Sau

### **Trước (Hiện Tại):**

```
XSS alerts (10):
- Group: src:1.2.3.4:attack:xss
- Correlation: is_correlated=True, group_size=10

SQL injection alerts (20):
- Group: src:1.2.3.4:attack:sql_injection
- Correlation: is_correlated=True, group_size=20

→ SOC thấy 2 campaigns riêng biệt ❌
```

### **Sau (Với source_campaign):**

```
XSS alerts (10):
- Group: src:1.2.3.4:attack:xss
- Campaign: campaign:src:1.2.3.4
- Correlation: is_correlated=True, group_size=10

SQL injection alerts (20):
- Group: src:1.2.3.4:attack:sql_injection
- Campaign: campaign:src:1.2.3.4  ← Same campaign!
- Correlation: is_correlated=True, group_size=30 (total)
- Supply chain: is_supply_chain=True, attack_types=["xss", "sql_injection"]

→ SOC thấy 1 supply chain attack! ✅
```

---

## ⚡ Real-Time Processing

### **Current Status:**

**Delay breakdown:**
- Indexer delay: 5-30s (không kiểm soát được)
- Poll interval: 8s (có thể giảm xuống 5s)
- Processing: <1s (nhanh)

**Total delay: 8-48 giây**

### **Cải Thiện:**

1. **Giảm poll interval:**
   - Hiện tại: 8s
   - Có thể: 5s (nhanh hơn 37.5%)
   - Trade-off: Tăng CPU usage

2. **Parallel processing:**
   - Process alerts song song (nếu có nhiều alerts)
   - Giảm processing time

3. **Streaming mode (future):**
   - WebSocket connection với Wazuh
   - Real-time alerts (delay <1s)
   - Cần Wazuh API support

---

## 🎯 Kết Luận

### **Hiện Tại:**

1. ✅ **Real-time:** Có thể hiển thị alerts trong 8-48 giây
2. ✅ **Attack tool detection:** Có thể detect sqlmap
3. ❌ **Supply chain detection:** KHÔNG - XSS và SQL injection không được group lại

### **Sau Khi Cải Thiện:**

1. ✅ **Real-time:** Vẫn 8-48 giây (có thể giảm xuống 5-40s)
2. ✅ **Attack tool detection:** Vẫn hoạt động
3. ✅ **Supply chain detection:** CÓ - Detect multi-stage attacks từ cùng source

---

## 📝 Khuyến Nghị

### **Priority 1: Thêm source_campaign correlation**

**Impact:** High
**Effort:** Low (1-2 giờ)
**Benefit:** Detect supply chain attacks, improve SOC visibility

### **Priority 2: Supply chain detection logic**

**Impact:** High
**Effort:** Medium (2-3 giờ)
**Benefit:** Auto-detect multi-stage attacks, priority boost

### **Priority 3: Enhanced notification**

**Impact:** Medium
**Effort:** Low (1 giờ)
**Benefit:** Better SOC awareness, faster response

### **Priority 4: Reduce poll interval**

**Impact:** Low
**Effort:** Low (5 phút)
**Benefit:** Slightly faster real-time (8s → 5s)

---

## 🔍 Test Case

### **Scenario: Supply Chain Attack**

**Setup:**
1. Attacker xả 10 XSS payloads từ 1.2.3.4
2. Sau 1 phút, attacker chuyển sang SQL injection (sqlmap) từ 1.2.3.4
3. Pipeline process alerts

**Expected (Sau khi implement):**
```
Campaign: campaign:src:1.2.3.4
- 10 XSS alerts
- 20 SQL injection alerts
- Supply chain: True
- Attack types: ["xss", "sql_injection"]
- Notification: "🚨 SUPPLY CHAIN ATTACK DETECTED"
```

**Current (Chưa implement):**
```
Group 1: src:1.2.3.4:attack:xss (10 alerts)
Group 2: src:1.2.3.4:attack:sql_injection (20 alerts)
→ Không link được 2 groups
```

