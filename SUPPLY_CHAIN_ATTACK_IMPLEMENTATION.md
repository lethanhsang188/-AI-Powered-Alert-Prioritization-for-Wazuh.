# ✅ Supply Chain Attack Detection - Implementation Summary

## 🎯 Mục Tiêu

**Phát hiện supply chain attacks:** Khi attacker thực hiện nhiều loại tấn công khác nhau từ cùng một source IP trong time window ngắn.

**Ví dụ:**
- Xả 10 XSS payloads → sau đó chuyển sang SQL injection (sqlmap)
- Pipeline phải detect đây là **cùng 1 attacker** đang thực hiện multi-stage attack

---

## ✅ Những Gì Đã Implement

### 1. **Thêm Correlation Type: `source_campaign`**

**File:** `src/common/correlation.py`

**Thay đổi:**
- Thêm correlation type `source_campaign` vào đầu danh sách (priority cao nhất)
- Group key: `campaign:src:{srcip}` (không có attack_type)
- Group tất cả attacks từ cùng source IP, không phân biệt attack type

**Code:**
```python
# Priority order
correlation_types = ["source_campaign", "source_attack", "destination_attack", "signature", "rule_pattern"]

# Generate group key
if correlation_type == "source_campaign":
    if srcip:
        return f"campaign:src:{srcip}"  # No attack_type!
```

**Kết quả:**
- ✅ XSS và SQL injection từ cùng source → **Cùng campaign group**
- ✅ Có thể detect supply chain attack

---

### 2. **Supply Chain Detection Logic**

**File:** `src/common/correlation.py`

**Function:** `_detect_supply_chain_attack()`

**Logic:**
- Extract attack types từ campaign group (sử dụng `normalize_attack_type`)
- Detect khi có **2+ attack types khác nhau** từ cùng source
- Determine severity:
  - **High:** 3+ attack types hoặc critical combo (XSS+SQL, SQL+Command Injection, etc.)
  - **Medium:** 2 attack types (không phải critical combo)
  - **Low:** 2 attack types (fallback)

**Return:**
```python
{
    "is_supply_chain": True,
    "attack_types": ["xss", "sql_injection"],
    "attack_type_counts": {"xss": 10, "sql_injection": 20},
    "severity": "high" | "medium" | "low",
    "total_alerts": 30
}
```

**Kết quả:**
- ✅ Auto-detect supply chain attacks
- ✅ Log supply chain detection với đầy đủ thông tin

---

### 3. **Heuristic Scoring Boost**

**File:** `src/analyzer/heuristic.py`

**Thay đổi:**
- Thêm supply chain bonus vào heuristic score
- Bonus dựa trên severity:
  - **High severity:** +0.25
  - **Medium severity:** +0.15
  - **Low severity:** +0.10

**Code:**
```python
supply_chain = correlation.get("supply_chain")
if supply_chain and supply_chain.get("is_supply_chain"):
    severity = supply_chain.get("severity", "low")
    if severity == "high":
        base_score += 0.25
    elif severity == "medium":
        base_score += 0.15
    else:
        base_score += 0.10
```

**Kết quả:**
- ✅ Supply chain attacks có score cao hơn
- ✅ Priority boost cho multi-stage attacks

---

### 4. **Notification Override**

**File:** `src/orchestrator/notify.py`

**Thay đổi:**
- Supply chain attack → **Always notify** (override thresholds)
- Hiển thị supply chain info trong Telegram message

**Notification Message:**
```
🚨 SUPPLY CHAIN ATTACK DETECTED 🚨
Multiple attack types from same source: xss (10 alerts), sql_injection (20 alerts)
Total alerts: 30, Severity: HIGH
```

**Telegram Message Section:**
```
*Correlation:*
Correlated Count: 30

🚨 SUPPLY CHAIN ATTACK 🚨
Attack Types: xss, sql_injection
Severity: HIGH
Total Campaign Alerts: 30
Breakdown: xss: 10, sql_injection: 20
```

**Kết quả:**
- ✅ SOC analyst thấy ngay supply chain attack
- ✅ Có đầy đủ thông tin để investigate

---

## 📊 So Sánh: Trước vs Sau

### **Trước (Chưa có Supply Chain Detection):**

```
XSS alerts (10):
- Group: src:1.2.3.4:attack:xss
- Correlation: is_correlated=True, group_size=10

SQL injection alerts (20):
- Group: src:1.2.3.4:attack:sql_injection
- Correlation: is_correlated=True, group_size=20

→ SOC thấy 2 campaigns riêng biệt ❌
→ Không biết đây là cùng 1 attacker
```

### **Sau (Với Supply Chain Detection):**

```
XSS alerts (10):
- Group: src:1.2.3.4:attack:xss
- Campaign: campaign:src:1.2.3.4
- Correlation: is_correlated=True, group_size=10
- Supply chain: is_supply_chain=True, attack_types=["xss", "sql_injection"]

SQL injection alerts (20):
- Group: src:1.2.3.4:attack:sql_injection
- Campaign: campaign:src:1.2.3.4  ← Same campaign!
- Correlation: is_correlated=True, group_size=30 (total)
- Supply chain: is_supply_chain=True, attack_types=["xss", "sql_injection"]

→ SOC thấy 1 supply chain attack! ✅
→ Notification: "🚨 SUPPLY CHAIN ATTACK DETECTED"
→ Score boost: +0.25 (high severity)
```

---

## 🔍 Test Case

### **Scenario: Supply Chain Attack**

**Setup:**
1. Attacker xả 10 XSS payloads từ `1.2.3.4` (T+0s)
2. Pipeline nhận XSS alerts → Group: `src:1.2.3.4:attack:xss` (T+30s)
3. Attacker chuyển sang SQL injection (sqlmap) từ `1.2.3.4` (T+60s)
4. Pipeline nhận SQL injection alerts → Group: `src:1.2.3.4:attack:sql_injection` (T+90s)

**Expected Result:**

**Correlation:**
```json
{
  "is_correlated": true,
  "group_key": "campaign:src:1.2.3.4",
  "group_size": 30,
  "correlation_type": "source_campaign",
  "supply_chain": {
    "is_supply_chain": true,
    "attack_types": ["xss", "sql_injection"],
    "attack_type_counts": {
      "xss": 10,
      "sql_injection": 20
    },
    "severity": "high",
    "total_alerts": 30
  }
}
```

**Heuristic Score:**
- Base score: 0.70
- Supply chain bonus: +0.25 (high severity)
- Final score: 0.95

**Notification:**
- ✅ Always notify (override)
- ✅ Message: "🚨 SUPPLY CHAIN ATTACK DETECTED 🚨"
- ✅ Telegram: Hiển thị attack types, severity, breakdown

---

## ⚡ Real-Time Processing

**Status:** ✅ Đã hoạt động

**Timeline:**
```
T+0s:   Attack xảy ra
T+1s:   Wazuh Manager phát hiện
T+2-5s: Wazuh Manager → Indexer
T+5-30s: Indexer index → OpenSearch (DELAY!)
T+30s:  Pipeline query → nhận alert
T+38s:  Pipeline process → notify (nếu poll interval = 8s)
```

**Delay:** 8-48 giây (chủ yếu do indexer, không phải pipeline)

**Supply Chain Detection:**
- ✅ Detect ngay khi có 2+ attack types từ cùng source
- ✅ Time window: 15 phút (configurable)
- ✅ Real-time notification khi detect

---

## 📝 Configuration

**File:** `src/common/config.py`

**Config variables:**
- `CORRELATION_ENABLE`: Enable/disable correlation (default: True)
- `CORRELATION_TIME_WINDOW_MINUTES`: Time window for correlation (default: 15 minutes)

**Recommendation:**
- Time window: 15-30 phút (đủ để detect supply chain attacks)
- Không nên quá dài (sẽ group alerts không liên quan)

---

## 🎯 Kết Luận

### **Đã Hoàn Thành:**

1. ✅ **Source campaign correlation:** Group tất cả attacks từ cùng source
2. ✅ **Supply chain detection:** Auto-detect multi-stage attacks
3. ✅ **Heuristic scoring boost:** Priority boost cho supply chain attacks
4. ✅ **Notification override:** Always notify supply chain attacks
5. ✅ **Telegram message:** Hiển thị đầy đủ supply chain info

### **Benefits:**

1. ✅ **SOC Visibility:** Thấy ngay supply chain attacks
2. ✅ **Faster Response:** Priority boost → faster investigation
3. ✅ **Better Context:** Hiểu được attack pattern (multi-stage)
4. ✅ **Real-time:** Detect và notify trong 8-48 giây

### **Next Steps:**

1. **Test với real attacks:**
   - Xả XSS payloads → SQL injection
   - Verify supply chain detection
   - Check notification và scoring

2. **Tune parameters:**
   - Time window (15 phút có đủ không?)
   - Severity thresholds (có cần điều chỉnh không?)

3. **Monitor:**
   - Log supply chain detections
   - Track false positives
   - Adjust logic nếu cần

---

## 📚 Files Modified

1. `src/common/correlation.py` - Thêm source_campaign và supply chain detection
2. `src/analyzer/heuristic.py` - Thêm supply chain bonus
3. `src/orchestrator/notify.py` - Thêm supply chain notification

## 📚 Files Created

1. `SUPPLY_CHAIN_ATTACK_DETECTION_ANALYSIS.md` - Phân tích chi tiết
2. `SUPPLY_CHAIN_ATTACK_IMPLEMENTATION.md` - Implementation summary (this file)

