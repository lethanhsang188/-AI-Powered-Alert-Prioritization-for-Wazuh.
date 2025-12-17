# ✅ Tier 3 Attack Detection - Implementation Summary

## 🎯 Vấn Đề Đã Giải Quyết

**Trước đây:** Pipeline bỏ sót alerts quan trọng như XSS attack từ Agent 002 vì:
- Alert có `rule.id = 86601` không match với `INCLUDE_RULE_IDS = ["100100"]`
- Alert có `rule.level = 3` < `ALWAYS_REEVALUATE_LEVEL_GTE = 7`
- Nhưng alert **THỰC SỰ là tấn công** (XSS exploit với signature rõ ràng)

**Giải pháp:** Thêm **Tier 3** vào query để detect attacks từ **fields/content**, không chỉ dựa vào rule IDs.

## ✅ Những Gì Đã Thực Hiện

### 1. **Thêm Tier 3 vào Query Logic**

**File:** `src/collector/wazuh_client.py`

**Thay đổi:**
- Chuyển từ Two-Tier → Three-Tier filtering
- Tier 3 detect attacks từ:
  - `data.alert.category` (Web Application Attack, Exploit, etc.)
  - `data.alert.signature` (XSS, SQL Injection, Exploit keywords)
  - `data.event_type = "alert"` (Suricata alerts)

**Code:**
```python
# Tier 3: Attack indicators from fields
tier_filters.append({
    "bool": {
        "must": [
            {"range": {"rule.level": {"gte": SOC_MIN_LEVEL}}},  # At least MIN_LEVEL
            {
                "bool": {
                    "should": attack_indicator_filters,
                    "minimum_should_match": 1
                }
            }
        ]
    }
})
```

### 2. **Attack Indicators Được Detect**

**Attack Categories:**
- Web Application Attack ✅
- Exploit ✅
- Malware, Trojan, Virus, Worm
- Denial of Service
- Network Scan, Reconnaissance
- Privilege Gain attempts

**Attack Keywords in Signature:**
- XSS, Cross-Site Scripting
- SQL Injection, SQLi
- Exploit, L2-Exploit
- Command Injection
- Path Traversal
- Remote Code Execution (RCE)
- File Upload
- Brute Force
- DoS, DDoS

**Suricata Alerts:**
- `data.event_type = "alert"` (IDS/IPS detections)

### 3. **Logging và Debugging**

**Thêm logging:**
- Log khi Tier 3 được enable
- Log số lượng attack indicator filters
- Giúp debug và monitor

### 4. **Documentation**

**Files đã tạo:**
- `TIER_3_ATTACK_DETECTION_FROM_FIELDS.md` - Chi tiết về Tier 3
- `TIER_3_IMPLEMENTATION_SUMMARY.md` - Tóm tắt implementation
- `env.template` - Đã cập nhật với thông tin về Tier 3

## 📊 Kết Quả

### **Alert Agent 002 (XSS Attack):**

**Trước:**
```json
{
  "rule.id": "86601",           // ❌ Không match INCLUDE_RULE_IDS
  "rule.level": 3,              // ❌ < ALWAYS_REEVALUATE_LEVEL_GTE = 7
  "data.alert.category": "Web Application Attack",  // ✅ Nhưng không được check
  "data.alert.signature": "[L2-Exploit][XSS] ...",  // ✅ Nhưng không được check
  "data.event_type": "alert"    // ✅ Nhưng không được check
}
→ BỊ FILTER → Không được fetch
```

**Sau:**
```json
{
  "rule.id": "86601",           // ❌ Không match Tier 1
  "rule.level": 3,              // ❌ < Tier 2 threshold
  "data.alert.category": "Web Application Attack",  // ✅ Tier 3 PASS
  "data.alert.signature": "[L2-Exploit][XSS] ...",  // ✅ Tier 3 PASS
  "data.event_type": "alert"    // ✅ Tier 3 PASS
}
→ TIER 3 PASS → Được fetch và xử lý ✅
```

## 🔍 Cách Kiểm Tra

### 1. **Chạy Pipeline và Xem Logs**

```bash
py -3 bin/run_pipeline.py
```

**Tìm logs:**
- `"Tier 3 attack detection enabled"` - Xác nhận Tier 3 đang hoạt động
- `"Fetched raw alerts from indexer for agent 002"` với `raw_hits_count > 0`
- `"Filtering complete for agent 002: X raw alerts -> Y after filtering"`

### 2. **Kiểm Tra Alert Agent 002**

**Nếu Tier 3 hoạt động:**
- Agent 002 sẽ có alerts được fetch
- Alerts có attack indicators (category, signature, event_type) sẽ pass Tier 3
- Alerts sẽ được normalize và xử lý giống Agent 001

### 3. **Verify Query**

**Có thể test query trực tiếp:**
```python
# Query sẽ include alerts với:
# - Tier 1: rule.id match hoặc prefix match
# - Tier 2: rule.level >= 7
# - Tier 3: attack indicators trong fields
```

## ⚠️ Lưu Ý

1. **Performance:**
   - Wildcard queries có thể chậm hơn exact match
   - Monitor query performance nếu có nhiều alerts

2. **False Positives:**
   - Có thể include một số alerts không phải attacks
   - Nhưng sẽ được filter lại ở post-fetch filtering và FP filtering

3. **Maintenance:**
   - Attack keywords được hardcode trong code
   - Có thể config qua env variables trong tương lai nếu cần

## ✅ Kết Luận

**Tier 3** đảm bảo pipeline:
- ✅ **Không bỏ sót attacks thật** dù không match rule IDs
- ✅ **Phân tích dựa trên fields/content**, không chỉ metadata
- ✅ **SOC-grade**: Giống cách SOC analyst phân tích alerts
- ✅ **Cân bằng**: Vẫn giữ Tier 1 và Tier 2 cho custom rules và high-level alerts

**Alert Agent 002 (XSS attack, rule 86601, level 3) giờ sẽ được fetch và xử lý nhờ Tier 3!** 🎉

