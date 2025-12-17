# Phân Tích: Tại Sao Agent 002 Alerts Không Được Lấy

## 🔍 Vấn Đề

Alert của Agent 002 (pfSense) **KHÔNG được lấy** bởi pipeline mặc dù:
- ✅ Pipeline đã query Agent 002 (có log `"Fetched raw alerts from indexer for agent 002"`)
- ✅ Alert tồn tại trong indexer (`raw_hits_count: 0` nghĩa là query không trả về alerts)
- ❌ Alert bị **filter bởi SOC query rules** ở tầng indexer query

## 📊 Alert Mẫu Agent 002

```json
{
  "agent.id": "002",
  "agent.name": "pfSense.home.arpa",
  "rule.id": "86601",
  "rule.level": 3,
  "rule.description": "Suricata: Alert - [L2-Exploit][XSS] DVWA xss_r/xss_d payload in URI",
  "data.alert.category": "Web Application Attack",
  "data.alert.signature": "[L2-Exploit][XSS] DVWA xss_r/xss_d payload in URI (WAN pre-NAT)",
  "data.event_type": "alert",
  "timestamp": "2025-12-17T09:31:12.627"
}
```

## 🚫 SOC Filtering Rules Hiện Tại

**Cấu hình mặc định:**
```python
MIN_LEVEL = 3
MAX_LEVEL = 7
INCLUDE_RULE_IDS = ["100100"]  # Chỉ rule ID 100100
INCLUDE_RULE_ID_PREFIX = "1001"  # Chỉ rule IDs bắt đầu với "1001"
ALWAYS_REEVALUATE_LEVEL_GTE = 7  # Chỉ level >= 7
```

**Query Logic (Two-tier):**
```python
# Tier 1: Level 3-7 VÀ (rule.id trong INCLUDE_RULE_IDS HOẶC bắt đầu với INCLUDE_RULE_ID_PREFIX)
# Tier 2: Level >= 7 (always include)
```

## ❌ Tại Sao Alert Bị Filter

**Alert của Agent 002:**
- `rule.level = 3` ✅ (nằm trong [3..7])
- `rule.id = 86601` ❌ (không match)

**Kiểm tra Tier 1:**
- ✅ `rule.level = 3` trong [MIN_LEVEL..MAX_LEVEL] = [3..7]
- ❌ `rule.id = 86601` không trong `INCLUDE_RULE_IDS = ["100100"]`
- ❌ `rule.id = 86601` không bắt đầu với `INCLUDE_RULE_ID_PREFIX = "1001"` (bắt đầu với "866")
- ❌ **Kết quả: KHÔNG PASS Tier 1**

**Kiểm tra Tier 2:**
- ❌ `rule.level = 3` < `ALWAYS_REEVALUATE_LEVEL_GTE = 7`
- ❌ **Kết quả: KHÔNG PASS Tier 2**

**Kết luận:** Alert bị **filter ở tầng query**, không bao giờ được trả về từ indexer.

## ✅ Giải Pháp

### Giải Pháp 1: Thêm Rule ID Cụ Thể (Khuyến Nghị)

**Thêm rule.id 86601 vào INCLUDE_RULE_IDS:**

```bash
# Trong file .env
INCLUDE_RULE_IDS=100100,86601
```

**Hoặc nếu có nhiều Suricata rules:**
```bash
INCLUDE_RULE_IDS=100100,86601,86602,86603
```

**Ưu điểm:**
- ✅ Chính xác, chỉ include rules cần thiết
- ✅ Không ảnh hưởng đến rules khác
- ✅ Dễ quản lý và audit

**Nhược điểm:**
- ❌ Phải thêm từng rule ID một
- ❌ Cần biết trước các rule IDs cần include

### Giải Pháp 2: Thêm Prefix Cho Suricata Rules

**Thêm prefix "86" hoặc "866" cho Suricata rules:**

```bash
# Trong file .env
INCLUDE_RULE_ID_PREFIX=1001,86
```

**Hoặc nếu chỉ muốn Suricata XSS rules:**
```bash
INCLUDE_RULE_ID_PREFIX=1001,866
```

**Lưu ý:** Cần kiểm tra xem có rule IDs khác bắt đầu với "86" không để tránh include nhầm.

**Ưu điểm:**
- ✅ Include tất cả Suricata rules (nếu dùng prefix "86")
- ✅ Không cần liệt kê từng rule ID

**Nhược điểm:**
- ❌ Có thể include cả rules không mong muốn
- ❌ Khó kiểm soát chính xác

### Giải Pháp 3: Giảm ALWAYS_REEVALUATE_LEVEL_GTE

**Giảm ngưỡng level để include tất cả alerts level >= 3:**

```bash
# Trong file .env
ALWAYS_REEVALUATE_LEVEL_GTE=3
```

**Ưu điểm:**
- ✅ Include tất cả alerts level >= 3 (bao gồm cả Agent 002)
- ✅ Đơn giản, không cần thay đổi rule IDs

**Nhược điểm:**
- ❌ Có thể include quá nhiều alerts (noise)
- ❌ Tăng tải cho pipeline và LLM
- ❌ Không phù hợp với SOC-grade filtering (quá rộng)

### Giải Pháp 4: Kết Hợp (Khuyến Nghị Cho Production)

**Sử dụng cả rule IDs cụ thể và prefix:**

```bash
# Trong file .env
MIN_LEVEL=3
MAX_LEVEL=7
INCLUDE_RULE_IDS=100100,86601  # Custom rules + Suricata XSS rules
INCLUDE_RULE_ID_PREFIX=1001,866  # Prefix cho custom rules và Suricata rules
ALWAYS_REEVALUATE_LEVEL_GTE=7  # Giữ nguyên cho high-severity alerts
```

**Logic:**
- Tier 1: Level 3-7 VÀ (rule.id trong [100100, 86601] HOẶC bắt đầu với "1001" hoặc "866")
- Tier 2: Level >= 7 (always include)

## 🔧 Cách Áp Dụng

### Bước 1: Cập Nhật File .env

```bash
# Mở file .env và cập nhật
INCLUDE_RULE_IDS=100100,86601
# Hoặc
INCLUDE_RULE_ID_PREFIX=1001,866
```

### Bước 2: Restart Pipeline

```bash
# Dừng pipeline hiện tại (Ctrl+C)
# Chạy lại
py -3 bin/run_pipeline.py
```

### Bước 3: Kiểm Tra Logs

Sau khi restart, kiểm tra logs:
- `"Fetched raw alerts from indexer for agent 002"` với `raw_hits_count > 0`
- `"Filtering complete for agent 002: X raw alerts -> Y after filtering"`

## 📝 Lưu Ý

1. **Suricata Rules:** Rule 86601 là Suricata rule (IDS/IPS), không phải Wazuh rule. Cần đảm bảo cấu hình phù hợp với cả 2 loại rules.

2. **Rule ID Format:** 
   - Wazuh rules: thường 5-6 chữ số (ví dụ: 100100, 31105)
   - Suricata rules: thường 6-7 chữ số (ví dụ: 86601, 2410020)

3. **Performance:** Thêm nhiều rule IDs hoặc prefix rộng có thể tăng số lượng alerts, ảnh hưởng đến performance. Cần monitor và điều chỉnh.

4. **Maintenance:** Cần cập nhật `INCLUDE_RULE_IDS` khi có rules mới cần include.

## ✅ Kết Luận

**Vấn đề:** Alert của Agent 002 bị filter bởi SOC query rules vì `rule.id = 86601` không match với `INCLUDE_RULE_IDS = ["100100"]` và không bắt đầu với `INCLUDE_RULE_ID_PREFIX = "1001"`.

**Giải pháp khuyến nghị:** Thêm `86601` vào `INCLUDE_RULE_IDS` hoặc thêm prefix `"866"` vào `INCLUDE_RULE_ID_PREFIX`.

**Sau khi áp dụng:** Pipeline sẽ lấy được alerts của Agent 002 và xử lý giống như Agent 001.

