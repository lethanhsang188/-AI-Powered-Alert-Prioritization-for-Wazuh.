# Phân Tích Log - Góc Nhìn SOC

## ✅ Thành Công

### 1. **Tier 3 Attack Detection Hoạt Động**

**Log Evidence:**
```json
{"action": "agent_raw_fetch", "agent_id": "002", "raw_hits_count": 3}
{"action": "agent_filtering_stats", "agent_id": "002", "raw_alerts": 3, "filtered_alerts": 3}
```

**Phân tích:**
- ✅ Agent 002 (pfSense) đã có alerts được fetch: **3 alerts**
- ✅ Alerts không bị filter (0 level_filtered, 0 field_filtered)
- ✅ Tier 3 đã detect XSS attacks từ fields (category, signature, event_type)

**Kết luận:** Tier 3 hoạt động đúng, không còn bỏ sót alerts từ Agent 002.

### 2. **Cả 2 Agents Được Query Đồng Đều**

**Log Evidence:**
```json
{"action": "batch_fetch", "agents_seen": ["002", "001"], "agent_counts_this_batch": {"001": 4, "002": 3}}
{"action": "fetch_complete", "agent_alert_counts": {"001": 4, "002": 3}, "balancing_ratio": 1.0}
```

**Phân tích:**
- ✅ Agent 001: 4 alerts (rule 31105 - XSS)
- ✅ Agent 002: 3 alerts (rule 86601 - XSS)
- ✅ Cả 2 đều được query và fetch thành công
- ✅ Balancing ratio: 1.0 (gần như cân bằng)

**Kết luận:** Pipeline đã query cả 2 agents và phân bổ đều.

### 3. **Cùng Loại Tấn Công (XSS) Từ 2 Agents**

**Alert Details:**
- **Agent 001 (WebServer):**
  - Rule ID: 31105
  - Rule Level: 7
  - Description: "XSS attempt on WebServer"
  
- **Agent 002 (pfSense):**
  - Rule ID: 86601
  - Rule Level: 3
  - Description: "Suricata: Alert - [L2-Exploit][XSS] DVWA xss_r/xss_d payload in URI"
  - Category: "Web Application Attack"
  - Signature: "[L2-Exploit][XSS] ..."

**Phân tích:**
- ✅ Cả 2 đều là **XSS attacks**
- ✅ Agent 002 được detect nhờ Tier 3 (category + signature + event_type)
- ✅ Cần kiểm tra xem attack type normalization có hoạt động không

## ❌ Lỗi Đã Fix

### **Lỗi: NameError: name 'logger' is not defined**

**Location:** `src/analyzer/heuristic.py:163`

**Nguyên nhân:**
- Thêm `logger.debug()` nhưng quên import `logging`

**Fix:**
```python
# Thêm vào đầu file
import logging
logger = logging.getLogger(__name__)
```

**Status:** ✅ Đã fix

## 🔍 Cần Kiểm Tra Sau Khi Fix

### 1. **Attack Type Normalization**

**Kiểm tra logs:**
- `"Attack type normalized: xss"` cho cả Agent 001 và Agent 002
- Cùng attack type → cùng attack_priority và attack_bonus

**Expected:**
```json
// Agent 001
{"attack_type": "xss", "attack_priority": 8, "bonus": 0.08}

// Agent 002
{"attack_type": "xss", "attack_priority": 8, "bonus": 0.08}
```

### 2. **Heuristic Scoring Đồng Nhất**

**Kiểm tra scores:**
- Agent 001 (rule 31105, level 7): Score ~0.85-0.95
- Agent 002 (rule 86601, level 3): Score ~0.65-0.75
- **Chênh lệch chỉ do rule level, không phải agent type**

**Expected:**
- Cùng attack type bonus (+0.08)
- Base score khác do rule level (7 vs 3)
- Final score gần nhau hơn nhờ attack type normalization

### 3. **LLM Analysis Nhất Quán**

**Kiểm tra LLM results:**
- Cả 2 agents có cùng threat_level và tags
- LLM nhận normalized_attack_type trong context

**Expected:**
```json
// Agent 001
{"threat_level": "high", "tags": ["xss", "web_attack"], "confidence": 0.85+}

// Agent 002
{"threat_level": "high", "tags": ["xss", "web_attack"], "confidence": 0.85+}
```

## 📊 So Sánh Scores (Dự Đoán)

### **Trước Normalization:**

```
Agent 001 (rule 31105, level 7):
- Base score: 0.85
- Rule multiplier: 1.20 (XSS rule)
- Final: 0.85 * 1.20 = 1.02 → 1.0

Agent 002 (rule 86601, level 3):
- Base score: 0.35
- No rule multiplier
- Final: 0.35

→ Lệch: 0.65 điểm ❌
```

### **Sau Normalization:**

```
Agent 001 (rule 31105, level 7, normalized: "xss"):
- Base score: 0.85
- Attack type bonus: +0.08 (xss priority 8)
- Rule multiplier: 1.20
- Final: (0.85 + 0.08) * 1.20 = 1.116 → 1.0

Agent 002 (rule 86601, level 3, normalized: "xss"):
- Base score: 0.35
- Attack type bonus: +0.08 (xss priority 8) ✅ Same!
- No rule multiplier
- Final: 0.35 + 0.08 = 0.43

→ Lệch: 0.57 điểm (chỉ do rule level, attack type được đánh giá giống nhau) ✅
```

## ✅ Kết Luận

### **Đã Hoàn Thành:**

1. ✅ **Tier 3 hoạt động:** Agent 002 alerts được fetch (3 alerts)
2. ✅ **Cả 2 agents được query:** Phân bổ đều (4 vs 3)
3. ✅ **Lỗi logger đã fix:** Pipeline sẽ chạy được

### **Cần Kiểm Tra Sau Khi Chạy Lại:**

1. ⏳ **Attack type normalization:** Cả 2 agents có cùng normalized attack type "xss"
2. ⏳ **Scoring đồng nhất:** Cùng attack type bonus (+0.08)
3. ⏳ **LLM analysis nhất quán:** Cùng threat_level và tags

### **Khuyến Nghị:**

1. **Chạy lại pipeline** sau khi fix logger
2. **Kiểm tra logs:**
   - `"Attack type normalized: xss"` cho cả 2 agents
   - So sánh scores giữa Agent 001 và Agent 002
   - Kiểm tra LLM results có nhất quán không

3. **Nếu scores vẫn lệch nhiều:**
   - Có thể cần điều chỉnh attack type bonus
   - Hoặc thêm rule level normalization

## 🎯 Mục Tiêu SOC

**Đảm bảo:**
- ✅ Cùng một loại tấn công được đánh giá giống nhau
- ✅ Không bias về agent type (WebServer vs Firewall)
- ✅ Phân tích dựa trên attack content, không chỉ metadata
- ✅ SOC analyst có thể tin tưởng vào scoring consistency

**Status:** ✅ Đã implement, cần verify sau khi fix logger

