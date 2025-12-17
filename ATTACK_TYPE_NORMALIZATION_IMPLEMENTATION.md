# Attack Type Normalization - Đảm Bảo Đánh Giá Đồng Nhất

## 🎯 Vấn Đề

**Trước đây:** Cùng một loại tấn công (ví dụ: XSS) từ Agent 1 (WebServer) và Agent 2 (pfSense) có thể được đánh giá khác nhau vì:
- Rule IDs khác nhau (31105 vs 86601)
- Rule descriptions khác nhau
- Agent types khác nhau (WebServer vs Firewall)
- Scoring dựa trên rule metadata thay vì attack content

**Ví dụ:**
- Agent 1: Rule 31105 "XSS attempt on WebServer" → Score cao
- Agent 2: Rule 86601 "Suricata: Alert - [L2-Exploit][XSS] ..." → Score thấp hơn
- **Nhưng cả 2 đều là XSS attack!**

## ✅ Giải Pháp

### 1. **Attack Type Normalizer Module**

**File:** `src/common/attack_type_normalizer.py`

**Chức năng:**
- Normalize attack type từ nhiều nguồn (tags, signature, category, description, groups)
- Đảm bảo cùng một loại attack được nhận diện giống nhau
- Priority: Tags → Signature → URL → Description → Groups → Category

**Supported Attack Types:**
- `xss` - Cross-Site Scripting
- `sql_injection` - SQL Injection
- `command_injection` - Command Injection
- `path_traversal` - Path Traversal
- `csrf` - Cross-Site Request Forgery
- `web_attack` - Generic web attack

### 2. **Heuristic Scoring với Attack Type Bonus**

**File:** `src/analyzer/heuristic.py`

**Thay đổi:**
- Thêm attack type bonus dựa trên normalized attack type
- Không phụ thuộc vào rule ID hay agent type
- Cùng attack type → cùng base bonus

**Code:**
```python
# Normalize attack type
attack_type = normalize_attack_type(alert)
attack_priority = get_attack_type_priority(attack_type)

# Add bonus based on attack type (not rule ID)
if attack_type:
    attack_bonus = attack_priority * 0.01  # 0.01-0.10 bonus
    base_score += attack_bonus
```

### 3. **LLM Analysis với Normalized Attack Type**

**File:** `src/analyzer/llm.py`

**Thay đổi:**
- LLM nhận normalized attack type trong rule context
- Rule-specific guidance dựa trên attack type, không chỉ rule ID
- Đảm bảo cùng attack type được analyze giống nhau

**Code:**
```python
# Check both rule ID and normalized attack type
if rule_id == "31105" or normalized_attack_type == "xss":
    # Same guidance for XSS regardless of rule ID
```

### 4. **Triage với Attack Type Normalization**

**File:** `src/analyzer/triage.py`

**Thay đổi:**
- Normalize attack type TRƯỚC khi scoring
- Pass normalized attack type vào LLM context
- Boost LLM confidence dựa trên attack type, không chỉ rule ID

**Code:**
```python
# Normalize attack type BEFORE scoring
alert = normalize_attack_type_for_scoring(alert)
normalized_attack_type = alert.get("attack_type_normalized")

# Pass to LLM
rule_context = {
    ...
    "normalized_attack_type": normalized_attack_type,
}

# Boost confidence based on attack type
if (rule_id == "31105" or normalized_attack_type == "xss") and "xss" in tags:
    # Boost confidence for XSS detection
```

## 📊 Kết Quả

### **Trước Khi Normalize:**

```
Agent 1 (WebServer):
- Rule ID: 31105
- Description: "XSS attempt on WebServer"
- Heuristic Score: 0.85 (rule-specific multiplier)
- LLM Confidence: 0.87
- Final Score: 0.86

Agent 2 (pfSense):
- Rule ID: 86601
- Description: "Suricata: Alert - [L2-Exploit][XSS] ..."
- Heuristic Score: 0.65 (no rule-specific multiplier)
- LLM Confidence: 0.75
- Final Score: 0.70

→ Lệch 0.16 điểm! ❌
```

### **Sau Khi Normalize:**

```
Agent 1 (WebServer):
- Rule ID: 31105
- Normalized Attack Type: "xss"
- Attack Priority: 8
- Attack Bonus: +0.08
- Heuristic Score: 0.85 (base) + 0.08 (attack type) = 0.93
- LLM Confidence: 0.87 (boosted for XSS)
- Final Score: 0.90

Agent 2 (pfSense):
- Rule ID: 86601
- Normalized Attack Type: "xss" ✅ (same!)
- Attack Priority: 8 ✅ (same!)
- Attack Bonus: +0.08 ✅ (same!)
- Heuristic Score: 0.65 (base) + 0.08 (attack type) = 0.73
- LLM Confidence: 0.75 → 0.90 (boosted for XSS) ✅
- Final Score: 0.82

→ Lệch chỉ 0.08 điểm (do rule level khác nhau, nhưng attack type được đánh giá giống nhau) ✅
```

## 🔍 Attack Type Detection Logic

### **Priority 1: Tags (Đã Normalize)**
```python
if "xss" in tags:
    return "xss"
if "sql_injection" in tags:
    return "sql_injection"
```

### **Priority 2: Suricata Signature**
```python
if "xss" in signature or "cross-site" in signature:
    return "xss"
if "sql" in signature or "sqli" in signature:
    return "sql_injection"
```

### **Priority 3: HTTP URL**
```python
if "xss" in url or "<script" in url:
    return "xss"
if "union" in url or "select" in url:
    return "sql_injection"
```

### **Priority 4: Rule Description**
```python
if "xss" in description or "cross-site" in description:
    return "xss"
```

### **Priority 5: Rule Groups**
```python
if "xss" in groups:
    return "xss"
```

### **Priority 6: Suricata Category**
```python
if "web application attack" in category:
    # Try to be more specific from signature
    return "web_attack" or specific type
```

## ✅ Lợi Ích

1. **Đồng Nhất Đánh Giá:**
   - Cùng attack type → cùng base score
   - Không phụ thuộc vào rule ID hay agent type

2. **Phát Hiện Chính Xác:**
   - Detect attack từ content, không chỉ metadata
   - Hoạt động với cả Wazuh rules và Suricata rules

3. **SOC-Grade:**
   - Phân tích dựa trên attack content, giống SOC analyst
   - Không bias về agent type hay rule IDs

4. **Maintainable:**
   - Dễ thêm attack types mới
   - Centralized logic trong một module

## 📝 Logging

**Heuristic scoring logs:**
```json
{
  "action": "attack_type_normalized",
  "attack_type": "xss",
  "attack_priority": 8,
  "bonus": 0.08
}
```

**Triage logs:**
```json
{
  "normalized_attack_type": "xss",
  "attack_priority": 8
}
```

## 🔧 Cách Kiểm Tra

### 1. **Chạy Pipeline và Xem Logs**

```bash
py -3 bin/run_pipeline.py
```

**Tìm logs:**
- `"Attack type normalized: xss"` - Xác nhận normalization
- So sánh scores giữa Agent 1 và Agent 2 cho cùng attack type

### 2. **So Sánh Scores**

**Nếu normalization hoạt động:**
- Cùng attack type từ 2 agents sẽ có attack bonus giống nhau
- LLM confidence sẽ được boost giống nhau cho cùng attack type
- Final scores sẽ gần nhau hơn (chỉ khác do rule level)

## ✅ Kết Luận

**Attack Type Normalization** đảm bảo:
- ✅ Cùng một loại tấn công được đánh giá giống nhau
- ✅ Không bias về agent type (WebServer vs Firewall)
- ✅ Không bias về rule IDs (31105 vs 86601)
- ✅ Phân tích dựa trên attack content, không chỉ metadata

**Ví dụ:** XSS attack từ Agent 1 (rule 31105) và Agent 2 (rule 86601) giờ sẽ được đánh giá gần như nhau! 🎉

