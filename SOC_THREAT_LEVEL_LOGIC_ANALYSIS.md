# 🔍 Phân Tích Logic Threat Level - Góc Độ SOC

## 📊 Wazuh Rule Level Nghĩa Là Gì?

Theo Wazuh documentation và best practices:

| Rule Level | Ý Nghĩa | Ví Dụ | Threat Level Nên Là |
|-----------|---------|-------|-------------------|
| **0-2** | Info/Noise | Log rotation, normal events | `none` hoặc `low` |
| **3-6** | Low severity | Configuration changes, minor anomalies | `low` hoặc `medium` |
| **7-9** | **Medium severity** | **Attack attempts** (XSS, SQLi attempts) | `medium` hoặc `high` |
| **10-11** | **High severity** | Successful attacks, suspicious activity | `high` hoặc `critical` |
| **12-15** | **CRITICAL/CONFIRMED** | **CONFIRMED attacks** (reverse shell, webshell execution) | **`critical`** |

---

## ❌ Vấn Đề Logic Hiện Tại

### **Code hiện tại (src/analyzer/triage.py line 183):**

```python
# Get threat_level from LLM result
threat_level = llm_result.get("threat_level", "medium")
```

**Vấn đề:**
- ❌ Threat level **100% phụ thuộc vào LLM**
- ❌ LLM có thể đánh **rule level 13 (CONFIRMED) → "high"** thay vì "critical"
- ❌ LLM có thể đánh **rule level 7 (attempt) → "critical"** (quá cao)
- ❌ **Không nhất quán** với Wazuh rule level

### **Ví dụ thực tế từ log:**

```
Rule 110231 (Level 13 - CONFIRMED reverse shell):
├─ LLM threat_level: "high"  ❌ SAI!
├─ Nên là: "critical" ✅
└─ Lý do: Level 13 = CONFIRMED attack, không phải attempt

Rule 31105 (Level 7 - XSS attempt):
├─ LLM threat_level: "high"  ✅ ĐÚNG
├─ Có thể là: "high" hoặc "medium" (tùy context)
└─ Lý do: Level 7 = attempt, chưa chắc thành công
```

---

## ✅ Logic Đúng Từ Góc Độ SOC

### **Nguyên tắc:**

1. **Rule Level là nguồn sự thật chính** (Wazuh đã phân tích)
2. **LLM bổ sung context**, không thay thế rule level
3. **CONFIRMED attacks (level 12-15) LUÔN là CRITICAL**

### **Logic đề xuất:**

```python
# 1. Rule level >= 12 (CONFIRMED) → LUÔN CRITICAL
if rule_level >= 12:
    threat_level = "critical"  # Override LLM
    reason = "CONFIRMED attack (rule level >= 12)"

# 2. Rule level 10-11 (High severity) → Ít nhất HIGH
elif rule_level >= 10:
    if threat_level not in ["critical", "high"]:
        threat_level = "high"  # Override nếu LLM đánh thấp
    # Giữ nguyên nếu LLM đánh "critical" hoặc "high"

# 3. Rule level 7-9 (Medium severity) → LLM quyết định
elif rule_level >= 7:
    # Giữ nguyên LLM threat_level (có thể là "high" hoặc "medium")
    pass

# 4. Rule level < 7 → Ít nhất MEDIUM
else:
    if threat_level in ["none", "low"]:
        threat_level = "medium"  # Override nếu LLM đánh quá thấp
```

---

## 🎯 So Sánh: Logic Hiện Tại vs Logic Đề Xuất

### **Case 1: Rule 110231 (Level 13 - CONFIRMED Reverse Shell**

| Aspect | Logic Hiện Tại | Logic Đề Xuất |
|--------|----------------|---------------|
| **Rule Level** | 13 (CONFIRMED) | 13 (CONFIRMED) |
| **LLM Output** | "high" | "high" |
| **Final Threat Level** | ❌ "high" | ✅ "critical" |
| **Lý do** | 100% tin LLM | Override: Level 13 = CRITICAL |
| **SOC Impact** | ⚠️ Alert bị đánh giá thấp | ✅ Alert được ưu tiên đúng |

### **Case 2: Rule 31105 (Level 7 - XSS Attempt)**

| Aspect | Logic Hiện Tại | Logic Đề Xuất |
|--------|----------------|---------------|
| **Rule Level** | 7 (Attempt) | 7 (Attempt) |
| **LLM Output** | "high" | "high" |
| **Final Threat Level** | ✅ "high" | ✅ "high" |
| **Lý do** | LLM đánh đúng | Giữ nguyên LLM (level 7-9) |
| **SOC Impact** | ✅ OK | ✅ OK |

### **Case 3: Rule 2902 (Level 7 - Package Install)**

| Aspect | Logic Hiện Tại | Logic Đề Xuất |
|--------|----------------|---------------|
| **Rule Level** | 7 | 7 |
| **LLM Output** | "medium" | "medium" |
| **Final Threat Level** | ✅ "medium" | ✅ "medium" |
| **Lý do** | LLM đánh đúng | Giữ nguyên LLM (level 7-9) |
| **SOC Impact** | ✅ OK | ✅ OK |

---

## 🔧 Implementation

### **Code đề xuất:**

```python
# Get threat_level from LLM result
threat_level = llm_result.get("threat_level", "medium")
llm_confidence = llm_result.get("confidence", 0.0)
tags = llm_result.get("tags", [])

# Override threat_level based on rule level (SOC logic)
# Rule level is the source of truth from Wazuh
if rule_level >= 12:
    # CONFIRMED attacks (level 12-15) are ALWAYS critical
    if threat_level != "critical":
        logger.info(
            "Overriding threat_level to critical based on rule level",
            extra={
                "component": "triage",
                "action": "threat_level_override",
                "rule_id": rule_id,
                "rule_level": rule_level,
                "llm_threat_level": threat_level,
                "final_threat_level": "critical",
                "reason": "CONFIRMED attack (rule level >= 12)"
            }
        )
        threat_level = "critical"
elif rule_level >= 10:
    # High severity rules (level 10-11) should be at least "high"
    if threat_level not in ["critical", "high"]:
        logger.debug(
            "Overriding threat_level to high based on rule level",
            extra={
                "component": "triage",
                "action": "threat_level_override",
                "rule_id": rule_id,
                "rule_level": rule_level,
                "llm_threat_level": threat_level,
                "final_threat_level": "high",
                "reason": "High severity rule (level >= 10)"
            }
        )
        threat_level = "high"
# Rule level 7-9: Keep LLM decision (can be "high" or "medium")
# Rule level < 7: Keep LLM decision (usually "medium" or "low")
```

---

## 📋 Tóm Tắt

### **Vấn đề:**
- ❌ Logic hiện tại **100% phụ thuộc LLM**
- ❌ **Không nhất quán** với Wazuh rule level
- ❌ CONFIRMED attacks (level 13) có thể bị đánh giá thấp

### **Giải pháp:**
- ✅ **Rule level là nguồn sự thật chính**
- ✅ **LLM bổ sung context**, không thay thế
- ✅ **CONFIRMED attacks (level 12-15) → LUÔN CRITICAL**
- ✅ **High severity (level 10-11) → Ít nhất HIGH**

### **Kết quả:**
- ✅ **Nhất quán** với Wazuh classification
- ✅ **SOC analyst tin tưởng** hơn
- ✅ **Critical alerts không bị bỏ qua**

