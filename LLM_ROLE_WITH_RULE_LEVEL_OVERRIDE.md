# 🤖 Vai Trò LLM Khi Có Rule Level Override

## ❓ Câu Hỏi

**Nếu rule level >= 12 → luôn "critical" (override LLM), thì LLM còn làm gì?**

---

## ✅ Trả Lời: LLM VẪN LÀM RẤT NHIỀU VIỆC QUAN TRỌNG!

### **LLM Output 4 Thứ:**

| Output | Bị Override? | Vai Trò |
|--------|--------------|---------|
| **1. threat_level** | ✅ **CÓ** (nếu rule level >= 12) | Chỉ bị override cho CONFIRMED attacks |
| **2. summary** | ❌ **KHÔNG** | **100% từ LLM** - Rất quan trọng! |
| **3. confidence** | ❌ **KHÔNG** | **100% từ LLM** - Dùng để tính score |
| **4. tags** | ❌ **KHÔNG** | **100% từ LLM** - Phân loại attack |

---

## 📊 Chi Tiết Vai Trò LLM

### **1. Summary (Tóm Tắt Alert) - 100% LLM**

**Vai trò:**
- ✅ **Giải thích "cái gì xảy ra"** trong 1-2 câu
- ✅ **Viết cho SOC analyst** đọc nhanh
- ✅ **Không cần đọc raw log**

**Ví dụ:**
```
Rule 110231 (Level 13 - CONFIRMED reverse shell):
├─ Rule Level Override: threat_level = "critical" ✅
└─ LLM Summary: "Auditd on WebServer detected an outbound network 
   connection initiated by the web server user, which is commonly 
   associated with a webshell spawning a reverse shell. This behavior 
   is unusual for a web server process and indicates potential compromise."
```

**Giá trị:**
- SOC analyst đọc summary → hiểu ngay attack là gì
- Không cần mở Wazuh dashboard để đọc raw log
- Tiết kiệm thời gian triage

---

### **2. Confidence (Độ Tin Cậy) - 100% LLM**

**Vai trò:**
- ✅ **Đánh giá độ chắc chắn** của phân tích (0.0 - 1.0)
- ✅ **Dùng để tính final score**
- ✅ **Dynamic weighting** dựa trên confidence

**Công thức tính score:**
```python
# Fuse heuristic và LLM confidence
fused_score = (heuristic_weight * h_score) + (llm_weight * llm_confidence)

# Dynamic weighting dựa trên LLM confidence
if llm_confidence < 0.3:
    # Low confidence → tin heuristic hơn
    h_weight = 0.7, l_weight = 0.3
elif llm_confidence > 0.8:
    # High confidence → tin LLM hơn
    h_weight = 0.3, l_weight = 0.7
```

**Ví dụ:**
```
Rule 110231 (Level 13):
├─ Rule Level Override: threat_level = "critical" ✅
├─ LLM confidence: 0.78 (cao)
├─ Heuristic score: 1.0 (level 13)
├─ Final score: (0.4 * 1.0) + (0.6 * 0.78) = 0.868 ✅
└─ → Score cao vì LLM confidence cao
```

**Giá trị:**
- Score phản ánh độ chắc chắn thực sự
- High confidence → SOC tin tưởng hơn
- Low confidence → SOC cần verify thêm

---

### **3. Tags (Phân Loại) - 100% LLM**

**Vai trò:**
- ✅ **Phân loại attack type** (xss, sql_injection, command_injection, etc.)
- ✅ **Gắn tags chuẩn hóa** cho SOC workflow
- ✅ **Dùng để boost confidence** cho specific rules

**Ví dụ:**
```
Rule 110231 (Level 13):
├─ Rule Level Override: threat_level = "critical" ✅
└─ LLM Tags: ["wazuh_rule_high", "network_intrusion", 
              "suspicious_process", "web_attack"] ✅

Rule 31105 (Level 7):
├─ Threat Level: "high" (từ LLM, không override)
└─ LLM Tags: ["web_attack", "xss", "wazuh_rule_high"] ✅
```

**Giá trị:**
- SOC biết attack type ngay (XSS, SQLi, reverse shell, etc.)
- Có thể filter/search theo tags
- Có thể route đến đúng playbook

---

### **4. Threat Level (Chỉ Bị Override Cho CONFIRMED)**

**Vai trò:**
- ✅ **Đánh giá mức độ nguy hiểm** (none, low, medium, high, critical)
- ✅ **Bị override** chỉ khi rule level >= 12 (CONFIRMED)
- ✅ **Vẫn dùng** cho rule level < 12

**Logic:**
```python
# LLM đánh threat_level
llm_threat_level = llm_result.get("threat_level", "medium")

# Override chỉ cho CONFIRMED attacks
if rule_level >= 12:
    threat_level = "critical"  # Override LLM
else:
    threat_level = llm_threat_level  # Dùng LLM
```

**Ví dụ:**
```
Rule 110231 (Level 13):
├─ LLM threat_level: "high"
├─ Rule Level Override: threat_level = "critical" ✅
└─ → Override vì level 13 = CONFIRMED

Rule 31105 (Level 7):
├─ LLM threat_level: "high"
├─ Rule Level Override: KHÔNG (level < 12)
└─ → Dùng LLM: threat_level = "high" ✅
```

**Giá trị:**
- CONFIRMED attacks luôn được đánh đúng (critical)
- Attempts vẫn được LLM đánh giá linh hoạt (high/medium)

---

## 🎯 Tổng Hợp: LLM Làm Gì?

### **Khi Rule Level >= 12 (CONFIRMED):**

| Task | LLM Làm? | Override? |
|------|----------|-----------|
| **Summary** | ✅ Có | ❌ Không |
| **Confidence** | ✅ Có | ❌ Không |
| **Tags** | ✅ Có | ❌ Không |
| **Threat Level** | ✅ Có | ✅ **Có** (override → "critical") |

**Kết quả:**
- ✅ LLM vẫn phân tích toàn bộ alert
- ✅ LLM vẫn tạo summary, tags, confidence
- ✅ Chỉ threat_level bị override (vì rule level = nguồn sự thật)

---

### **Khi Rule Level < 12 (Attempts/Normal):**

| Task | LLM Làm? | Override? |
|------|----------|-----------|
| **Summary** | ✅ Có | ❌ Không |
| **Confidence** | ✅ Có | ❌ Không |
| **Tags** | ✅ Có | ❌ Không |
| **Threat Level** | ✅ Có | ❌ Không (dùng LLM) |

**Kết quả:**
- ✅ LLM quyết định 100% (không override)
- ✅ LLM đánh giá linh hoạt dựa trên context

---

## 💡 Ví Dụ Thực Tế

### **Case 1: Rule 110231 (Level 13 - CONFIRMED Reverse Shell)**

**LLM Output:**
```json
{
  "summary": "Auditd on WebServer detected an outbound network connection...",
  "threat_level": "high",  // ← Bị override
  "confidence": 0.78,
  "tags": ["network_intrusion", "suspicious_process", "web_attack"]
}
```

**Final Result:**
```python
threat_level = "critical"  # Override từ "high" → "critical"
summary = "Auditd on WebServer..."  # Dùng LLM
confidence = 0.78  # Dùng LLM
tags = ["network_intrusion", ...]  # Dùng LLM
final_score = (0.4 * 1.0) + (0.6 * 0.78) = 0.868  # Dùng LLM confidence
```

**LLM vẫn làm:**
- ✅ Tạo summary (SOC đọc để hiểu attack)
- ✅ Tính confidence (0.78 → score cao)
- ✅ Gắn tags (network_intrusion, suspicious_process)
- ✅ Phân tích context (reverse shell pattern)

**Chỉ threat_level bị override:**
- ❌ LLM đánh "high" → Override → "critical"
- ✅ Vì rule level 13 = CONFIRMED (nguồn sự thật)

---

### **Case 2: Rule 31105 (Level 7 - XSS Attempt)**

**LLM Output:**
```json
{
  "summary": "Wazuh rule 31105 triggered on the WebServer, indicating a potential Cross-Site Scripting (XSS) attempt...",
  "threat_level": "high",  // ← KHÔNG bị override
  "confidence": 0.87,
  "tags": ["web_attack", "xss", "wazuh_rule_high"]
}
```

**Final Result:**
```python
threat_level = "high"  # Dùng LLM (không override)
summary = "Wazuh rule 31105..."  # Dùng LLM
confidence = 0.87  # Dùng LLM
tags = ["web_attack", "xss", ...]  # Dùng LLM
final_score = (0.4 * 0.47) + (0.6 * 0.87) = 0.71  # Dùng LLM confidence
```

**LLM quyết định 100%:**
- ✅ Threat level: "high" (LLM đánh đúng)
- ✅ Summary: Giải thích XSS attempt
- ✅ Confidence: 0.87 (cao, vì LLM chắc chắn)
- ✅ Tags: ["xss", "web_attack"]

---

## 🔍 So Sánh: Có LLM vs Không LLM

### **Không Có LLM (Chỉ Rule Level):**

```
Rule 110231 (Level 13):
├─ threat_level: "critical" ✅
├─ summary: "Rule 110231 triggered" ❌ (quá ngắn, không giải thích)
├─ confidence: 0.0 ❌ (không biết độ chắc chắn)
├─ tags: [] ❌ (không phân loại)
└─ → SOC phải mở Wazuh để đọc raw log
```

**Vấn đề:**
- ❌ SOC không biết attack là gì (reverse shell? webshell? command execution?)
- ❌ SOC không biết độ chắc chắn (có thể false positive?)
- ❌ SOC không biết attack type (không có tags để filter)

---

### **Có LLM (Với Rule Level Override):**

```
Rule 110231 (Level 13):
├─ threat_level: "critical" ✅ (override từ rule level)
├─ summary: "Auditd detected outbound network connection by web server user, 
│           consistent with reverse shell/webshell callback..." ✅
├─ confidence: 0.78 ✅ (cao, chắc chắn)
├─ tags: ["network_intrusion", "suspicious_process", "web_attack"] ✅
└─ → SOC đọc summary là hiểu ngay, không cần mở Wazuh
```

**Ưu điểm:**
- ✅ SOC biết ngay attack là gì (reverse shell)
- ✅ SOC biết độ chắc chắn (0.78 = cao)
- ✅ SOC biết attack type (network_intrusion, suspicious_process)
- ✅ SOC không cần mở Wazuh để đọc raw log

---

## 📋 Tóm Tắt

### **LLM Vẫn Làm Rất Nhiều Việc:**

1. **Summary** (100% LLM)
   - Giải thích "cái gì xảy ra"
   - SOC đọc để hiểu attack
   - Tiết kiệm thời gian triage

2. **Confidence** (100% LLM)
   - Đánh giá độ chắc chắn
   - Dùng để tính final score
   - Dynamic weighting

3. **Tags** (100% LLM)
   - Phân loại attack type
   - Gắn tags chuẩn hóa
   - Filter/search/route

4. **Threat Level** (LLM + Override)
   - LLM đánh giá linh hoạt
   - Override chỉ cho CONFIRMED (level >= 12)
   - Attempts vẫn dùng LLM

### **Rule Level Override Chỉ Làm:**

- ✅ Đảm bảo CONFIRMED attacks (level >= 12) → luôn "critical"
- ✅ Không thay thế LLM, chỉ bổ sung logic SOC

### **Kết Luận:**

**LLM vẫn là "Junior SOC Analyst" tự động:**
- ✅ Đọc và hiểu alert context
- ✅ Tạo summary cho SOC
- ✅ Đánh giá confidence
- ✅ Phân loại attack type
- ✅ Đánh giá threat level (cho attempts)

**Rule Level Override chỉ là "Senior SOC Analyst" review:**
- ✅ Đảm bảo CONFIRMED attacks được đánh đúng
- ✅ Không thay thế LLM, chỉ validate

---

**LLM vẫn rất quan trọng, chỉ threat_level bị override cho CONFIRMED attacks!**

