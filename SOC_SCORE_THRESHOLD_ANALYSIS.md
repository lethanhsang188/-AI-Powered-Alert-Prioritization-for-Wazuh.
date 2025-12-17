# 🔍 Phân Tích Logic Score Threshold - Góc Độ SOC

**Project:** AI-Powered Alert Prioritization for Wazuh  
**Date:** 2025-12-14  
**Perspective:** SOC Analyst

---

## ⚠️ VẤN ĐỀ PHÁT HIỆN

### **Tình huống:**

**Alert nguy hiểm nhưng score < 0.7:**
- Rule 110231 (Level 13) - CONFIRMED Reverse Shell
- Rule 110230 (Level 13) - CONFIRMED Command Execution
- Rule 31105 (Level 7) - XSS Attack
- Rule 31103 (Level 7) - SQL Injection

**Vấn đề:**
- ❌ **n8n workflow chỉ check `score >= 0.7`**
- ❌ **Không check `critical_attack_override` flag**
- ❌ **Alerts nguy hiểm có thể bị miss nếu score < 0.7**

---

## 🔍 PHÂN TÍCH LOGIC HIỆN TẠI

### **1. Logic trong Python (notify.py):**

```python
# Check if this is a critical attack that must notify regardless of score
is_critical_attack, override_reason = should_notify_critical_attack(alert, triage)

# Check threshold
if score < TRIAGE_THRESHOLD:
    if is_critical_attack:
        # CRITICAL: Override threshold for critical attacks
        # Continue to send notification (don't return early)
        payload["critical_attack_override"] = True
        payload["override_reason"] = override_reason
    else:
        # Normal alert below threshold - suppress
        return True  # Skip notification
```

**Kết quả:**
- ✅ **Python code có Critical Attack Override**
- ✅ **Gửi webhook với `critical_attack_override: true`**
- ✅ **Payload có flag `critical_attack_override`**

---

### **2. Logic trong n8n Workflow (HIỆN TẠI):**

```javascript
// Check Score >= 0.7
IF score >= 0.7:
  → Send to Telegram
ELSE:
  → Log Low Score (KHÔNG gửi Telegram)
```

**Vấn đề:**
- ❌ **Chỉ check score, KHÔNG check `critical_attack_override`**
- ❌ **Alerts có `critical_attack_override: true` nhưng score < 0.7 → KHÔNG gửi Telegram**
- ❌ **Miss alerts nguy hiểm!**

---

## 🚨 SCENARIO: MISS CRITICAL ALERTS

### **Ví dụ 1: CONFIRMED Reverse Shell (Rule 110231, Level 13)**

**Alert:**
```json
{
  "rule_id": "110231",
  "rule_level": 13,
  "score": 0.65,  // < 0.7 (thấp vì thiếu context)
  "critical_attack_override": true,  // ← Python đã set flag này
  "override_reason": "High rule level 13 indicates critical threat",
  "threat_level": "CRITICAL"
}
```

**Flow:**
1. ✅ Python code detect: `rule_level >= 12` → `critical_attack_override = true`
2. ✅ Python code gửi webhook với flag `critical_attack_override: true`
3. ❌ **n8n workflow check: `score (0.65) >= 0.7` → FALSE**
4. ❌ **n8n workflow route đến "Log Low Score" → KHÔNG gửi Telegram**
5. ❌ **SOC team KHÔNG nhận được alert!**

**Hậu quả:**
- 🔴 **CONFIRMED Reverse Shell không được notify**
- 🔴 **SOC team không biết có attacker đã compromise server**
- 🔴 **False negative - rất nguy hiểm!**

---

### **Ví dụ 2: XSS Attack (Rule 31105, Level 7)**

**Alert:**
```json
{
  "rule_id": "31105",
  "rule_level": 7,
  "score": 0.68,  // < 0.7 (thấp vì LLM confidence thấp)
  "critical_attack_override": true,  // ← Python đã set flag này
  "override_reason": "Critical attack rule 31105 (level 7)",
  "threat_level": "HIGH",
  "tags": ["web_attack", "xss"]
}
```

**Flow:**
1. ✅ Python code detect: `rule_id in CRITICAL_ATTACK_RULES` → `critical_attack_override = true`
2. ✅ Python code gửi webhook với flag `critical_attack_override: true`
3. ❌ **n8n workflow check: `score (0.68) >= 0.7` → FALSE**
4. ❌ **n8n workflow route đến "Log Low Score" → KHÔNG gửi Telegram**
5. ❌ **SOC team KHÔNG nhận được alert!**

**Hậu quả:**
- 🟠 **XSS Attack không được notify**
- 🟠 **SOC team không biết có XSS attempt**
- 🟠 **False negative - có thể miss attack**

---

## 🔍 TẠI SAO SCORE CÓ THỂ THẤP?

### **Nguyên nhân score thấp:**

1. **LLM Confidence thấp:**
   - LLM không chắc chắn về threat level
   - Confidence < 0.6 → LLM score thấp
   - Final score = (heuristic * 0.6) + (llm * 0.4) → Thấp

2. **Thiếu context:**
   - Alert thiếu source IP, destination IP
   - Alert thiếu HTTP context
   - Alert thiếu flow statistics
   - → LLM không đủ context để đánh giá đúng

3. **Heuristic score thấp:**
   - Rule level 7 → Base score = 7/15 = 0.47
   - Không có group bonus
   - → Heuristic score thấp

4. **Dynamic weighting:**
   - Nếu LLM confidence thấp → h_weight = 0.7, l_weight = 0.3
   - Final score = (0.47 * 0.7) + (0.5 * 0.3) = 0.479 → Rất thấp!

---

## ✅ GIẢI PHÁP: UPDATE N8N WORKFLOW

### **Vấn đề:**
- ❌ n8n workflow chỉ check `score >= 0.7`
- ❌ Không check `critical_attack_override` flag

### **Giải pháp:**
- ✅ **Update n8n workflow để check CẢ HAI:**
  1. `score >= 0.7` (normal threshold)
  2. **HOẶC** `critical_attack_override === true` (critical attack override)

---

## 🔧 CẬP NHẬT N8N WORKFLOW

### **Option 1: Update IF Node (RECOMMENDED)**

**Thay đổi condition trong "Check Score >= 0.7" node:**

**CŨ:**
```javascript
// Chỉ check score
{{ $json.originalAlert.score }} >= 0.7
```

**MỚI:**
```javascript
// Check score HOẶC critical_attack_override
{{ $json.originalAlert.score }} >= 0.7 || {{ $json.originalAlert.critical_attack_override }} === true
```

**Hoặc dùng Expression:**
```
Score >= 0.7 OR Critical Attack Override
```

**Logic:**
```
IF (score >= 0.7 OR critical_attack_override === true):
  → Send to Telegram
ELSE:
  → Log Low Score
```

---

### **Option 2: Thêm Node Riêng (SAFER)**

**Thêm "Check Critical Attack" node trước "Check Score":**

```
Parse Alert Data
  ↓
Check Critical Attack Override
  ├─→ [TRUE] → Send to Telegram (CRITICAL PATH)
  └─→ [FALSE] → Check Score >= 0.7
                  ├─→ [TRUE] → Send to Telegram
                  └─→ [FALSE] → Log Low Score
```

**Function Node: "Check Critical Attack Override"**
```javascript
const alert = $input.item.json.originalAlert;

// Check critical attack override
const isCritical = alert.critical_attack_override === true;
const overrideReason = alert.override_reason || "";

return {
  json: {
    isCriticalAttack: isCritical,
    overrideReason: overrideReason,
    originalAlert: alert
  }
};
```

**IF Node: "Check Critical Attack Override"**
```
Condition: {{ $json.isCriticalAttack }} === true
```

**Kết quả:**
- ✅ **Critical attacks được gửi Telegram ngay (không cần check score)**
- ✅ **Normal alerts vẫn check score >= 0.7**
- ✅ **Không miss critical alerts**

---

### **Option 3: Combine Logic trong Function Node (BEST)**

**Update "Parse Alert Data" node:**

```javascript
// ... existing code ...

// Check if should send to Telegram
const score = alert.score || 0;
const isCriticalOverride = alert.critical_attack_override === true;
const shouldNotify = score >= 0.7 || isCriticalOverride;

return {
  json: {
    message: message,
    chatId: process.env.TELEGRAM_CHAT_ID || "YOUR_CHAT_ID_HERE",
    parseMode: "Markdown",
    originalAlert: alert,
    shouldNotify: shouldNotify,  // ← Thêm flag này
    isCriticalOverride: isCriticalOverride,  // ← Thêm flag này
    overrideReason: alert.override_reason || null  // ← Thêm reason
  }
};
```

**Update "Check Score >= 0.7" node:**

**Thay đổi condition:**
```
{{ $json.shouldNotify }} === true
```

**Hoặc:**
```
{{ $json.originalAlert.score }} >= 0.7 || {{ $json.isCriticalOverride }} === true
```

**Kết quả:**
- ✅ **Check cả score VÀ critical_attack_override**
- ✅ **Không miss critical alerts**
- ✅ **Logic rõ ràng, dễ maintain**

---

## 📊 SO SÁNH LOGIC

### **Logic CŨ (CHỈ CHECK SCORE):**

```
IF score >= 0.7:
  → Send to Telegram
ELSE:
  → Log Low Score (KHÔNG gửi Telegram)
```

**Vấn đề:**
- ❌ Miss alerts nguy hiểm có score < 0.7
- ❌ Không sử dụng `critical_attack_override` flag
- ❌ False negatives

---

### **Logic MỚI (CHECK CẢ HAI):**

```
IF (score >= 0.7 OR critical_attack_override === true):
  → Send to Telegram
ELSE:
  → Log Low Score (KHÔNG gửi Telegram)
```

**Ưu điểm:**
- ✅ Không miss critical alerts
- ✅ Sử dụng `critical_attack_override` flag từ Python
- ✅ Giảm false negatives
- ✅ SOC team nhận được tất cả alerts quan trọng

---

## 🎯 RECOMMENDED SOLUTION

### **Update n8n Workflow - Option 3 (BEST):**

**1. Update "Parse Alert Data" Function Node:**

```javascript
// ... existing parse code ...

// Check if should send to Telegram
const score = alert.score || 0;
const isCriticalOverride = alert.critical_attack_override === true;
const overrideReason = alert.override_reason || null;

// Should notify if:
// - Score >= 0.7 (normal threshold)
// - OR critical_attack_override === true (critical attack)
const shouldNotify = score >= 0.7 || isCriticalOverride;

// Add warning emoji if critical override
let messagePrefix = "";
if (isCriticalOverride && score < 0.7) {
  messagePrefix = "🚨 *CRITICAL ATTACK OVERRIDE* 🚨\n";
  messagePrefix += `*Reason:* ${overrideReason}\n`;
  messagePrefix += `*Score:* ${score.toFixed(3)} (below threshold 0.7)\n\n`;
}

const finalMessage = messagePrefix + message;

return {
  json: {
    message: finalMessage,
    chatId: process.env.TELEGRAM_CHAT_ID || "YOUR_CHAT_ID_HERE",
    parseMode: "Markdown",
    originalAlert: alert,
    shouldNotify: shouldNotify,
    isCriticalOverride: isCriticalOverride,
    overrideReason: overrideReason
  }
};
```

**2. Update "Check Score >= 0.7" IF Node:**

**Rename node:** "Check Should Notify"

**Condition:**
```
{{ $json.shouldNotify }} === true
```

**Hoặc:**
```
{{ $json.originalAlert.score }} >= 0.7 || {{ $json.isCriticalOverride }} === true
```

**Kết quả:**
- ✅ **Critical attacks được gửi Telegram (dù score < 0.7)**
- ✅ **Normal alerts vẫn check score >= 0.7**
- ✅ **Message có warning nếu là critical override**
- ✅ **Không miss alerts nguy hiểm**

---

## 📋 TEST SCENARIOS

### **Scenario 1: High Score Alert (Normal)**

**Input:**
```json
{
  "score": 0.85,
  "critical_attack_override": false
}
```

**Flow:**
- `score (0.85) >= 0.7` → TRUE
- `shouldNotify = true`
- → Send to Telegram ✅

---

### **Scenario 2: Critical Attack với Score Thấp**

**Input:**
```json
{
  "score": 0.65,
  "critical_attack_override": true,
  "override_reason": "High rule level 13 indicates critical threat"
}
```

**Flow (CŨ):**
- `score (0.65) >= 0.7` → FALSE
- → Log Low Score ❌ (MISS!)

**Flow (MỚI):**
- `score (0.65) >= 0.7` → FALSE
- `critical_attack_override === true` → TRUE
- `shouldNotify = true`
- → Send to Telegram ✅ (KHÔNG MISS!)

---

### **Scenario 3: Low Score Alert (Normal)**

**Input:**
```json
{
  "score": 0.50,
  "critical_attack_override": false
}
```

**Flow:**
- `score (0.50) >= 0.7` → FALSE
- `critical_attack_override === false` → FALSE
- `shouldNotify = false`
- → Log Low Score ✅ (Đúng - không phải critical)

---

## 🎯 KẾT LUẬN

### **Vấn đề:**
- ❌ **n8n workflow chỉ check `score >= 0.7`**
- ❌ **Không check `critical_attack_override` flag**
- ❌ **Có thể miss alerts nguy hiểm có score < 0.7**

### **Giải pháp:**
- ✅ **Update n8n workflow để check CẢ HAI:**
  1. `score >= 0.7` (normal threshold)
  2. **HOẶC** `critical_attack_override === true` (critical attack override)

### **Implementation:**
- ✅ **Update "Parse Alert Data" node** → Thêm `shouldNotify` flag
- ✅ **Update "Check Score >= 0.7" node** → Check `shouldNotify` thay vì chỉ score
- ✅ **Add warning message** nếu là critical override

---

## 📚 REFERENCES

- Critical Attack Override Logic: `src/orchestrator/notify.py`
- n8n Workflow: `configs/n8n/workflow_telegram_alerts.json`
- Workflow Explanation: `N8N_WORKFLOW_EXPLANATION.md`

---

**Document Version:** 1.0  
**Last Updated:** 2025-12-14  
**Author:** SOC Analysis Team


