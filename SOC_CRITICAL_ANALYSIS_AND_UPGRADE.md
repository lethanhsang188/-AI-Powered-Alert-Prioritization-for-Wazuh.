# 🔍 Phân Tích SOC: Phân Bổ Alerts & Critical Attack Detection

**Ngày:** 2025-12-13  
**Người phân tích:** SOC Analyst  
**Mục đích:** Đánh giá và nâng cấp hệ thống cho production

---

## 📊 PHẦN 1: PHÂN BỔ ALERTS TỪ 2 AGENTS

### **Hiện Trạng:**

**✅ Đã có:**
- Query từng agent riêng (`expected_agents = ["001", "002"]`)
- Fetch 50 alerts per agent per batch
- Tracking `agent_distribution` trong log
- Filter pfSense spam (rule 100100, event_type="alert")

**❌ Vấn Đề:**

1. **Không đảm bảo cân bằng thực sự:**
   ```python
   # Nếu agent 001 có 1000 alerts, agent 002 có 10 alerts
   # → Agent 001 vẫn fetch 50, agent 002 fetch 10
   # → Không cân bằng về tổng số alerts processed
   ```

2. **Không có adaptive balancing:**
   - Nếu một agent có quá nhiều alerts, agent kia bị "chết đói"
   - Không có cơ chế điều chỉnh `per_agent_size` dựa trên backlog

3. **Không có monitoring:**
   - Không track số alerts bị skip do imbalance
   - Không có alert khi một agent bị bỏ qua quá lâu

---

## 📊 PHẦN 2: CRITICAL ATTACK DETECTION

### **Vấn Đề Nghiêm Trọng:**

**❌ AI KHÔNG BIẾT NGUY HIỂM khi hệ thống bị tấn công nhưng alerts có score thấp:**

**Ví dụ thực tế:**
```
Rule 31105 (XSS Attack):
├─ Heuristic: 0.68
├─ LLM confidence: 0.4 (không nhận ra XSS)
├─ Fused: (0.6 × 0.68) + (0.4 × 0.4) = 0.568
├─ Threat adjustment: +0.0 (medium)
└─ Final: 0.568 ❌ (dưới threshold 0.70)
→ KHÔNG GỬI NOTIFICATION → SOC KHÔNG BIẾT!
```

**Hậu quả:**
- ✅ Hệ thống BỊ TẤN CÔNG (XSS, SQL injection, command injection)
- ❌ Alert có score thấp (< 0.70)
- ❌ Không gửi notification
- ❌ SOC không biết → **FALSE NEGATIVE NGHIÊM TRỌNG**

---

## 🔧 GIẢI PHÁP NÂNG CẤP

### **1. Critical Attack Override (CRITICAL)**

**Logic:**
- Nếu phát hiện attack pattern nguy hiểm (XSS, SQL injection, command injection) → **BẮT BUỘC NOTIFY** dù score thấp
- Override threshold cho critical attacks

**Implementation:**
```python
# Critical attack rules that MUST notify regardless of score
CRITICAL_ATTACK_RULES = {
    "31105",  # XSS
    "31103", "31104",  # SQL injection
    "100144", "100145", "100146",  # Command injection
    "31106",  # Successful web attack (HTTP 200)
}

# Critical attack tags
CRITICAL_ATTACK_TAGS = {
    "xss", "sql_injection", "command_injection", "path_traversal"
}

def should_notify_critical_attack(alert, triage):
    rule_id = alert.get("rule", {}).get("id", "")
    tags = triage.get("tags", [])
    threat_level = triage.get("threat_level", "").lower()
    
    # Rule-based override
    if rule_id in CRITICAL_ATTACK_RULES:
        return True, f"Critical attack rule {rule_id}"
    
    # Tag-based override
    if any(tag in CRITICAL_ATTACK_TAGS for tag in tags):
        return True, f"Critical attack tag detected: {tags}"
    
    # Threat level override
    if threat_level in ["critical", "high"]:
        return True, f"High threat level: {threat_level}"
    
    return False, None
```

---

### **2. Improved Agent Balancing**

**Logic:**
- Track alerts per agent trong time window
- Điều chỉnh `per_agent_size` dựa trên backlog
- Đảm bảo mỗi agent được xử lý đều

**Implementation:**
```python
class AgentBalancer:
    def __init__(self):
        self.agent_stats = {}  # Track alerts per agent
        self.min_alerts_per_agent = 20  # Minimum to ensure balance
    
    def calculate_per_agent_size(self, agent_backlog):
        # Adaptive sizing based on backlog
        if agent_backlog > 1000:
            return 100  # More alerts for high-volume agent
        elif agent_backlog > 100:
            return 50   # Standard
        else:
            return 20   # Minimum
```

---

### **3. Alert Suppression Warning**

**Logic:**
- Log warning khi alert quan trọng bị suppress
- Track metrics về suppressed alerts
- Alert SOC khi có pattern nguy hiểm bị bỏ qua

**Implementation:**
```python
def notify(alert, triage):
    score = triage.get("score", 0.0)
    is_critical, reason = should_notify_critical_attack(alert, triage)
    
    if score < TRIAGE_THRESHOLD and not is_critical:
        # Log warning for suppressed alerts
        logger.warning(
            "Alert suppressed (score below threshold)",
            extra={
                "rule_id": alert.get("rule", {}).get("id"),
                "score": score,
                "threshold": TRIAGE_THRESHOLD,
                "tags": triage.get("tags", []),
                "threat_level": triage.get("threat_level")
            }
        )
        return True
    
    # Override for critical attacks
    if is_critical and score < TRIAGE_THRESHOLD:
        logger.warning(
            "CRITICAL: Overriding threshold for critical attack",
            extra={
                "rule_id": alert.get("rule", {}).get("id"),
                "score": score,
                "threshold": TRIAGE_THRESHOLD,
                "override_reason": reason
            }
        )
        # Continue to send notification
```

---

## 🎯 IMPLEMENTATION PLAN

### **Priority 1: Critical Attack Override (CRITICAL)**

1. Thêm `should_notify_critical_attack()` function
2. Modify `notify()` để check critical attacks
3. Override threshold cho critical attacks
4. Log warning khi override

### **Priority 2: Improved Agent Balancing**

1. Thêm `AgentBalancer` class
2. Track agent statistics
3. Adaptive `per_agent_size`
4. Monitoring và alerting

### **Priority 3: Metrics & Monitoring**

1. Track suppressed alerts
2. Track critical attack overrides
3. Dashboard metrics
4. Alert SOC khi có pattern nguy hiểm

---

## 📋 TESTING CHECKLIST

- [ ] Test với XSS attack (Rule 31105) có score < 0.70
- [ ] Verify notification được gửi dù score thấp
- [ ] Test với SQL injection có score < 0.70
- [ ] Test với command injection có score < 0.70
- [ ] Verify agent balancing với 2 agents
- [ ] Verify logging và metrics

---

## 🎯 KẾT LUẬN

**Vấn đề hiện tại:**
1. ❌ Alerts quan trọng bị bỏ qua nếu score < 0.70
2. ❌ Không có override cho critical attacks
3. ⚠️ Agent balancing chưa hoàn hảo

**Giải pháp:**
1. ✅ Critical attack override
2. ✅ Improved agent balancing
3. ✅ Metrics và monitoring

**Timeline:**
- **Day 1:** Implement critical attack override
- **Day 2:** Improve agent balancing
- **Day 3:** Add metrics và testing
- **Day 4:** Documentation và demo prep

