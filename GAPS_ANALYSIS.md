# Phân Tích Các Phần Còn Thiếu - AI-Powered Alert Prioritization Pipeline

## 🔴 CRITICAL ISSUES (Phải sửa ngay)

### 1. Bug trong `src/analyzer/llm.py` - Missing Logger
**Vấn đề:** Dòng 36 sử dụng `logger.warning()` nhưng `logger` chưa được khai báo.

```python
# Line 15-16: Thiếu dòng này
logger = logging.getLogger(__name__)
```

**Impact:** Runtime error khi LLM_ENABLE=true nhưng không có API key.

**Fix:** Thêm `logger = logging.getLogger(__name__)` sau dòng 14.

---

### 2. Configuration Validation - Triage Weights
**Vấn đề:** Không validate `HEURISTIC_WEIGHT + LLM_WEIGHT = 1.0`. Nếu weights không đúng sẽ cho kết quả sai.

**Impact:** Scores không chính xác, có thể > 1.0 hoặc < 0.0 sau khi clamp.

**Fix:** Thêm validation trong `src/common/config.py`:
```python
# Validate weights sum to 1.0
if abs(HEURISTIC_WEIGHT + LLM_WEIGHT - 1.0) > 0.001:
    raise ValueError(f"HEURISTIC_WEIGHT ({HEURISTIC_WEIGHT}) + LLM_WEIGHT ({LLM_WEIGHT}) must equal 1.0")
```

---

### 3. Readiness Check Không Đầy Đủ
**Vấn đề:** `readyz` endpoint chỉ check file system, không check kết nối đến Wazuh/TheHive.

**Impact:** Service có thể report "ready" nhưng không thể kết nối đến upstream services.

**Fix:** Thêm health checks:
```python
@app.route("/readyz", methods=["GET"])
def readyz():
    # Check Wazuh connection
    # Check TheHive connection
    # Check cursor directory
```

---

### 4. Missing Authentication Validation
**Vấn đề:** Không validate Wazuh auth (phải có TOKEN hoặc USER+PASS).

**Impact:** Pipeline sẽ fail khi start nhưng không báo lỗi rõ ràng.

**Fix:** Thêm validation trong `WazuhClient.__init__()`.

---

## 🟡 HIGH PRIORITY (Nên có cho production)

### 5. Metrics & Monitoring
**Vấn đề:** Không có metrics để track:
- Số alerts processed/second
- Success/failure rate
- LLM response time
- TheHive API latency
- Error rates

**Impact:** Khó debug và monitor performance trong production.

**Recommendation:** Thêm metrics endpoint `/metrics` (Prometheus format) hoặc structured logging với metrics.

---

### 6. Circuit Breaker Pattern
**Vấn đề:** Nếu Wazuh/TheHive/LLM API down, sẽ liên tục retry và waste resources.

**Impact:** Throttling/quota issues, không graceful degradation.

**Recommendation:** Implement circuit breaker cho external API calls.

---

### 7. Input Validation & Sanitization
**Vấn đề:** 
- Không validate alert structure trước khi process
- Không sanitize user input trong API endpoints
- JSON parsing trong LLM response không safe (có thể crash)

**Impact:** 
- Runtime errors với malformed alerts
- Potential security issues
- LLM response parsing có thể fail

**Recommendation:**
- Validate alert schema
- Safe JSON parsing với fallback
- Input sanitization

---

### 8. Better Error Handling & Alerting
**Vấn đề:**
- Errors chỉ log, không có alert mechanism
- No dead letter queue cho failed alerts
- No retry with exponential backoff cho specific errors

**Impact:** Alerts có thể bị mất nếu service fail.

**Recommendation:**
- Dead letter queue cho failed alerts
- Alert khi error rate cao
- Different retry strategies cho different error types

---

### 9. Test Coverage
**Vấn đề:**
- E2E test file rỗng (`tests/e2e/test_pipeline_e2e.py`)
- Không có integration tests
- Thiếu tests cho error cases

**Impact:** Khó đảm bảo quality và regression testing.

**Recommendation:**
- Implement E2E tests với mocked services
- Add integration tests
- Test error scenarios

---

## 🟢 MEDIUM PRIORITY (Nice to have)

### 10. Configuration Documentation
**Vấn đề:** Một số config values không rõ ràng (ví dụ: `TRIAGE_THRESHOLD` không được dùng trong code).

**Impact:** Confusion khi setup.

**Recommendation:** Document tất cả config variables và usage.

---

### 11. Rate Limiting
**Vấn đề:** Không có rate limiting cho API endpoints.

**Impact:** Potential DoS risk.

**Recommendation:** Add rate limiting cho Flask API.

---

### 12. Enhanced Logging
**Vấn đề:**
- Thiếu correlation IDs cho tracking
- Logs không có structured fields cho alert processing
- No log rotation strategy

**Impact:** Khó trace issues across services.

**Recommendation:**
- Add correlation/trace IDs
- Structured logging với more context
- Log rotation config

---

### 13. Alert Filtering Options
**Vấn đề:** Chỉ filter theo `rule.level`, không có options để:
- Filter by rule groups
- Filter by agent
- Filter by time range
- Whitelist/blacklist rules

**Impact:** Không flexible cho different use cases.

**Recommendation:** Add configurable filtering.

---

### 14. LLM Response Parsing Robustness
**Vấn đề:** LLM response có thể không đúng JSON format, code sẽ crash.

**Impact:** LLM analysis fails silently hoặc crash.

**Recommendation:** 
- Better JSON parsing với fallback
- Validation của LLM response structure
- Retry với different prompts nếu parsing fails

---

### 15. State Management Improvements
**Vấn đề:**
- Cursor chỉ lưu timestamp, không track processed alert IDs
- No checkpoint mechanism
- Có thể duplicate nếu process fails giữa chừng

**Impact:** Potential duplicate processing.

**Recommendation:**
- Track processed alert IDs
- Checkpoint mechanism
- Idempotency checks

---

### 16. API Endpoints Cho Management
**Vấn đề:** Không có endpoints để:
- View pipeline status
- Manual trigger processing
- View recent processed alerts
- Configuration reload

**Impact:** Khó quản lý và debug.

**Recommendation:** Add management API endpoints.

---

### 17. Docker Healthcheck Improvement
**Vấn đề:** Healthcheck chỉ test HTTP endpoint, không test actual pipeline functionality.

**Impact:** Container có thể report healthy nhưng pipeline không chạy.

**Recommendation:** Better healthcheck logic.

---

### 18. Documentation Gaps
**Vấn đề:**
- Không có API documentation (OpenAPI/Swagger)
- Thiếu troubleshooting guide
- Không có architecture diagram chi tiết
- Không có deployment guide

**Impact:** Khó onboard và maintain.

**Recommendation:**
- Add OpenAPI spec
- Troubleshooting guide
- Architecture diagrams
- Deployment guide

---

## 📊 Summary Checklist

### Must Fix (Trước khi demo):
- [x] Fix logger bug trong `llm.py` - ✅ Đã có sẵn logger
- [x] Add config validation cho triage weights - ✅ Đã thêm validation
- [x] Improve readiness checks - ✅ Đã thêm checks cho Wazuh/TheHive
- [x] Add Wazuh auth validation - ✅ Đã thêm validation trong config
- [x] Improve LLM JSON parsing - ✅ Đã thêm robust parsing với fallback

### Should Have (Cho production-ready):
- [ ] Metrics endpoint
- [ ] Circuit breaker
- [ ] Input validation
- [ ] Better error handling
- [ ] E2E tests

### Nice to Have (Future improvements):
- [ ] Rate limiting
- [ ] Enhanced logging
- [ ] Alert filtering options
- [ ] Management API
- [ ] Better documentation

---

## 🎯 Priority Action Plan

1. **Phase 1 (Critical - 1-2 days):**
   - Fix logger bug
   - Add config validation
   - Improve health checks
   - Add auth validation

2. **Phase 2 (High Priority - 3-5 days):**
   - Add metrics
   - Implement E2E tests
   - Better error handling
   - Input validation

3. **Phase 3 (Enhancement - Future):**
   - Circuit breaker
   - Management API
   - Enhanced filtering
   - Better documentation

---

*Phân tích bởi: SOC Analyst Review*
*Date: $(date)*

