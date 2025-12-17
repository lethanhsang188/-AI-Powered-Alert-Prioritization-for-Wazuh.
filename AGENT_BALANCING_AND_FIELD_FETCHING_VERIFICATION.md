# Xác Nhận Phân Bổ Agents và Lấy Fields Đầy Đủ

## ✅ Đảm Bảo Phân Bổ Đều 2 Agents

### 1. Logic Query Từng Agent Riêng Biệt

**Vị trí code**: `src/collector/wazuh_client.py:1052-1091`

```python
# SOC Strategy: Query each agent separately to ensure balanced distribution
expected_agents = ["001", "002"]  # WebServer and pfSense

for batch_num in range(max_batches):
    batch_alerts = []
    batch_agent_counts = {agent_id: 0 for agent_id in expected_agents}

    # Fetch from each agent separately
    # IMPORTANT: Query ALL expected agents to ensure balanced distribution
    for agent_id in expected_agents:
        agent_cursor = agent_cursors.get(agent_id)
        alerts, new_cursor = self._fetch_alerts_for_agent(
            agent_id, agent_cursor, page_size=per_agent_size
        )
        # ... process alerts ...
```

**Đảm bảo**:
- ✅ Loop qua **TẤT CẢ** agents trong `expected_agents` (001 và 002)
- ✅ Query **RIÊNG BIỆT** cho từng agent
- ✅ Không bỏ sót agent nào
- ✅ Logging cho cả trường hợp có và không có alerts

### 2. Logging Để Xác Nhận

**Log khi query từng agent**:
- `agent_query_start`: Bắt đầu query agent
- `agent_raw_fetch`: Số alerts thô từ indexer (trước filter)
- `agent_no_alerts`: Không có alerts từ indexer
- `agent_filtering_stats`: Thống kê filtering
- `agent_fetch_success`: Query thành công có alerts
- `agent_fetch_empty`: Query thành công nhưng không có alerts

**Ví dụ log**:
```json
{
  "action": "agent_raw_fetch",
  "agent_id": "002",
  "raw_hits_count": 0,
  "total_available": 0
}
```

## ✅ Đảm Bảo Lấy Đầy Đủ Fields Từ wazuh-alerts-*

### 1. Query Payload Không Giới Hạn Fields

**Vị trí code**: `src/collector/wazuh_client.py:757-771`

```python
# IMPORTANT: No _source_includes or _source_excludes - we fetch ALL fields from _source
# This ensures both Agent 001 and Agent 002 get the same complete field set for filtering
payload: Dict[str, Any] = {
    "size": size,
    "sort": [...],
    "track_total_hits": False,
    # NOTE: We intentionally do NOT specify _source_includes or _source_excludes
    # This means OpenSearch will return ALL fields from _source, ensuring:
    # 1. Both Agent 001 and Agent 002 get identical field sets
    # 2. All fields needed for filtering are available
    # 3. No silent field drops that could cause filtering inconsistencies
    "query": {...}
}
```

**Đảm bảo**:
- ✅ **KHÔNG** có `_source_includes` → Lấy TẤT CẢ fields
- ✅ **KHÔNG** có `_source_excludes` → Không loại bỏ field nào
- ✅ OpenSearch trả về **TOÀN BỘ** `_source` document
- ✅ Agent 001 và Agent 002 nhận **CÙNG MỘT** bộ fields

### 2. Normalize Alert Lấy Tất Cả Fields

**Vị trí code**: `src/collector/wazuh_client.py:866-868`

```python
normalized = [
    self._normalize_alert(hit.get("_source", {})) for hit in hits
]
```

**Vị trí code**: `src/collector/wazuh_client.py:442-611`

```python
def _normalize_alert(self, raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Wazuh alert to common format with full SOC-required fields."""
    # Extract từ raw.get("data", {}) - lấy TẤT CẢ fields
    data_section = raw.get("data", {}) if isinstance(raw.get("data", {}), dict) else {}
    
    # Extract tất cả fields cần thiết:
    # - Core network fields (src_ip, dest_ip, ports, proto, etc.)
    # - Flow context (flow.src_ip, flow.dest_ip, etc.)
    # - HTTP context (http.url, http.method, etc.)
    # - Suricata alert context
    # - Metadata (http_anomaly_count)
    # - Full data section (full_data)
    # - Raw JSON (raw_json) - giữ nguyên TOÀN BỘ _source
    
    return {
        # ... normalized fields ...
        "raw": raw,  # Giữ nguyên raw alert
        "raw_json": raw_json,  # Explicit raw_json field for LLM context
    }
```

**Đảm bảo**:
- ✅ Lấy **TOÀN BỘ** `_source` từ hit
- ✅ Extract **TẤT CẢ** fields cần thiết
- ✅ Giữ nguyên `raw` và `raw_json` để không mất field nào
- ✅ Agent 001 và Agent 002 được normalize **GIỐNG NHAU**

## ✅ Đảm Bảo Filtering Logic Giống Nhau

### 1. Filtering Áp Dụng Cho Tất Cả Alerts

**Vị trí code**: `src/collector/wazuh_client.py:870-930`

```python
# TWO-STAGE FILTERING: Classification + Field-Based Filtering
# SOC Perspective: Phân loại theo rule level, sau đó lọc lại theo field indicators
filtered_alerts = []
level_filtered_count = 0
field_filtered_count = 0

for alert in normalized:
    rule_id = alert.get("rule", {}).get("id")
    rule_level = alert.get("rule", {}).get("level", 0)
    
    # Stage 2: Classification by rule level
    level_class = self._classify_alert_by_level(alert)
    
    # Stage 3: Level-specific field-based filtering
    should_process, filter_reason = self._apply_level_specific_filter(alert, level_class)
    if not should_process:
        level_filtered_count += 1
        continue
    
    # Stage 4: General field-based filtering (check all alerts)
    should_process, filter_reason = self._apply_field_based_filter(alert)
    if not should_process:
        field_filtered_count += 1
        continue
    
    filtered_alerts.append(alert)
```

**Đảm bảo**:
- ✅ **TẤT CẢ** alerts (từ cả Agent 001 và 002) đi qua **CÙNG MỘT** filtering pipeline
- ✅ Không có logic đặc biệt cho agent nào
- ✅ Logging thống kê filtering cho từng agent

### 2. Logging Thống Kê Filtering

**Vị trí code**: `src/collector/wazuh_client.py:930-945`

```python
# Log filtering statistics
logger.info(
    "Filtering complete for agent %s: %d raw alerts -> %d after filtering",
    agent_id,
    len(normalized),
    len(filtered_alerts),
    extra={
        "component": "wazuh_client",
        "action": "agent_filtering_stats",
        "agent_id": agent_id,
        "raw_alerts": len(normalized),
        "filtered_alerts": len(filtered_alerts),
        "level_filtered": level_filtered_count,
        "field_filtered": field_filtered_count,
    },
)
```

**Đảm bảo**:
- ✅ Log số alerts thô (trước filter) cho từng agent
- ✅ Log số alerts sau filter cho từng agent
- ✅ Log số alerts bị filter bởi level-specific filter
- ✅ Log số alerts bị filter bởi field-based filter
- ✅ Có thể so sánh filtering giữa Agent 001 và 002

## 📊 Cách Kiểm Tra

### 1. Kiểm Tra Logs

Khi chạy pipeline, tìm các log entries:

**Agent 001**:
```json
{"action": "agent_raw_fetch", "agent_id": "001", "raw_hits_count": 10}
{"action": "agent_filtering_stats", "agent_id": "001", "raw_alerts": 10, "filtered_alerts": 10}
```

**Agent 002**:
```json
{"action": "agent_raw_fetch", "agent_id": "002", "raw_hits_count": 0}
{"action": "agent_no_alerts", "agent_id": "002"}
```

### 2. Kiểm Tra Fields

Để đảm bảo fields đầy đủ, kiểm tra trong log:
- `raw_alerts`: Số alerts thô từ indexer
- Nếu `raw_alerts > 0` nhưng `filtered_alerts = 0` → Có thể bị filter
- Kiểm tra `level_filtered` và `field_filtered` để biết lý do

### 3. So Sánh Filtering

So sánh logs giữa Agent 001 và 002:
- Nếu Agent 001 có `raw_alerts > 0` nhưng Agent 002 có `raw_alerts = 0` → Agent 002 không có alerts trong khoảng thời gian lookback
- Nếu cả 2 đều có `raw_alerts > 0` nhưng `filtered_alerts` khác nhau → Kiểm tra filtering logic

## 🔍 Các Khả Năng Agent 002 Không Có Alerts

1. **Không có alerts trong khoảng thời gian lookback** (48 giây)
   - Agent 002 có thể không có hoạt động trong thời gian này
   - Giải pháp: Tăng `WAZUH_LOOKBACK_MINUTES` hoặc kiểm tra Wazuh dashboard

2. **Alerts bị filter bởi SOC rules** (rule level, rule ID)
   - Kiểm tra `agent_filtering_stats` log
   - Xem `level_filtered` và `field_filtered` counts

3. **Alerts không đạt điều kiện query** (level < MIN_LEVEL hoặc không match rule ID prefix)
   - Kiểm tra query trong `_build_indexer_query`
   - Xem SOC filtering rules: `MIN_LEVEL`, `MAX_LEVEL`, `INCLUDE_RULE_IDS`, `INCLUDE_RULE_ID_PREFIX`

## ✅ Kết Luận

**Đảm bảo đã được thực hiện**:
1. ✅ Pipeline query **CẢ 2 AGENTS** (001 và 002) trong mỗi batch
2. ✅ Query lấy **ĐẦY ĐỦ TẤT CẢ FIELDS** từ `_source` (không có `_source_includes/excludes`)
3. ✅ Filtering logic **GIỐNG NHAU** cho cả 2 agents
4. ✅ Logging **ĐẦY ĐỦ** để debug và xác nhận

**Cần kiểm tra**:
- Chạy pipeline và xem logs để xác nhận Agent 002 được query
- Kiểm tra `agent_raw_fetch` và `agent_filtering_stats` logs
- So sánh filtering statistics giữa 2 agents

