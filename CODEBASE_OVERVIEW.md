# Codebase Overview (Wazuh Alert Triage Pipeline)

Mục tiêu: Thu thập cảnh báo từ Wazuh (index `wazuh-alerts-*`), lọc SOC hai tầng, chuẩn hóa dữ liệu, tương quan + nhãn FP, hợp nhất điểm heuristic + LLM, và gửi thông báo Telegram giàu ngữ cảnh, không bỏ sót cảnh báo quan trọng.

## Luồng chính (end-to-end)
1) Collector `src/collector/wazuh_client.py`  
   - Kết nối Wazuh API/Indexer, kéo alert theo truy vấn hai tầng (MIN/MAX level + rule ids/prefix, và luôn lấy level >= ALWAYS_REEVALUATE_LEVEL_GTE).  
   - Hỗ trợ realtime/lookback động, cursor, sort cân bằng theo thời gian và `agent.id` (đảm bảo agent 001/002 được xử lý đồng nhất).  
   - Chuẩn hóa `AlertNormalized`: timestamp (UTC/local), event_id, index, agent/rule/decoder/manager/location, network (src/dest ip/port, proto, app_proto, direction, flow stats), http, suricata_alert, tags, full_data, raw_json. Không crash nếu thiếu trường.

2) Correlation `src/common/correlation.py`  
   - Nhóm cảnh báo theo source/destination attack, signature, rule pattern trong cửa sổ thời gian; trả về `is_correlated`, `group_size`, `first_seen`, `attack_pattern`. Dùng cho giảm trùng lặp và ngữ cảnh chiến dịch.

3) FP labeling `src/common/fp_filtering.py`  
   - Gắn nhãn FP mà không loại bỏ: internal IP + 404, benign signature/user-agent, lặp lại, cron pattern. Xuất `fp_risk`, `fp_reason`, `noise_signals`, `allowlist_hit`.

4) Enrichment `src/common/enrichment.py` (nếu bật)  
   - GeoIP/Threat intel bổ sung trường hỗ trợ LLM/Telegram.

5) Triage `src/analyzer/triage.py`  
   - Tính heuristic score, gọi LLM triage_llm, dynamic weighting theo confidence, điều chỉnh theo threat level, boost khi LLM nhận đúng SQLi/XSS/command injection.  
   - Kết hợp correlation + FP context vào alert, xây `alert_card`/`alert_card_short` cho hiển thị.  
   - Trả về score, threat_level, summary, tags, title.

6) Notification `src/orchestrator/notify.py`  
   - Kiểm tra override critical (rule danh sách, critical tags, high level, Suricata severity, attack tools, correlation chiến dịch).  
   - Dùng `_to_int` để xử lý số dạng chuỗi; định dạng Telegram SOC-grade với đầy đủ phần: header, điểm số, danh tính, network, “what happened”, evidence, IOCs, correlation, khuyến nghị, MITRE, query.  
   - Validate Markdown, fallback gửi plain text nếu lỗi parse; fallback message nếu format lỗi để không mất cảnh báo.

7) Common utilities  
   - `src/common/config.py`: nạp ENV, SOC filtering, correlation/dedup window, LLM/Telegram keys, SSL verify.  
   - `src/common/dedup.py`: giảm spam trong cửa sổ dedup.  
   - `src/common/alert_formatter.py`: dựng thẻ hiển thị cho triage/notify.  
   - `src/common/llm_cache.py`: cache kết quả LLM.  
   - `src/common/logging.py`: cấu hình logger.

8) API entrypoint `src/api/app.py`  
   - FastAPI nhẹ để nhận sự kiện/gửi ra kết quả (nếu dùng).

9) Runner & tools  
   - `bin/run_pipeline.py`: chạy collector → triage → notify.  
   - `bin/test_telegram_message_formatting.py`, `bin/demo_telegram_message.py`: kiểm tra định dạng Telegram.  
   - `tests/`: unit/e2e cho collector, dedup, heuristic, redaction, pipeline.

## Các nguyên tắc SOC được áp dụng
- Không “silent drop”: tất cả alert đủ điều kiện đều đi qua FP labeling, LLM, Telegram (có fallback).  
- Ưu tiên cảnh báo quan trọng: override critical theo rule/tag/level/Suricata severity/chiến dịch.  
- Đủ ngữ cảnh cho phân tích: giữ raw_json, network/flow, HTTP, Suricata, enrichment.  
- Giảm FP bằng nhãn (fp_risk) chứ không loại bỏ; analyst vẫn nhận cảnh báo nhưng có cảnh báo mức độ FP.  
- Cân bằng agent: sort và truy vấn theo agent, không loại riêng agent 002.

