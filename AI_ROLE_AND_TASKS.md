# AI Role and Tasks in the SOC Pipeline

Mục tiêu: AI (LLM) hỗ trợ phân tích cảnh báo Wazuh theo chuẩn SOC, giảm false positive bằng nhãn (không drop), nâng cao độ chính xác/đầy đủ ngữ cảnh và xuất kết quả dạng JSON nghiêm ngặt cho tự động hóa.

## Vai trò chính của AI
- **Tóm tắt & phân loại**: Nhận đầu vào AlertNormalized (identity, network, HTTP, Suricata, flow, enrichment, raw_json) + correlation + fp_filtering; tạo summary ngắn, threat_level, tags, confidence.  
- **Chấm điểm bổ trợ**: Hợp cùng heuristic score (dynamic weighting). AI không tự quyết drop; chỉ gợi ý mức độ và tự tin.  
- **Bổ sung ngữ cảnh SOC**: Nhận dạng kỹ thuật tấn công (SQLi, XSS, command injection, DoS/SYN flood, webshell, brute force), MITRE ATT&CK, và yếu tố chứng cứ (field=value).  
- **Tuân thủ chống bịa**: Không bịa giá trị; nếu thiếu thì ghi “Not present/Unknown”. Chỉ dùng trường có thật trong alert/raw_json.  
- **Xuất JSON chuẩn**: Trả về schema cố định (threat_level, confidence, summary, tags, evidence[]) để formatter/Telegram dùng trực tiếp.

## Dòng dữ liệu vào AI
- Đầu vào gồm:  
  - AlertNormalized: `agent`, `rule`, `decoder`, `manager`, `location`, `http`, `suricata_alert`, `flow`, `full_data`, `tags`, `raw_json`.  
  - Correlation: `is_correlated`, `group_size`, `first_seen`, `attack_pattern`.  
  - FP context: `fp_risk`, `fp_reason`, `noise_signals`, `allowlist_hit`.  
  - Heuristic clues: rule level/id/groups/mitre, network/flow stats, HTTP status/method/url, user_agent/tool patterns.

## Nhiệm vụ chi tiết
- **Phân loại mối đe dọa**: Gán `threat_level` (critical/high/medium/low/none) và `confidence` 0–1.  
- **Nhận dạng kỹ thuật**: Gắn `tags` theo hành vi (sql_injection, xss, command_injection, path_traversal, csrf, webshell, bruteforce, dos/syn_flood, exfil).  
- **Tóm tắt**: Sinh `summary` ngắn, ưu tiên “what + where + impact + evidence”.  
- **Bằng chứng**: Liệt kê trường cụ thể `field=value` (vd: `src_ip=1.2.3.4`, `http.status=404`, `flow.pkts_toserver=120`). Không tự tạo giá trị không có trong alert/raw_json.  
- **Nhạy cảm FP**: Nếu `fp_risk` MEDIUM/HIGH, nêu rõ trong kết quả để analyst cân nhắc; không hạ cấp hoặc bỏ qua cảnh báo.  
- **MITRE**: Nếu rule/alert có mitre ids, phản ánh trong output; nếu không có, ghi “Unknown”.

## Ràng buộc quan trọng
- Không được suy diễn giá trị không tồn tại. Thiếu trường → “Not present/Unknown”.  
- Giữ nguyên chuỗi/giá trị gốc khi trích dẫn; không chuẩn hóa sai.  
- Đầu ra phải là JSON hợp lệ, không thêm lời văn ngoài schema.  
- Không áp dụng lọc agent đặc biệt: agent 002 phải giống 001.

## Vị trí AI trong kiến trúc
- Collector → Normalize → Correlation/FP → **LLM triage** → Telegram formatter.  
- AI sử dụng cả dữ liệu cấu trúc lẫn raw_json để kiểm tra chéo, tránh thiếu sót.

