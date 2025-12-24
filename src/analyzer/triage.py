"""Fuse heuristic and LLM scores to produce final triage result."""
import logging
import re
from typing import Any, Dict

from .heuristic import score as heuristic_score
from .llm import triage_llm
from src.common.config import HEURISTIC_WEIGHT, LLM_WEIGHT, CORRELATION_ENABLE, ENRICHMENT_ENABLE
from src.common.redaction import Redactor
from src.common.correlation import correlate_alert, get_correlation_engine
from src.common.enrichment import enrich_alert
from src.common.fp_filtering import analyze_fp_risk
from src.common.attack_type_normalizer import normalize_attack_type, normalize_attack_type_for_scoring
from src.common.config import ESCALATION_HIGH_COUNT, ESCALATION_SCORE_HIGH

logger = logging.getLogger(__name__)

# Ánh xạ điều chỉnh điểm số theo mức độ đe dọa
THREAT_LEVEL_ADJUSTMENTS = {
    "critical": 0.10,   # +10% cho mối đe dọa critical
    "high": 0.05,       # +5% cho mối đe dọa high
    "medium": 0.0,      # Không điều chỉnh
    "low": -0.05,       # -5% cho mối đe dọa low
    "none": -0.10,      # -10% cho benign/noise
}


def run(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run triage analysis on alert.
    
    Args:
        alert: Normalized alert dictionary
        
    Returns:
        Dict with keys: title, score (0.0-1.0), threat_level, summary, tags (list)
    """
    # Làm giàu alert với GeoIP và threat intelligence
    if ENRICHMENT_ENABLE:
        try:
            enrichment_data = enrich_alert(alert)
            # Thêm dữ liệu làm giàu vào alert để sử dụng sau
            alert["enrichment"] = enrichment_data
        except Exception as e:
            logger.debug(f"Enrichment failed: {e}", exc_info=True)
            alert["enrichment"] = {}
    
    # Tương quan alert với các nhóm hiện có
    correlation_info = {}
    if CORRELATION_ENABLE:
        try:
            correlation_info = correlate_alert(alert)
            alert["correlation"] = correlation_info
        except Exception as e:
            logger.debug(f"Correlation failed: {e}", exc_info=True)
            correlation_info = {"is_correlated": False, "group_size": 1}
    
    # Lọc FP (SOC-grade: gắn nhãn, không drop)
    fp_result = {}
    try:
        fp_result = analyze_fp_risk(alert, correlation_info)
        alert["fp_filtering"] = fp_result
    except Exception as e:
        logger.debug(f"FP filtering failed: {e}", exc_info=True)
        fp_result = {"fp_risk": "LOW", "fp_reason": [], "allowlist_hit": False, "noise_signals": []}
    
    # Chuẩn hóa loại tấn công TRƯỚC KHI tính điểm để đảm bảo tính nhất quán giữa các agent
    alert = normalize_attack_type_for_scoring(alert)
    normalized_attack_type = alert.get("attack_type_normalized")
    
    # Trích xuất các thành phần alert
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    message = alert.get("message", "")
    srcip = alert.get("srcip", "")
    user = alert.get("user", "")
    http_context = alert.get("http")
    suricata_alert = alert.get("suricata_alert")
    
    # Trích xuất ngữ cảnh bổ sung từ alert
    rule_id = str(rule.get("id", "N/A"))
    rule_level = rule.get("level", 0)
    rule_description = rule.get("description", "")
    rule_groups = rule.get("groups", [])
    mitre = rule.get("mitre", {})
    
    # Trích xuất mã trạng thái HTTP nếu có (cho tấn công web)
    http_status = None
    if http_context and http_context.get("status"):
        http_status = http_context.get("status")
    elif isinstance(message, str):
        # Fallback: Thử trích xuất mã trạng thái HTTP từ message
        status_match = re.search(r'\b(?:HTTP/[\d.]+|Status:?)\s+(\d{3})\b', message, re.IGNORECASE)
        if status_match:
            http_status = status_match.group(1)
    
    # Điểm heuristic
    h_score = heuristic_score(alert)
    
    # Chuẩn bị văn bản nâng cao cho LLM (redact PII)
    redactor = Redactor()
    alert_text = f"Rule ID: {rule_id}, "
    alert_text += f"Level: {rule_level}, "
    alert_text += f"Groups: {rule_groups}, "
    if rule_description:
        alert_text += f"Description: {rule_description}, "
    if mitre:
        mitre_ids = mitre.get("id", [])
        if mitre_ids:
            alert_text += f"MITRE ATT&CK: {mitre_ids}, "
    
    # Thêm ngữ cảnh cảnh báo Suricata (signature ID, tên signature, category)
    if suricata_alert:
        if suricata_alert.get("signature_id"):
            alert_text += f"Suricata Signature ID: {suricata_alert.get('signature_id')}, "
        if suricata_alert.get("signature"):
            alert_text += f"Suricata Signature: {suricata_alert.get('signature')}, "
        if suricata_alert.get("category"):
            alert_text += f"Suricata Category: {suricata_alert.get('category')}, "
    
    # Thêm ngữ cảnh HTTP (quan trọng cho phát hiện tấn công web)
    if http_context:
        if http_context.get("url"):
            alert_text += f"HTTP URL: {http_context.get('url')}, "
        if http_context.get("method"):
            alert_text += f"HTTP Method: {http_context.get('method')}, "
        if http_context.get("status"):
            alert_text += f"HTTP Status: {http_context.get('status')}, "
        if http_context.get("hostname"):
            alert_text += f"HTTP Hostname: {http_context.get('hostname')}, "
        if http_context.get("referer"):
            alert_text += f"HTTP Referer: {http_context.get('referer')}, "
        if http_context.get("user_agent"):
            alert_text += f"HTTP User-Agent: {http_context.get('user_agent')}, "
        if http_context.get("redirect"):
            alert_text += f"HTTP Redirect: {http_context.get('redirect')}, "  # Redirect 302 (quan trọng cho SOC)
    
    # Thêm thông tin mạng (QUAN TRỌNG cho SOC) - sử dụng các trường top-level
    if alert.get("src_ip"):
        alert_text += f"Network Src IP: {alert.get('src_ip')}, "
    if alert.get("dest_ip"):
        alert_text += f"Network Dest IP: {alert.get('dest_ip')}, "
    if alert.get("src_port"):
        alert_text += f"Network Src Port: {alert.get('src_port')}, "
    if alert.get("dest_port"):
        alert_text += f"Network Dest Port: {alert.get('dest_port')}, "
    if alert.get("direction"):
        alert_text += f"Network Direction: {alert.get('direction')}, "
    if alert.get("proto"):
        alert_text += f"Network Protocol: {alert.get('proto')}, "
    if alert.get("app_proto"):
        alert_text += f"Network App Protocol: {alert.get('app_proto')}, "
    
    # Thêm thống kê flow (QUAN TRỌNG cho phân tích mạng SOC)
    flow_info = alert.get("flow")
    if flow_info:
        if flow_info.get("bytes_toserver"):
            alert_text += f"Flow Bytes to Server: {flow_info.get('bytes_toserver')}, "
        if flow_info.get("bytes_toclient"):
            alert_text += f"Flow Bytes to Client: {flow_info.get('bytes_toclient')}, "
        if flow_info.get("pkts_toserver"):
            alert_text += f"Flow Packets to Server: {flow_info.get('pkts_toserver')}, "
        if flow_info.get("pkts_toclient"):
            alert_text += f"Flow Packets to Client: {flow_info.get('pkts_toclient')}, "
    
    # Thêm hành động cảnh báo Suricata (QUAN TRỌNG cho SOC)
    if suricata_alert and suricata_alert.get("action"):
        alert_text += f"Suricata Action: {suricata_alert.get('action')}, "  # "allowed" vs "blocked"
    
    # Thêm số lần rule được kích hoạt (QUAN TRỌNG cho tương quan)
    rule_firedtimes = rule.get("firedtimes", "")
    if rule_firedtimes:
        alert_text += f"Rule Fired Times: {rule_firedtimes}, "
    
    # Thêm số lượng bất thường HTTP (QUAN TRỌNG cho SOC)
    if alert.get("http_anomaly_count"):
        alert_text += f"HTTP Anomaly Count: {alert.get('http_anomaly_count')}, "
    
    alert_text += f"Message: {message}, "
    alert_text += f"Agent: {agent.get('name', 'N/A')}, "
    alert_text += f"Src IP: {srcip}, "
    alert_text += f"User: {user}"
    
    redacted_text, _ = redactor.redact(alert_text)
    
    # Chuẩn bị ngữ cảnh rule cho LLM (bao gồm loại tấn công đã chuẩn hóa để phân tích nhất quán)
    rule_context = {
        "id": rule_id,
        "level": rule_level,
        "description": rule_description,
        "groups": rule_groups,
        "mitre": mitre,
        "normalized_attack_type": normalized_attack_type,  # Thêm loại tấn công đã chuẩn hóa
    }
    
    # Phân tích LLM với ngữ cảnh rule
    llm_result = triage_llm(redacted_text, rule_context=rule_context)
    
    # Lấy threat_level từ kết quả LLM
    threat_level = llm_result.get("threat_level", "medium")
    llm_confidence = llm_result.get("confidence", 0.0)
    tags = llm_result.get("tags", [])
    
    # SOC-Grade: Logic ghi đè Rule Level
    # Rule level là nguồn sự thật từ Wazuh - đảm bảo tính nhất quán
    original_threat_level = threat_level
    
    # Ghi đè threat_level dựa trên rule level (logic SOC)
    # Tấn công CONFIRMED (level 12-15) LUÔN là critical
    if rule_level >= 12:
        if threat_level != "critical":
            logger.info(
                "Overriding threat_level to critical based on rule level",
                extra={
                    "component": "triage",
                    "action": "threat_level_override",
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "llm_threat_level": original_threat_level,
                    "final_threat_level": "critical",
                    "reason": "CONFIRMED attack (rule level >= 12)"
                }
            )
            threat_level = "critical"
    # Rules mức độ nghiêm trọng cao (level 10-11) nên ít nhất là "high"
    elif rule_level >= 10:
        if threat_level not in ["critical", "high"]:
            logger.debug(
                "Overriding threat_level to high based on rule level",
                extra={
                    "component": "triage",
                    "action": "threat_level_override",
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "llm_threat_level": original_threat_level,
                    "final_threat_level": "high",
                    "reason": "High severity rule (level >= 10)"
                }
            )
            threat_level = "high"
    # Rules mức độ nghiêm trọng trung bình (level 7-9) nên ít nhất là "medium"
    # Nhưng cho phép LLM tăng lên "high" nếu ngữ cảnh cho phép
    elif rule_level >= 7:
        if threat_level in ["low", "none"]:
            logger.debug(
                "Overriding threat_level to medium based on rule level",
                extra={
                    "component": "triage",
                    "action": "threat_level_override",
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "llm_threat_level": original_threat_level,
                    "final_threat_level": "medium",
                    "reason": "Medium severity rule (level >= 7)"
                }
            )
            threat_level = "medium"
    
    # Giới hạn mức độ đe dọa dựa trên rule level (ngăn chặn over-scoring)
    # Rules mức độ nghiêm trọng thấp không nên là HIGH hoặc CRITICAL
    if rule_level < 7:
        if threat_level in ["high", "critical"]:
            logger.debug(
                "Capped threat_level to medium (rule level < 7)",
                extra={
                    "component": "triage",
                    "action": "threat_level_cap",
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "original_threat_level": threat_level,
                    "capped_threat_level": "medium",
                    "reason": "Low severity rule should not be HIGH/CRITICAL"
                }
            )
            threat_level = "medium"
    # Rules mức độ nghiêm trọng trung bình không nên là CRITICAL
    elif rule_level < 10:
        if threat_level == "critical":
            logger.debug(
                "Capped threat_level to high (rule level < 10)",
                extra={
                    "component": "triage",
                    "action": "threat_level_cap",
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "original_threat_level": threat_level,
                    "capped_threat_level": "high",
                    "reason": "Medium severity rule should not be CRITICAL"
                }
            )
            threat_level = "high"
    
    # Tăng độ tin cậy LLM cho các loại rule cụ thể nếu LLM nhận diện đúng
    # Điều này thưởng LLM vì nhận diện đúng các tấn công quan trọng
    if rule_id == "31105" and "xss" in tags:
        # LLM correctly identified XSS → Boost confidence
        original_confidence = llm_confidence
        llm_confidence = min(llm_confidence + 0.15, 1.0)
        logger.debug(
            "Boosted LLM confidence for XSS detection",
            extra={
                "component": "triage",
                "action": "llm_confidence_boost",
                "rule_id": rule_id,
                "original_confidence": round(original_confidence, 3),
                "boosted_confidence": round(llm_confidence, 3),
                "reason": "LLM correctly identified XSS attack"
            }
        )
    elif (rule_id in ["31103", "31104"] or normalized_attack_type == "sql_injection") and "sql_injection" in tags:
        # LLM correctly identified SQL injection → Boost confidence
        original_confidence = llm_confidence
        llm_confidence = min(llm_confidence + 0.20, 1.0)
        logger.debug(
            "Boosted LLM confidence for SQL injection detection",
            extra={
                "component": "triage",
                "action": "llm_confidence_boost",
                "rule_id": rule_id,
                "original_confidence": round(original_confidence, 3),
                "boosted_confidence": round(llm_confidence, 3),
                "reason": "LLM correctly identified SQL injection attack"
            }
        )
    elif rule_id in ["100144", "100145", "100146"] and "command_injection" in tags:
        # LLM correctly identified command injection → Boost confidence
        original_confidence = llm_confidence
        llm_confidence = min(llm_confidence + 0.20, 1.0)
        logger.debug(
            "Boosted LLM confidence for command injection detection",
            extra={
                "component": "triage",
                "action": "llm_confidence_boost",
                "rule_id": rule_id,
                "original_confidence": round(original_confidence, 3),
                "boosted_confidence": round(llm_confidence, 3),
                "reason": "LLM correctly identified command injection attack"
            }
        )
    
    # Trọng số động dựa trên độ tin cậy và rule level
    # Nếu độ tin cậy LLM rất thấp, dựa nhiều hơn vào heuristic
    # Nếu độ tin cậy LLM rất cao, dựa nhiều hơn vào LLM
    if llm_confidence < 0.3:
        # Độ tin cậy LLM thấp: tăng trọng số heuristic
        effective_h_weight = min(HEURISTIC_WEIGHT + 0.2, 0.9)
        effective_l_weight = max(LLM_WEIGHT - 0.2, 0.1)
    elif llm_confidence > 0.8:
        # Độ tin cậy LLM cao: tăng trọng số LLM
        effective_h_weight = max(HEURISTIC_WEIGHT - 0.1, 0.3)
        effective_l_weight = min(LLM_WEIGHT + 0.1, 0.7)
    else:
        # Độ tin cậy bình thường: sử dụng trọng số mặc định
        effective_h_weight = HEURISTIC_WEIGHT
        effective_l_weight = LLM_WEIGHT
    
    # Kết hợp điểm số với trọng số động
    fused_score = (effective_h_weight * h_score) + (effective_l_weight * llm_confidence)
    
    # Áp dụng điều chỉnh mức độ đe dọa
    threat_adjustment = THREAT_LEVEL_ADJUSTMENTS.get(threat_level, 0.0)
    final_score = fused_score + threat_adjustment
    
    # Giới hạn trong [0, 1]
    final_score = max(0.0, min(1.0, final_score))
    
    # Tags đã được trích xuất ở trên (trước khi tăng độ tin cậy)
    
    # Xây dựng tiêu đề - sử dụng tiêu đề cải tiến từ alert formatter nếu có
    from src.common.alert_formatter import format_alert_card
    try:
        alert_card = format_alert_card(alert, {
            "score": final_score,
            "threat_level": threat_level,
            "tags": tags,
            "summary": llm_result.get("summary", "")
        })
        title = alert_card.get("title", f"[Auto-Triage] rule {rule_id} on {agent.get('name', 'unknown')}")
    except Exception as e:
        # Fallback sang tiêu đề đơn giản nếu formatter thất bại
        logger.debug(f"Alert formatter failed, using fallback title: {e}")
        agent_name = agent.get("name", "unknown")
        title = f"[Auto-Triage] rule {rule_id} on {agent_name}"
    
    # Trích xuất ngữ cảnh để ghi log
    agent_id = agent.get("id", "unknown")
    agent_name = agent.get("name", "unknown")
    
    # Ghi log ghi đè mức độ đe dọa nếu có xảy ra
    threat_level_override_applied = (original_threat_level != threat_level)
    
    logger.info(
        "Triage analysis completed",
        extra={
            "component": "triage",
            "action": "analysis_complete",
            "rule_id": rule_id,
            "rule_level": rule_level,
            "agent_name": agent_name,
            "agent_id": agent_id,
            "score": round(final_score, 3),
            "threat_level": threat_level,
            "heuristic_score": round(h_score, 3),
            "llm_confidence": round(llm_confidence, 3),
            "llm_threat_level": original_threat_level,  # Log original LLM threat level
            "threat_level_override_applied": threat_level_override_applied,
            "llm_tags": tags,
            "llm_summary": llm_result.get("summary", "")[:200],
            "threat_adjustment": round(THREAT_LEVEL_ADJUSTMENTS.get(threat_level, 0.0), 3),
            "effective_h_weight": round(effective_h_weight, 3),
            "effective_l_weight": round(effective_l_weight, 3),
            "tags_count": len(tags)
        }
    )
    # Attach triage_score back to alert so correlation groups can use it for escalation rules
    try:
        alert["triage_score"] = final_score
    except Exception:
        # Non-critical: if alert object not writable, continue
        logger.debug("Unable to attach triage_score to alert object")

    # Numeric escalation: if correlated group has >= ESCALATION_HIGH_COUNT alerts with score >= ESCALATION_SCORE_HIGH,
    # escalate group to critical (P1).
    escalation_info = None
    try:
        correlation = correlation_info or alert.get("correlation", {})
        if correlation and correlation.get("is_correlated"):
            group_key = correlation.get("group_key")
            engine = get_correlation_engine()
            group = engine.alert_groups.get(group_key, []) if group_key else []
            # Count alerts in group that have triage_score >= ESCALATION_SCORE_HIGH
            high_count = sum(1 for a in group if (a.get("triage_score", 0.0) >= ESCALATION_SCORE_HIGH) or (a.get("rule", {}).get("level", 0) >= 10))
            if high_count >= ESCALATION_HIGH_COUNT:
                escalation_info = {"rule": "numeric_escalation", "high_count": high_count, "threshold": ESCALATION_HIGH_COUNT}
                if threat_level != "critical":
                    logger.warning(
                        "Escalating group to critical due to numeric escalation rule",
                        extra={
                            "component": "triage",
                            "action": "numeric_escalation",
                            "group_key": group_key,
                            "high_count": high_count,
                            "threshold": ESCALATION_HIGH_COUNT
                        }
                    )
                threat_level = "critical"
                # Boost score to reflect escalation
                final_score = max(final_score, 0.95)
    except Exception as e:
        logger.debug(f"Numeric escalation check failed: {e}", exc_info=True)

    # Map threat_level to priority (P1..P4)
    priority_map = {
        "critical": "P1",
        "high": "P2",
        "medium": "P3",
        "low": "P4",
        "none": "P4",
    }
    priority = priority_map.get(threat_level, "P4")

    return {
        "title": title,
        "score": final_score,
        "threat_level": threat_level,
        "summary": llm_result.get("summary", "No summary"),
        "tags": tags,
        "llm_confidence": llm_confidence,  # Include for override logic
        "priority": priority,
        "escalation": escalation_info,
    }

