"""Tạo khóa dedup deterministic."""
import hashlib
from datetime import datetime
from typing import Any, Dict

from src.common.timezone import LOCAL_TZ


def dedup_key(alert: Dict[str, Any]) -> str:
    """
    Tạo khóa dedup định danh từ alert.
    
    Định dạng: rule.id + agent.id + srcip + ngày địa phương hiện tại
    Trả về: tiền tố 16 ký tự hex của hàm băm SHA256
    """
    rule_id = str(alert.get("rule", {}).get("id", "")).strip()
    agent_id = str(alert.get("agent", {}).get("id", "")).strip()
    srcip = str(alert.get("srcip", "")).strip()
    
    # Ngày địa phương hiện tại (YYYY-MM-DD) sử dụng timezone cấu hình
    day = datetime.now(LOCAL_TZ).strftime("%Y-%m-%d")
    
    # Ghép các thành phần lại
    key_str = f"{rule_id}:{agent_id}:{srcip}:{day}"
    
    # Sinh SHA256 và lấy 16 ký tự đầu
    hash_obj = hashlib.sha256(key_str.encode("utf-8"))
    return hash_obj.hexdigest()[:16]

