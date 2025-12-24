"""Cấu hình logging dạng JSON với hỗ trợ request ID."""
import json
import logging
import sys
from typing import Optional

from .config import LOG_LEVEL, LOCAL_TIMEZONE
from .timezone import now_local_iso, now_utc_iso


class JSONFormatter(logging.Formatter):
    """Bộ định dạng JSON cho log cấu trúc có hỗ trợ các trường SOC."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with SOC context fields."""
        log_obj = {
            "level": record.levelname,
            "ts": now_local_iso(),
            "ts_utc": now_utc_iso(),
            "tz": LOCAL_TIMEZONE,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        
        # Thêm trace_id nếu có
        if hasattr(record, "trace_id"):
            log_obj["trace_id"] = record.trace_id
        
        # Các trường đặc thù SOC (trích từ thuộc tính record)
        soc_fields = [
            "alert_id", "case_id", "rule_id", "rule_level", "agent_id", "agent_name",
            "srcip", "dstip", "user", "threat_level", "score", "severity",
            "action", "component", "duration_ms", "alert_count", "status"
        ]
        for field in soc_fields:
            if hasattr(record, field):
                value = getattr(record, field)
                if value is not None:
                    log_obj[field] = value
        
        # Thêm thông tin exception nếu có
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        
        # Thêm các trường bổ sung (từ LoggerAdapter hoặc dict extra thủ công)
        # Lưu ý: record.extra không phải là thuộc tính tiêu chuẩn, cần kiểm tra dict extra được truyền qua logger.log()
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            log_obj.update(record.extra)
        else:
            # Kiểm tra các trường extra được truyền qua tham số extra= trong các cuộc gọi logger
            # Những trường này được lưu như các thuộc tính trên record
            for key, value in record.__dict__.items():
                if key not in [
                    "name", "msg", "args", "created", "filename", "funcName",
                    "levelname", "levelno", "lineno", "module", "msecs", "message",
                    "pathname", "process", "processName", "relativeCreated", "thread",
                    "threadName", "exc_info", "exc_text", "stack_info", "extra"
                ]:
                    if value is not None:
                        log_obj[key] = value
        
        # Đảm bảo JSON được định dạng đúng và thêm newline để dễ đọc
        return json.dumps(log_obj, ensure_ascii=False) + "\n"


def setup_logging(level: Optional[str] = None) -> None:
    """Cấu hình root logger với định dạng JSON."""
    log_level = getattr(logging, (level or LOG_LEVEL).upper(), logging.INFO)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    # Đảm bảo output an toàn theo luồng bằng cách flush ngay lập tức
    handler.flush = lambda: sys.stdout.flush()
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = [handler]


def get_logger(name: str) -> logging.Logger:
    """Lấy instance logger với hỗ trợ tuỳ chọn trace_id."""
    return logging.getLogger(name)


def log_with_soc_context(
    logger: logging.Logger,
    level: int,
    message: str,
    **soc_fields
) -> None:
    """
    Ghi log kèm các trường ngữ cảnh SOC.
    
    Args:
        logger: Instance logger
        level: Mức log (logging.INFO, logging.WARNING, v.v.)
        message: Thông điệp log
        **soc_fields: Các trường ngữ cảnh SOC (alert_id, case_id, rule_id, ...)
    
    Ví dụ:
        log_with_soc_context(
            logger, logging.INFO,
            "Alert processed",
            alert_id="alert-123",
            rule_id=61109,
            threat_level="high",
            score=0.85
        )
    """
    extra = {}
    for key, value in soc_fields.items():
        if value is not None:
            extra[key] = value
    
    logger.log(level, message, extra=extra)

