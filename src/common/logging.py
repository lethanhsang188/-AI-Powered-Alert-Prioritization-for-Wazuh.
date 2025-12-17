"""JSON logging configuration with request ID support."""
import json
import logging
import sys
from typing import Optional

from .config import LOG_LEVEL, LOCAL_TIMEZONE
from .timezone import now_local_iso, now_utc_iso


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logs with SOC field support."""

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
        
        # Add trace_id if present
        if hasattr(record, "trace_id"):
            log_obj["trace_id"] = record.trace_id
        
        # SOC-specific fields (extracted from record attributes)
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
        
        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields (from LoggerAdapter or manual extra dict)
        # Note: record.extra is not a standard attribute, we need to check extra dict passed via logger.log()
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            log_obj.update(record.extra)
        else:
            # Check for extra fields passed via extra= parameter in logger calls
            # These are stored as attributes on the record
            for key, value in record.__dict__.items():
                if key not in [
                    "name", "msg", "args", "created", "filename", "funcName",
                    "levelname", "levelno", "lineno", "module", "msecs", "message",
                    "pathname", "process", "processName", "relativeCreated", "thread",
                    "threadName", "exc_info", "exc_text", "stack_info", "extra"
                ]:
                    if value is not None:
                        log_obj[key] = value
        
        # Ensure JSON is properly formatted and add newline for readability
        return json.dumps(log_obj, ensure_ascii=False) + "\n"


def setup_logging(level: Optional[str] = None) -> None:
    """Configure root logger with JSON formatting."""
    log_level = getattr(logging, (level or LOG_LEVEL).upper(), logging.INFO)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    # Ensure thread-safe output by flushing immediately
    handler.flush = lambda: sys.stdout.flush()
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = [handler]


def get_logger(name: str) -> logging.Logger:
    """Get logger instance with optional trace_id support."""
    return logging.getLogger(name)


def log_with_soc_context(
    logger: logging.Logger,
    level: int,
    message: str,
    **soc_fields
) -> None:
    """
    Log message with SOC context fields.
    
    Args:
        logger: Logger instance
        level: Log level (logging.INFO, logging.WARNING, etc.)
        message: Log message
        **soc_fields: SOC context fields (alert_id, case_id, rule_id, etc.)
    
    Example:
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

