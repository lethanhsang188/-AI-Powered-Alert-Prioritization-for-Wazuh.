"""JSON logging configuration with request ID support."""
import json
import logging
import sys
import time
from datetime import datetime
from typing import Optional

from .config import LOG_LEVEL


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logs."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_obj = {
            "level": record.levelname,
            "ts": datetime.utcnow().isoformat() + "Z",
            "msg": record.getMessage(),
            "logger": record.name,
        }
        
        # Add trace_id if present
        if hasattr(record, "trace_id"):
            log_obj["trace_id"] = record.trace_id
        
        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "extra"):
            log_obj.update(record.extra)
        
        return json.dumps(log_obj)


def setup_logging(level: Optional[str] = None) -> None:
    """Configure root logger with JSON formatting."""
    log_level = getattr(logging, (level or LOG_LEVEL).upper(), logging.INFO)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = [handler]


def get_logger(name: str) -> logging.Logger:
    """Get logger instance with optional trace_id support."""
    return logging.getLogger(name)

