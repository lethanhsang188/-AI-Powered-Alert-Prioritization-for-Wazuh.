"""Dịch vụ API Flask với các endpoint healthz/readyz."""
import logging
import os

from flask import Flask, jsonify

from src.common.config import ENV_NAME
from src.common.logging import setup_logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

app = Flask(__name__)


@app.route("/healthz", methods=["GET"])
def healthz():
    """Liveness probe - trả về 200 nếu dịch vụ đang chạy."""
    return jsonify({"status": "ok"}), 200


@app.route("/readyz", methods=["GET"])
def readyz():
    """
    Readiness probe - trả về 200 nếu dịch vụ sẵn sàng.
    
    Kiểm tra:
    - Thư mục file cursor tồn tại (hoặc có thể tạo được)
    - Kết nối tới Wazuh API (kiểm tra cơ bản)
    """
    from src.common.config import (
        CURSOR_PATH,
        WAZUH_API_URL,
    )
    from src.common.web import RetrySession
    
    checks = {}
    all_ready = True
    
    try:
        # Check cursor directory
        cursor_dir = os.path.dirname(CURSOR_PATH)
        if not os.path.exists(cursor_dir):
            os.makedirs(cursor_dir, exist_ok=True)
        checks["cursor_dir"] = "ok"
    except Exception as e:
        logger.error(f"Cursor directory check failed: {e}")
        checks["cursor_dir"] = f"error: {str(e)}"
        all_ready = False
    
    # Check Wazuh API (lightweight connection test)
    try:
        session = RetrySession(max_retries=1)
        # Quick HEAD request to check if service is reachable
        response = session.request("HEAD", WAZUH_API_URL, timeout=3)
        checks["wazuh"] = "ok" if response.status_code < 500 else "unavailable"
    except Exception as e:
        logger.warning(f"Wazuh connection check failed: {e}")
        checks["wazuh"] = "unreachable"
        # Don't fail readiness for this, as it might be transient
    
    if all_ready:
        return jsonify({
            "status": "ready",
            "env": ENV_NAME,
            "checks": checks,
        }), 200
    else:
        return jsonify({
            "status": "not ready",
            "env": ENV_NAME,
            "checks": checks,
        }), 503


@app.route("/", methods=["GET"])
def root():
    """Root endpoint."""
    return jsonify({
        "service": "AI-APW",
        "name": "AI-Powered Alert Prioritization for Wazuh",
        "version": "1.0.0",
        "env": ENV_NAME,
    }), 200


if __name__ == "__main__":
    from src.common.config import API_PORT
    app.run(host="0.0.0.0", port=API_PORT, debug=False)

