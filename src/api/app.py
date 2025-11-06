"""Flask API service with healthz/readyz endpoints."""
import logging
import os
from flask import Flask, jsonify

from common.config import ENV_NAME
from common.logging import setup_logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

app = Flask(__name__)


@app.route("/healthz", methods=["GET"])
def healthz():
    """Liveness probe - returns 200 if service is running."""
    return jsonify({"status": "ok"}), 200


@app.route("/readyz", methods=["GET"])
def readyz():
    """
    Readiness probe - returns 200 if service is ready.
    
    Checks:
    - Cursor file directory exists (or can be created)
    - Wazuh API connection (basic check)
    - TheHive API connection (basic check)
    """
    from common.config import (
        CURSOR_PATH,
        WAZUH_API_URL,
        THEHIVE_URL,
        THEHIVE_API_KEY,
    )
    from common.web import RetrySession
    
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
        session = RetrySession(max_retries=1, trust_env=False)
        # Quick HEAD request to check if service is reachable
        response = session.request("HEAD", WAZUH_API_URL, timeout=3)
        checks["wazuh"] = "ok" if response.status_code < 500 else "unavailable"
    except Exception as e:
        logger.warning(f"Wazuh connection check failed: {e}")
        checks["wazuh"] = "unreachable"
        # Don't fail readiness for this, as it might be transient
    
    # Check TheHive API (lightweight connection test)
    try:
        if THEHIVE_API_KEY:
            session = RetrySession(max_retries=1, trust_env=False)
            session.headers.update({"Authorization": f"Bearer {THEHIVE_API_KEY}"})
            response = session.request("HEAD", THEHIVE_URL, timeout=3)
            checks["thehive"] = "ok" if response.status_code < 500 else "unavailable"
        else:
            checks["thehive"] = "no_api_key"
    except Exception as e:
        logger.warning(f"TheHive connection check failed: {e}")
        checks["thehive"] = "unreachable"
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
    from common.config import API_PORT
    app.run(host="0.0.0.0", port=API_PORT, debug=False)

