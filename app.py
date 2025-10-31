"""Flask application entry point."""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from src.api.app import app

if __name__ == "__main__":
    from src.common.config import API_PORT
    app.run(host="0.0.0.0", port=API_PORT, debug=False)

