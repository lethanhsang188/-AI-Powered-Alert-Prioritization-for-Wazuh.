"""Wazuh 4.14.0 API client for alert collection."""
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..common.config import (
    WAZUH_API_URL,
    WAZUH_API_USER,
    WAZUH_API_PASS,
    WAZUH_API_TOKEN,
    WAZUH_MIN_LEVEL,
    WAZUH_PAGE_LIMIT,
    CURSOR_PATH,
    WAZUH_CA_CERT,
    WAZUH_VERIFY_SSL,
)
from ..common.web import RetrySession

logger = logging.getLogger(__name__)

# Wazuh API endpoint - default /alerts, can be changed to /security/alerts
WAZUH_ALERTS_ENDPOINT = "/alerts"


class WazuhClient:
    """Client for Wazuh 4.14.0 API."""
    
    def __init__(self):
        self.base_url = WAZUH_API_URL.rstrip("/")
        self.session = RetrySession()
        self._using_static_token = bool(WAZUH_API_TOKEN)

        if WAZUH_CA_CERT:
            self.session.verify = WAZUH_CA_CERT
        else:
            self.session.verify = WAZUH_VERIFY_SSL

        self._setup_auth()

    def _setup_auth(self) -> None:
        """Configure authentication (token preferred, else Basic)."""
        if self._using_static_token:
            self.session.headers.update({
                "Authorization": f"Bearer {WAZUH_API_TOKEN}"
            })
            logger.info("Using Wazuh API token authentication")
        else:
            self._authenticate_with_credentials()

    def _authenticate_with_credentials(self) -> None:
        """Request a JWT token using configured credentials."""
        if not WAZUH_API_USER or not WAZUH_API_PASS:
            raise ValueError(
                "Wazuh credentials are required when WAZUH_API_TOKEN is not set"
            )

        auth_url = f"{self.base_url}/security/user/authenticate"
        payload = {"username": WAZUH_API_USER, "password": WAZUH_API_PASS}

        try:
            response = self.session.request_with_backoff(
                "POST", auth_url, json=payload
            )
            response.raise_for_status()
        except Exception as exc:
            logger.error(
                f"Failed to authenticate with Wazuh API at {auth_url}: {exc}",
                exc_info=True,
            )
            raise

        try:
            data = response.json() if response.content else {}
        except ValueError as exc:
            logger.error(
                "Authentication response from Wazuh API was not valid JSON", exc_info=True
            )
            raise ValueError("Invalid JSON in Wazuh authentication response") from exc
        token = None

        if isinstance(data, dict):
            token = data.get("data", {}).get("token")

        if not token:
            raise ValueError("Wazuh authentication response missing token")

        self.session.headers.update({"Authorization": f"Bearer {token}"})
        self.session.auth = None
        logger.info("Authenticated with Wazuh API using JWT token")
    
    def _load_cursor(self) -> Optional[str]:
        """Load last processed timestamp from cursor file."""
        if not os.path.exists(CURSOR_PATH):
            return None
        
        try:
            with open(CURSOR_PATH, "r") as f:
                data = json.load(f)
                return data.get("timestamp")
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load cursor: {e}")
            return None
    
    def _save_cursor(self, timestamp: str) -> None:
        """Save last processed timestamp to cursor file."""
        os.makedirs(os.path.dirname(CURSOR_PATH), exist_ok=True)
        
        try:
            with open(CURSOR_PATH, "w") as f:
                json.dump({"timestamp": timestamp}, f)
        except IOError as e:
            logger.error(f"Failed to save cursor: {e}")
    
    def _normalize_alert(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Wazuh alert to common format."""
        return {
            "@timestamp": raw.get("@timestamp", ""),
            "agent": raw.get("agent", {}),
            "rule": raw.get("rule", {}),
            "srcip": raw.get("srcip", ""),
            "user": raw.get("user", ""),
            "message": raw.get("message", ""),
            "raw": raw,
        }
    
    def fetch_alerts(self) -> List[Dict[str, Any]]:
        """
        Fetch alerts from Wazuh API.
        
        Returns:
            List of normalized alert dictionaries
        """
        # Build query params
        params = {
            "q": f"rule.level>={WAZUH_MIN_LEVEL}",
            "limit": WAZUH_PAGE_LIMIT,
            "sort": "@timestamp:asc",
        }
        
        # Add cursor if available
        cursor = self._load_cursor()
        if cursor:
            params["from"] = cursor
        
        # Build URL
        url = f"{self.base_url}{WAZUH_ALERTS_ENDPOINT}"
        
        logger.info(f"Fetching alerts from {url} with params: {params}")
        
        try:
            response = self.session.request_with_backoff("GET", url, params=params)

            if response.status_code == 401 and not self._using_static_token:
                logger.info("Wazuh token expired or unauthorized, refreshing token")
                self._authenticate_with_credentials()
                response = self.session.request_with_backoff(
                    "GET", url, params=params
                )

            response.raise_for_status()
            
            data = response.json()
            alerts_data = data.get("data", {}).get("affected_items", [])
            
            if not alerts_data:
                logger.debug("No new alerts found")
                return []
            
            # Normalize alerts
            normalized = [self._normalize_alert(alert) for alert in alerts_data]
            
            # Update cursor with latest timestamp
            if normalized:
                latest_ts = normalized[-1].get("@timestamp")
                if latest_ts:
                    self._save_cursor(latest_ts)
                    logger.info(f"Processed {len(normalized)} alerts, cursor: {latest_ts}")
            
            return normalized
        
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}", exc_info=True)
            return []

