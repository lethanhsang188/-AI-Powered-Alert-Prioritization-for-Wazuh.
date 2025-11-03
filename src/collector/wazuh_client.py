"""Wazuh 4.14.0 API client for alert collection."""
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from ..common.config import (
    WAZUH_API_URL,
    WAZUH_API_USER,
    WAZUH_API_PASS,
    WAZUH_API_TOKEN,
    WAZUH_MIN_LEVEL,
    WAZUH_PAGE_LIMIT,
    CURSOR_PATH,
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
        self._token: Optional[str] = None
        self._token_expires_at: Optional[float] = None
        self._using_static_token = bool(WAZUH_API_TOKEN)
        self._setup_auth()

    def _setup_auth(self) -> None:
        """Configure authentication (token preferred, else Basic)."""
        if self._using_static_token:
            self._set_token(WAZUH_API_TOKEN)
            logger.info("Using Wazuh API token authentication from configuration")
            return

        if not WAZUH_API_USER or not WAZUH_API_PASS:
            raise RuntimeError(
                "Wazuh API credentials are required to obtain a JWT token; "
                "set WAZUH_API_USER and WAZUH_API_PASS or provide WAZUH_API_TOKEN."
            )

        logger.info("Fetching Wazuh API token via authentication endpoint")
        self._refresh_token()

    def _set_token(self, token: str, timeout: Optional[int] = None) -> None:
        """Store token and configure Authorization header."""
        self._token = token
        self.session.headers.pop("Authorization", None)
        self.session.headers.update({"Authorization": f"Bearer {token}"})

        if timeout:
            # Refresh slightly before actual expiration to avoid race conditions
            self._token_expires_at = time.time() + max(0, timeout - 30)
        elif self._using_static_token:
            self._token_expires_at = None

    def _obtain_token(self) -> Tuple[Optional[str], Optional[int]]:
        """Request a new JWT token from the Wazuh API."""
        auth_url = f"{self.base_url}/security/user/authenticate"
        payload = {
            "username": WAZUH_API_USER,
            "password": WAZUH_API_PASS,
        }

        # Temporarily remove Authorization header to avoid sending an expired token
        original_headers = self.session.headers.copy()
        self.session.headers.pop("Authorization", None)
        self.session.headers.setdefault("Content-Type", "application/json")

        try:
            response = self.session.post(auth_url, json=payload)
            response.raise_for_status()
            data = response.json().get("data", {})
            token = data.get("token")
            timeout = data.get("timeout") or data.get("expires_in")

            if token and token.count(".") != 2:
                logger.error(
                    "Wazuh API returned a token that does not appear to be a JWT"
                )
                token = None

            if isinstance(timeout, str):
                try:
                    timeout = int(timeout)
                except ValueError:
                    timeout = None

            if token:
                logger.info("Obtained Wazuh API token")
            else:
                logger.error("Wazuh API authentication response did not include a token")

            return token, timeout
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Failed to obtain Wazuh API token: %s", exc, exc_info=True)
            return None, None
        finally:
            self.session.headers.clear()
            self.session.headers.update(original_headers)

    def _refresh_token(self) -> None:
        """Fetch and store a fresh Wazuh JWT token."""
        token, timeout = self._obtain_token()
        if not token:
            raise RuntimeError("Unable to obtain Wazuh API token")

        self._set_token(token, timeout)

    def _ensure_token(self) -> None:
        """Refresh token if needed before making API requests."""
        if self._using_static_token:
            return

        if not self._token:
            self._refresh_token()
            return

        if self._token_expires_at and time.time() >= self._token_expires_at:
            logger.info("Wazuh API token expired, refreshing")
            self._refresh_token()

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
            self._ensure_token()

            response = self.session.request_with_backoff("GET", url, params=params)

            if response.status_code == 401 and not self._using_static_token:
                logger.info("Wazuh API rejected token, attempting refresh")
                self._refresh_token()
                response = self.session.request_with_backoff("GET", url, params=params)

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

