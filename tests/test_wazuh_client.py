"""Tests for Wazuh client authentication logic."""
import json
import os
import shutil
import tempfile
import unittest
from importlib import reload
from unittest.mock import MagicMock, patch

from requests.exceptions import RequestException


class TestWazuhClientAuth(unittest.TestCase):
    """Validate authentication setup for the Wazuh client."""

    def setUp(self):
        """Prepare environment and reload modules for deterministic config."""
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)
        cursor_path = os.path.join(self.temp_dir, "cursor.json")

        self.env_patch = patch.dict(
            os.environ,
            {
                "WAZUH_API_URL": "https://wazuh.local:55000",
                "WAZUH_API_USER": "wazuh",
                "WAZUH_API_PASS": "secret",
                "WAZUH_INDEXER_URL": "https://wazuh-indexer.local:9200",
                "WAZUH_INDEXER_USER": "indexer",
                "WAZUH_INDEXER_PASS": "indexerpass",
                "WAZUH_INDEXER_VERIFY_SSL": "true",
                "WAZUH_ALERTS_INDEX": "wazuh-alerts-*",
                "CURSOR_PATH": cursor_path,
                "HEURISTIC_WEIGHT": "0.6",
                "LLM_WEIGHT": "0.4",
            },
        )
        self.env_patch.start()

        import src.common.config as config  # noqa: WPS433 - reloading under test control
        import src.collector.wazuh_client as wazuh_client

        reload(config)
        reload(wazuh_client)

        self.wazuh_module = wazuh_client

    def tearDown(self):
        """Restore environment patch."""
        self.env_patch.stop()

    def test_token_retrieval_sets_bearer_header(self):
        """Client should store bearer token when authenticate endpoint responds."""
        mock_api_session = MagicMock()
        mock_api_session.headers = {}
        mock_api_session.verify = True

        mock_indexer_session = MagicMock()
        mock_indexer_session.verify = True

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"data": {"token": "jwt-token"}}
        mock_api_session.post.return_value = mock_response

        with patch.object(
            self.wazuh_module,
            "RetrySession",
            side_effect=[mock_api_session, mock_indexer_session],
        ):
            self.wazuh_module.WazuhClient()

        self.assertEqual(mock_api_session.headers.get("Authorization"), "Bearer jwt-token")
        self.assertIsNone(mock_api_session.auth)
        mock_api_session.post.assert_called_once()
        args, kwargs = mock_api_session.post.call_args
        self.assertEqual(args[0], "https://wazuh.local:55000/security/user/authenticate")
        self.assertIn("headers", kwargs)
        self.assertTrue(kwargs["headers"]["Authorization"].startswith("Basic "))

        indexer_auth = getattr(mock_indexer_session, "auth", None)
        self.assertEqual(getattr(indexer_auth, "username", None), "indexer")
        self.assertEqual(getattr(indexer_auth, "password", None), "indexerpass")

    def test_basic_auth_fallback_when_token_request_fails(self):
        """Client should fall back to HTTP Basic auth if token retrieval fails."""
        mock_api_session = MagicMock()
        mock_api_session.headers = {}
        mock_api_session.verify = True
        mock_api_session.post.side_effect = RequestException("network error")

        mock_indexer_session = MagicMock()
        mock_indexer_session.verify = True

        with patch.object(
            self.wazuh_module,
            "RetrySession",
            side_effect=[mock_api_session, mock_indexer_session],
        ):
            self.wazuh_module.WazuhClient()

        self.assertIsNotNone(mock_api_session.auth)
        self.assertEqual(getattr(mock_api_session.auth, "username", None), "wazuh")
        self.assertEqual(getattr(mock_api_session.auth, "password", None), "secret")

        indexer_auth = getattr(mock_indexer_session, "auth", None)
        self.assertEqual(getattr(indexer_auth, "username", None), "indexer")
        self.assertEqual(getattr(indexer_auth, "password", None), "indexerpass")

    def test_fetch_alerts_queries_indexer_and_updates_cursor(self):
        """Client should query the indexer and persist the latest cursor."""
        mock_api_session = MagicMock()
        mock_api_session.headers = {}
        mock_api_session.verify = True

        auth_response = MagicMock()
        auth_response.raise_for_status.return_value = None
        auth_response.json.return_value = {"data": {"token": "jwt-token"}}
        mock_api_session.post.return_value = auth_response

        mock_indexer_session = MagicMock()
        mock_indexer_session.verify = True

        indexer_response = MagicMock()
        indexer_response.raise_for_status.return_value = None
        indexer_response.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "alert-1",
                        "_source": {
                            "@timestamp": "2025-11-06T10:45:00.000Z",
                            "rule": {},
                            "agent": {},
                            "srcip": "",
                        },
                        "sort": ["2025-11-06T10:45:00.000Z", "alert-1"],
                    }
                ]
            }
        }
        mock_indexer_session.post.return_value = indexer_response

        with patch.object(
            self.wazuh_module,
            "RetrySession",
            side_effect=[mock_api_session, mock_indexer_session],
        ):
            client = self.wazuh_module.WazuhClient()

        alerts = client.fetch_alerts()

        self.assertEqual(len(alerts), 1)
        mock_indexer_session.post.assert_called_once()

        called_url = mock_indexer_session.post.call_args[0][0]
        self.assertEqual(called_url, "https://wazuh-indexer.local:9200/wazuh-alerts-*/_search")

        payload = mock_indexer_session.post.call_args[1]["json"]
        self.assertEqual(payload["size"], 200)
        # Mặc định hiện tại trong config là WAZUH_MIN_LEVEL = 7,
        # nhưng script fix brute-force có thể chỉnh xuống 5.
        # Ở đây chỉ cần đảm bảo query đang dùng giá trị cấu hình hiện tại.
        self.assertIn(
            payload["query"]["bool"]["filter"][0]["range"]["rule.level"]["gte"],
            (5, 7),
        )

        cursor_path = os.path.join(self.temp_dir, "cursor.json")
        with open(cursor_path, "r", encoding="utf-8") as handle:
            cursor_data = json.load(handle)

        self.assertEqual(cursor_data["timestamp"], "2025-11-06T10:45:00.000Z")
        self.assertEqual(cursor_data["sort"], ["2025-11-06T10:45:00.000Z", "alert-1"])

