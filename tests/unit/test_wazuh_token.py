"""Kiểm thử đơn vị cho logic lấy JWT token của Wazuh."""

import importlib
import sys
import time
from pathlib import Path
from typing import Any, Dict

import pytest


class DummyResponse:
    def __init__(self, payload: Dict[str, Any], status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> Dict[str, Any]:
        return self._payload


@pytest.fixture
def wazuh_module(monkeypatch):
    project_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(project_root))

    monkeypatch.setenv("WAZUH_API_URL", "https://172.16.69.163:55000")
    monkeypatch.setenv("WAZUH_API_USER", "admin")
    monkeypatch.setenv("WAZUH_API_PASS", "admin")
    monkeypatch.setenv("WAZUH_API_TOKEN", "")
    monkeypatch.setenv("THEHIVE_API_KEY", "test-key")

    sys.modules.pop("src.collector.wazuh_client", None)
    sys.modules.pop("src.common.config", None)

    config_module = importlib.import_module("src.common.config")
    importlib.reload(config_module)
    client_module = importlib.import_module("src.collector.wazuh_client")
    importlib.reload(client_module)
    return client_module


def test_wazuh_client_fetches_jwt_token(monkeypatch, wazuh_module):
    captured: Dict[str, Any] = {}

    def fake_post(self, url: str, json: Dict[str, Any], **_kwargs):
        captured["url"] = url
        captured["json"] = json
        return DummyResponse({"data": {"token": "header.payload.sig", "timeout": 120}})

    monkeypatch.setattr(wazuh_module.RetrySession, "post", fake_post)

    client = wazuh_module.WazuhClient()

    assert captured["url"] == "https://172.16.69.163:55000/security/user/authenticate"
    assert captured["json"] == {"username": "admin", "password": "admin"}
    assert client._token == "header.payload.sig"
    assert client.session.headers["Authorization"] == "Bearer header.payload.sig"
    assert client._token_expires_at is not None
    assert client._token_expires_at > time.time()


def test_wazuh_client_raises_when_token_missing(monkeypatch, wazuh_module):
    def fake_post(self, url: str, json: Dict[str, Any], **_kwargs):
        return DummyResponse({"data": {}})

    monkeypatch.setattr(wazuh_module.RetrySession, "post", fake_post)

    with pytest.raises(RuntimeError, match="Unable to obtain Wazuh API token"):
        wazuh_module.WazuhClient()
