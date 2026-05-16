import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def fallback_client(monkeypatch):
    import main
    import app.middleware as middleware

    async def fake_init_db():
        return None

    def fake_from_url(*args, **kwargs):
        raise RuntimeError("Redis unavailable")

    class DummyDBSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def fake_is_blocked(db, client_ip):
        return False

    monkeypatch.setattr(main, "init_db", fake_init_db)
    monkeypatch.setattr(main.aioredis, "from_url", fake_from_url)
    monkeypatch.setattr(middleware, "AsyncSessionLocal", lambda: DummyDBSession())
    monkeypatch.setattr(middleware.ip_blocker, "is_blocked", fake_is_blocked)

    with TestClient(main.app) as client:
        yield client


def test_local_pubsub_fallback_initializes(fallback_client):
    import main

    assert getattr(main.app.state, "redis", None) is None
    assert hasattr(main.app.state, "local_pubsub")
    assert "ws:attacks" in main.app.state.local_pubsub
    assert "cache:security:invalidate" in main.app.state.local_pubsub


def test_internal_publish_reaches_websocket(fallback_client):
    payload = {
        "id": 12345,
        "attack_type": "test_injection",
        "payload": "SELECT * FROM users WHERE id=1; -- test",
        "target": "database",
        "severity": "low",
        "detection_method": "pytest",
        "blocked": True,
        "timestamp": "2026-05-16T00:00:00",
    }

    with fallback_client.websocket_connect("/api/v1/ws/attacks") as websocket:
        response = fallback_client.post(
            "/api/v1/internal/publish",
            json={"channel": "ws:attacks", "message": payload},
        )

        assert response.status_code == 200
        assert response.json()["published"] is True
        assert response.json().get("fallback") is True

        message = websocket.receive_json()
        assert message["type"] == "attack"
        assert message["data"]["id"] == payload["id"]
        assert message["data"]["attack_type"] == payload["attack_type"]


def test_internal_publish_requires_channel_and_message(fallback_client):
    response = fallback_client.post("/api/v1/internal/publish", json={})

    assert response.status_code == 400
