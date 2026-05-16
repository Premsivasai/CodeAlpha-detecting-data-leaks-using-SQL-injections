from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


class FakeSelect:
    def __init__(self, model):
        self.model = model

    def where(self, *args, **kwargs):
        return self


class FakeResult:
    def __init__(self, item=None):
        self._item = item

    def scalar_one_or_none(self):
        return self._item


class FakeDB:
    def __init__(self, incident):
        self.incident = incident
        self.commits = 0
        self.refreshed = []
        self.added = []

    async def execute(self, statement):
        return FakeResult(self.incident)

    def add(self, item):
        self.added.append(item)

    async def commit(self):
        self.commits += 1

    async def refresh(self, item):
        self.refreshed.append(item)


@pytest.fixture()
def client(monkeypatch):
    import main
    import app.middleware as middleware
    import app.routes as routes
    from app.database import get_db

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

    incident = SimpleNamespace(
        id=7,
        title="Test Incident",
        description="Test description",
        severity="high",
        status="open",
        meta={"attack_ids": [1], "event_count": 1, "fingerprint": "abc"},
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    fake_db = FakeDB(incident)

    async def override_get_db():
        yield fake_db

    async def fake_user():
        return SimpleNamespace(id=42, role=SimpleNamespace(value="admin"))

    monkeypatch.setattr(main, "init_db", fake_init_db)
    monkeypatch.setattr(main.aioredis, "from_url", fake_from_url)
    monkeypatch.setattr(middleware, "AsyncSessionLocal", lambda: DummyDBSession())
    monkeypatch.setattr(middleware.ip_blocker, "is_blocked", fake_is_blocked)
    monkeypatch.setattr(routes, "select", lambda model: FakeSelect(model))
    monkeypatch.setattr(routes.alert_service, "create_alert", lambda *args, **kwargs: None)

    main.app.dependency_overrides[get_db] = override_get_db
    main.app.dependency_overrides[routes.get_current_user] = fake_user

    with TestClient(main.app) as test_client:
        yield test_client, fake_db, incident

    main.app.dependency_overrides.clear()


def test_resolve_incident_endpoint(client):
    test_client, fake_db, incident = client

    response = test_client.post(f"/api/v1/incidents/{incident.id}/resolve", json={"resolution_note": "Contained"})

    assert response.status_code == 200
    assert response.json()["status"] == "resolved"
    assert incident.status == "resolved"
    assert incident.meta["resolved_by"] == 42
    assert incident.meta["resolution_note"] == "Contained"
    assert fake_db.commits >= 1
