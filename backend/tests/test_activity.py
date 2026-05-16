import pytest
from fastapi.testclient import TestClient
from datetime import datetime


class DummyRole:
    def __init__(self, value="admin"):
        self.value = value


class DummyUser:
    def __init__(self):
        self.id = 1
        self.role = DummyRole()


class DummyAttempt:
    def __init__(self, id=1):
        self.id = id
        self.notification_id = 10
        self.target = "http://example.local/webhook"
        self.attempt_number = 1
        self.status = "failed"
        self.error_message = "connection refused"
        self.response_code = None
        self.created_at = datetime.utcnow()


class DummyNotification:
    def __init__(self, id=10):
        self.id = id
        self.title = "Test Notification"


class DummyIncident:
    def __init__(self, id=2):
        self.id = id
        self.title = "Test Incident"
        self.severity = "medium"
        self.status = "open"
        self.updated_at = datetime.utcnow()
        self.created_at = datetime.utcnow()


class DummyResult:
    def __init__(self, items):
        self._items = items

    def scalars(self):
        class R:
            def __init__(self, items):
                self._items = items

            def all(self):
                return self._items

        return R(self._items)


class DummyDBSession:
    def __init__(self):
        self.attempts = [DummyAttempt(id=1), DummyAttempt(id=2)]
        self.notifications = {10: DummyNotification(10)}
        self.incidents = [DummyIncident(2)]

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def close(self):
        return None

    async def execute(self, query):
        q = str(query).lower()
        if 'notification_delivery_attempts' in q:
            return DummyResult(self.attempts)
        if 'notifications' in q:
            # return single notification if filtered
            return DummyResult(list(self.notifications.values()))
        if 'incidents' in q:
            return DummyResult(self.incidents)
        return DummyResult([])


@pytest.fixture()
def client(monkeypatch):
    import main
    import app.database as database
    import app.routes as routes

    async def fake_init_db():
        return None

    monkeypatch.setattr(main, 'init_db', fake_init_db)
    monkeypatch.setattr(database, 'AsyncSessionLocal', lambda: DummyDBSession())

    async def fake_get_current_user():
        return DummyUser()

    monkeypatch.setattr(routes, 'get_current_user', fake_get_current_user)
    import app.auth as auth
    # Override FastAPI dependency to ensure the route uses the fake user
    main.app.dependency_overrides[auth.get_current_user] = fake_get_current_user
    # Allow permissions for test by patching the permission_checker used in routes
    monkeypatch.setattr(routes, 'permission_checker', type('P', (), {'has_permission': staticmethod(lambda *a, **k: True), 'get_permissions': staticmethod(lambda r: {})}))
    # sanity check
    assert routes.permission_checker.has_permission(None, 'activity:read') is True

    with TestClient(main.app) as c:
        yield c


def test_activity_returns_items(client):
    res = client.get('/api/v1/activity')
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    # should include attempts
    assert any(item['type'] == 'notification_attempt' for item in data)
    # may include incidents as well
    assert any(item['type'] in ('incident', 'notification_attempt') for item in data)
