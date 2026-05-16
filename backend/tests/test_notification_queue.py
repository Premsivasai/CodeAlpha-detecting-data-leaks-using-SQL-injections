from types import SimpleNamespace

import pytest


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code


class FakeSuccessClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json=None):
        return FakeResponse(200)


class FakeFailureClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json=None):
        raise RuntimeError("webhook down")


@pytest.mark.asyncio
async def test_process_notification_delivery_success(monkeypatch):
    import main

    calls = []

    async def fake_persist(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(main, "persist_notification_attempt", fake_persist)
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda timeout=5: FakeSuccessClient())

    app = SimpleNamespace(state=SimpleNamespace(notification_delivery_queue=None))
    await main.process_notification_delivery_job(
        app,
        {
            "notification_id": 1,
            "target": "https://example.com/webhook",
            "payload": {"title": "Hello"},
            "attempt_number": 1,
            "max_attempts": 3,
        },
    )

    assert calls
    assert calls[0][0][4] == "delivered"


@pytest.mark.asyncio
async def test_process_notification_delivery_failure_schedules_retry(monkeypatch):
    import main

    calls = []
    created_tasks = []

    async def fake_persist(*args, **kwargs):
        calls.append((args, kwargs))

    def fake_create_task(coro):
        created_tasks.append(coro)
        coro.close()
        return SimpleNamespace(cancel=lambda: None)

    monkeypatch.setattr(main, "persist_notification_attempt", fake_persist)
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda timeout=5: FakeFailureClient())
    monkeypatch.setattr(main.asyncio, "create_task", fake_create_task)

    app = SimpleNamespace(state=SimpleNamespace(notification_delivery_queue=None))
    await main.process_notification_delivery_job(
        app,
        {
            "notification_id": 2,
            "target": "https://example.com/webhook",
            "payload": {"title": "Hello"},
            "attempt_number": 1,
            "max_attempts": 3,
        },
    )

    assert calls
    assert calls[0][0][4] == "failed"
    assert calls[0][1]["next_attempt_at"] is not None
    assert created_tasks
