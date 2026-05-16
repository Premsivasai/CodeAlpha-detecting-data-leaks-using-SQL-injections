from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest


class FakeSelect:
    def __init__(self, model):
        self.model = model

    def where(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self


class FakeResult:
    def __init__(self, items=None):
        self._items = items or []

    def scalars(self):
        return self

    def all(self):
        return list(self._items)

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None


class FakeDB:
    def __init__(self, attacks, incidents):
        self.attacks = attacks
        self.incidents = incidents
        self.added = []
        self.commits = 0

    async def execute(self, statement):
        model = getattr(statement, "model", None)
        if model is None:
            return FakeResult([])

        if model.__name__ == "AttackLog":
            return FakeResult(self.attacks)
        if model.__name__ == "Incident":
            return FakeResult(self.incidents)
        return FakeResult([])

    def add(self, item):
        self.added.append(item)

    async def commit(self):
        self.commits += 1

    async def refresh(self, item):
        return None


@pytest.fixture()
def logs_module(monkeypatch):
    import app.logs as logs

    monkeypatch.setattr(logs, "select", lambda model: FakeSelect(model))
    monkeypatch.setattr(logs.alert_service, "create_alert", lambda *args, **kwargs: None)
    return logs


def test_incident_fingerprint_is_stable(logs_module):
    first = logs_module.LogService._build_incident_fingerprint("1.2.3.4", "union_based", "database", "rule")
    second = logs_module.LogService._build_incident_fingerprint("1.2.3.4", "union_based", "database", "rule")
    third = logs_module.LogService._build_incident_fingerprint("5.6.7.8", "union_based", "database", "rule")

    assert first == second
    assert first != third


@pytest.mark.asyncio
async def test_correlate_incident_creates_new_incident_after_threshold(logs_module):
    now = datetime.utcnow()
    attacks = [
        SimpleNamespace(id=1, ip_address="10.0.0.5", attack_type="sql_injection", target="database", detection_method="rule", severity="medium", timestamp=now - timedelta(minutes=10)),
        SimpleNamespace(id=2, ip_address="10.0.0.5", attack_type="sql_injection", target="database", detection_method="rule", severity="medium", timestamp=now - timedelta(minutes=5)),
        SimpleNamespace(id=3, ip_address="10.0.0.5", attack_type="sql_injection", target="database", detection_method="rule", severity="medium", timestamp=now),
    ]
    db = FakeDB(attacks=attacks, incidents=[])

    attack_log = attacks[-1]
    incident = await logs_module.LogService.correlate_incident(db, attack_log)

    assert incident is not None
    assert incident.title.startswith("Correlated attacks")
    assert incident.meta["event_count"] == 3
    assert incident.meta["attack_ids"] == [1, 2, 3]
    assert db.commits >= 1
    assert db.added


@pytest.mark.asyncio
async def test_correlate_incident_updates_open_incident(logs_module):
    now = datetime.utcnow()
    fingerprint = logs_module.LogService._build_incident_fingerprint("10.0.0.8", "union_based", "database", "rule")
    existing_incident = SimpleNamespace(
        id=99,
        title="Correlated attacks from 10.0.0.8",
        description="Old description",
        severity="medium",
        status="open",
        meta={"fingerprint": fingerprint, "attack_ids": [10], "event_count": 1, "first_seen": now.isoformat()},
        created_at=now - timedelta(minutes=30),
        updated_at=now - timedelta(minutes=30),
    )
    attacks = [
        SimpleNamespace(id=11, ip_address="10.0.0.8", attack_type="union_based", target="database", detection_method="rule", severity="high", timestamp=now),
    ]
    db = FakeDB(attacks=attacks, incidents=[existing_incident])

    incident = await logs_module.LogService.correlate_incident(db, attacks[0])

    assert incident is existing_incident
    assert existing_incident.severity == "high"
    assert existing_incident.meta["event_count"] == 2
    assert existing_incident.meta["attack_ids"] == [10, 11]
