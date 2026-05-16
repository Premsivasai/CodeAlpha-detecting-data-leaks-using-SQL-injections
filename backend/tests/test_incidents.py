def test_incident_model_exists():
    from app.models import Incident

    # basic smoke test to ensure the Incident model is importable and has expected attributes
    assert hasattr(Incident, '__tablename__')
    assert Incident.__tablename__ == 'incidents'
    assert hasattr(Incident, 'title')
    assert hasattr(Incident, 'severity')
