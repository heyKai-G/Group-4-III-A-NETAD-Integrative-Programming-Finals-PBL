from datetime import timedelta

from app.extensions import db
from app.models import Alert, Device, TrafficSample, utcnow
from sensor.runner import Inventory, SensorService


def test_inventory_flush_creates_and_updates(app):
    inv = Inventory("192.168.1.1")
    inv.seen("02:aa:00:00:00:01", "192.168.1.1")
    inv.seen("02:aa:00:00:00:02", "192.168.1.50", "kali")
    inv.flush(app)
    inv.seen("02:aa:00:00:00:02", "192.168.1.51")
    inv.flush(app)
    with app.app_context():
        devs = {d.mac: d for d in Device.query.all()}
        assert len(devs) == 2
        assert devs["02:aa:00:00:00:01"].is_gateway
        assert devs["02:aa:00:00:00:02"].ip == "192.168.1.51"
        assert devs["02:aa:00:00:00:02"].hostname == "kali"


def test_retention_deletes_only_old_alerts(app):
    with app.app_context():
        old = utcnow() - timedelta(days=91)
        db.session.add(Alert(source="sensor", category="Other", signature="old", ts=old))
        db.session.add(Alert(source="sensor", category="Other", signature="new"))
        db.session.add(TrafficSample(ts=utcnow() - timedelta(days=8)))
        db.session.commit()
    svc = SensorService(app)
    svc.purge_once()
    with app.app_context():
        assert [a.signature for a in Alert.query.all()] == ["new"]
        assert TrafficSample.query.count() == 0
