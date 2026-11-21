import pyotp
import pytest

from app import security as sec
from app.extensions import db
from app.models import NetworkConfig, User

PW = "Correct-horse-battery-9"


def code_now(app, fresh=True):
    with app.app_context():
        u = User.query.first()
        secret = sec.decrypt_secret(u.totp_secret_enc)
        if fresh:
            u.last_totp_step = 0
            db.session.commit()
    return pyotp.TOTP(secret).now()


def create_admin(client, app, username="kaisser"):
    r = client.post("/setup", data={"username": username, "email": "k@example.com",
                                    "password": PW, "confirm": PW})
    assert r.status_code == 302 and r.headers["Location"].endswith("/2fa/enroll")
    r = client.post("/2fa/enroll", data={"code": code_now(app)})
    assert r.status_code == 200 and "Save your recovery codes" in r.get_data(as_text=True)
    return r


def test_first_visit_goes_to_setup(client):
    r = client.get("/")
    assert r.status_code == 302 and "/setup" in r.headers["Location"]
    assert client.get("/login").status_code == 302


def test_setup_validation(client):
    r = client.post("/setup", data={"username": "ab", "email": "bad", "password": "short",
                                    "confirm": "different"})
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Username must be" in body and "valid email" in body and "do not match" in body
    with client.application.app_context():
        assert User.query.count() == 0


def test_register_then_locked(client, app):
    create_admin(client, app)
    with app.app_context():
        u = User.query.first()
        assert u.totp_enabled and u.password_hash.startswith("$argon2")
        assert PW not in u.totp_secret_enc
    client.post("/logout")
    r = client.post("/setup", data={"username": "evil", "email": "e@e.io",
                                    "password": PW, "confirm": PW})
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    with app.app_context():
        assert User.query.count() == 1


def test_login_requires_2fa_and_blocks_replay(client, app):
    create_admin(client, app)
    client.post("/logout")
    assert client.get("/dashboard").status_code == 302
    r = client.post("/login", data={"username": "kaisser", "password": PW})
    assert r.headers["Location"].endswith("/login/2fa")
    assert client.get("/dashboard").status_code == 302     # password alone is not enough
    good = code_now(app)
    assert client.post("/login/2fa", data={"code": "000000"}).status_code == 200
    r = client.post("/login/2fa", data={"code": good})
    assert r.status_code == 302
    client.post("/logout")
    # same code again must not work
    client.post("/login", data={"username": "kaisser", "password": PW})
    r = client.post("/login/2fa", data={"code": good})
    assert r.status_code == 200 and "not valid" in r.get_data(as_text=True)


def test_lockout_after_five_failures(client, app):
    create_admin(client, app)
    client.post("/logout")
    for _ in range(5):
        r = client.post("/login", data={"username": "kaisser", "password": "wrong-password-1"})
        assert r.status_code == 200
    r = client.post("/login", data={"username": "kaisser", "password": PW})
    assert r.status_code == 200 and "Too many failed attempts" in r.get_data(as_text=True)
    # same behaviour for a username that does not exist (no user enumeration)
    for _ in range(5):
        client.post("/login", data={"username": "ghost", "password": "x"})
    r = client.post("/login", data={"username": "ghost", "password": "x"})
    assert "Too many failed attempts" in r.get_data(as_text=True)


def test_lockout_expires(client, app):
    from datetime import timedelta
    from app.models import LoginAttempt, utcnow
    create_admin(client, app)
    client.post("/logout")
    for _ in range(5):
        client.post("/login", data={"username": "kaisser", "password": "wrong-password-1"})
    with app.app_context():
        for a in LoginAttempt.query.all():
            a.ts = utcnow() - timedelta(minutes=16)
        db.session.commit()
    r = client.post("/login", data={"username": "kaisser", "password": PW})
    assert r.status_code == 302


def test_wizard_gate_and_pages(client, app):
    create_admin(client, app)
    r = client.get("/dashboard")
    assert r.status_code == 302 and r.headers["Location"].endswith("/wizard")
    r = client.get("/wizard")
    assert r.status_code == 200 and "tell the IDS about your network" in r.get_data(as_text=True)
    ifaces = [i for i in __import__("app.services.netinfo", fromlist=["x"]).list_interfaces()]
    assert ifaces
    name = ifaces[0]["name"]
    bad = client.post("/wizard", data={"network_name": "Lab", "subnet_cidr": "nope",
                                       "gateway_ip": "10.0.0.1", "iface_name": name,
                                       "sensitivity": "medium"})
    assert bad.status_code == 200 and "Subnet must be" in bad.get_data(as_text=True)
    ok = client.post("/wizard", data={"network_name": "NETAD Lab", "subnet_cidr": "192.168.1.0/24",
                                      "gateway_ip": "192.168.1.1", "iface_name": name,
                                      "sensitivity": "high", "dhcp_servers": ""})
    assert ok.status_code == 302
    with app.app_context():
        c = NetworkConfig.query.first()
        assert c.dhcp_servers == "192.168.1.1" and c.sensitivity == "high"
    import os
    rules = open(app.config["LOCAL_RULES_PATH"]).read()
    assert "Sensitivity: high" in rules
    for page in ("/dashboard", "/alerts", "/devices", "/map", "/settings", "/account"):
        assert client.get(page).status_code == 200, page
    for api in ("/api/summary", "/api/traffic", "/api/alerts/latest", "/api/network"):
        r = client.get(api)
        assert r.status_code == 200 and r.is_json, api


def test_change_password(client, app):
    create_admin(client, app)
    r = client.post("/account", data={"current": "nope", "new": "Another-long-pass-77",
                                      "confirm": "Another-long-pass-77"})
    assert "incorrect" in r.get_data(as_text=True)
    r = client.post("/account", data={"current": PW, "new": "Another-long-pass-77",
                                      "confirm": "Another-long-pass-77"})
    assert r.status_code == 302
    with app.app_context():
        u = User.query.first()
        assert sec.verify_password(u.password_hash, "Another-long-pass-77")


def test_csrf_enforced(tmp_path):
    from app import create_app
    from app.extensions import db
    app = create_app({"TESTING": True, "SECRET_KEY": "k" * 40,
                      "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'c.db'}",
                      "SESSION_COOKIE_SECURE": False, "WTF_CSRF_ENABLED": True})
    with app.app_context():
        db.create_all()
    c = app.test_client()
    r = c.post("/setup", data={"username": "kaisser", "email": "k@example.com",
                               "password": PW, "confirm": PW})
    assert r.status_code == 400
    with app.app_context():
        assert User.query.count() == 0


def test_security_headers(client):
    r = client.get("/setup")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert "no-store" in r.headers["Cache-Control"]
