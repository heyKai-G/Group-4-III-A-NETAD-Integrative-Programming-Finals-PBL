"""Extra accounts, deletion with verification, recovery codes and password reset."""
import re
import time

import pyotp
import pytest

from app import security as sec
from app.extensions import db
from app.models import AuditLog, PasswordReset, RecoveryCode, User, utcnow
from tests.test_auth import PW, create_admin

PW2 = "Other-secret-phrase-42"
CODE_RE = re.compile(r"\b[A-Z2-9]{5}-[A-Z2-9]{5}\b")


def totp_for(app, username):
    """A fresh, unused code for `username` (clears the replay guard first)."""
    with app.app_context():
        u = User.query.filter_by(username=username).first()
        secret = sec.decrypt_secret(u.totp_secret_enc)
        u.last_totp_step = 0
        db.session.commit()
    return pyotp.TOTP(secret).now()


def admin_with_codes(client, app):
    r = create_admin(client, app)
    return CODE_RE.findall(r.get_data(as_text=True))


def add_user(client, name="second", pw=PW2, email="s@example.com"):
    return client.post("/users", data={"username": name, "email": email,
                                       "password": pw, "confirm": pw})


def login(client, app, name, pw):
    client.post("/logout")
    r = client.post("/login", data={"username": name, "password": pw})
    assert r.status_code == 302
    if r.headers["Location"].endswith("/2fa/enroll"):
        r = client.post("/2fa/enroll", data={"code": totp_for(app, name)})
        assert r.status_code == 200
        return r
    r = client.post("/login/2fa", data={"code": totp_for(app, name)})
    assert r.status_code == 302
    return r


# ------------------------------------------------------------ recovery codes
def test_first_login_shows_eight_distinct_codes_and_stores_only_hashes(client, app):
    codes = admin_with_codes(client, app)
    assert len(codes) == 8 and len(set(codes)) == 8
    with app.app_context():
        rows = RecoveryCode.query.all()
        assert len(rows) == 8
        plain = {c.replace("-", "") for c in codes}
        assert all(r.code_hash not in plain and len(r.code_hash) == 64 for r in rows)


def test_regenerate_codes_needs_password_and_cancels_old(client, app):
    old = admin_with_codes(client, app)
    client.get("/account")
    r = client.post("/account/recovery-codes", data={"password": "wrong-password-1"})
    assert r.status_code == 302
    with app.app_context():
        assert sec.recovery_codes_left(User.query.first()) == 8
    r = client.post("/account/recovery-codes", data={"password": PW})
    new = CODE_RE.findall(r.get_data(as_text=True))
    assert len(new) == 8 and not set(new) & set(old)
    with app.app_context():
        u = User.query.first()
        assert not sec.use_recovery_code(u, old[0])
        assert sec.use_recovery_code(u, new[0])


# --------------------------------------------------------- forgot: recovery
def test_reset_with_recovery_code_once_only(client, app):
    codes = admin_with_codes(client, app)
    client.post("/logout")
    newpw = "Brand-new-password-5"
    r = client.post("/forgot", data={"method": "recovery", "username": "kaisser",
                                     "code": codes[0].lower(), "new": newpw, "confirm": newpw})
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
    with app.app_context():
        u = User.query.first()
        assert sec.verify_password(u.password_hash, newpw)
        assert sec.recovery_codes_left(u) == 7
    # the same code cannot be used again
    r = client.post("/forgot", data={"method": "recovery", "username": "kaisser",
                                     "code": codes[0], "new": "Another-pass-word-8",
                                     "confirm": "Another-pass-word-8"})
    assert r.status_code == 200 and "not correct" in r.get_data(as_text=True)
    # password alone still does not log in: 2FA is required
    r = client.post("/login", data={"username": "kaisser", "password": newpw})
    assert r.headers["Location"].endswith("/login/2fa")
    assert client.get("/dashboard").status_code == 302


def test_bad_new_password_does_not_burn_the_code(client, app):
    codes = admin_with_codes(client, app)
    client.post("/logout")
    r = client.post("/forgot", data={"method": "recovery", "username": "kaisser",
                                     "code": codes[1], "new": "short", "confirm": "short"})
    assert r.status_code == 200 and "at least" in r.get_data(as_text=True)
    with app.app_context():
        assert sec.recovery_codes_left(User.query.first()) == 8


def test_recovery_reset_failures_are_generic_and_locked_out(client, app):
    admin_with_codes(client, app)
    client.post("/logout")
    msgs = set()
    for name in ("kaisser", "ghost"):
        r = client.post("/forgot", data={"method": "recovery", "username": name,
                                         "code": "AAAAA-BBBBB", "new": "x", "confirm": "x"})
        msgs.add("not correct" in r.get_data(as_text=True))
    assert msgs == {True}                      # same answer for real and unknown users
    for _ in range(6):
        r = client.post("/forgot", data={"method": "recovery", "username": "kaisser",
                                         "code": "AAAAA-BBBBB", "new": "x", "confirm": "x"})
    assert "Too many failed attempts" in r.get_data(as_text=True)


# -------------------------------------------------------- forgot: email link
@pytest.fixture()
def mail_app(app):
    app.config.update(SMTP_HOST="smtp.test", SMTP_FROM="ids@test", PUBLIC_URL="https://10.0.0.5:5443")
    sent = []

    from app.services import mailer
    orig = mailer.send_mail
    mailer.send_mail = lambda to, subject, body: sent.append((to, subject, body)) or True
    yield app, sent
    mailer.send_mail = orig


def test_email_option_hidden_when_not_configured(client, app):
    admin_with_codes(client, app)
    client.post("/logout")
    body = client.get("/forgot").get_data(as_text=True)
    assert "Not set up on this server" in body
    r = client.post("/forgot", data={"method": "email", "username": "kaisser"})
    assert "not set up" in r.get_data(as_text=True)


def test_email_reset_link_flow(client, mail_app):
    app, sent = mail_app
    admin_with_codes(client, app)
    client.post("/logout")
    r = client.post("/forgot", data={"method": "email", "username": "kaisser"})
    assert "If that account exists" in r.get_data(as_text=True)
    assert len(sent) == 1 and sent[0][0] == "k@example.com"
    link = re.search(r"https://10\.0\.0\.5:5443(/reset/[\w-]+)", sent[0][2]).group(1)
    # unknown user: identical message, nothing sent
    r = client.post("/forgot", data={"method": "email", "username": "ghost"})
    assert "If that account exists" in r.get_data(as_text=True) and len(sent) == 1
    assert client.get(link).status_code == 200
    assert client.get("/reset/not-a-token").status_code == 400
    newpw = "Emailed-reset-pass-3"
    r = client.post(link, data={"new": newpw, "confirm": newpw})
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
    with app.app_context():
        assert sec.verify_password(User.query.first().password_hash, newpw)
    assert client.get(link).status_code == 400          # single use


def test_email_link_expires_and_new_request_cancels_old(client, mail_app):
    from datetime import timedelta
    app, sent = mail_app
    admin_with_codes(client, app)
    client.post("/logout")
    client.post("/forgot", data={"method": "email", "username": "kaisser"})
    client.post("/forgot", data={"method": "email", "username": "k@example.com"})
    assert len(sent) == 2
    first = re.search(r"/reset/[\w-]+", sent[0][2]).group(0)
    second = re.search(r"/reset/[\w-]+", sent[1][2]).group(0)
    assert client.get(first).status_code == 400          # replaced by the newer link
    assert client.get(second).status_code == 200
    with app.app_context():
        for p in PasswordReset.query.all():
            p.expires_at = utcnow() - timedelta(minutes=1)
        db.session.commit()
    assert client.get(second).status_code == 400


def test_email_host_header_cannot_poison_link(client, mail_app):
    app, sent = mail_app
    admin_with_codes(client, app)
    client.post("/logout")
    client.post("/forgot", data={"method": "email", "username": "kaisser"},
                headers={"Host": "evil.example"})
    assert "evil.example" not in sent[0][2] and "10.0.0.5:5443" in sent[0][2]


def test_email_requests_are_rate_limited(client, mail_app):
    app, sent = mail_app
    admin_with_codes(client, app)
    client.post("/logout")
    for _ in range(4):
        client.post("/forgot", data={"method": "email", "username": "kaisser"})
    assert len(sent) <= 3


def test_smtp_failure_still_gives_generic_answer(client, mail_app):
    from app.services import mailer
    app, sent = mail_app
    mailer.send_mail = lambda *a: False
    admin_with_codes(client, app)
    client.post("/logout")
    r = client.post("/forgot", data={"method": "email", "username": "kaisser"})
    assert r.status_code == 200 and "If that account exists" in r.get_data(as_text=True)


# ------------------------------------------------------------- more accounts
def test_users_page_needs_login(client, app):
    admin_with_codes(client, app)
    client.post("/logout")
    assert client.get("/users").status_code == 302
    assert client.post("/users", data={}).status_code == 302


def test_create_second_account_and_it_can_log_in(client, app):
    admin_with_codes(client, app)
    r = add_user(client)
    assert r.status_code == 302
    page = client.get("/users").get_data(as_text=True)
    assert "second" in page and "kaisser" in page
    r = login(client, app, "second", PW2)                    # first login: 2FA + codes
    assert len(CODE_RE.findall(r.get_data(as_text=True))) == 8
    with app.app_context():
        u = User.query.filter_by(username="second").first()
        assert u.totp_enabled and u.password_hash.startswith("$argon2")
        assert sec.recovery_codes_left(u) == 8
        # each user has their own secret and their own codes
        assert u.totp_secret_enc != User.query.filter_by(username="kaisser").first().totp_secret_enc
        assert RecoveryCode.query.count() == 16


def test_create_account_validation(client, app):
    admin_with_codes(client, app)
    for data, msg in [
        ({"username": "ab", "email": "x@y.io", "password": PW2, "confirm": PW2}, "Username must be"),
        ({"username": "good", "email": "bad", "password": PW2, "confirm": PW2}, "valid email"),
        ({"username": "good", "email": "x@y.io", "password": PW2, "confirm": "nope"}, "do not match"),
        ({"username": "good", "email": "x@y.io", "password": "short", "confirm": "short"}, "at least"),
        ({"username": "KAISSER", "email": "x@y.io", "password": PW2, "confirm": PW2}, "already taken"),
    ]:
        r = client.post("/users", data=data)
        assert r.status_code == 200 and msg in r.get_data(as_text=True), msg
    with app.app_context():
        assert User.query.count() == 1


def test_public_setup_stays_closed_with_many_accounts(client, app):
    admin_with_codes(client, app)
    add_user(client)
    client.post("/logout")
    r = client.post("/setup", data={"username": "evil", "email": "e@e.io",
                                    "password": PW, "confirm": PW})
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    with app.app_context():
        assert User.query.count() == 2


# ------------------------------------------------------- delete + verification
def second_user_id(app):
    with app.app_context():
        return User.query.filter_by(username="second").first().id


def test_delete_requires_password_and_totp(client, app):
    admin_with_codes(client, app)
    add_user(client)
    uid = second_user_id(app)
    assert client.get(f"/users/{uid}/delete").status_code == 200
    # wrong password
    r = client.post(f"/users/{uid}/delete", data={"password": "wrong-password-1",
                                                   "code": totp_for(app, "kaisser")})
    assert r.status_code == 200 and "password is not correct" in r.get_data(as_text=True)
    # right password, wrong code
    r = client.post(f"/users/{uid}/delete", data={"password": PW, "code": "000000"})
    assert r.status_code == 200 and "not valid" in r.get_data(as_text=True)
    # no fields at all
    assert client.post(f"/users/{uid}/delete", data={}).status_code == 200
    with app.app_context():
        assert User.query.count() == 2
    # both right
    r = client.post(f"/users/{uid}/delete", data={"password": PW, "code": totp_for(app, "kaisser")})
    assert r.status_code == 302
    with app.app_context():
        assert User.query.filter_by(username="second").first() is None
        assert User.query.count() == 1
        events = [a.event for a in AuditLog.query.all()]
        assert "user_deleted" in events and events.count("user_delete_denied") == 3


def test_delete_cleans_related_rows_and_old_login_stops(client, app):
    admin_with_codes(client, app)
    add_user(client)
    login(client, app, "second", PW2)
    login(client, app, "kaisser", PW)
    uid = second_user_id(app)
    client.post(f"/users/{uid}/delete", data={"password": PW, "code": totp_for(app, "kaisser")})
    with app.app_context():
        assert RecoveryCode.query.count() == 8              # only kaisser's remain
        assert PasswordReset.query.count() == 0
    client.post("/logout")
    r = client.post("/login", data={"username": "second", "password": PW2})
    assert r.status_code == 200 and "Invalid username or password" in r.get_data(as_text=True)


def test_cannot_delete_yourself_or_missing_user(client, app):
    admin_with_codes(client, app)
    with app.app_context():
        me = User.query.first().id
    r = client.post(f"/users/{me}/delete", data={"password": PW, "code": totp_for(app, "kaisser")})
    assert r.status_code == 302
    with app.app_context():
        assert User.query.count() == 1
    assert client.get("/users/9999/delete").status_code == 302


def test_delete_requires_login(client, app):
    admin_with_codes(client, app)
    add_user(client)
    uid = second_user_id(app)
    client.post("/logout")
    assert client.get(f"/users/{uid}/delete").status_code == 302
    assert client.post(f"/users/{uid}/delete", data={"password": PW, "code": "123456"}).status_code == 302
    with app.app_context():
        assert User.query.count() == 2


def test_repeated_failed_delete_checks_lock_the_account(client, app):
    admin_with_codes(client, app)
    add_user(client)
    uid = second_user_id(app)
    for _ in range(5):
        client.post(f"/users/{uid}/delete", data={"password": "wrong-password-1", "code": "000000"})
    r = client.post(f"/users/{uid}/delete", data={"password": PW, "code": totp_for(app, "kaisser")})
    assert "Too many failed attempts" in r.get_data(as_text=True)
    with app.app_context():
        assert User.query.count() == 2


def test_pages_render(client, app):
    admin_with_codes(client, app)
    for page in ("/users", "/account"):
        assert client.get(page).status_code == 200, page
    client.post("/logout")
    for page in ("/login", "/forgot"):
        body = client.get(page)
        assert body.status_code == 200
    assert "Forgot password?" in client.get("/login").get_data(as_text=True)
