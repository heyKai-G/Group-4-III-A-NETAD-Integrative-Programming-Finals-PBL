"""Password hashing, lockout, TOTP 2FA and audit helpers."""
import base64
import hashlib
import hmac
import re
import secrets
import time
from datetime import timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app, request
from sqlalchemy import func

from .extensions import db
from .models import AuditLog, LoginAttempt, PasswordReset, RecoveryCode, utcnow

_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("not-a-real-password")


# ---------------------------------------------------------------- passwords
def hash_password(password):
    return _hasher.hash(password)


def verify_password(stored_hash, password):
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def burn_password_check(password):
    """Spend the same time as a real check when the username does not exist."""
    verify_password(_DUMMY_HASH, password)


def password_problems(password, username=""):
    min_len = current_app.config["MIN_PASSWORD_LENGTH"]
    problems = []
    if len(password) < min_len:
        problems.append(f"Password must be at least {min_len} characters.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        problems.append("Password must contain letters and at least one number.")
    if username and username.lower() in password.lower():
        problems.append("Password must not contain the username.")
    return problems


# ----------------------------------------------------------------- lockout
def client_ip():
    return request.remote_addr or "unknown"


def lockout_status(username):
    """Return (locked, unlock_time). Based on failed attempts since the last success."""
    key = (username or "").strip().lower()
    cfg = current_app.config
    max_fails = cfg["LOCKOUT_MAX_FAILS"]
    window = timedelta(minutes=cfg["LOCKOUT_MINUTES"])
    now = utcnow()
    start = now - window
    last_ok = (
        db.session.query(func.max(LoginAttempt.ts))
        .filter(LoginAttempt.username == key, LoginAttempt.success.is_(True))
        .scalar()
    )
    if last_ok and last_ok > start:
        start = last_ok
    fails = (
        LoginAttempt.query.filter(
            LoginAttempt.username == key,
            LoginAttempt.success.is_(False),
            LoginAttempt.ts > start,
        )
        .order_by(LoginAttempt.ts.desc())
        .limit(max_fails)
        .all()
    )
    if len(fails) >= max_fails:
        until = fails[0].ts + window
        if until > now:
            return True, until
    return False, None


def record_attempt(username, success):
    db.session.add(
        LoginAttempt(
            username=(username or "").strip().lower()[:80],
            ip=client_ip(),
            success=success,
        )
    )
    db.session.commit()


def audit(event, username=None, detail=None):
    db.session.add(
        AuditLog(
            event=event,
            username=(username or "")[:80],
            ip=client_ip() if request else None,
            detail=(detail or "")[:255],
        )
    )
    db.session.commit()


# -------------------------------------------------------------------- TOTP
def _fernet():
    key = hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def new_totp_secret():
    return pyotp.random_base32()


def encrypt_secret(secret):
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(token):
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, AttributeError):
        return None


def totp_uri(secret, username):
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Lab IDS")


def verify_totp(user, code):
    """Check a 6-digit code (+-1 step). A code can only be used once."""
    code = (code or "").strip().replace(" ", "")
    if not re.fullmatch(r"\d{6}", code):
        return False
    secret = decrypt_secret(user.totp_secret_enc)
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    now_step = int(time.time() // 30)
    for offset in (-1, 0, 1):
        step = now_step + offset
        if step <= (user.last_totp_step or 0):
            continue
        if hmac.compare_digest(totp.at(step * 30), code):
            user.last_totp_step = step
            db.session.commit()
            return True
    return False


# ------------------------------------------------- recovery codes / reset links
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"      # no 0/O/1/I


def _keyed_hash(kind, value):
    key = (current_app.config["SECRET_KEY"] + "|" + kind).encode()
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def normalize_code(code):
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def new_recovery_codes(user):
    """Replace the user's recovery codes with a fresh set. Returns the plain codes (shown once)."""
    RecoveryCode.query.filter_by(user_id=user.id).delete()
    codes = []
    for _ in range(current_app.config["RECOVERY_CODE_COUNT"]):
        raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
        db.session.add(RecoveryCode(user_id=user.id, code_hash=_keyed_hash("recovery", raw)))
    db.session.commit()
    return codes


def recovery_codes_left(user):
    return RecoveryCode.query.filter_by(user_id=user.id, used_at=None).count()


def use_recovery_code(user, code):
    """True (and the code is burned) if `code` is one of the user's unused codes."""
    norm = normalize_code(code)
    if len(norm) != 10:
        return False
    row = RecoveryCode.query.filter_by(
        user_id=user.id, code_hash=_keyed_hash("recovery", norm), used_at=None).first()
    if not row:
        return False
    row.used_at = utcnow()
    db.session.commit()
    return True


def new_reset_token(user):
    """Create a single-use reset link token (older unused ones are cancelled)."""
    now = utcnow()
    PasswordReset.query.filter_by(user_id=user.id, used_at=None).update({"used_at": now})
    token = secrets.token_urlsafe(32)
    db.session.add(PasswordReset(
        user_id=user.id, token_hash=_keyed_hash("reset", token),
        expires_at=now + timedelta(minutes=current_app.config["RESET_LINK_MINUTES"])))
    db.session.commit()
    return token


def find_reset(token):
    if not token or len(token) > 100:
        return None
    row = PasswordReset.query.filter_by(token_hash=_keyed_hash("reset", token)).first()
    if not row or row.used_at is not None or row.expires_at < utcnow():
        return None
    return row


def recent_reset_requests(user, minutes=60):
    return PasswordReset.query.filter(
        PasswordReset.user_id == user.id,
        PasswordReset.created_at > utcnow() - timedelta(minutes=minutes)).count()
