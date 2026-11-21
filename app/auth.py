"""First-run admin setup, login with TOTP 2FA, lockout, password change, extra accounts,
account deletion with verification, and password reset (recovery code or emailed link)."""
import re
import time

import segno
from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, session, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from .extensions import db, login_manager
from .models import AuditLog, PasswordReset, RecoveryCode, User, utcnow
from .services import mailer
from . import security as sec

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def _set_pre2fa(user):
    session.clear()
    session["pre2fa"] = {"uid": user.id, "ts": int(time.time())}


def _pre2fa_user():
    data = session.get("pre2fa")
    if not data:
        return None
    if time.time() - data.get("ts", 0) > current_app.config["PRE2FA_SECONDS"]:
        session.pop("pre2fa", None)
        return None
    return db.session.get(User, data["uid"])


def _finish_login(user):
    session.clear()
    login_user(user, remember=False)
    session.permanent = True
    user.last_login = utcnow()
    db.session.commit()
    sec.record_attempt(user.username, True)
    sec.audit("login_success", user.username)


def _after_login_redirect():
    return redirect(url_for("main.dashboard"))


# ------------------------------------------------------------------ setup
@bp.route("/setup", methods=["GET", "POST"])
def setup():
    """Create the first admin account. Locked once an account exists (more accounts are
    created from the Users page by a logged-in user)."""
    if User.query.count() > 0:
        return redirect(url_for("auth.login"))
    errors = []
    form = {"username": "", "email": ""}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        form = {"username": username, "email": email}
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-40 characters: letters, numbers, . _ -")
        if not EMAIL_RE.match(email):
            errors.append("Enter a valid email address.")
        if password != confirm:
            errors.append("Passwords do not match.")
        errors += sec.password_problems(password, username)
        if not errors:
            user = User(
                username=username,
                email=email,
                password_hash=sec.hash_password(password),
                totp_secret_enc=sec.encrypt_secret(sec.new_totp_secret()),
                totp_enabled=False,
                is_admin=True,
            )
            db.session.add(user)
            db.session.commit()
            sec.audit("admin_created", username)
            _set_pre2fa(user)
            return redirect(url_for("auth.enroll_2fa"))
    return render_template("setup.html", errors=errors, form=form,
                           min_len=current_app.config["MIN_PASSWORD_LENGTH"])


# ------------------------------------------------------------------ login
@bp.route("/login", methods=["GET", "POST"])
def login():
    if User.query.count() == 0:
        return redirect(url_for("auth.setup"))
    if current_user.is_authenticated:
        return _after_login_redirect()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        locked, until = sec.lockout_status(username)
        if locked:
            mins = max(int((until - utcnow()).total_seconds() // 60) + 1, 1)
            error = f"Too many failed attempts. Try again in about {mins} minute(s)."
        else:
            user = User.query.filter(User.username.ilike(username)).first() if username else None
            if user and sec.verify_password(user.password_hash, password):
                _set_pre2fa(user)
                if not user.totp_enabled:
                    return redirect(url_for("auth.enroll_2fa"))
                return redirect(url_for("auth.login_2fa"))
            if not user:
                sec.burn_password_check(password)
            sec.record_attempt(username, False)
            sec.audit("login_failed", username, "bad username or password")
            locked, until = sec.lockout_status(username)
            error = "Invalid username or password."
            if locked:
                error = (f"Too many failed attempts. The account is locked for "
                         f"{current_app.config['LOCKOUT_MINUTES']} minutes.")
    return render_template("login.html", error=error)


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    user = _pre2fa_user()
    if not user:
        return redirect(url_for("auth.login"))
    if not user.totp_enabled:
        return redirect(url_for("auth.enroll_2fa"))
    error = None
    if request.method == "POST":
        locked, until = sec.lockout_status(user.username)
        if locked:
            error = "Too many failed attempts. Please wait and log in again."
        elif sec.verify_totp(user, request.form.get("code", "")):
            _finish_login(user)
            return _after_login_redirect()
        else:
            sec.record_attempt(user.username, False)
            sec.audit("2fa_failed", user.username)
            error = "That code is not valid."
            locked, _ = sec.lockout_status(user.username)
            if locked:
                session.pop("pre2fa", None)
                return redirect(url_for("auth.login"))
    return render_template("login_2fa.html", error=error)


@bp.route("/2fa/enroll", methods=["GET", "POST"])
def enroll_2fa():
    """Show the QR code for the authenticator app and confirm one code."""
    user = _pre2fa_user()
    if not user:
        return redirect(url_for("auth.login"))
    if user.totp_enabled:
        return redirect(url_for("auth.login_2fa"))
    secret = sec.decrypt_secret(user.totp_secret_enc)
    if not secret:
        user.totp_secret_enc = sec.encrypt_secret(sec.new_totp_secret())
        db.session.commit()
        secret = sec.decrypt_secret(user.totp_secret_enc)
    error = None
    if request.method == "POST":
        if sec.verify_totp(user, request.form.get("code", "")):
            user.totp_enabled = True
            db.session.commit()
            sec.audit("2fa_enabled", user.username)
            _finish_login(user)
            codes = sec.new_recovery_codes(user)
            sec.audit("recovery_codes_created", user.username)
            return render_template("recovery_codes.html", codes=codes, first_time=True)
        error = "That code is not valid. Check the time on your phone and try again."
    qr = segno.make(sec.totp_uri(secret, user.username), error="m")
    return render_template(
        "enroll_2fa.html",
        qr_uri=qr.svg_data_uri(scale=5, border=2),
        secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
        error=error,
    )


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    sec.audit("logout", current_user.username)
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------- account
@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    errors = []
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        if not sec.verify_password(current_user.password_hash, current):
            errors.append("Current password is incorrect.")
        if new != confirm:
            errors.append("New passwords do not match.")
        errors += sec.password_problems(new, current_user.username)
        if new and current and new == current:
            errors.append("New password must differ from the current one.")
        if not errors:
            current_user.password_hash = sec.hash_password(new)
            db.session.commit()
            sec.audit("password_changed", current_user.username)
            flash("Password changed.", "success")
            return redirect(url_for("auth.account"))
    events = AuditLog.query.order_by(AuditLog.id.desc()).limit(30).all()
    return render_template("account.html", errors=errors, events=events,
                           min_len=current_app.config["MIN_PASSWORD_LENGTH"],
                           codes_left=sec.recovery_codes_left(current_user))


@bp.route("/account/recovery-codes", methods=["POST"])
@login_required
def new_recovery_codes():
    """Replace the recovery codes with a new set (asks for the password first)."""
    locked, _ = sec.lockout_status(current_user.username)
    if locked:
        flash("Too many failed attempts. Try again later.", "danger")
        return redirect(url_for("auth.account"))
    if not sec.verify_password(current_user.password_hash, request.form.get("password", "")):
        sec.record_attempt(current_user.username, False)
        sec.audit("recovery_codes_denied", current_user.username, "bad password")
        flash("Password is incorrect. Recovery codes were not changed.", "danger")
        return redirect(url_for("auth.account"))
    codes = sec.new_recovery_codes(current_user)
    sec.audit("recovery_codes_created", current_user.username)
    return render_template("recovery_codes.html", codes=codes, first_time=False)


# ------------------------------------------------------- forgot / reset password
GENERIC_EMAIL_MSG = ("If that account exists and has an email address, a reset link has been sent. "
                     "The link works once and expires in {m} minutes.")


def _reset_key(username):
    return "reset:" + (username or "").strip().lower()[:60]


@bp.route("/forgot", methods=["GET", "POST"])
def forgot():
    if User.query.count() == 0:
        return redirect(url_for("auth.setup"))
    if current_user.is_authenticated:
        return redirect(url_for("auth.account"))
    cfg = current_app.config
    errors, info = [], None
    method = request.form.get("method")
    form = {"username": request.form.get("username", "").strip()}
    if request.method == "POST" and method == "recovery":
        username = form["username"]
        code = request.form.get("code", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        key = _reset_key(username)
        locked, _ = sec.lockout_status(key)
        user = User.query.filter(User.username.ilike(username)).first() if username else None
        if locked:
            errors.append("Too many failed attempts. Try again later.")
        else:
            ok_code = bool(user) and sec.use_recovery_code(user, code)
            if not ok_code:
                sec.record_attempt(key, False)
                sec.audit("password_reset_failed", username, "bad recovery code")
                errors.append("The username or recovery code is not correct.")
            else:
                if new != confirm:
                    errors.append("New passwords do not match.")
                errors += sec.password_problems(new, user.username)
                if errors:
                    # the code was valid but the new password was not: give the code back
                    row = (RecoveryCode.query.filter_by(user_id=user.id)
                           .filter(RecoveryCode.used_at.isnot(None))
                           .order_by(RecoveryCode.used_at.desc()).first())
                    if row:
                        row.used_at = None
                        db.session.commit()
                else:
                    user.password_hash = sec.hash_password(new)
                    db.session.commit()
                    sec.record_attempt(user.username, True)      # clears a login lockout
                    sec.audit("password_reset_recovery", user.username)
                    flash("Password changed. Log in with the new password. "
                          "That recovery code can not be used again.", "success")
                    return redirect(url_for("auth.login"))
    elif request.method == "POST" and method == "email":
        ident = form["username"]
        if not mailer.email_configured():
            errors.append("Email reset is not set up on this server (needs SMTP settings in .env).")
        else:
            key = _reset_key(ident)
            locked, _ = sec.lockout_status(key)
            sec.record_attempt(key, False)            # throttles repeated requests
            if not locked and ident:
                user = (User.query.filter(User.username.ilike(ident)).first()
                        or User.query.filter(User.email.ilike(ident)).first())
                if user and sec.recent_reset_requests(user) < 3:
                    token = sec.new_reset_token(user)
                    link = f"{cfg['PUBLIC_URL']}{url_for('auth.reset', token=token)}"
                    body = (f"Hello {user.username},\n\nSomeone asked to reset your Lab IDS password. "
                            f"Open this link within {cfg['RESET_LINK_MINUTES']} minutes:\n\n{link}\n\n"
                            f"If it was not you, ignore this email. Your password stays the same.\n")
                    sent = mailer.send_mail(user.email, "Lab IDS password reset", body)
                    sec.audit("password_reset_email", user.username, "sent" if sent else "send failed")
            info = GENERIC_EMAIL_MSG.format(m=cfg["RESET_LINK_MINUTES"])
    return render_template("forgot.html", errors=errors, info=info, form=form,
                           email_ok=mailer.email_configured(), method=method,
                           min_len=cfg["MIN_PASSWORD_LENGTH"], rcount=cfg["RECOVERY_CODE_COUNT"])


@bp.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    row = sec.find_reset(token)
    if not row:
        return render_template("error.html", code=400,
                               message="This reset link is not valid or has expired."), 400
    user = db.session.get(User, row.user_id)
    errors = []
    if request.method == "POST":
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        if new != confirm:
            errors.append("New passwords do not match.")
        errors += sec.password_problems(new, user.username)
        if not errors:
            user.password_hash = sec.hash_password(new)
            row.used_at = utcnow()
            PasswordReset.query.filter_by(user_id=user.id, used_at=None).update({"used_at": utcnow()})
            db.session.commit()
            sec.record_attempt(user.username, True)
            sec.audit("password_reset_email_done", user.username)
            flash("Password changed. Log in with the new password.", "success")
            return redirect(url_for("auth.login"))
    return render_template("reset.html", errors=errors, username=user.username,
                           min_len=current_app.config["MIN_PASSWORD_LENGTH"])


# ------------------------------------------------------------ user accounts
@bp.route("/users", methods=["GET", "POST"])
@login_required
def users():
    errors = []
    form = {"username": "", "email": ""}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        form = {"username": username, "email": email}
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-40 characters: letters, numbers, . _ -")
        elif User.query.filter(User.username.ilike(username)).first():
            errors.append("That username is already taken.")
        if not EMAIL_RE.match(email):
            errors.append("Enter a valid email address.")
        if password != confirm:
            errors.append("Passwords do not match.")
        errors += sec.password_problems(password, username)
        if not errors:
            user = User(username=username, email=email,
                        password_hash=sec.hash_password(password),
                        totp_secret_enc=sec.encrypt_secret(sec.new_totp_secret()),
                        totp_enabled=False, is_admin=True)
            db.session.add(user)
            db.session.commit()
            sec.audit("user_created", current_user.username, f"new account: {username}")
            flash(f"Account '{username}' created. Give them the username and password. "
                  "At the first login they set up their authenticator app and get their recovery codes.",
                  "success")
            return redirect(url_for("auth.users"))
    rows = User.query.order_by(User.id).all()
    return render_template("users.html", users=rows, errors=errors, form=form,
                           min_len=current_app.config["MIN_PASSWORD_LENGTH"])


@bp.route("/users/<int:user_id>/delete", methods=["GET", "POST"])
@login_required
def delete_user(user_id):
    target = db.session.get(User, user_id)
    if not target:
        flash("That account does not exist.", "warning")
        return redirect(url_for("auth.users"))
    if target.id == current_user.id:
        flash("You cannot delete the account you are logged in with. "
              "Log in with another account to delete this one.", "warning")
        return redirect(url_for("auth.users"))
    error = None
    if request.method == "POST":
        locked, _ = sec.lockout_status(current_user.username)
        if locked:
            error = "Too many failed attempts. Try again later."
        elif not sec.verify_password(current_user.password_hash, request.form.get("password", "")):
            sec.record_attempt(current_user.username, False)
            sec.audit("user_delete_denied", current_user.username, f"bad password for {target.username}")
            error = "Your password is not correct."
        elif not sec.verify_totp(current_user, request.form.get("code", "")):
            sec.record_attempt(current_user.username, False)
            sec.audit("user_delete_denied", current_user.username, f"bad 2FA code for {target.username}")
            error = "That authenticator code is not valid."
        else:
            name = target.username
            RecoveryCode.query.filter_by(user_id=target.id).delete()
            PasswordReset.query.filter_by(user_id=target.id).delete()
            db.session.delete(target)
            db.session.commit()
            sec.audit("user_deleted", current_user.username, f"deleted account: {name}")
            flash(f"Account '{name}' was deleted.", "success")
            return redirect(url_for("auth.users"))
    return render_template("delete_user.html", target=target, error=error)
