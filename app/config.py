"""Configuration, loaded from environment variables / the .env file."""
import os
from datetime import timedelta

from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _bool(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Where Suricata writes its alerts.
    EVE_JSON_PATH = os.environ.get(
        "EVE_JSON_PATH", r"C:\Program Files\Suricata\log\eve.json"
    )
    # Where the generated local rules file is written.
    LOCAL_RULES_PATH = os.environ.get(
        "LOCAL_RULES_PATH", os.path.join(BASE_DIR, "suricata", "local.rules")
    )
    SURICATA_EXE = os.environ.get(
        "SURICATA_EXE", r"C:\Program Files\Suricata\suricata.exe"
    )
    SURICATA_YAML = os.environ.get(
        "SURICATA_YAML", r"C:\Program Files\Suricata\suricata.yaml"
    )

    # Web server
    BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
    HTTPS_PORT = _int("HTTPS_PORT", 5443)
    CERT_FILE = os.environ.get("CERT_FILE", os.path.join(BASE_DIR, "certs", "server.crt"))
    KEY_FILE = os.environ.get("KEY_FILE", os.path.join(BASE_DIR, "certs", "server.key"))

    # Security
    SESSION_MINUTES = _int("SESSION_MINUTES", 15)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_MINUTES)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("COOKIE_SECURE", True)
    SESSION_COOKIE_NAME = "labids_session"
    WTF_CSRF_TIME_LIMIT = 3600
    LOCKOUT_MAX_FAILS = _int("LOCKOUT_MAX_FAILS", 5)
    LOCKOUT_MINUTES = _int("LOCKOUT_MINUTES", 15)
    PRE2FA_SECONDS = 300
    MIN_PASSWORD_LENGTH = 12
    RECOVERY_CODE_COUNT = 8
    RESET_LINK_MINUTES = _int("RESET_LINK_MINUTES", 30)

    # Optional: "email me a reset link". Needs an SMTP server that this laptop can reach
    # (so, normally, internet) and PUBLIC_URL = the address people type to open the dashboard,
    # e.g. https://192.168.1.10:5443  (the link in the email is built from it, never from the
    # request, so a forged Host header cannot redirect it).
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = _int("SMTP_PORT", 587)
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "")
    SMTP_SECURITY = os.environ.get("SMTP_SECURITY", "starttls").strip().lower()  # starttls | ssl | none
    PUBLIC_URL = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")

    # Data retention
    RETENTION_DAYS = _int("RETENTION_DAYS", 90)
    TRAFFIC_RETENTION_DAYS = _int("TRAFFIC_RETENTION_DAYS", 7)

    # Display
    APP_TZ = os.environ.get("APP_TZ", "Asia/Manila")
    PAGE_SIZE = 50
    EXPORT_MAX_ROWS = 5000
    PDF_MAX_ROWS = 1000
