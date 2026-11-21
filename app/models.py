"""Database models. All timestamps are stored as naive UTC."""
from datetime import datetime, timezone

from flask_login import UserMixin

from .extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


SEVERITY_LABELS = {1: "low", 2: "medium", 3: "high"}

CATEGORIES = [
    "Brute Force",
    "Port Scan",
    "DDoS",
    "ARP Spoofing",
    "Rogue DHCP",
    "DNS Anomaly",
    "Malware/C2",
    "Exploit/Web Attack",
    "Policy/Info",
    "Other",
]


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(200), nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    totp_secret_enc = db.Column(db.Text, nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    last_totp_step = db.Column(db.BigInteger, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=True, nullable=False)


class RecoveryCode(db.Model):
    """One-time codes that let a user reset a forgotten password. Only a keyed hash is stored."""
    __tablename__ = "recovery_codes"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True, nullable=False)
    code_hash = db.Column(db.String(64), index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)


class PasswordReset(db.Model):
    """Single-use, expiring password-reset link (emailed). Only a keyed hash is stored."""
    __tablename__ = "password_resets"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True, nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), index=True, nullable=False)
    ip = db.Column(db.String(64))
    ts = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    success = db.Column(db.Boolean, default=False, nullable=False)


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    event = db.Column(db.String(60), nullable=False)
    username = db.Column(db.String(80))
    ip = db.Column(db.String(64))
    detail = db.Column(db.String(255))


class NetworkConfig(db.Model):
    """Single-row table with the answers from the setup wizard."""
    __tablename__ = "network_config"
    id = db.Column(db.Integer, primary_key=True)
    network_name = db.Column(db.String(120), nullable=False)
    subnet_cidr = db.Column(db.String(64), nullable=False)
    gateway_ip = db.Column(db.String(64), nullable=False)
    iface_name = db.Column(db.String(200), nullable=False)    # friendly name, e.g. "Ethernet 2"
    iface_device = db.Column(db.String(300))                  # \Device\NPF_{GUID} for Suricata
    sensitivity = db.Column(db.String(10), default="medium", nullable=False)
    dhcp_servers = db.Column(db.String(300), default="")       # authorized DHCP server IPs
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    source = db.Column(db.String(20), nullable=False)          # suricata | sensor
    category = db.Column(db.String(40), index=True, nullable=False)
    severity = db.Column(db.Integer, default=2, nullable=False)  # 1 low, 2 medium, 3 high
    signature = db.Column(db.String(400), nullable=False)
    sid = db.Column(db.Integer)
    src_ip = db.Column(db.String(64), index=True)
    src_port = db.Column(db.Integer)
    dest_ip = db.Column(db.String(64), index=True)
    dest_port = db.Column(db.Integer)
    proto = db.Column(db.String(16))
    raw = db.Column(db.Text)
    acknowledged = db.Column(db.Boolean, default=False, nullable=False, index=True)

    @property
    def severity_label(self):
        return SEVERITY_LABELS.get(self.severity, "low")


class Device(db.Model):
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(17), unique=True, nullable=False)
    ip = db.Column(db.String(64), index=True)
    hostname = db.Column(db.String(120))
    first_seen = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    is_gateway = db.Column(db.Boolean, default=False, nullable=False)


class TrafficSample(db.Model):
    __tablename__ = "traffic_samples"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    rx_bps = db.Column(db.Float, default=0)
    tx_bps = db.Column(db.Float, default=0)
    rx_pps = db.Column(db.Float, default=0)
    tx_pps = db.Column(db.Float, default=0)


class Heartbeat(db.Model):
    __tablename__ = "heartbeats"
    component = db.Column(db.String(40), primary_key=True)
    ts = db.Column(db.DateTime, default=utcnow, nullable=False)
    detail = db.Column(db.String(255))


class AppSetting(db.Model):
    __tablename__ = "app_settings"
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.Text)
