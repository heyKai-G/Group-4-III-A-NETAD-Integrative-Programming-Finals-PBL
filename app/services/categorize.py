"""Turn Suricata eve.json alert events into rows for the alerts table."""
import json
import re
from datetime import datetime, timezone

from .rules import REVERSED_SIDS

LAB_RE = re.compile(r"^LAB-IDS \[(?P<cat>[^\]]+)\]\s*(?P<text>.*)$")

# Emerging Threats rule-name prefixes -> our categories
ET_PREFIXES = [
    ("ET SCAN", "Port Scan"),
    ("GPL SCAN", "Port Scan"),
    ("ET DOS", "DDoS"),
    ("ET DROP", "Malware/C2"),
    ("ET CNC", "Malware/C2"),
    ("ET MALWARE", "Malware/C2"),
    ("ET TROJAN", "Malware/C2"),
    ("ET BOTCC", "Malware/C2"),
    ("ET COINMINER", "Malware/C2"),
    ("ET ADWARE", "Malware/C2"),
    ("ET MOBILE_MALWARE", "Malware/C2"),
    ("ET EXPLOIT", "Exploit/Web Attack"),
    ("ET WEB_", "Exploit/Web Attack"),
    ("ET SHELLCODE", "Exploit/Web Attack"),
    ("ET ACTIVEX", "Exploit/Web Attack"),
    ("ET DNS", "DNS Anomaly"),
    ("ET POLICY", "Policy/Info"),
    ("ET INFO", "Policy/Info"),
    ("ET USER_AGENTS", "Policy/Info"),
    ("ET P2P", "Policy/Info"),
    ("ET GAMES", "Policy/Info"),
    ("ET CHAT", "Policy/Info"),
]

# Suricata "alert.category" text -> our categories (fallback)
CLASS_MAP = {
    "attempted denial of service": "DDoS",
    "denial of service": "DDoS",
    "attempted information leak": "Port Scan",
    "network scan": "Port Scan",
    "a network trojan was detected": "Malware/C2",
    "malware command and control activity detected": "Malware/C2",
    "attempted administrator privilege gain": "Exploit/Web Attack",
    "attempted user privilege gain": "Exploit/Web Attack",
    "web application attack": "Exploit/Web Attack",
    "potentially bad traffic": "Policy/Info",
    "not suspicious traffic": "Policy/Info",
    "misc activity": "Policy/Info",
    "potential corporate privacy violation": "Policy/Info",
}

SURICATA_SEV = {1: 3, 2: 2, 3: 1}  # Suricata 1=high -> our 3=high


def _parse_ts(value):
    """eve timestamps look like 2026-11-19T14:49:00.123456+0800"""
    if not value:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo:
            dt = dt.astimezone(timezone.utc)
        return dt.replace(tzinfo=None)
    except ValueError:
        return datetime.now(timezone.utc).replace(tzinfo=None)


def categorize(signature, suricata_category):
    m = LAB_RE.match(signature or "")
    if m:
        return m.group("cat"), m.group("text") or signature
    sig = signature or ""
    for prefix, cat in ET_PREFIXES:
        if sig.startswith(prefix):
            return cat, sig
    cat = CLASS_MAP.get((suricata_category or "").strip().lower())
    return (cat or "Other"), sig


def parse_eve_line(line):
    """Return a dict for an eve.json *alert* line, else None."""
    line = line.strip()
    if not line or '"alert"' not in line:
        return None
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    if ev.get("event_type") != "alert":
        return None
    a = ev.get("alert") or {}
    signature = a.get("signature") or "Unknown signature"
    category, clean_sig = categorize(signature, a.get("category"))
    sid = a.get("signature_id")
    src_ip, src_port = ev.get("src_ip"), ev.get("src_port")
    dst_ip, dst_port = ev.get("dest_ip"), ev.get("dest_port")
    if sid in REVERSED_SIDS:
        src_ip, dst_ip = dst_ip, src_ip
        src_port, dst_port = dst_port, src_port
    try:
        sev = SURICATA_SEV.get(int(a.get("severity", 3)), 1)
    except (TypeError, ValueError):
        sev = 1
    if category in ("DDoS", "Malware/C2") and sev < 2:
        sev = 2
    return {
        "ts": _parse_ts(ev.get("timestamp")),
        "source": "suricata",
        "category": category,
        "severity": sev,
        "signature": clean_sig[:400],
        "sid": sid if isinstance(sid, int) else None,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": ev.get("proto"),
        "raw": line[:8000],
    }
