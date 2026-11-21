"""JSON endpoints used by the dashboard (login required, read-only)."""
import os
from datetime import timedelta

from flask import Blueprint, current_app, jsonify, request
from flask_login import login_required

from .extensions import db
from .models import Alert, Device, Heartbeat, NetworkConfig, TrafficSample, utcnow

bp = Blueprint("api", __name__, url_prefix="/api")


def _iso(dt):
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def _hour_bucket(column):
    if db.engine.dialect.name == "sqlite":
        return db.func.strftime("%Y-%m-%dT%H:00:00", column)
    # literal_column keeps 'hour' and the format inline: bind parameters would make the
    # SELECT and GROUP BY expressions differ and PostgreSQL would reject the query.
    return db.func.to_char(db.func.date_trunc(db.literal_column("'hour'"), column),
                           db.literal_column("'YYYY-MM-DD\"T\"HH24:00:00'"))


def service_status():
    now = utcnow()
    out = {}
    hb = db.session.get(Heartbeat, "sensor")
    out["sensor"] = {
        "ok": bool(hb and now - hb.ts < timedelta(seconds=45)),
        "detail": hb.detail if hb else "Sensor has not started (run_sensor.ps1).",
    }
    path = current_app.config["EVE_JSON_PATH"]
    try:
        age = now.timestamp() - os.stat(path).st_mtime
        # Suricata writes stats lines regularly, so a quiet file means it is stopped
        suri_ok = age < 120
        detail = "eve.json is being written." if suri_ok else \
            f"eve.json has not changed for {int(age)} s (Suricata stopped or idle)."
    except OSError:
        suri_ok, detail = False, "eve.json not found. Is Suricata running?"
    out["suricata"] = {"ok": suri_ok, "detail": detail}
    return out


@bp.route("/summary")
@login_required
def summary():
    now = utcnow()
    since = now - timedelta(hours=24)
    base = Alert.query.filter(Alert.ts >= since)
    by_cat = dict(
        db.session.query(Alert.category, db.func.count(Alert.id))
        .filter(Alert.ts >= since).group_by(Alert.category).all()
    )
    by_sev = dict(
        db.session.query(Alert.severity, db.func.count(Alert.id))
        .filter(Alert.ts >= since).group_by(Alert.severity).all()
    )
    top = (
        db.session.query(Alert.src_ip, db.func.count(Alert.id).label("n"))
        .filter(Alert.ts >= since, Alert.src_ip.isnot(None))
        .group_by(Alert.src_ip).order_by(db.text("n DESC")).limit(5).all()
    )
    bucket = _hour_bucket(Alert.ts)
    rows = (
        db.session.query(bucket, db.func.count(Alert.id))
        .filter(Alert.ts >= since).group_by(bucket).all()
    )
    hourly = {str(k)[:13]: v for k, v in rows}
    timeline = []
    start = since.replace(minute=0, second=0, microsecond=0)
    for i in range(25):
        h = start + timedelta(hours=i)
        timeline.append({"t": _iso(h), "n": hourly.get(h.strftime("%Y-%m-%dT%H"), 0)})
    return jsonify({
        "total_24h": base.count(),
        "open_24h": base.filter(Alert.acknowledged.is_(False)).count(),
        "high_24h": by_sev.get(3, 0),
        "devices_active": Device.query.filter(
            Device.last_seen >= now - timedelta(minutes=10)).count(),
        "devices_total": Device.query.count(),
        "by_category": by_cat,
        "by_severity": {"low": by_sev.get(1, 0), "medium": by_sev.get(2, 0),
                        "high": by_sev.get(3, 0)},
        "top_sources": [{"ip": ip, "n": n} for ip, n in top],
        "timeline": timeline,
        "status": service_status(),
    })


@bp.route("/traffic")
@login_required
def traffic():
    minutes = min(max(request.args.get("minutes", 10, type=int), 1), 240)
    since = utcnow() - timedelta(minutes=minutes)
    rows = (TrafficSample.query.filter(TrafficSample.ts >= since)
            .order_by(TrafficSample.ts).limit(5000).all())
    return jsonify([
        {"t": _iso(r.ts), "rx_kbps": round(r.rx_bps * 8 / 1000, 1),
         "tx_kbps": round(r.tx_bps * 8 / 1000, 1),
         "rx_pps": round(r.rx_pps, 1), "tx_pps": round(r.tx_pps, 1)}
        for r in rows
    ])


@bp.route("/alerts/latest")
@login_required
def latest_alerts():
    after = request.args.get("after", 0, type=int)
    q = Alert.query
    if after:
        q = q.filter(Alert.id > after)
    rows = q.order_by(Alert.id.desc()).limit(10 if not after else 50).all()
    return jsonify([
        {"id": a.id, "t": _iso(a.ts), "severity": a.severity_label,
         "category": a.category, "signature": a.signature,
         "src": f"{a.src_ip or '?'}" + (f":{a.src_port}" if a.src_port else ""),
         "dst": f"{a.dest_ip or '?'}" + (f":{a.dest_port}" if a.dest_port else "")}
        for a in reversed(rows)
    ])


@bp.route("/network")
@login_required
def network():
    cfg = NetworkConfig.query.first()
    now = utcnow()
    since = now - timedelta(hours=1)
    recent = dict(
        db.session.query(Alert.src_ip, db.func.count(Alert.id))
        .filter(Alert.ts >= since).group_by(Alert.src_ip).all()
    )
    victims = dict(
        db.session.query(Alert.dest_ip, db.func.count(Alert.id))
        .filter(Alert.ts >= since).group_by(Alert.dest_ip).all()
    )
    nodes = []
    for d in Device.query.order_by(Device.last_seen.desc()).limit(200).all():
        nodes.append({
            "mac": d.mac, "ip": d.ip or "", "hostname": d.hostname or "",
            "gateway": bool(d.is_gateway or (cfg and d.ip == cfg.gateway_ip)),
            "active": (now - d.last_seen) < timedelta(minutes=10),
            "attacker_alerts": recent.get(d.ip, 0), "target_alerts": victims.get(d.ip, 0),
            "last_seen": _iso(d.last_seen),
        })
    return jsonify({
        "network": cfg.network_name if cfg else "", "gateway": cfg.gateway_ip if cfg else "",
        "subnet": cfg.subnet_cidr if cfg else "", "nodes": nodes,
    })
