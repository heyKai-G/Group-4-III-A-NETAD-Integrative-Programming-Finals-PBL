"""Pages: dashboard, alerts, devices, network map, wizard/settings, exports."""
import csv
import io
import ipaddress
from datetime import datetime, timedelta

from flask import (Blueprint, Response, abort, current_app, flash, redirect,
                   render_template, request, url_for)
from flask_login import login_required

from .extensions import db
from .models import CATEGORIES, Alert, Device, NetworkConfig, SEVERITY_LABELS, utcnow
from .security import audit
from .services import netinfo
from .services.pdfgen import make_pdf
from .services.rules import write_local_rules

bp = Blueprint("main", __name__)


@bp.route("/")
@login_required
def index():
    return redirect(url_for("main.dashboard"))


@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", cfg=NetworkConfig.query.first())


# ----------------------------------------------------------------- alerts
def filtered_alerts(args):
    q = Alert.query
    ip = (args.get("ip") or "").strip()
    if ip:
        like = f"%{ip}%"
        q = q.filter(db.or_(Alert.src_ip.like(like), Alert.dest_ip.like(like)))
    cat = args.get("category")
    if cat in CATEGORIES:
        q = q.filter(Alert.category == cat)
    sev = args.get("severity")
    if sev in ("1", "2", "3"):
        q = q.filter(Alert.severity >= int(sev))
    src = args.get("source")
    if src in ("suricata", "sensor"):
        q = q.filter(Alert.source == src)
    ack = args.get("ack")
    if ack == "open":
        q = q.filter(Alert.acknowledged.is_(False))
    elif ack == "done":
        q = q.filter(Alert.acknowledged.is_(True))
    text = (args.get("q") or "").strip()
    if text:
        q = q.filter(Alert.signature.ilike(f"%{text}%"))
    for key, op in (("from", "ge"), ("to", "lt")):
        val = args.get(key)
        if val:
            try:
                d = datetime.strptime(val, "%Y-%m-%d")
            except ValueError:
                continue
            # the form dates are in local time; compare in UTC using a fixed offset lookup
            d_utc = _local_midnight_to_utc(d if op == "ge" else d + timedelta(days=1))
            q = q.filter(Alert.ts >= d_utc) if op == "ge" else q.filter(Alert.ts < d_utc)
    return q.order_by(Alert.id.desc())


def _local_midnight_to_utc(naive_local):
    from zoneinfo import ZoneInfo
    try:
        tz = ZoneInfo(current_app.config["APP_TZ"])
    except Exception:
        tz = ZoneInfo("UTC")
    return naive_local.replace(tzinfo=tz).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)


@bp.route("/alerts")
@login_required
def alerts():
    page = request.args.get("page", 1, type=int)
    pagination = filtered_alerts(request.args).paginate(
        page=page, per_page=current_app.config["PAGE_SIZE"], error_out=False,
    )
    args = {k: v for k, v in request.args.items() if k != "page" and v}
    return render_template("alerts.html", pagination=pagination, args=args,
                           severities=SEVERITY_LABELS)


@bp.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        abort(404)
    pretty = alert.raw or ""
    try:
        import json
        pretty = json.dumps(json.loads(alert.raw), indent=2)
    except (TypeError, ValueError):
        pass
    return render_template("alert_detail.html", alert=alert, raw=pretty)


@bp.route("/alerts/<int:alert_id>/ack", methods=["POST"])
@login_required
def ack(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        abort(404)
    alert.acknowledged = True
    db.session.commit()
    return redirect(request.form.get("next") or url_for("main.alerts"))


@bp.route("/alerts/ack-all", methods=["POST"])
@login_required
def ack_all():
    ids = [a.id for a in filtered_alerts(request.form).limit(5000).all()]
    if ids:
        Alert.query.filter(Alert.id.in_(ids)).update({"acknowledged": True},
                                                    synchronize_session=False)
        db.session.commit()
    flash(f"Acknowledged {len(ids)} alert(s).", "success")
    return redirect(url_for("main.alerts"))


def _csv_safe(value):
    """Stop spreadsheet formula injection from attacker-controlled text."""
    s = "" if value is None else str(value)
    if s and s[0] in "=+-@\t\r":
        return "'" + s
    return s


EXPORT_FIELDS = ["time (local)", "severity", "category", "signature", "source ip",
                 "src port", "dest ip", "dest port", "proto", "engine", "acknowledged"]


def _export_rows(alerts, localtime):
    for a in alerts:
        yield [
            localtime(a.ts), a.severity_label, a.category, a.signature,
            a.src_ip or "", a.src_port or "", a.dest_ip or "", a.dest_port or "",
            a.proto or "", a.source, "yes" if a.acknowledged else "no",
        ]


@bp.route("/alerts/export.csv")
@login_required
def export_csv():
    lt = current_app.jinja_env.filters["localtime"]
    rows = filtered_alerts(request.args).limit(current_app.config["EXPORT_MAX_ROWS"]).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(EXPORT_FIELDS)
    for r in _export_rows(rows, lt):
        w.writerow([_csv_safe(c) for c in r])
    audit("export_csv", detail=f"{len(rows)} rows")
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=lab-ids-alerts.csv"},
    )


@bp.route("/alerts/export.pdf")
@login_required
def export_pdf():
    lt = current_app.jinja_env.filters["localtime"]
    rows = filtered_alerts(request.args).limit(current_app.config["PDF_MAX_ROWS"]).all()
    cols = [("Time", 105), ("Sev", 38), ("Category", 78), ("Signature", 270),
            ("Source", 88), ("Dest", 88), ("Proto", 36), ("Engine", 50)]
    data = [
        [lt(a.ts), a.severity_label, a.category, a.signature,
         f"{a.src_ip or ''}:{a.src_port or ''}", f"{a.dest_ip or ''}:{a.dest_port or ''}",
         a.proto or "", a.source]
        for a in rows
    ]
    cfg = NetworkConfig.query.first()
    sub = f"{cfg.network_name if cfg else 'Lab IDS'} - generated {lt(utcnow())} - {len(rows)} alert(s)"
    pdf = make_pdf("Lab IDS alert report", sub, cols, data)
    audit("export_pdf", detail=f"{len(rows)} rows")
    return Response(
        pdf, mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=lab-ids-alerts.pdf"},
    )


# ---------------------------------------------------------- devices & map
@bp.route("/devices")
@login_required
def devices():
    since = utcnow() - timedelta(hours=24)
    counts = dict(
        db.session.query(Alert.src_ip, db.func.count(Alert.id))
        .filter(Alert.ts >= since).group_by(Alert.src_ip).all()
    )
    rows = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template("devices.html", devices=rows, counts=counts,
                           active_cutoff=utcnow() - timedelta(minutes=10))


@bp.route("/map")
@login_required
def network_map():
    return render_template("map.html", cfg=NetworkConfig.query.first())


# ------------------------------------------------------ wizard / settings
def _validate_config(form, interfaces):
    errors = []
    name = form.get("network_name", "").strip()
    cidr = form.get("subnet_cidr", "").strip()
    gw = form.get("gateway_ip", "").strip()
    iface = form.get("iface_name", "")
    sens = form.get("sensitivity", "medium")
    dhcp_raw = form.get("dhcp_servers", "").strip()
    if not (1 <= len(name) <= 120):
        errors.append("Enter a network name.")
    net = None
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version != 4:
            raise ValueError
        if net.num_addresses < 4:
            errors.append("The subnet is too small.")
    except ValueError:
        errors.append("Subnet must be IPv4 CIDR, for example 192.168.1.0/24.")
    try:
        gw_ip = ipaddress.ip_address(gw)
        if net and gw_ip not in net:
            errors.append("The gateway IP must be inside the subnet.")
    except ValueError:
        errors.append("Enter a valid gateway IP address.")
    chosen = next((i for i in interfaces if i["name"] == iface), None)
    if not chosen:
        errors.append("Choose the network adapter to monitor.")
    if sens not in ("low", "medium", "high"):
        errors.append("Choose a sensitivity level.")
    dhcp_list = []
    for part in [p.strip() for p in dhcp_raw.replace(";", ",").split(",") if p.strip()]:
        try:
            dhcp_list.append(str(ipaddress.ip_address(part)))
        except ValueError:
            errors.append(f"'{part}' is not a valid DHCP server IP.")
    return errors, {
        "network_name": name, "subnet_cidr": str(net) if net else cidr,
        "gateway_ip": gw, "iface_name": iface,
        "iface_device": chosen["device"] if chosen else "",
        "sensitivity": sens, "dhcp_servers": ",".join(dhcp_list),
    }, chosen


def _save_config(values):
    cfg = NetworkConfig.query.first()
    if cfg is None:
        cfg = NetworkConfig(**values)
        db.session.add(cfg)
    else:
        for k, v in values.items():
            setattr(cfg, k, v)
    db.session.commit()
    # Regenerate Suricata's local rules to match the chosen sensitivity.
    try:
        write_local_rules(current_app.config["LOCAL_RULES_PATH"], cfg.sensitivity)
    except OSError as exc:
        flash(f"Could not write the Suricata rules file: {exc}", "danger")
    return cfg


@bp.route("/wizard", methods=["GET", "POST"])
@login_required
def wizard():
    return _config_page(first_run=NetworkConfig.query.first() is None)


@bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    return _config_page(first_run=False)


def _config_page(first_run):
    interfaces = netinfo.list_interfaces()
    cfg = NetworkConfig.query.first()
    errors = []
    form = {
        "network_name": cfg.network_name if cfg else "",
        "subnet_cidr": cfg.subnet_cidr if cfg else "",
        "gateway_ip": cfg.gateway_ip if cfg else "",
        "iface_name": cfg.iface_name if cfg else "",
        "sensitivity": cfg.sensitivity if cfg else "medium",
        "dhcp_servers": cfg.dhcp_servers if cfg else "",
    }
    if request.method == "POST":
        errors, values, _chosen = _validate_config(request.form, interfaces)
        form = {k: request.form.get(k, "") for k in form}
        if not errors:
            if not values["dhcp_servers"]:
                values["dhcp_servers"] = values["gateway_ip"]
            cfg = _save_config(values)
            audit("network_config_saved", detail=f"{cfg.subnet_cidr} on {cfg.iface_name}")
            flash("Settings saved. Restart Suricata so it loads the new rules.", "success")
            return redirect(url_for("main.settings" if not first_run else "main.dashboard"))
    c = current_app.config
    suricata_cmd = None
    if cfg:
        suricata_cmd = (f'& "{c["SURICATA_EXE"]}" -c "{c["SURICATA_YAML"]}" '
                        f"-i '{cfg.iface_device or '<run: suricata --list-interfaces>'}'")
    return render_template(
        "config.html", first_run=first_run, interfaces=interfaces, form=form,
        errors=errors, cfg=cfg, suricata_cmd=suricata_cmd,
        rules_path=c["LOCAL_RULES_PATH"], retention=c["RETENTION_DAYS"],
    )
