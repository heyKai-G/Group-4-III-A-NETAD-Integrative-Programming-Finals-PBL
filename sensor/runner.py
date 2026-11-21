"""The sensor service: runs next to Suricata and feeds the database.

Threads:  heartbeat, traffic sampler, packet sniffer (Scapy), eve.json tailer,
device inventory flusher, data retention.
"""
import threading
import time
from datetime import timedelta

import psutil

from app.extensions import db
from app.models import (Alert, AuditLog, Device, Heartbeat, LoginAttempt,
                        NetworkConfig, TrafficSample, utcnow)
from . import eve_tailer
from .detectors import Detectors
from .packets import BPF_FILTER, PacketHandler


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def beat(app, detail):
    with app.app_context():
        hb = db.session.get(Heartbeat, "sensor")
        if hb is None:
            hb = Heartbeat(component="sensor")
            db.session.add(hb)
        hb.ts, hb.detail = utcnow(), detail[:255]
        db.session.commit()
        db.session.remove()


def load_config(app):
    with app.app_context():
        c = NetworkConfig.query.first()
        data = None
        if c:
            data = {
                "iface_name": c.iface_name, "gateway_ip": c.gateway_ip,
                "subnet": c.subnet_cidr, "sensitivity": c.sensitivity,
                "dhcp_servers": [s for s in (c.dhcp_servers or "").split(",") if s],
                "version": c.updated_at.isoformat() if c.updated_at else "",
            }
        db.session.remove()
        return data


class Inventory:
    """Collects device sightings in memory and writes them out every few seconds."""

    def __init__(self, gateway_ip):
        self.gateway_ip = gateway_ip
        self.lock = threading.Lock()
        self.pending = {}

    def seen(self, mac, ip, hostname=None):
        with self.lock:
            cur = self.pending.get(mac, {})
            cur["ip"] = ip or cur.get("ip")
            if hostname:
                cur["hostname"] = hostname
            cur["ts"] = utcnow()
            self.pending[mac] = cur

    def flush(self, app):
        with self.lock:
            items, self.pending = self.pending, {}
        if not items:
            return
        with app.app_context():
            for mac, d in items.items():
                dev = Device.query.filter_by(mac=mac).first()
                if dev is None:
                    dev = Device(mac=mac, first_seen=d["ts"])
                    db.session.add(dev)
                if d.get("ip"):
                    dev.ip = d["ip"]
                if d.get("hostname"):
                    dev.hostname = d["hostname"][:120]
                dev.last_seen = d["ts"]
                dev.is_gateway = bool(dev.ip and dev.ip == self.gateway_ip)
            db.session.commit()
            db.session.remove()


def resolve_scapy_iface(name, device):
    """Find the Scapy interface object for the adapter chosen in the wizard."""
    from scapy.all import conf
    guid = ""
    if device and "{" in device:
        guid = device[device.index("{"):].lower()
    try:
        for iface in conf.ifaces.values():
            names = {str(getattr(iface, "name", "")).lower(),
                     str(getattr(iface, "description", "")).lower()}
            iguid = str(getattr(iface, "guid", "") or getattr(iface, "network_name", "")).lower()
            if name.lower() in names or (guid and guid in iguid):
                return iface
    except Exception:
        pass
    return name  # let Scapy try the plain name


class SensorService:
    def __init__(self, app):
        self.app = app
        self.stop = threading.Event()
        self.cfg = None
        self.sniffer = None
        self.inventory = None
        self.detectors = None
        self.sniffer_note = "waiting for configuration"
        self.threads = []

    # ----------------------------------------------------------- alert sink
    def emit(self, alert):
        alert = dict(alert)
        alert.pop("ts_epoch", None)
        try:
            with self.app.app_context():
                db.session.add(Alert(**alert))
                db.session.commit()
                db.session.remove()
            log(f"ALERT [{alert['category']}] {alert['signature']}")
        except Exception as exc:
            log(f"could not store alert: {exc!r}")

    # ------------------------------------------------------------- sniffing
    def _start_sniffer(self):
        from scapy.all import AsyncSniffer, conf
        self._stop_sniffer()
        cfg = self.cfg
        self.inventory = Inventory(cfg["gateway_ip"])
        self.detectors = Detectors(
            self.emit, gateway_ip=cfg["gateway_ip"], subnet=cfg["subnet"],
            dhcp_servers=cfg["dhcp_servers"], sensitivity=cfg["sensitivity"])
        handler = PacketHandler(self.detectors, self.inventory.seen)
        with self.app.app_context():
            c = NetworkConfig.query.first()
            device = c.iface_device if c else ""
            db.session.remove()
        iface = resolve_scapy_iface(cfg["iface_name"], device)
        conf.verb = 0
        for flt in (BPF_FILTER, None):
            try:
                s = AsyncSniffer(iface=iface, prn=handler.handle, store=False, filter=flt)
                s.start()
                time.sleep(1.5)
                if getattr(s, "running", True) and not getattr(s, "exception", None):
                    self.sniffer = s
                    self.sniffer_note = ("sniffing " + cfg["iface_name"]
                                         + ("" if flt else " (no BPF filter)"))
                    log(self.sniffer_note)
                    return
                try:
                    s.stop()
                except Exception:
                    pass
            except Exception as exc:
                last = repr(exc)
                log(f"sniffer start failed ({'filter' if flt else 'no filter'}): {last}")
        self.sniffer_note = ("cannot capture on '%s' - is Npcap installed and are you "
                             "running as Administrator?" % cfg["iface_name"])
        log(self.sniffer_note)

    def _stop_sniffer(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None

    def _supervisor(self):
        """Watch for wizard/settings changes and (re)start the sniffer."""
        while not self.stop.is_set():
            new = load_config(self.app)
            if new and (self.cfg is None or new["version"] != self.cfg["version"]):
                self.cfg = new
                log(f"configuration loaded: {new['subnet']} on '{new['iface_name']}', "
                    f"sensitivity {new['sensitivity']}")
                self._start_sniffer()
            elif self.sniffer is not None and not getattr(self.sniffer, "running", True):
                log("sniffer stopped unexpectedly, restarting")
                self._start_sniffer()
            self.stop.wait(5)
        self._stop_sniffer()

    # --------------------------------------------------------------- loops
    def _heartbeat(self):
        while not self.stop.is_set():
            try:
                beat(self.app, self.sniffer_note if self.cfg else "waiting for the setup wizard")
                if self.inventory:
                    self.inventory.flush(self.app)
            except Exception as exc:
                log(f"heartbeat error: {exc!r}")
            self.stop.wait(5)

    def _traffic(self):
        prev = None
        while not self.stop.is_set():
            self.stop.wait(5)
            if not self.cfg:
                prev = None
                continue
            try:
                counters = psutil.net_io_counters(pernic=True).get(self.cfg["iface_name"])
                now = time.time()
                if counters is None:
                    continue
                cur = (now, counters.bytes_recv, counters.bytes_sent,
                       counters.packets_recv, counters.packets_sent)
                if prev:
                    dt = max(cur[0] - prev[0], 0.001)
                    sample = TrafficSample(
                        rx_bps=max(cur[1] - prev[1], 0) / dt, tx_bps=max(cur[2] - prev[2], 0) / dt,
                        rx_pps=max(cur[3] - prev[3], 0) / dt, tx_pps=max(cur[4] - prev[4], 0) / dt)
                    with self.app.app_context():
                        db.session.add(sample)
                        db.session.commit()
                        db.session.remove()
                prev = cur
            except Exception as exc:
                log(f"traffic sampler error: {exc!r}")

    def purge_once(self):
        with self.app.app_context():
            cfg = self.app.config
            now = utcnow()
            n = Alert.query.filter(
                Alert.ts < now - timedelta(days=cfg["RETENTION_DAYS"])).delete()
            t = TrafficSample.query.filter(
                TrafficSample.ts < now - timedelta(days=cfg["TRAFFIC_RETENTION_DAYS"])).delete()
            LoginAttempt.query.filter(LoginAttempt.ts < now - timedelta(days=30)).delete()
            AuditLog.query.filter(AuditLog.ts < now - timedelta(days=365)).delete()
            db.session.commit()
            db.session.remove()
            if n or t:
                log(f"retention: removed {n} old alert(s) and {t} traffic sample(s)")

    def _retention(self):
        while not self.stop.is_set():
            try:
                self.purge_once()
            except Exception as exc:
                log(f"retention error: {exc!r}")
            self.stop.wait(3600)

    # ----------------------------------------------------------------- run
    def run(self):
        targets = [self._supervisor, self._heartbeat, self._traffic, self._retention,
                   lambda: eve_tailer.run(self.app, self.stop)]
        for fn in targets:
            th = threading.Thread(target=fn, daemon=True)
            th.start()
            self.threads.append(th)
        log("sensor running. Press Ctrl+C to stop.")
        try:
            while not self.stop.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()
            self._stop_sniffer()
            log("sensor stopped.")
