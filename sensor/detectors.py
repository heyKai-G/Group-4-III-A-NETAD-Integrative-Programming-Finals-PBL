"""Detection logic that Suricata rules cannot express well.

Pure Python, no packet library needed, so it can be unit-tested with plain values.
The sensor feeds it ARP / DHCP / DNS / TCP-SYN events; it calls emit(alert_dict).

Covers: ARP spoofing, rogue DHCP server, port scans (distinct ports), DNS
anomalies (long/high-entropy names, many unique sub-domains, TXT/NULL bursts).
"""
import ipaddress
import json
import math
import time
from collections import defaultdict, deque

THRESHOLDS = {
    "low":    {"scan_ports": 40, "arp_rate": 60, "dns_len": 60, "dns_unique": 60,
               "dns_entropy": 4.1, "dns_entropy_len": 24, "dns_txt": 20, "arp_all_changes": False},
    "medium": {"scan_ports": 20, "arp_rate": 30, "dns_len": 52, "dns_unique": 40,
               "dns_entropy": 3.8, "dns_entropy_len": 20, "dns_txt": 12, "arp_all_changes": True},
    "high":   {"scan_ports": 10, "arp_rate": 15, "dns_len": 45, "dns_unique": 25,
               "dns_entropy": 3.5, "dns_entropy_len": 16, "dns_txt": 8, "arp_all_changes": True},
}

SCAN_WINDOW = 10      # seconds
ARP_WINDOW = 5
DNS_WINDOW = 60
COOLDOWN = 60         # seconds between identical alerts

IGNORED_DNS_SUFFIXES = (".arpa", ".local", ".lan", ".home", ".localdomain")


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_unicast_mac(mac):
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return not (first & 1) and mac.lower() != "00:00:00:00:00:00"


class Detectors:
    def __init__(self, emit, gateway_ip="", subnet="", dhcp_servers=(), sensitivity="medium",
                 clock=time.time):
        self.emit = emit
        self.clock = clock
        self.gateway_ip = gateway_ip
        self.net = ipaddress.ip_network(subnet, strict=False) if subnet else None
        self.dhcp_servers = {s for s in dhcp_servers if s} or ({gateway_ip} if gateway_ip else set())
        self.t = THRESHOLDS.get(sensitivity, THRESHOLDS["medium"])
        self.arp_table = {}                       # ip -> mac
        self.arp_times = defaultdict(deque)       # mac -> times of ARP packets
        self.scan = defaultdict(deque)            # src_ip -> (t, dst, port)
        self.dns_names = defaultdict(lambda: defaultdict(deque))  # src -> base -> (t, name)
        self.dns_txt = defaultdict(deque)         # src -> times
        self._last_alert = {}
        self.gateway_mac = None

    # ------------------------------------------------------------ helpers
    def in_subnet(self, ip):
        if not self.net:
            return True
        try:
            return ipaddress.ip_address(ip) in self.net
        except ValueError:
            return False

    def _fire(self, key, **alert):
        now = self.clock()
        if now - self._last_alert.get(key, 0) < COOLDOWN:
            return False
        self._last_alert[key] = now
        alert.setdefault("source", "sensor")
        alert.setdefault("severity", 2)
        raw = alert.pop("details", None)
        alert["raw"] = json.dumps(raw) if raw is not None else None
        alert["ts_epoch"] = now
        self.emit(alert)
        return True

    def _prune(self, dq, window, now, key=lambda x: x):
        while dq and now - key(dq[0]) > window:
            dq.popleft()

    # ---------------------------------------------------------------- ARP
    def on_arp(self, op, src_mac, src_ip, dst_ip=None):
        """op: 1 = who-has (request), 2 = is-at (reply)."""
        now = self.clock()
        if not src_ip or src_ip == "0.0.0.0" or not is_unicast_mac(src_mac):
            return
        src_mac = src_mac.lower()

        # 1) Address binding changed (classic ARP spoofing / poisoning)
        known = self.arp_table.get(src_ip)
        if known and known != src_mac:
            is_gw = src_ip == self.gateway_ip
            if is_gw or self.t["arp_all_changes"]:
                self._fire(
                    ("arp-bind", src_ip, src_mac),
                    category="ARP Spoofing", severity=3 if is_gw else 2,
                    signature=(f"ARP spoofing: {src_ip} changed from {known} to {src_mac}"
                               + (" (this is the GATEWAY)" if is_gw else "")),
                    src_ip=src_ip, dest_ip=dst_ip, proto="ARP",
                    details={"ip": src_ip, "old_mac": known, "new_mac": src_mac, "op": op},
                )
            self.arp_table[src_ip] = src_mac
        elif not known:
            self.arp_table[src_ip] = src_mac
        if src_ip == self.gateway_ip and self.gateway_mac is None:
            self.gateway_mac = src_mac

        # 2) ARP storm from one MAC
        dq = self.arp_times[src_mac]
        dq.append(now)
        self._prune(dq, ARP_WINDOW, now)
        if len(dq) >= self.t["arp_rate"]:
            self._fire(
                ("arp-storm", src_mac),
                category="ARP Spoofing", severity=2,
                signature=f"ARP storm: {len(dq)} ARP packets in {ARP_WINDOW}s from {src_mac}",
                src_ip=src_ip, dest_ip=dst_ip, proto="ARP",
                details={"mac": src_mac, "packets": len(dq), "window_s": ARP_WINDOW},
            )

    # --------------------------------------------------------------- DHCP
    def on_dhcp_server_message(self, server_ip, server_mac, msg_type):
        """Called for DHCP OFFER (2) / ACK (5) packets."""
        if not server_ip or server_ip == "0.0.0.0":
            return
        if server_ip in self.dhcp_servers:
            return
        name = {2: "OFFER", 5: "ACK"}.get(msg_type, str(msg_type))
        self._fire(
            ("rogue-dhcp", server_ip),
            category="Rogue DHCP", severity=3,
            signature=f"Rogue DHCP server: unauthorized {name} from {server_ip} ({server_mac})",
            src_ip=server_ip, src_port=67, dest_port=68, proto="UDP",
            details={"server_ip": server_ip, "server_mac": server_mac, "message": name,
                     "authorized": sorted(self.dhcp_servers)},
        )

    # ---------------------------------------------------------- port scan
    def on_syn(self, src_ip, dst_ip, dst_port):
        """Called for TCP packets with SYN set and ACK clear."""
        now = self.clock()
        dq = self.scan[src_ip]
        dq.append((now, dst_ip, dst_port))
        self._prune(dq, SCAN_WINDOW, now, key=lambda x: x[0])
        distinct = {(d, p) for _, d, p in dq}
        if len(distinct) >= self.t["scan_ports"]:
            ports = {p for _, _, p in dq}
            hosts = {d for _, d, _ in dq}
            target = max(hosts, key=lambda h: sum(1 for _, d, _ in dq if d == h))
            self._fire(
                ("scan", src_ip),
                category="Port Scan", severity=2,
                signature=(f"Port scan: {src_ip} probed {len(ports)} port(s) on "
                           f"{len(hosts)} host(s) in {SCAN_WINDOW}s"),
                src_ip=src_ip, dest_ip=target, proto="TCP",
                details={"ports": sorted(ports)[:50], "hosts": sorted(hosts)[:20]},
            )
        # keep memory bounded
        if len(self.scan) > 5000:
            for k in [k for k, v in self.scan.items() if not v][:1000]:
                self.scan.pop(k, None)

    # ---------------------------------------------------------------- DNS
    def on_dns_query(self, src_ip, qname, qtype):
        now = self.clock()
        name = (qname or "").rstrip(".").lower()
        if not name or name.endswith(IGNORED_DNS_SUFFIXES):
            return
        labels = name.split(".")
        base = ".".join(labels[-2:]) if len(labels) >= 2 else name
        sub = ".".join(labels[:-2])

        # long query names
        if len(name) >= self.t["dns_len"]:
            self._fire(
                ("dns-long", src_ip, base),
                category="DNS Anomaly", severity=2,
                signature=f"Unusually long DNS query ({len(name)} chars) for {base}",
                src_ip=src_ip, dest_port=53, proto="UDP",
                details={"query": name[:200], "length": len(name)},
            )
        # random-looking label (typical of tunnelling / DGA)
        for lab in labels[:-1]:
            if len(lab) >= self.t["dns_entropy_len"] and shannon_entropy(lab) >= self.t["dns_entropy"]:
                self._fire(
                    ("dns-entropy", src_ip, base),
                    category="DNS Anomaly", severity=2,
                    signature=f"Random-looking DNS name (possible tunnelling/DGA) under {base}",
                    src_ip=src_ip, dest_port=53, proto="UDP",
                    details={"query": name[:200], "label": lab,
                             "entropy": round(shannon_entropy(lab), 2)},
                )
                break
        # many unique sub-domains of one domain
        if sub:
            dq = self.dns_names[src_ip][base]
            dq.append((now, sub))
            self._prune(dq, DNS_WINDOW, now, key=lambda x: x[0])
            unique = len({s for _, s in dq})
            if unique >= self.t["dns_unique"]:
                self._fire(
                    ("dns-unique", src_ip, base),
                    category="DNS Anomaly", severity=3,
                    signature=f"DNS tunnelling suspected: {unique} unique sub-domains of {base} in {DNS_WINDOW}s",
                    src_ip=src_ip, dest_port=53, proto="UDP",
                    details={"domain": base, "unique_subdomains": unique},
                )
        # TXT (16) / NULL (10) query bursts
        if qtype in (16, 10):
            dq = self.dns_txt[src_ip]
            dq.append(now)
            self._prune(dq, DNS_WINDOW, now)
            if len(dq) >= self.t["dns_txt"]:
                self._fire(
                    ("dns-txt", src_ip),
                    category="DNS Anomaly", severity=2,
                    signature=f"Burst of {len(dq)} TXT/NULL DNS queries in {DNS_WINDOW}s",
                    src_ip=src_ip, dest_port=53, proto="UDP",
                    details={"queries": len(dq), "last": name[:200]},
                )
