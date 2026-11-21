import json
import os

from sensor.detectors import Detectors, shannon_entropy


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def make(sens="medium", **kw):
    out, clock = [], Clock()
    d = Detectors(out.append, gateway_ip="192.168.1.1", subnet="192.168.1.0/24",
                  dhcp_servers=["192.168.1.1"], sensitivity=sens, clock=clock, **kw)
    return d, out, clock


def test_arp_gateway_spoof_is_high():
    d, out, _ = make()
    d.on_arp(2, "aa:aa:aa:aa:aa:01", "192.168.1.1")
    assert not out
    d.on_arp(2, "02:bb:bb:bb:bb:02", "192.168.1.1")
    assert len(out) == 1 and out[0]["category"] == "ARP Spoofing" and out[0]["severity"] == 3
    assert "GATEWAY" in out[0]["signature"]


def test_arp_low_sensitivity_only_gateway():
    d, out, _ = make("low")
    d.on_arp(2, "aa:aa:aa:aa:aa:01", "192.168.1.50")
    d.on_arp(2, "02:bb:bb:bb:bb:02", "192.168.1.50")
    assert not out


def test_arp_ignores_probes_and_multicast():
    d, out, _ = make()
    d.on_arp(1, "aa:aa:aa:aa:aa:01", "0.0.0.0")
    d.on_arp(2, "ff:ff:ff:ff:ff:ff", "192.168.1.9")
    assert not out and not d.arp_table


def test_arp_storm_and_cooldown():
    d, out, clock = make()
    for i in range(40):
        d.on_arp(1, "aa:aa:aa:aa:aa:09", "192.168.1.9", "192.168.1.1")
    assert sum(1 for a in out if "storm" in a["signature"]) == 1      # cooldown: one alert
    clock.t += 61
    d.on_arp(1, "aa:aa:aa:aa:aa:09", "192.168.1.9")
    # old packets expired from window, so no second alert yet
    assert sum(1 for a in out if "storm" in a["signature"]) == 1


def test_rogue_dhcp():
    d, out, _ = make()
    d.on_dhcp_server_message("192.168.1.1", "aa:aa:aa:aa:aa:01", 2)
    assert not out
    d.on_dhcp_server_message("192.168.1.77", "02:cc:cc:cc:cc:03", 5)
    assert len(out) == 1 and out[0]["category"] == "Rogue DHCP" and out[0]["severity"] == 3
    assert json.loads(out[0]["raw"])["server_ip"] == "192.168.1.77"


def test_port_scan_counts_distinct_ports_not_connections():
    d, out, clock = make()
    for _ in range(200):                           # same port again and again = not a scan
        d.on_syn("192.168.1.66", "192.168.1.5", 80)
    assert not out
    for p in range(1, 25):
        clock.t += 0.1
        d.on_syn("192.168.1.66", "192.168.1.5", p)
    assert len(out) == 1 and out[0]["category"] == "Port Scan"
    assert out[0]["src_ip"] == "192.168.1.66" and out[0]["dest_ip"] == "192.168.1.5"


def test_port_scan_window_expires():
    d, out, clock = make()
    for p in range(1, 15):
        d.on_syn("192.168.1.66", "192.168.1.5", p)
        clock.t += 2                                # slow scan, under threshold per 10 s
    assert not out


def test_dns_tunnel_detection():
    d, out, clock = make()
    import random, string
    rnd = random.Random(7)
    for _ in range(45):
        label = "".join(rnd.choice(string.ascii_lowercase + string.digits) for _ in range(30))
        d.on_dns_query("192.168.1.66", f"{label}.evil-tunnel.example.", 1)
        clock.t += 0.2
    cats = {a["category"] for a in out}
    sigs = " | ".join(a["signature"] for a in out)
    assert cats == {"DNS Anomaly"}
    assert "tunnelling suspected" in sigs and "Random-looking" in sigs


def test_dns_normal_names_do_not_alert():
    d, out, _ = make()
    for name in ["www.google.com", "mail.example.org", "cdn.shopee.ph", "1.0.168.192.in-addr.arpa",
                 "printer.local", "update.microsoft.com"]:
        d.on_dns_query("192.168.1.20", name, 1)
    assert not out


def test_dns_txt_burst():
    d, out, clock = make()
    for i in range(14):
        d.on_dns_query("192.168.1.66", "x.example.com", 16)
        clock.t += 1
    assert any("TXT/NULL" in a["signature"] for a in out)


def test_entropy():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcdefgh") == 3.0
