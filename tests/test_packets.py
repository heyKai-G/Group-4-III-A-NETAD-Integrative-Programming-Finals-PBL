from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP
from scapy.layers.dhcp import BOOTP, DHCP

from sensor.detectors import Detectors
from sensor.packets import PacketHandler


def setup(sens="medium"):
    alerts, devices = [], {}

    def seen(mac, ip, host=None):
        devices[mac] = (ip, host)

    det = Detectors(alerts.append, gateway_ip="192.168.1.1", subnet="192.168.1.0/24",
                    dhcp_servers=["192.168.1.1"], sensitivity=sens)
    return PacketHandler(det, seen), alerts, devices


def test_arp_and_inventory():
    h, alerts, devices = setup()
    h.handle(Ether(src="aa:aa:aa:aa:aa:01") / ARP(op=2, hwsrc="aa:aa:aa:aa:aa:01", psrc="192.168.1.1", pdst="192.168.1.50"))
    h.handle(Ether(src="02:bb:bb:bb:bb:02") / ARP(op=2, hwsrc="02:bb:bb:bb:bb:02", psrc="192.168.1.1", pdst="192.168.1.50"))
    assert devices["aa:aa:aa:aa:aa:01"][0] == "192.168.1.1"
    assert [a["category"] for a in alerts] == ["ARP Spoofing"]


def test_rogue_dhcp_offer():
    h, alerts, devices = setup()
    pkt = (Ether(src="02:cc:cc:cc:cc:03") / IP(src="192.168.1.77", dst="255.255.255.255") /
           UDP(sport=67, dport=68) / BOOTP(op=2, chaddr=b"\x12\x22\x33\x44\x55\x66") /
           DHCP(options=[("message-type", "offer"), ("server_id", "192.168.1.77"), "end"]))
    h.handle(Ether(bytes(pkt)))          # round-trip like a sniffed packet
    assert alerts and alerts[0]["category"] == "Rogue DHCP"


def test_dhcp_request_learns_hostname():
    h, alerts, devices = setup()
    pkt = (Ether(src="12:22:33:44:55:66") / IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) / BOOTP(chaddr=b"\x12\x22\x33\x44\x55\x66") /
           DHCP(options=[("message-type", "request"), ("requested_addr", "192.168.1.88"),
                         ("hostname", "kali"), "end"]))
    h.handle(Ether(bytes(pkt)))
    assert devices["12:22:33:44:55:66"] == ("192.168.1.88", "kali")
    assert not alerts


def test_syn_scan_packets():
    h, alerts, devices = setup()
    for p in range(1, 30):
        h.handle(Ether(src="de:ad:be:ef:00:01") / IP(src="192.168.1.66", dst="192.168.1.5") / TCP(dport=p, flags="S"))
    assert any(a["category"] == "Port Scan" for a in alerts)
    assert devices["de:ad:be:ef:00:01"][0] == "192.168.1.66"


def test_established_traffic_is_not_a_scan():
    h, alerts, _ = setup()
    for p in range(1, 60):
        h.handle(Ether() / IP(src="192.168.1.66", dst="192.168.1.5") / TCP(dport=p, flags="SA"))
        h.handle(Ether() / IP(src="192.168.1.66", dst="192.168.1.5") / TCP(dport=p, flags="A"))
    assert not alerts


def test_internet_ip_does_not_overwrite_gateway_ip():
    h, alerts, devices = setup()
    gw_mac = "aa:aa:aa:aa:aa:01"
    h.handle(Ether(src=gw_mac) / ARP(op=2, hwsrc=gw_mac, psrc="192.168.1.1", pdst="192.168.1.50"))
    h.handle(Ether(src=gw_mac) / IP(src="8.8.8.8", dst="192.168.1.50") / TCP(dport=1234, flags="A"))
    assert devices[gw_mac][0] == "192.168.1.1"


def test_dns_query_packet():
    h, alerts, _ = setup()
    long = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.tunnel-domain.example."
    h.handle(Ether() / IP(src="192.168.1.66", dst="192.168.1.1") / UDP(sport=5353, dport=53) /
             DNS(rd=1, qd=DNSQR(qname=long)))
    assert any(a["category"] == "DNS Anomaly" for a in alerts)


def test_garbage_does_not_raise():
    h, _, _ = setup()
    h.handle(object())
    h.handle(Ether())
