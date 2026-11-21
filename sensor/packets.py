"""Turn Scapy packets into calls on Detectors and the device inventory."""
from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP
from scapy.layers.dhcp import BOOTP, DHCP

from .detectors import is_unicast_mac

# bit values
SYN, ACK = 0x02, 0x10

BPF_FILTER = ("arp or (udp and (port 67 or port 68 or port 53)) or (tcp port 53) "
              "or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)")


DHCP_TYPES = {"discover": 1, "offer": 2, "request": 3, "decline": 4,
              "ack": 5, "nak": 6, "release": 7, "inform": 8}


def _dhcp_options(pkt):
    opts = {}
    for o in pkt[DHCP].options:
        if isinstance(o, tuple) and len(o) >= 2:
            opts[o[0]] = o[1]
    mt = opts.get("message-type")
    if isinstance(mt, str):               # packets built by hand use names, sniffed ones use numbers
        opts["message-type"] = DHCP_TYPES.get(mt.lower())
    return opts


class PacketHandler:
    def __init__(self, detectors, device_seen):
        """device_seen(mac, ip, hostname=None) records a device in the inventory."""
        self.det = detectors
        self.device_seen = device_seen

    def handle(self, pkt):
        try:
            self._handle(pkt)
        except Exception:  # never let one odd packet kill the sniffer
            pass

    def _handle(self, pkt):
        eth_src = pkt[Ether].src.lower() if pkt.haslayer(Ether) else None

        if pkt.haslayer(ARP):
            a = pkt[ARP]
            self.det.on_arp(int(a.op), a.hwsrc, a.psrc, a.pdst)
            if is_unicast_mac(a.hwsrc) and a.psrc not in ("0.0.0.0", ""):
                if self.det.in_subnet(a.psrc):
                    self.device_seen(a.hwsrc.lower(), a.psrc)
            return

        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]

        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            opts = _dhcp_options(pkt)
            msg_type = opts.get("message-type")
            if msg_type in (2, 5):                       # OFFER / ACK from a server
                self.det.on_dhcp_server_message(ip.src, eth_src, msg_type)
            elif msg_type in (1, 3):                     # DISCOVER / REQUEST from a client
                chaddr = pkt[BOOTP].chaddr[:6]
                mac = ":".join(f"{b:02x}" for b in chaddr)
                host = opts.get("hostname")
                if isinstance(host, bytes):
                    host = host.decode("utf-8", "replace")
                req_ip = opts.get("requested_addr") or pkt[BOOTP].ciaddr
                if req_ip and req_ip != "0.0.0.0" and is_unicast_mac(mac):
                    self.device_seen(mac, req_ip, host)
            return

        if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            q = pkt[DNSQR]
            qname = q.qname.decode("utf-8", "replace") if isinstance(q.qname, bytes) else str(q.qname)
            self.det.on_dns_query(ip.src, qname, int(q.qtype))

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            flags = int(t.flags)
            if flags & SYN and not flags & ACK:
                self.det.on_syn(ip.src, ip.dst, int(t.dport))

        # passive device discovery: only trust MAC<->IP for addresses inside our subnet
        if eth_src and is_unicast_mac(eth_src) and self.det.in_subnet(ip.src) \
                and ip.src not in ("0.0.0.0", "255.255.255.255"):
            self.device_seen(eth_src, ip.src)
