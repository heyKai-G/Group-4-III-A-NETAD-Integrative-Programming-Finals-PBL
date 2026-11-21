"""Build crafted packet captures that should trigger each Lab IDS rule."""
from scapy.all import Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

M_C, M_S = "02:00:00:00:00:66", "02:00:00:00:00:05"
ATT, VIC = "192.168.1.66", "192.168.1.5"


class Pcap:
    def __init__(self):
        self.pkts = []
        self.t = 1_700_000_000.0

    def add(self, pkt, dt=0.001):
        self.t += dt
        pkt.time = self.t
        self.pkts.append(pkt)

    def tcp(self, src, dst, sp, dp, flags, seq=0, ack=0, payload=b"", dt=0.001):
        smac, dmac = (M_C, M_S) if src == ATT else (M_S, M_C)
        p = Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / TCP(
            sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)
        if payload:
            p = p / Raw(payload)
        self.add(p, dt)

    def session(self, cport, sport, steps, cip=ATT, sip=VIC, dt=0.001):
        """steps: list of ('c'|'s', bytes). Does handshake, data with ACKs, then FIN."""
        cs, ss = 1000, 5000
        self.tcp(cip, sip, cport, sport, "S", cs, 0, dt=dt)
        self.tcp(sip, cip, sport, cport, "SA", ss, cs + 1, dt=dt)
        cs += 1
        ss += 1
        self.tcp(cip, sip, cport, sport, "A", cs, ss, dt=dt)
        for who, data in steps:
            if who == "c":
                self.tcp(cip, sip, cport, sport, "PA", cs, ss, data, dt=dt)
                cs += len(data)
                self.tcp(sip, cip, sport, cport, "A", ss, cs, dt=dt)
            else:
                self.tcp(sip, cip, sport, cport, "PA", ss, cs, data, dt=dt)
                ss += len(data)
                self.tcp(cip, sip, cport, sport, "A", cs, ss, dt=dt)
        self.tcp(cip, sip, cport, sport, "FA", cs, ss, dt=dt)
        self.tcp(sip, cip, sport, cport, "FA", ss, cs + 1, dt=dt)
        self.tcp(cip, sip, cport, sport, "A", cs + 1, ss + 1, dt=dt)

    def gap(self, seconds=10):
        """Idle time so Suricata's fixed threshold windows start fresh for the next phase."""
        self.t += seconds

    def save(self, path):
        wrpcap(path, self.pkts)


HTTP_POST = (b"POST /login HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\n"
             b"Content-Length: 21\r\n\r\nuser=admin&password=x1")
HTTP_401 = (b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: 7\r\n\r\ninvalid")
# only a fragment of the standard EICAR string, never the full string
HTTP_EICAR = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 40\r\n\r\n"
              b"zz-EICAR-STANDARD-ANTIVIRUS-TEST-FILE-zz")


def attack_pcap(path):
    """Everything an attacker would do, at the medium sensitivity thresholds."""
    p = Pcap()
    for port in (22, 21, 23, 3389):                       # connection bursts (>= 8 in 60 s)
        for i in range(10):
            p.tcp(ATT, VIC, 40000 + i, port, "S", 100 + i, dt=0.05)
    p.gap()
    p.session(41000, 21, [("s", b"220 ready\r\n")] + [("s", b"530 Login incorrect.\r\n")] * 7)
    p.session(41001, 23, [("s", b"login: ")] + [("s", b"Login incorrect\r\nlogin: ")] * 7)
    for i in range(8):                                    # HTTP 401 replies (>= 5) + POST /login (>= 8)
        p.session(42000 + i, 80, [("c", HTTP_POST), ("s", HTTP_401)])
    p.session(42100, 80, [("c", HTTP_POST), ("s", HTTP_401)])
    p.gap()
    for i in range(6):                                    # Xmas / NULL / FIN scans (>= 4)
        p.tcp(ATT, VIC, 50000, 100 + i, "FPU", dt=0.1)
        p.tcp(ATT, VIC, 50001, 200 + i, 0, dt=0.1)
        p.tcp(ATT, VIC, 50002, 300 + i, "F", dt=0.1)
    p.gap()
    for i in range(1700):                                 # SYN flood (>= 1500 in 5 s)
        p.tcp(ATT, VIC, 10000 + (i % 50000), 80, "S", dt=0.002)
    p.gap()
    for i in range(1700):                                 # UDP flood
        p.add(Ether(src=M_C, dst=M_S) / IP(src=ATT, dst=VIC) / UDP(sport=3000 + (i % 1000), dport=53)
              / Raw(b"x" * 20), 0.002)
    p.gap()
    for i in range(650):                                  # ICMP flood (>= 500 in 5 s)
        p.add(Ether(src=M_C, dst=M_S) / IP(src=ATT, dst=VIC) / ICMP(type=8, seq=i), 0.004)
    p.gap()
    p.session(43000, 8000, [("c", b"GET /f HTTP/1.1\r\nHost: t\r\n\r\n"), ("s", HTTP_EICAR)])   # EICAR
    p.tcp(VIC, ATT, 51000, 4444, "S", 7, dt=0.1)          # outbound to reverse-shell port
    p.save(path)
    return p


def benign_pcap(path):
    p = Pcap()
    p.session(44000, 80, [("c", b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"),
                          ("s", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")])
    for i in range(3):
        p.tcp(ATT, VIC, 45000 + i, 22, "S", dt=1)         # under every threshold
    for i in range(5):
        p.add(Ether(src=M_C, dst=M_S) / IP(src=ATT, dst=VIC) / ICMP(type=8, seq=i), 1)
    p.session(46000, 21, [("s", b"220 ready\r\n"), ("s", b"530 Login incorrect.\r\n")])   # one typo
    p.save(path)
    return p
