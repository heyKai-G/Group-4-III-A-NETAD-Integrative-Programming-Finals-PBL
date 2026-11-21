import json
import os

from app.extensions import db
from app.models import Alert, AppSetting
from app.services.categorize import parse_eve_line
from app.services.rules import REVERSED_SIDS, build_rules
from sensor import eve_tailer


def eve(sig, sid, sev=2, cat="Misc activity", src="192.168.1.66", dst="192.168.1.5", sport=40000, dport=22):
    return json.dumps({
        "timestamp": "2026-11-19T14:49:00.123456+0800", "event_type": "alert",
        "src_ip": src, "src_port": sport, "dest_ip": dst, "dest_port": dport, "proto": "TCP",
        "alert": {"action": "allowed", "signature_id": sid, "signature": sig,
                  "category": cat, "severity": sev}})


def test_parse_local_rule_and_timezone():
    a = parse_eve_line(eve("LAB-IDS [Brute Force] SSH connection burst from one source", 9000001, 1))
    assert a["category"] == "Brute Force" and a["severity"] == 3
    assert a["signature"] == "SSH connection burst from one source"
    assert a["ts"].isoformat() == "2026-11-19T06:49:00.123456"      # +0800 converted to UTC


def test_parse_et_rules():
    assert parse_eve_line(eve("ET SCAN Nmap Scripting Engine User-Agent Detected", 2009358, 2))["category"] == "Port Scan"
    assert parse_eve_line(eve("ET MALWARE Win32/Foo CnC Beacon", 1, 1))["category"] == "Malware/C2"
    m = parse_eve_line(eve("ET MALWARE Win32/Foo CnC Beacon", 1, 3))
    assert m["severity"] == 2      # malware is never shown as 'low'
    assert parse_eve_line(eve("Something odd", 5, 3, "Attempted Denial of Service"))["category"] == "DDoS"
    assert parse_eve_line(eve("Something odd", 5, 3, "Unheard of"))["category"] == "Other"


def test_failed_login_rules_swap_attacker_to_source():
    sid = sorted(REVERSED_SIDS)[0]
    a = parse_eve_line(eve("LAB-IDS [Brute Force] FTP repeated failed logins", sid,
                           src="192.168.1.5", dst="192.168.1.66", sport=21, dport=51000))
    assert a["src_ip"] == "192.168.1.66" and a["dest_ip"] == "192.168.1.5" and a["dest_port"] == 21


def test_ignores_non_alerts_and_garbage():
    assert parse_eve_line('{"event_type":"stats","stats":{}}') is None
    assert parse_eve_line("not json {") is None
    assert parse_eve_line("") is None
    assert parse_eve_line('{"event_type":"dns","note":"alert"}') is None


def test_ingest_resume_partial_line_and_rotation(app, tmp_path):
    path = str(tmp_path / "eve.json")
    line1 = eve("LAB-IDS [DDoS] SYN flood", 9000030)
    line2 = eve("LAB-IDS [Port Scan] TCP FIN scan", 9000022)
    with open(path, "w") as f:
        f.write('{"event_type":"stats"}\n' + line1 + "\n" + line2[:40])     # last line incomplete
    with app.app_context():
        assert eve_tailer.ingest_once(path) == 1
        assert eve_tailer.ingest_once(path) == 0                            # nothing new
        with open(path, "a") as f:
            f.write(line2[40:] + "\n")
        assert eve_tailer.ingest_once(path) == 1
        assert Alert.query.count() == 2
        # simulate restart: state persisted in the DB, no duplicates
        assert eve_tailer.ingest_once(path) == 0
        # rotation: file replaced by a smaller one
        with open(path, "w") as f:
            f.write(eve("LAB-IDS [DDoS] UDP flood", 9000031) + "\n")
        assert eve_tailer.ingest_once(path) == 1
        assert Alert.query.count() == 3


def test_missing_file_is_fine(app, tmp_path):
    with app.app_context():
        assert eve_tailer.ingest_once(str(tmp_path / "nope.json")) == 0


def test_rules_are_wellformed():
    for sens in ("low", "medium", "high"):
        text = build_rules(sens)
        sids = []
        for line in text.splitlines():
            if not line.startswith("alert "):
                continue
            assert line.endswith(")") and line.count("(") == line.count(")"), line
            assert 'msg:"LAB-IDS [' in line
            sid = int(line.split("sid:")[1].split(";")[0])
            sids.append(sid)
            assert "rev:1;" in line and "classtype:" in line
        assert len(sids) == len(set(sids)) >= 16
    assert "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in text
    assert "ANTIVIRUS-TEST-FILE!" not in text   # the full test string would trip antivirus
    assert "count 5, seconds 60" in build_rules("high")
    assert "count 12, seconds 60" in build_rules("low")


def test_exports_and_filters(client, app):
    from tests.test_auth import create_admin
    from app.models import Alert, NetworkConfig
    create_admin(client, app)
    with app.app_context():
        db.session.add(NetworkConfig(network_name="Lab", subnet_cidr="192.168.1.0/24",
                                     gateway_ip="192.168.1.1", iface_name="eth0", sensitivity="medium"))
        db.session.add(Alert(source="suricata", category="Brute Force", severity=3,
                             signature="=HYPERLINK(\"http://evil\")", src_ip="192.168.1.66",
                             dest_ip="192.168.1.5", proto="TCP", raw="{}"))
        db.session.add(Alert(source="sensor", category="Port Scan", severity=1,
                             signature="scan <script>alert(1)</script>", src_ip="192.168.1.77",
                             dest_ip="192.168.1.5", proto="TCP"))
        db.session.commit()
    csv_text = client.get("/alerts/export.csv?category=Brute+Force").get_data(as_text=True)
    assert "'=HYPERLINK" in csv_text and "Port Scan" not in csv_text
    pdf = client.get("/alerts/export.pdf").get_data()
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    import io
    from pypdf import PdfReader
    text = PdfReader(io.BytesIO(pdf)).pages[0].extract_text()
    assert "Lab IDS alert report" in text and "192.168.1.66" in text
    page = client.get("/alerts").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page   # output is escaped
    assert "192.168.1.77" not in client.get("/alerts?ip=1.66").get_data(as_text=True)
    assert client.get("/alerts?severity=3").get_data(as_text=True).count("sev-high") >= 1
    r = client.post("/alerts/ack-all", data={"category": "Port Scan"})
    assert r.status_code == 302
    with app.app_context():
        assert Alert.query.filter_by(acknowledged=True).count() == 1
    summ = client.get("/api/summary").get_json()
    assert summ["total_24h"] == 2 and summ["by_category"]["Brute Force"] == 1
    assert len(summ["timeline"]) == 25


def test_pdf_many_pages():
    from app.services.pdfgen import make_pdf
    rows = [[f"t{i}", "high", "DDoS", "sig (with) \\ parens " + "x" * 200, "1.1.1.1:1", "2.2.2.2:2", "TCP", "suricata"]
            for i in range(300)]
    pdf = make_pdf("T", "S", [("a", 60), ("b", 40), ("c", 60), ("d", 270), ("e", 80), ("f", 80), ("g", 30), ("h", 50)], rows)
    import io
    from pypdf import PdfReader
    assert len(PdfReader(io.BytesIO(pdf)).pages) >= 3
