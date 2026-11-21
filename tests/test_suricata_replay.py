"""Replay crafted traffic through the REAL Suricata and check our rules + importer.

Skipped automatically when Suricata is not installed at the usual Linux path.
"""
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

import pytest

from app.services.categorize import parse_eve_line
from app.services.rules import write_local_rules

YAML = os.environ.get("SURICATA_TEST_YAML", "/etc/suricata/suricata.yaml")
pytestmark = pytest.mark.skipif(
    not (shutil.which("suricata") and os.path.exists(YAML)), reason="Suricata not installed")

EXPECTED = {
    9000001: "Brute Force", 9000002: "Brute Force", 9000003: "Brute Force", 9000004: "Brute Force",
    9000010: "Brute Force", 9000011: "Brute Force", 9000012: "Brute Force", 9000014: "Brute Force",
    9000020: "Port Scan", 9000021: "Port Scan", 9000022: "Port Scan",
    9000030: "DDoS", 9000031: "DDoS", 9000032: "DDoS",
    9000040: "Malware/C2", 9000041: "Malware/C2",
}


def run_suricata(tmp_path, pcap, rules):
    out = pathlib.Path(tempfile.mkdtemp(dir=tmp_path))   # fresh folder: Suricata appends to eve.json
    r = subprocess.run(["suricata", "-c", YAML, "-S", str(rules), "-r", str(pcap), "-l", str(out),
                        "-k", "none"], capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr[-800:]
    alerts = []
    with open(out / "eve.json", encoding="utf-8") as f:
        for line in f:
            a = parse_eve_line(line)
            if a:
                alerts.append(a)
    return alerts


@pytest.fixture(scope="module")
def paths(tmp_path_factory):
    from tests.pcapgen import attack_pcap, benign_pcap
    d = tmp_path_factory.mktemp("replay")
    attack_pcap(str(d / "attack.pcap"))
    benign_pcap(str(d / "benign.pcap"))
    return d


def test_every_rule_fires_at_medium(paths):
    rules = paths / "medium.rules"
    write_local_rules(str(rules), "medium")
    alerts = run_suricata(paths, paths / "attack.pcap", rules)
    got = {a["sid"]: a["category"] for a in alerts}
    missing = {sid: c for sid, c in EXPECTED.items() if sid not in got}
    assert not missing, f"rules that did not fire: {missing}; got {sorted(got)}"
    assert {sid: got[sid] for sid in EXPECTED} == EXPECTED


def test_failed_login_alerts_name_the_attacker_as_source(paths):
    rules = paths / "medium.rules"
    write_local_rules(str(rules), "medium")
    alerts = run_suricata(paths, paths / "attack.pcap", rules)
    for a in alerts:
        if a["sid"] in (9000010, 9000011, 9000012):
            assert a["src_ip"] == "192.168.1.66" and a["dest_ip"] == "192.168.1.5", a


def test_normal_traffic_raises_nothing(paths):
    rules = paths / "medium.rules"
    write_local_rules(str(rules), "medium")
    assert run_suricata(paths, paths / "benign.pcap", rules) == []


def test_low_sensitivity_is_quieter_than_high(paths):
    counts = {}
    for sens in ("low", "high"):
        rules = paths / f"{sens}.rules"
        write_local_rules(str(rules), sens)
        counts[sens] = len({a["sid"] for a in run_suricata(paths, paths / "attack.pcap", rules)})
    assert counts["high"] >= counts["low"]
