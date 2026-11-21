"""List the network adapters of this machine (for the setup wizard)."""
import csv
import io
import json
import re
import socket
import subprocess
import sys

import psutil

IS_WINDOWS = sys.platform.startswith("win")


def _windows_adapters():
    """Use PowerShell Get-NetAdapter (has the GUID Npcap/Suricata need)."""
    cmd = [
        "powershell", "-NoProfile", "-Command",
        "Get-NetAdapter -IncludeHidden:$false | "
        "Select-Object Name,InterfaceDescription,InterfaceGuid,Status,MacAddress,LinkSpeed | "
        "ConvertTo-Json -Compress",
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
        if out:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            return {
                a["Name"]: {
                    "description": a.get("InterfaceDescription") or "",
                    "guid": (a.get("InterfaceGuid") or "").strip(),
                    "status": a.get("Status") or "",
                    "mac": a.get("MacAddress") or "",
                    "speed": a.get("LinkSpeed") or "",
                }
                for a in data
                if a.get("Name")
            }
    except Exception:
        pass
    # Fallback: getmac prints "\Device\Tcpip_{GUID}" for connected adapters.
    try:
        out = subprocess.run(
            ["getmac", "/v", "/fo", "csv"], capture_output=True, text=True, timeout=20
        ).stdout
        rows = list(csv.reader(io.StringIO(out)))[1:]
        result = {}
        for r in rows:
            if len(r) >= 4:
                m = re.search(r"\{[0-9A-Fa-f-]+\}", r[3])
                result[r[0]] = {
                    "description": r[1],
                    "guid": m.group(0) if m else "",
                    "status": "Up" if m else "Down",
                    "mac": r[2],
                    "speed": "",
                }
        return result
    except Exception:
        return {}


def list_interfaces():
    """Return a list of dicts: name, description, ipv4, mac, status, speed, device."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    win = _windows_adapters() if IS_WINDOWS else {}
    names = list(win.keys()) if win else list(addrs.keys())
    result = []
    for name in names:
        ipv4 = ""
        mac = ""
        for a in addrs.get(name, []):
            if a.family == socket.AF_INET and not ipv4:
                ipv4 = a.address
            elif a.family == psutil.AF_LINK and not mac:
                mac = a.address
        info = win.get(name, {})
        st = stats.get(name)
        guid = info.get("guid", "")
        if IS_WINDOWS:
            device = rf"\Device\NPF_{guid}" if guid else ""
        else:
            device = name
        result.append(
            {
                "name": name,
                "description": info.get("description", ""),
                "ipv4": ipv4,
                "mac": info.get("mac") or mac,
                "status": info.get("status") or ("Up" if st and st.isup else "Down"),
                "speed": info.get("speed") or (f"{st.speed} Mbps" if st and st.speed else ""),
                "device": device,
            }
        )
    return result


def find_interface(name):
    for i in list_interfaces():
        if i["name"] == name:
            return i
    return None
