"""Show network adapters and the device IDs Suricata/Npcap use:  python tools/list_interfaces.py"""
import _path  # noqa: F401

from app.services.netinfo import list_interfaces

for i in list_interfaces():
    print(f"{i['name']:<28} {i['status']:<14} IPv4={i['ipv4'] or '-':<16} MAC={i['mac'] or '-'}")
    if i["description"]:
        print(f"    {i['description']}")
    print(f"    Suricata -i value: {i['device'] or '(none)'}")
