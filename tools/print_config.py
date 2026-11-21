"""Print one saved setting for the PowerShell scripts:  python tools/print_config.py suricata-iface|local-rules|eve-path"""
import _path  # noqa: F401
import sys

from app import create_app
from app.models import NetworkConfig

what = sys.argv[1] if len(sys.argv) > 1 else ""
app = create_app()
with app.app_context():
    cfg = NetworkConfig.query.first()
    if what == "local-rules":
        print(app.config["LOCAL_RULES_PATH"])
    elif what == "eve-path":
        print(app.config["EVE_JSON_PATH"])
    elif what == "suricata-iface":
        if not cfg or not cfg.iface_device:
            sys.exit("Setup wizard not finished yet: open the dashboard and complete it first.")
        print(cfg.iface_device)
    else:
        sys.exit("usage: print_config.py suricata-iface|local-rules|eve-path")
