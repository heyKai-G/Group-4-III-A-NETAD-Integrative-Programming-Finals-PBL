"""Start the sensor service (needs Administrator rights for packet capture)."""
import ctypes
import sys

from app import create_app
from app.extensions import db
from sensor.runner import SensorService


def is_admin():
    if sys.platform.startswith("win"):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    import os
    return os.geteuid() == 0


if __name__ == "__main__":
    if not is_admin():
        print("WARNING: not running as Administrator - packet capture will probably fail.")
    app = create_app()
    with app.app_context():
        db.create_all()
    SensorService(app).run()
