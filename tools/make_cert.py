"""Create the self-signed HTTPS certificate:  python tools/make_cert.py [extra-ip ...]"""
import _path  # noqa: F401
import sys

from app.config import Config
from app.services.cert import make_self_signed

cert, key = make_self_signed(Config.CERT_FILE, Config.KEY_FILE, extra_ips=sys.argv[1:])
print(f"Created {cert} and {key}")
