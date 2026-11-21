"""Start the dashboard over HTTPS (cheroot WSGI server, pure Python, works on Windows)."""
import os
import sys

from cheroot.ssl.builtin import BuiltinSSLAdapter
from cheroot.wsgi import Server

from app import create_app
from app.extensions import db


def main():
    app = create_app()
    cfg = app.config
    with app.app_context():
        db.create_all()
    cert, key = cfg["CERT_FILE"], cfg["KEY_FILE"]
    if not (os.path.exists(cert) and os.path.exists(key)):
        print(f"HTTPS certificate not found ({cert}). Run setup.ps1 or: python tools/make_cert.py")
        sys.exit(1)
    server = Server((cfg["BIND_HOST"], cfg["HTTPS_PORT"]), app, numthreads=10)
    server.ssl_adapter = BuiltinSSLAdapter(cert, key)
    print(f"Lab IDS dashboard: https://{cfg['BIND_HOST']}:{cfg['HTTPS_PORT']}  (Ctrl+C to stop)")
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
