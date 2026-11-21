"""A small FTP server to practise FTP brute-force detection.

Needs:  pip install pyftpdlib      (see requirements-targets.txt)
Run on the IDS laptop:  python tools\\targets\\ftp_target.py
Listens on port 21. The only valid login is  labuser / lab-password-123  (read-only, empty folder).
For lab use on your own isolated network.
"""
import os
import tempfile

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

root = tempfile.mkdtemp(prefix="lab-ftp-")
auth = DummyAuthorizer()
auth.add_user("labuser", "lab-password-123", root, perm="elr")
handler = FTPHandler
handler.authorizer = auth
handler.banner = "Lab FTP target ready."
print(f"FTP target on port 21, folder {root}  (Ctrl+C to stop)")
FTPServer(("0.0.0.0", 21), handler).serve_forever()
