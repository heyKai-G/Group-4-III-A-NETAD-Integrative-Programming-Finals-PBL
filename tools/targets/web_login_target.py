"""A tiny web login page to practise HTTP brute-force detection.

Run on the IDS laptop:   python tools\\targets\\web_login_target.py
It listens on port 8080. The only valid login is  admin / lab-password-123
Standard library only. For lab use on your own isolated network.
"""
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

PAGE = """<!doctype html><title>Lab target login</title>
<h1>Lab target login</h1><p>{msg}</p>
<form method="post" action="/login">
User <input name="user"> Password <input name="password" type="password">
<button>Log in</button></form>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(200, PAGE.format(msg="Please log in."))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = parse_qs(self.rfile.read(min(length, 4096)).decode(errors="replace"))
        ok = form.get("user", [""])[0] == "admin" and form.get("password", [""])[0] == "lab-password-123"
        if ok:
            self._send(200, PAGE.format(msg="Welcome, admin."))
        else:
            # 200 + message, like most real login forms (hydra treats a 401 as HTTP auth, not a form)
            self._send(200, PAGE.format(msg=html.escape("Invalid credentials.")))

    def log_message(self, fmt, *args):
        print(self.client_address[0], fmt % args)


if __name__ == "__main__":
    print("Web login target on http://0.0.0.0:8080  (Ctrl+C to stop)")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
