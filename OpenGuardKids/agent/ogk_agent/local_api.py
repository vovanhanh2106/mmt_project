"""API cục bộ 127.0.0.1:47600 cho Tray & trang cho trẻ. Chặn DNS-rebinding (kiểm tra Host) và yêu cầu token cục bộ."""
from __future__ import annotations
import json, logging, secrets, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from . import kidpages

log = logging.getLogger("ogk.local")


class LocalApi:
    def __init__(self, runtime, port=47600):
        self.rt, self.port = runtime, port
        self.token = secrets.token_urlsafe(24)
        self.httpd: ThreadingHTTPServer | None = None

    def start(self):
        api = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _ok(self):
                host = (self.headers.get("Host") or "").split(":")[0]
                if host not in ("127.0.0.1", "localhost"):
                    return False
                q = parse_qs(urlparse(self.path).query)
                tok = self.headers.get("X-OGK-Token") or (q.get("t") or [""])[0] or self._cookie()
                return secrets.compare_digest(tok, api.token)
            def _cookie(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "ogk": return v
                return ""
            def _send(self, code, body, ctype="application/json"):
                b = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode()
                self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8")
                self.send_header("Set-Cookie", f"ogk={api.token}; HttpOnly; SameSite=Strict; Path=/")
                self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(b)
            def do_GET(self):
                if not self._ok(): return self._send(403, {"error": "forbidden"})
                p = urlparse(self.path).path; rt = api.rt
                if p == "/api/status": return self._send(200, rt.enforcer.status())
                if p == "/": return self._send(200, kidpages.home(rt.enforcer.status(), rt.local_requests(), ""), "text/html")
                if p == "/what": return self._send(200, kidpages.what(), "text/html")
                if p == "/today": return self._send(200, kidpages.today(rt.summary(), ""), "text/html")
                if p == "/rules": return self._send(200, kidpages.rules(rt.audit(), ""), "text/html")
                self._send(404, {"error": "not found"})
            def do_POST(self):
                if not self._ok(): return self._send(403, {"error": "forbidden"})
                n = int(self.headers.get("Content-Length") or 0); body = json.loads(self.rfile.read(n) or b"{}")
                p = urlparse(self.path).path; rt = api.rt
                if p == "/api/tray/ping":
                    return self._send(200, rt.bridge.ping(body.get("idle", 0), body.get("locked", False)))
                if p == "/api/request":
                    ok = rt.child_request(body.get("kind", ""), str(body.get("subject", ""))[:100], str(body.get("note", ""))[:300])
                    return self._send(200 if ok else 400, {"ok": ok})
                self._send(404, {"error": "not found"})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True, name="ogk-local").start()

    def stop(self):
        if self.httpd: self.httpd.shutdown()
