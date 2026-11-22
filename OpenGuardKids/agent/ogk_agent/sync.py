"""Giao tiếp với OGK-Server: HTTPS TLS1.2+ có ghim chứng chỉ (certificate pinning), làm mới token, WebSocket lệnh khẩn."""
from __future__ import annotations
import hashlib, http.client, json, logging, ssl, threading, time
from urllib.parse import urlparse

log = logging.getLogger("ogk.sync")


def verify_pin(der_cert: bytes, pin_hex: str) -> bool:
    return hashlib.sha256(der_cert).hexdigest().lower() == pin_hex.lower().replace(":", "")


def pinned_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False          # CA tự ký trong lab: thay xác thực CA bằng ghim SHA-256 của chứng chỉ
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, pin, timeout=10):
        super().__init__(host, port, timeout=timeout, context=pinned_context())
        self.pin = pin

    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        if not der or not verify_pin(der, self.pin):
            self.close()
            raise ssl.SSLError("Chứng chỉ máy chủ không khớp mã ghim – từ chối kết nối")


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body}")
        self.status, self.body = status, body


class ApiClient:
    def __init__(self, server_url: str, pin: str, secrets: dict, on_secrets=None):
        u = urlparse(server_url)
        self.scheme, self.host, self.port = u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)
        self.pin, self.sec, self.on_secrets = pin, secrets, on_secrets
        self.lock = threading.Lock()

    def _conn(self):
        if self.scheme == "https":
            return PinnedHTTPSConnection(self.host, self.port, self.pin)
        return http.client.HTTPConnection(self.host, self.port, timeout=10)   # chỉ dùng khi phát triển

    def raw(self, method, path, body=None, token=None):
        c = self._conn()
        try:
            h = {"Content-Type": "application/json"}
            if token: h["Authorization"] = "Bearer " + token
            c.request(method, path, json.dumps(body) if body is not None else None, h)
            r = c.getresponse(); data = r.read()
            return r.status, (json.loads(data) if data else {})
        finally:
            c.close()

    def call(self, method, path, body=None, auth=True):
        tok = self.sec.get("access_token") if auth else None
        st, js = self.raw(method, path, body, tok)
        if st == 401 and auth and self.sec.get("refresh_token"):
            self.refresh()
            st, js = self.raw(method, path, body, self.sec.get("access_token"))
        if st >= 400:
            raise ApiError(st, js)
        return js

    def refresh(self):
        with self.lock:
            st, js = self.raw("POST", "/api/device/refresh", {"refresh_token": self.sec["refresh_token"]})
            if st != 200:
                raise ApiError(st, js)
            self.sec["access_token"] = js["access_token"]
            if js.get("refresh_token"): self.sec["refresh_token"] = js["refresh_token"]
            if self.on_secrets: self.on_secrets(self.sec)

    # --- API cụ thể ---
    def enroll(self, code, fingerprint, hostname):
        return self.call("POST", "/api/enroll", {"code": code, "fingerprint": fingerprint, "hostname": hostname}, auth=False)
    def heartbeat(self, payload): return self.call("POST", "/api/device/heartbeat", payload)
    def get_policy(self): return self.call("GET", "/api/device/policy")
    def post_events(self, batch_id, events): return self.call("POST", "/api/device/events", {"batch_id": batch_id, "events": events})
    def post_request(self, kind, subject, note): return self.call("POST", "/api/device/requests", {"kind": kind, "subject": subject, "note": note})
    def get_requests(self): return self.call("GET", "/api/device/requests")
    def get_summary(self, days=1): return self.call("GET", f"/api/device/summary?days={days}")
    def get_audit(self): return self.call("GET", "/api/device/audit")
    def uninstall_auth(self, email, password): return self.call("POST", "/api/device/uninstall", {"email": email, "password": password})


def ws_loop(client: ApiClient, on_message, stop: threading.Event, send_queue=None):
    """Kênh lệnh khẩn (độ trễ < 5 s). Tự kết nối lại; nếu mất kênh, lệnh vẫn đến qua nhịp tim 60 s."""
    try:
        from websockets.sync.client import connect
    except ImportError:
        log.warning("thiếu thư viện websockets – chỉ dùng nhịp tim")
        return
    backoff = 2
    while not stop.is_set():
        try:
            scheme = "wss" if client.scheme == "https" else "ws"
            uri = f"{scheme}://{client.host}:{client.port}/ws/device"
            kw = {"ssl": pinned_context()} if scheme == "wss" else {}
            with connect(uri, additional_headers={"Authorization": "Bearer " + client.sec["access_token"]}, open_timeout=10, **kw) as ws:
                if scheme == "wss":
                    sock = ws.socket
                    if not verify_pin(sock.getpeercert(binary_form=True), client.pin):
                        raise ssl.SSLError("pin không khớp (ws)")
                backoff = 2
                while not stop.is_set():
                    try:
                        msg = ws.recv(timeout=1.0)
                    except TimeoutError:
                        continue
                    reply = on_message(json.loads(msg))
                    if reply:
                        ws.send(json.dumps(reply))
        except Exception as e:
            log.info("ws ngắt: %s", e)
            try: client.refresh()
            except Exception: pass
            stop.wait(backoff); backoff = min(backoff * 2, 60)
