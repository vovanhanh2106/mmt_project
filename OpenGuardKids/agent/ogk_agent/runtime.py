"""AgentRuntime: lắp ráp mọi thành phần và chạy các luồng (tick 1 s, đồng bộ 60 s, WebSocket, DNS proxy, API cục bộ)."""
from __future__ import annotations
import logging, os, threading, time
from . import config as C
from .app_control import HashCache
from .dnsfilter import DnsFilter
from .dnsproxy import DnsProxy
from .enforcer import Enforcer
from .local_api import LocalApi
from .store import Store
from .sync import ApiClient, ApiError, ws_loop
from .timeguard import TimeGuard
from .upstream import UdpUpstream
from .winplatform import ServicePlatform, TrayBridge, has_interactive_user, spawn_tray
from ogk_common.classify import load_classification
from ogk_common.policy import verify_envelope
from . import __version__

log = logging.getLogger("ogk.runtime")


class AgentRuntime:
    def __init__(self):
        self.cfg = C.load_config()
        self.sec = C.load_secrets()
        self.store = Store(str(C.home() / "agent.db"))
        self.tg = TimeGuard(self.store)
        self.bridge = TrayBridge()
        self.platform = ServicePlatform(self.bridge)
        self.enforcer = Enforcer(self.store, self.tg, self.platform, self.cfg["device_id"], self.cfg["child_id"], HashCache())
        self.client = ApiClient(self.cfg["server_url"], self.cfg["pin_sha256"], self.sec, on_secrets=C.save_secrets) if self.cfg["server_url"] else None
        host = (self.cfg["server_url"].split("//")[-1].split(":")[0]) if self.cfg["server_url"] else ""
        self.dnsfilter = DnsFilter(load_classification(), extra_allow=(host,) if host and not host.replace(".", "").isdigit() else ())
        self.dns = DnsProxy(self.dnsfilter, UdpUpstream(self.cfg["upstream"]), lambda: self.enforcer.policy,
                            lambda: self.enforcer.exhausted, self.enforcer.on_dns_decision, port=self.cfg["dns_port"])
        self.local = LocalApi(self, self.cfg["local_port"])
        self.stop = threading.Event()
        self.sync_now = threading.Event()
        self.acked: list[int] = []
        self._tray_fail = 0
        self._tray_since = time.monotonic()
        self._load_cached_policy()

    # ---------- chính sách ----------
    def _load_cached_policy(self):
        env = self.store.get("policy_env")
        if env and self.sec:
            try:
                if verify_envelope(env, C.policy_key(self.sec), self.cfg["device_id"]):
                    self.enforcer.set_policy(env["policy"], synced=False)
                    self.enforcer.last_sync_ts = self.store.get("last_sync") or self.tg.now()
            except Exception:
                log.exception("chính sách cache hỏng")

    def _accept_policy(self, env: dict) -> bool:
        key = C.policy_key(self.sec)
        if not verify_envelope(env, key, self.cfg["device_id"]):
            log.error("Từ chối chính sách: chữ ký không hợp lệ")
            self.enforcer.emit("quota_warning", "policy_rejected")
            return False
        cur = (self.enforcer.policy or {}).get("version", 0)
        if env["policy"]["version"] < cur:
            log.error("Từ chối chính sách cũ hơn (chống rollback)"); return False
        self.store.set("policy_env", env)
        self.enforcer.set_policy(env["policy"])
        return True

    # ---------- đồng bộ ----------
    def sync_once(self):
        if not self.client: return
        e = self.enforcer
        hb = {"status": e.state, "quota_used_sec": int(e.used_today()), "day": e._day(self.tg.now()),
              "policy_version": (e.policy or {}).get("version", 0), "acked": self.acked, "agent_version": __version__}
        res = self.client.heartbeat(hb)
        self.acked = []
        self.tg.sync_server(res["server_time"])
        if res.get("policy_version", 0) != hb["policy_version"]:
            self._accept_policy(self.client.get_policy())
        for cmd in res.get("commands", []):
            self.handle_message({"type": "command", **cmd})
        self.flush_events()
        e.mark_synced(); self.store.set("last_sync", e.last_sync_ts)

    def flush_events(self):
        bid, rows = self.store.freeze_batch()
        if bid:
            self.client.post_events(bid, rows)
            self.store.ack_batch(bid)

    def handle_message(self, m: dict):
        if m.get("type") == "command":
            self.enforcer.apply_command(m["kind"], int(m.get("minutes") or 15))
            self.acked.append(m["id"])
            return {"type": "ack", "id": m["id"]}
        if m.get("type") == "policy_changed":
            self.sync_now.set()

    def _sync_loop(self):
        while not self.stop.is_set():
            try: self.sync_once()
            except Exception as ex: log.info("đồng bộ lỗi (ngoại tuyến?): %s", ex)
            self.sync_now.wait(self.cfg["heartbeat_sec"]); self.sync_now.clear()

    # ---------- phục vụ trang cho trẻ ----------
    def local_requests(self):
        try: return self.client.get_requests()["items"] if self.client else []
        except Exception: return []

    def summary(self):
        try: return self.client.get_summary(1)
        except Exception: return {"total_sec": self.enforcer.used_today(), "blocked": 0, "top_apps": [], "top_domains": []}

    def audit(self):
        try: return self.client.get_audit()["items"]
        except Exception: return []

    def child_request(self, kind: str, subject: str, note: str) -> bool:
        if kind not in ("more_time", "unblock") or not self.client: return False
        self.enforcer.emit("unlock_request", "more_time" if kind == "more_time" else (subject if "." in subject else "unblock"))
        try: self.client.post_request(kind, subject, note); return True
        except Exception: return False

    # ---------- chống lạm dụng (stalkerware): tray phải hiện, nếu không agent tự dừng ----------
    def _tray_watchdog(self):
        if not has_interactive_user() or self.bridge.alive(15):
            self._tray_fail, self._tray_since = 0, time.monotonic(); return
        if time.monotonic() - self._tray_since < 45: return
        self._tray_fail += 1; self._tray_since = time.monotonic()
        self.enforcer.emit("quota_warning", "tray_missing")
        if self._tray_fail >= 3 or not spawn_tray():
            if self._tray_fail >= 3:
                self.enforcer.emit("quota_warning", "agent_stopped")
                try: self.flush_events()
                except Exception: pass
                log.error("Không hiển thị được biểu tượng khay – agent tự dừng (NT1)")
                self.stop.set()

    # ---------- chạy ----------
    def run(self):
        with open(C.home() / "local_token", "w") as f: f.write(self.local.token)
        self.local.start(); self.dns.start()
        threading.Thread(target=self._sync_loop, daemon=True, name="ogk-sync").start()
        if self.client:
            threading.Thread(target=ws_loop, args=(self.client, self.handle_message, self.stop), daemon=True, name="ogk-ws").start()
        self.platform.notify("OpenGuard Kids đang chạy", "Chương trình giúp em dùng máy an toàn. Em bấm vào biểu tượng để xem nó ghi gì nhé.", "info")
        n = 0
        while not self.stop.is_set():
            t0 = time.monotonic()
            try:
                self.enforcer.tick()
                n += 1
                if n % 5 == 0: self._tray_watchdog()
            except Exception: log.exception("tick")
            self.stop.wait(max(0.0, 1.0 - (time.monotonic() - t0)))
        self.dns.stop(); self.local.stop()
