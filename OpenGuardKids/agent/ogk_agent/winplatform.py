"""Nền tảng Windows. Service (session 0) không thấy bàn phím/màn hình của trẻ => Tray (session người dùng) báo trạng thái
(idle, khóa màn hình) và thực thi khóa/hiện thông báo; service chỉ liệt kê/kết thúc tiến trình bằng psutil."""
from __future__ import annotations
import logging, threading, time
from collections import deque
from .app_control import ProcInfo

log = logging.getLogger("ogk.win")


class TrayBridge:
    """Hộp thư an toàn giữa service và tray (qua API cục bộ 127.0.0.1)."""
    def __init__(self):
        self.lock = threading.Lock()
        self.idle, self.locked, self.last_ping = 0.0, False, 0.0
        self.commands: deque = deque(); self.notices: deque = deque(maxlen=50); self.history: deque = deque(maxlen=100)

    def ping(self, idle: float, locked: bool):
        with self.lock:
            self.idle, self.locked, self.last_ping = float(idle), bool(locked), time.monotonic()
            out = {"commands": list(self.commands), "notices": list(self.notices)}
            self.commands.clear(); self.notices.clear()
            return out

    def alive(self, within: float = 10.0) -> bool:
        return (time.monotonic() - self.last_ping) < within if self.last_ping else False


class ServicePlatform:
    def __init__(self, bridge: TrayBridge):
        self.bridge = bridge

    def list_processes(self):
        import psutil
        out = []
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                i = p.info
                if i["name"]:
                    out.append(ProcInfo(i["pid"], i["name"], i.get("exe")))
            except Exception:
                pass
        return out

    def kill(self, pid: int) -> bool:
        import psutil
        try:
            psutil.Process(pid).kill(); return True
        except Exception as e:
            log.warning("kill %s: %s", pid, e); return False

    def lock(self):
        if self.bridge.alive():
            self.bridge.commands.append("lock")
        else:
            self._wts_disconnect()

    def _wts_disconnect(self):
        try:
            import win32ts
            sid = win32ts.WTSGetActiveConsoleSessionId()
            if sid != 0xFFFFFFFF:
                win32ts.WTSDisconnectSession(win32ts.WTS_CURRENT_SERVER_HANDLE, sid, False)
        except Exception as e:
            log.warning("WTSDisconnectSession: %s", e)

    def notify(self, title, text, kind="info"):
        item = {"title": title, "text": text, "kind": kind, "ts": time.time()}
        self.bridge.notices.append(item); self.bridge.history.append(item)

    def idle_seconds(self): return self.bridge.idle if self.bridge.alive() else 0.0
    def session_locked(self): return self.bridge.locked if self.bridge.alive() else False


def has_interactive_user() -> bool:
    try:
        import psutil
        return bool(psutil.users())
    except Exception:
        return True


def spawn_tray() -> bool:
    """Chạy lại Tray trong phiên của người dùng đang đăng nhập (NT1 – biểu tượng phải luôn hiện)."""
    try:
        import sys, win32ts, win32process, win32security, win32con, win32profile
        sid = win32ts.WTSGetActiveConsoleSessionId()
        token = win32ts.WTSQueryUserToken(sid)
        env = win32profile.CreateEnvironmentBlock(token, False)
        si = win32process.STARTUPINFO(); si.lpDesktop = "winsta0\\default"
        win32process.CreateProcessAsUser(token, None, f'"{sys.executable}" -m ogk_agent tray', None, None, False,
                                         win32con.NORMAL_PRIORITY_CLASS | 0x400, env, None, si)
        return True
    except Exception as e:
        log.warning("spawn_tray thất bại: %s", e)
        return False
