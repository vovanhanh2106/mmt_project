"""Tray UI – chạy trong phiên người dùng (quyền thường). Biểu tượng LUÔN hiển thị (NT1); báo idle/khóa cho service; hiện lý do chặn (NT4)."""
from __future__ import annotations
import ctypes, json, threading, time, urllib.request, webbrowser
from ctypes import wintypes
from . import config as C


class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


def idle_seconds() -> float:
    li = LASTINPUTINFO(); li.cbSize = ctypes.sizeof(li)
    ctypes.windll.user32.GetLastInputInfo(ctypes.byref(li))
    return (ctypes.windll.kernel32.GetTickCount() - li.dwTime) / 1000.0


def workstation_locked() -> bool:
    h = ctypes.windll.user32.OpenInputDesktop(0, False, 0x0100)   # DESKTOP_SWITCHDESKTOP
    if not h:
        return True
    ctypes.windll.user32.CloseDesktop(h)
    return False


class Tray:
    def __init__(self):
        self.base = f"http://127.0.0.1:{C.load_config()['local_port']}"
        self.token = ""
        self.notices: list[dict] = []
        self.status: dict = {}
        self.lock = threading.Lock()

    def _call(self, method, path, body=None):
        if not self.token:
            self.token = (C.home() / "local_token").read_text().strip()
        req = urllib.request.Request(self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"X-OGK-Token": self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read() or b"{}")

    def open_page(self, page=""):
        webbrowser.open(f"{self.base}/{page}?t={self.token}")

    def poll(self):
        while True:
            try:
                out = self._call("POST", "/api/tray/ping", {"idle": idle_seconds(), "locked": workstation_locked()})
                if "lock" in out.get("commands", []):
                    ctypes.windll.user32.LockWorkStation()
                with self.lock: self.notices += out.get("notices", [])
                self.status = self._call("GET", "/api/status")
            except Exception:
                self.token = ""
            time.sleep(2)

    def run(self):
        import tkinter as tk
        import pystray
        from PIL import Image, ImageDraw
        root = tk.Tk(); root.withdraw()

        def icon_image(color="#2b8a3e"):
            im = Image.new("RGB", (64, 64), "white"); d = ImageDraw.Draw(im)
            d.ellipse((4, 4, 60, 60), fill=color); d.text((22, 22), "OGK", fill="white"); return im

        def title():
            s = self.status; r = s.get("remaining_sec")
            return "OpenGuard Kids – " + ("không giới hạn" if r is None else f"còn {int(r // 60)} phút") + (" (tạm nghỉ)" if s.get("paused") else "")

        menu = pystray.Menu(
            pystray.MenuItem(lambda i: title(), lambda: self.open_page(""), default=True),
            pystray.MenuItem("⏰ Xin thêm giờ / 🙋 Báo chặn nhầm", lambda: self.open_page("")),
            pystray.MenuItem("🔍 Ứng dụng này ghi nhận gì về em?", lambda: self.open_page("what")),
            pystray.MenuItem("📊 Hôm nay em đã dùng gì?", lambda: self.open_page("today")),
            pystray.MenuItem("📜 Ai đã đổi luật?", lambda: self.open_page("rules")))
        icon = pystray.Icon("ogk", icon_image(), "OpenGuard Kids", menu)
        icon.run_detached()
        threading.Thread(target=self.poll, daemon=True).start()

        def pump():
            with self.lock:
                items, self.notices = self.notices, []
            for n in items:
                self.popup(root, n)
            try: icon.title = title()
            except Exception: pass
            root.after(1000, pump)
        root.after(1000, pump); root.mainloop()

    def popup(self, root, n):
        import tkinter as tk
        w = tk.Toplevel(root); w.title(n["title"]); w.attributes("-topmost", True); w.geometry("460x220+80+80")
        color = {"blocked": "#fff3bf", "warn": "#ffe3e3", "grace": "#ffc9c9"}.get(n.get("kind"), "#e7f5ff"); w.configure(bg=color)
        tk.Label(w, text=n["title"], font=("Segoe UI", 16, "bold"), bg=color, wraplength=420).pack(pady=(14, 6))
        tk.Label(w, text=n["text"], font=("Segoe UI", 13), bg=color, wraplength=420, justify="left").pack(padx=14)
        tk.Button(w, text="Em hiểu rồi", font=("Segoe UI", 13), command=w.destroy).pack(pady=12)
        if n.get("kind") == "blocked":
            tk.Button(w, text="Em nghĩ bị chặn nhầm", command=lambda: (self.open_page(""), w.destroy())).pack()
        w.after(20000, lambda: w.winfo_exists() and w.destroy())


def main():
    Tray().run()
