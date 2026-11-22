"""F2 – Kiểm soát ứng dụng: đối chiếu tên tiến trình VÀ mã băm SHA-256 của tệp thực thi (đổi tên vẫn bị nhận diện)."""
from __future__ import annotations
import hashlib, os
from dataclasses import dataclass


@dataclass
class ProcInfo:
    pid: int
    name: str
    exe: str | None = None


@dataclass
class AppDecision:
    action: str            # allow | block
    reason: str = ""
    group: str | None = None
    rule: dict | None = None


def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class HashCache:
    def __init__(self, hasher=sha256_file):
        self._c: dict = {}
        self._hasher = hasher

    def get(self, path: str | None) -> str | None:
        if not path:
            return None
        try:
            st = os.stat(path); key = (path, st.st_mtime_ns, st.st_size)
        except OSError:
            return None
        if key not in self._c:
            self._c[key] = self._hasher(path)
        return self._c[key]


SYSTEM_DIRS = ("c:\\windows\\", "c:\\program files\\windowsapps\\")
PROTECTED = {"explorer.exe", "csrss.exe", "winlogon.exe", "services.exe", "svchost.exe", "lsass.exe", "dwm.exe", "taskmgr.exe", "ogk-tray.exe"}


def is_system_path(exe: str | None) -> bool:
    return bool(exe) and exe.lower().replace("/", "\\").startswith(SYSTEM_DIRS)


def decide_app(proc: ProcInfo, sha: str | None, policy: dict, exhausted_groups: set[str] | frozenset = frozenset()) -> AppDecision:
    name = proc.name.lower()
    if name in PROTECTED or is_system_path(proc.exe):
        return AppDecision("allow")
    who = policy.get("set_by", "Bố/Mẹ")
    matched = None
    for r in policy.get("app_rules", []):
        if (r.get("sha256") and sha and r["sha256"].lower() == sha) or (r.get("name") and r["name"].lower() == name):
            matched = r
            if r["action"] == "block":
                break   # block thắng allow khi cùng khớp
    if matched:
        who = matched.get("set_by", who)
        if matched["action"] == "block":
            return AppDecision("block", matched.get("reason") or f"Ứng dụng này bị chặn (luật do {who} đặt).", matched.get("group"), matched)
        g = matched.get("group")
        if g and g in exhausted_groups:
            return AppDecision("block", f"Đã hết thời gian cho nhóm '{g}' hôm nay.", g, matched)
        return AppDecision("allow", group=g, rule=matched)
    if policy.get("app_mode") == "allowlist":
        return AppDecision("block", f"Ứng dụng này chưa được {who} cho phép.")
    return AppDecision("allow")
