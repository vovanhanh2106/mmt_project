"""Bộ điều phối chính của agent: mỗi giây gọi tick(). Tách khỏi hệ điều hành qua giao diện Platform để kiểm thử được."""
from __future__ import annotations
import logging, time
from typing import Protocol
from ogk_common.events import validate_event
from .app_control import AppDecision, HashCache, ProcInfo, PROTECTED, decide_app, is_system_path
from .timeeval import evaluate_time

log = logging.getLogger("ogk.enforcer")


class Platform(Protocol):
    def list_processes(self) -> list[ProcInfo]: ...
    def kill(self, pid: int) -> bool: ...
    def lock(self) -> None: ...
    def notify(self, title: str, text: str, kind: str = "info") -> None: ...
    def idle_seconds(self) -> float: ...
    def session_locked(self) -> bool: ...


class Enforcer:
    MAX_DT = 5.0   # giới hạn bước cộng dồn (sau khi máy ngủ không cộng bù)

    def __init__(self, store, timeguard, platform: Platform, device_id: int = 0, child_id: int = 0, hashcache: HashCache | None = None):
        self.store, self.tg, self.plat = store, timeguard, platform
        self.device_id, self.child_id = device_id, child_id
        self.hashes = hashcache or HashCache()
        self.policy: dict | None = None
        self.last_sync_ts: float | None = None
        self.exhausted: frozenset[str] = frozenset()
        self.state, self.reason, self.remaining = "init", "", None
        self.grace_until: float | None = None
        self._last_now: float | None = None
        self._warned: set = set()
        self._running: dict[int, tuple[str, float]] = {}
        self._last_lock_cmd = 0.0
        self._locked_episode: str | None = None
        self._notice_at: dict[str, float] = {}
        self._dom_event_at: dict[str, float] = {}
        self._global_notice_at = 0.0
        self.force_lock = bool(store.get("force_lock", False))
        self.override_until = float(store.get("override_until", 0))
        self.paused_until = float(store.get("paused_until", 0))
        self.degraded = False

    # ---------- chính sách ----------
    def set_policy(self, policy: dict, synced: bool = True) -> None:
        self.policy = policy
        if synced:
            self.last_sync_ts = self.tg.now()
            self.degraded = False

    def mark_synced(self) -> None:
        self.last_sync_ts = self.tg.now()

    # ---------- sự kiện ----------
    def emit(self, type_: str, subject: str, dur: int = 0) -> None:
        ev = {"ts": int(self.tg.now()), "type": type_, "subject": subject, "duration_sec": int(dur)}
        if self.policy:
            ev["policy_id"] = f"v{self.policy.get('version', 0)}"
        errs = validate_event({k: v for k, v in ev.items() if k != "policy_id"} | ({"policy_id": ev["policy_id"]} if "policy_id" in ev else {}))
        if errs:
            log.warning("bỏ sự kiện không hợp lệ %s: %s", ev, errs)
            return
        self.store.enqueue_event(ev)

    def notify(self, title: str, text: str, kind: str = "info") -> None:
        try: self.plat.notify(title, text, kind)
        except Exception: log.exception("notify")

    # ---------- DNS callback (NT2/NT4) ----------
    def on_dns_decision(self, dec) -> None:
        now = self.tg.now()
        dom = dec.domain
        if not dom or dec.rule == "always_allow":
            return
        if dec.action == "block":
            if now - self._dom_event_at.get("b:" + dom, 0) > 60:
                self._dom_event_at["b:" + dom] = now
                self.emit("blocked_domain", dom)
                if now - self._global_notice_at > 20:
                    self._global_notice_at = now
                    self.notify(f"Trang {dom} bị chặn", dec.reason, "blocked")
        elif now - self._dom_event_at.get("q:" + dom, 0) > 300:
            self._dom_event_at["q:" + dom] = now
            self.emit("domain_query", dom)

    # ---------- lệnh khẩn ----------
    def apply_command(self, kind: str, minutes: int = 15) -> None:
        now = self.tg.now()
        if kind == "lock":
            self.force_lock = True; self.store.set("force_lock", True)
            self.emit("locked", "parent_command")
        elif kind == "unlock":
            self.force_lock = False; self.store.set("force_lock", False)
            self.override_until = now + 15 * 60; self.store.set("override_until", self.override_until)
            self.grace_until = None
            self.emit("override_granted", "unlock", 15 * 60)
        elif kind == "add_time":
            self.store.usage_add(self._day(now), "_bonus", minutes * 60)
            self.emit("override_granted", "add_time", minutes * 60)
        elif kind == "pause":
            self.paused_until = now + minutes * 60; self.store.set("paused_until", self.paused_until)
            self.emit("override_granted", "parent_pause", minutes * 60)
        elif kind == "purge_data":
            self.store.purge_all()
        else:
            log.warning("lệnh không biết: %s", kind)
            return
        self.notify("Bố/Mẹ vừa gửi lệnh", {"lock": "Máy sẽ được khóa.", "unlock": "Máy đã được mở khóa thêm 15 phút.",
                    "add_time": f"Em được cộng thêm {minutes} phút.", "pause": "Bố/Mẹ tạm nghỉ kiểm soát.", "purge_data": "Dữ liệu của em đã được xóa."}.get(kind, ""), "info")

    # ---------- tiện ích ----------
    @staticmethod
    def _day(now: float) -> str:
        return time.strftime("%Y-%m-%d", time.localtime(now))

    def _fail_mode_check(self, now: float) -> bool:
        """True nếu chính sách đã quá hạn ngoại tuyến và phải xử theo fail_open/fail_closed."""
        if not self.policy or self.last_sync_ts is None:
            return False
        limit = self.policy.get("offline_max_days", 7) * 86400
        return now - self.last_sync_ts > limit

    def used_today(self) -> float:
        return self.store.usage_get(self._day(self.tg.now()), "_total")

    # ---------- vòng lặp ----------
    def tick(self) -> dict:
        now = self.tg.now()
        for skew in self.tg.pop_tamper():
            self.emit("quota_warning", "clock_changed", abs(skew))
            self.notify("Đồng hồ máy bị chỉnh", "Máy ghi nhận đồng hồ bị thay đổi; thời gian dùng vẫn được tính đúng.", "info")
        dt = 0.0 if self._last_now is None else min(max(now - self._last_now, 0.0), self.MAX_DT)
        self._last_now = now
        pol = self.policy
        killed: list[str] = []
        if pol is None:
            self.state = "no_policy"
            return {"state": self.state, "killed": killed}
        day = self._day(now)

        if self._fail_mode_check(now):
            if not self.degraded:
                self.degraded = True
                self.notify("Mất liên lạc với máy chủ lâu ngày", "Luật tạm thời " + ("được nới lỏng." if pol.get("fail_mode") == "fail_open" else "khóa máy cho đến khi kết nối lại."), "info")
            if pol.get("fail_mode") == "fail_open":
                self.state = "degraded_open"
                return {"state": self.state, "killed": killed}
            self._lock_if_needed(now, "offline")
            self.state, self.reason = "locked", "offline"
            return {"state": self.state, "killed": killed}

        paused = self.paused_until > now or pol.get("paused_until", 0) > now

        # 1) tiến trình
        procs = self.plat.list_processes()
        groups_running: set[str] = set()
        seen: set[int] = set()
        if not paused:
            for p in procs:
                sha = self.hashes.get(p.exe)
                dec: AppDecision = decide_app(p, sha, pol, self.exhausted)
                if dec.action == "block":
                    if self.plat.kill(p.pid):
                        killed.append(p.name)
                        if now - self._notice_at.get(p.name, 0) > 30:
                            self._notice_at[p.name] = now
                            self.emit("blocked_app", p.name)
                            self.notify(f"{p.name} bị đóng", dec.reason, "blocked")
                    continue
                if dec.group:
                    groups_running.add(dec.group)
                if p.name.lower() not in PROTECTED and p.exe and not is_system_path(p.exe):
                    seen.add(p.pid)
                    if p.pid not in self._running:
                        self._running[p.pid] = (p.name, now)
                        self.emit("app_start", p.name)
        for pid in [k for k in self._running if k not in seen]:
            name, t0 = self._running.pop(pid)
            self.emit("app_stop", name, int(now - t0))

        # 2) cộng dồn thời gian (không tính khi khóa máy / không thao tác quá idle_timeout / đang bị khóa)
        active = (not self.plat.session_locked()) and self.plat.idle_seconds() < pol.get("idle_timeout_sec", 300) and self.state not in ("locked", "grace")
        if active and not paused and dt > 0:
            self.store.usage_add(day, "_total", dt)
            for g in groups_running:
                self.store.usage_add(day, g, dt)
        ex = {g for g, cfg in pol.get("groups", {}).items() if cfg.get("limit_min") is not None and self.store.usage_get(day, g) >= cfg["limit_min"] * 60}
        self.exhausted = frozenset(ex)

        # 3) đánh giá thời gian
        v = evaluate_time(pol, now, self.store.usage_get(day, "_total"), self.store.usage_get(day, "_bonus"),
                          self.force_lock, self.override_until, self.paused_until)
        prev = self.state
        self.remaining, self.reason = v.remaining_sec, v.reason
        if v.state == "expired":
            if self.grace_until is None and prev in ("ok", "warn") and v.reason in ("quota", "schedule") and pol.get("grace_sec", 60) > 0:
                self.grace_until = now + pol["grace_sec"]
                self.notify("Sắp khóa máy", f"{v.text} Máy sẽ khóa sau {pol['grace_sec']} giây, em hãy lưu bài nhé. Cần giúp đỡ: gọi 111.", "grace")
            if self.grace_until is not None and now < self.grace_until:
                self.state = "grace"
            else:
                self.state = "locked"
                self._lock_if_needed(now, v.reason)
        else:
            self.grace_until = None
            self._locked_episode = None
            self.state = v.state
            if v.state == "warn" and (day, v.warn_level) not in self._warned:
                self._warned.add((day, v.warn_level))
                self.emit("quota_warning", f"warn_{v.warn_level}m", int(v.remaining_sec or 0))
                self.notify(f"Còn {v.warn_level} phút", v.text, "warn")
        return {"state": self.state, "reason": self.reason, "remaining": self.remaining, "killed": killed, "day": day}

    def _lock_if_needed(self, now: float, reason: str) -> None:
        if self._locked_episode != reason:
            self._locked_episode = reason
            self.emit("locked", reason if reason in ("quota", "schedule", "parent_command") else "offline")
        if not self.plat.session_locked() and now - self._last_lock_cmd >= 3:
            self._last_lock_cmd = now
            self.plat.lock()

    def status(self) -> dict:
        now = self.tg.now()
        day = self._day(now)
        return {"state": self.state, "reason": self.reason, "remaining_sec": self.remaining,
                "used_sec": self.store.usage_get(day, "_total"), "paused": self.paused_until > now,
                "policy_version": (self.policy or {}).get("version"), "set_by": (self.policy or {}).get("set_by"),
                "degraded": self.degraded, "pending_events": self.store.pending_events()}
