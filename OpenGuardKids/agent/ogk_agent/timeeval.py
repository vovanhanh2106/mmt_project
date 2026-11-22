"""F1 – Đánh giá thời gian: lịch tuần 30 phút, hạn mức ngày, ngưỡng cảnh báo 10/5/1 phút. Hàm thuần, dễ kiểm thử."""
from __future__ import annotations
import time
from dataclasses import dataclass
from ogk_common.policy import quota_for, slot_allowed, seconds_until_blocked


@dataclass
class TimeVerdict:
    state: str                 # ok | warn | expired | paused
    reason: str = ""           # quota | schedule | parent_command | ""
    remaining_sec: float | None = None
    warn_level: int | None = None   # 10 | 5 | 1
    text: str = ""


def evaluate_time(policy: dict, now: float, used_sec: float, bonus_sec: float = 0.0,
                  force_lock: bool = False, override_until: float = 0.0, paused_until: float = 0.0) -> TimeVerdict:
    if paused_until > now or policy.get("paused_until", 0) > now:
        return TimeVerdict("paused", text="Phụ huynh đang tạm nghỉ kiểm soát.")
    if force_lock:
        return TimeVerdict("expired", "parent_command", 0, text="Bố/Mẹ đã khóa máy.")
    if override_until > now:
        return TimeVerdict("ok", remaining_sec=override_until - now)
    lt = time.localtime(now)
    sod = lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec
    if not slot_allowed(policy, lt.tm_wday, sod):
        who = policy.get("set_by", "Bố/Mẹ")
        return TimeVerdict("expired", "schedule", 0, text=f"Bây giờ ngoài giờ được dùng máy (lịch do {who} đặt).")
    q_left = quota_for(policy, lt.tm_wday) * 60 + bonus_sec - used_sec
    s_left = seconds_until_blocked(policy, lt.tm_wday, sod)
    remaining, reason = q_left, "quota"
    if s_left is not None and s_left < q_left:
        remaining, reason = s_left, "schedule"
    if remaining <= 0:
        return TimeVerdict("expired", reason, 0, text="Em đã dùng hết thời gian hôm nay." if reason == "quota" else "Đã hết giờ được phép theo lịch.")
    for lvl in sorted(policy.get("warn_minutes", [10, 5, 1])):
        if remaining <= lvl * 60:
            return TimeVerdict("warn", reason, remaining, lvl, f"Còn {lvl} phút nữa là hết giờ.")
    return TimeVerdict("ok", reason, remaining)
