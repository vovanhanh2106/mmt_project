"""Lược đồ sự kiện (NT2 – tối thiểu dữ liệu). Chỉ 7 trường, subject KHÔNG BAO GIỜ là URL đầy đủ."""
from __future__ import annotations
import re
from .domains import registered_domain

EVENT_TYPES = (
    "app_start", "app_stop", "domain_query", "blocked_app", "blocked_domain",
    "quota_warning", "locked", "unlock_request", "override_granted",
)
FIELDS = ("ts", "device_id", "child_id", "type", "subject", "duration_sec", "policy_id")

APP_TYPES = {"app_start", "app_stop", "blocked_app"}
DOMAIN_TYPES = {"domain_query", "blocked_domain"}

# Các loại còn lại dùng token hệ thống cố định (không chứa dữ liệu cá nhân). Quy ước:
#   quota_warning: warn_10m | warn_5m | warn_1m | clock_changed | tray_missing | agent_stopped | agent_uninstalled
#   locked: quota | schedule | parent_command      override_granted: add_time | unlock | parent_pause
#   unlock_request: more_time | unblock (hoặc tên miền cấp hai)
SYSTEM_SUBJECT_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")
_APP_RE = re.compile(r"^[^\\/:*?\"<>|\x00-\x1f]{1,100}$")  # chỉ tên tệp, không có đường dẫn


def validate_event(ev: dict) -> list[str]:
    errs: list[str] = []
    extra = set(ev) - set(FIELDS)
    if extra:
        errs.append(f"trường không được phép: {sorted(extra)}")
    for f in ("ts", "type", "subject"):
        if f not in ev:
            errs.append(f"thiếu trường {f}")
    if errs:
        return errs
    if not isinstance(ev["ts"], int) or ev["ts"] <= 0:
        errs.append("ts phải là số nguyên epoch giây")
    if ev["type"] not in EVENT_TYPES:
        errs.append("type không hợp lệ")
        return errs
    dur = ev.get("duration_sec", 0)
    if not isinstance(dur, int) or dur < 0 or dur > 86400 * 7:
        errs.append("duration_sec không hợp lệ")
    subj = ev["subject"]
    if not isinstance(subj, str):
        errs.append("subject phải là chuỗi")
        return errs
    t = ev["type"]
    if "/" in subj or "?" in subj or "://" in subj:
        errs.append("subject không được là URL hoặc đường dẫn")
    elif t in DOMAIN_TYPES:
        if not _DOMAIN_RE.match(subj) or registered_domain(subj) != subj:
            errs.append("subject phải là tên miền cấp hai (không URL, không tên miền con)")
    elif t in APP_TYPES:
        if not _APP_RE.match(subj):
            errs.append("subject phải là tên ứng dụng (không đường dẫn)")
    elif not (SYSTEM_SUBJECT_RE.match(subj) or _DOMAIN_RE.match(subj)):
        errs.append("subject không hợp lệ")
    return errs
