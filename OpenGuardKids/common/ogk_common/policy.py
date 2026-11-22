"""Chính sách: lược đồ, lịch tuần 7x48, chữ ký HMAC (F4), mặc định theo độ tuổi 6–11 (F2)."""
from __future__ import annotations
import hashlib, hmac, json
from typing import Any

SLOTS_PER_DAY = 48
CATEGORIES = ("education", "entertainment", "social", "games", "inappropriate", "unclassified")
CATEGORY_VI = {
    "education": "Học tập", "entertainment": "Giải trí", "social": "Mạng xã hội",
    "games": "Trò chơi", "inappropriate": "Không phù hợp lứa tuổi", "unclassified": "Chưa phân loại",
}
# NT6: danh sách miễn chặn vĩnh viễn (trường học, tổng đài 111, kết nối hệ điều hành)
ALWAYS_ALLOW = ("edu.vn", "moet.gov.vn", "tongdai111.vn", "msftconnecttest.com", "msftncsi.com")


def _sched(start_slot: int, end_slot: int) -> str:
    return "".join("1" if start_slot <= i < end_slot else "0" for i in range(SLOTS_PER_DAY))


AGE_DEFAULT_CATEGORIES = {
    "6-11": {"education": "allow", "entertainment": "allow", "social": "block", "games": "budget:games",
             "inappropriate": "block", "unclassified": "allow"},
    "12-14": {"education": "allow", "entertainment": "allow", "social": "budget:social", "games": "budget:games",
              "inappropriate": "block", "unclassified": "allow"},
    "15-17": {"education": "allow", "entertainment": "allow", "social": "allow", "games": "budget:games",
              "inappropriate": "block", "unclassified": "allow"},
}


def default_policy(child_id: int, age_band: str = "6-11", set_by: str = "Mặc định theo độ tuổi") -> dict:
    cats = dict(AGE_DEFAULT_CATEGORIES.get(age_band, AGE_DEFAULT_CATEGORIES["6-11"]))
    groups = {"games": {"limit_min": 45}}
    if any(v == "budget:social" for v in cats.values()):
        groups["social"] = {"limit_min": 30}
    return {
        "schema": 1, "child_id": child_id, "version": 1, "age_band": age_band,
        "daily_quota_min": {"weekday": 90, "weekend": 120},
        "schedule": [_sched(12, 42)] * 5 + [_sched(12, 44)] * 2,   # T2–T6 06:00–21:00, T7–CN 06:00–22:00
        "idle_timeout_sec": 300, "warn_minutes": [10, 5, 1], "grace_sec": 60,
        "groups": groups, "categories": cats,
        "app_mode": "denylist", "app_rules": [], "domain_rules": [],
        "safesearch": True, "fail_mode": "fail_open", "offline_max_days": 7,
        "paused_until": 0, "set_by": set_by,
    }


def validate_policy(p: dict) -> list[str]:
    errs = []
    sch = p.get("schedule")
    if not (isinstance(sch, list) and len(sch) == 7 and all(isinstance(r, str) and len(r) == SLOTS_PER_DAY and set(r) <= {"0", "1"} for r in sch)):
        errs.append("schedule phải là 7 chuỗi 48 ký tự 0/1")
    q = p.get("daily_quota_min", {})
    for k in ("weekday", "weekend"):
        if not isinstance(q.get(k), int) or not 0 <= q[k] <= 1440:
            errs.append(f"daily_quota_min.{k} phải trong 0..1440")
    if p.get("fail_mode") not in ("fail_open", "fail_closed"):
        errs.append("fail_mode phải là fail_open hoặc fail_closed")
    if p.get("app_mode") not in ("denylist", "allowlist"):
        errs.append("app_mode không hợp lệ")
    cats = p.get("categories", {})
    for c in CATEGORIES:
        v = cats.get(c)
        if v not in ("allow", "block") and not (isinstance(v, str) and v.startswith("budget:")):
            errs.append(f"categories.{c} không hợp lệ")
    for r in p.get("domain_rules", []):
        if r.get("action") not in ("allow", "block") or not r.get("domain"):
            errs.append("domain_rules có mục không hợp lệ")
    for r in p.get("app_rules", []):
        if r.get("action") not in ("allow", "block") or not (r.get("name") or r.get("sha256")):
            errs.append("app_rules có mục không hợp lệ")
    return errs


def quota_for(policy: dict, weekday: int) -> int:
    """Số phút/ngày; weekday: 0=Thứ hai … 6=Chủ nhật."""
    return policy["daily_quota_min"]["weekend" if weekday >= 5 else "weekday"]


def slot_allowed(policy: dict, weekday: int, sec_of_day: int) -> bool:
    return policy["schedule"][weekday][min(sec_of_day // 1800, SLOTS_PER_DAY - 1)] == "1"


def seconds_until_blocked(policy: dict, weekday: int, sec_of_day: int):
    """Giây còn lại đến ô bị khóa kế tiếp (None nếu 48h tới không khóa)."""
    slot = sec_of_day // 1800
    elapsed_in_slot = sec_of_day % 1800
    if policy["schedule"][weekday][slot] != "1":
        return 0
    total = 1800 - elapsed_in_slot
    for i in range(1, 96):
        idx = slot + i
        wd = (weekday + idx // SLOTS_PER_DAY) % 7
        if policy["schedule"][wd][idx % SLOTS_PER_DAY] != "1":
            return total
        total += 1800
    return None


# ---- chữ ký toàn vẹn (HMAC-SHA256) gắn với device_id để chống phát lại sang thiết bị khác ----
def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_envelope(device_id: int, policy: dict, key: bytes) -> dict:
    body = {"device_id": device_id, "policy": policy}
    return {**body, "sig": hmac.new(key, canonical(body), hashlib.sha256).hexdigest()}


def verify_envelope(env: dict, key: bytes, expected_device_id: int) -> bool:
    try:
        body = {"device_id": env["device_id"], "policy": env["policy"]}
        if env["device_id"] != expected_device_id:
            return False
        good = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
        return hmac.compare_digest(good, str(env["sig"]))
    except (KeyError, TypeError):
        return False
