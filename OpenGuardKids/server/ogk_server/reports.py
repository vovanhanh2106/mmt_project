"""Báo cáo dùng chung cho dashboard phụ huynh và màn hình 'Hôm nay em đã dùng gì' của trẻ (NT5: cùng một bộ dữ liệu)."""
from __future__ import annotations
import time
from sqlalchemy import func, select
from .db import ChildRequest, DailyUsage, Event


def build_report(db, child_id: int, days: int = 7) -> dict:
    days = max(1, min(int(days), 90))
    since = int(time.time()) - days * 86400
    dates = [time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400)) for i in range(days - 1, -1, -1)]
    rows = db.execute(select(DailyUsage.day, func.sum(DailyUsage.used_sec)).where(DailyUsage.child_id == child_id, DailyUsage.day >= dates[0]).group_by(DailyUsage.day)).all()
    per_day = {d: int(s or 0) for d, s in rows}
    daily = [{"day": d, "seconds": per_day.get(d, 0)} for d in dates]

    apps = db.execute(select(Event.subject, func.sum(Event.duration_sec)).where(Event.child_id == child_id, Event.ts >= since, Event.type == "app_stop")
                      .group_by(Event.subject).order_by(func.sum(Event.duration_sec).desc()).limit(10)).all()
    doms = db.execute(select(Event.subject, func.count()).where(Event.child_id == child_id, Event.ts >= since, Event.type == "domain_query")
                      .group_by(Event.subject).order_by(func.count().desc()).limit(10)).all()
    blocked = db.scalar(select(func.count()).where(Event.child_id == child_id, Event.ts >= since, Event.type.in_(("blocked_app", "blocked_domain")))) or 0
    pend = db.scalar(select(func.count()).where(ChildRequest.child_id == child_id, ChildRequest.status == "pending")) or 0
    return {"days": days, "daily": daily, "total_sec": sum(x["seconds"] for x in daily),
            "top_apps": [{"name": n, "seconds": int(s or 0)} for n, s in apps],
            "top_domains": [{"name": n, "count": int(c)} for n, c in doms],
            "blocked": int(blocked), "pending_requests": int(pend)}
