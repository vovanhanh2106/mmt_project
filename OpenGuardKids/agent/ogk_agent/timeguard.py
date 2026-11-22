"""M6 – Đồng bộ & chống chỉnh đồng hồ. Thời gian tin cậy = mốc neo + đồng hồ ĐƠN ĐIỆU (không đổi khi người dùng chỉnh giờ).
Mốc neo: giờ máy chủ (mỗi nhịp tim) hoặc, khi chưa có, giờ máy nhưng không bao giờ lùi so với mốc đã lưu."""
from __future__ import annotations
import time


class TimeGuard:
    def __init__(self, store=None, mono=time.monotonic, wall=time.time, skew_threshold: float = 120.0):
        self.store, self.mono, self.wall, self.threshold = store, mono, wall, skew_threshold
        self.tamper: list[int] = []          # độ lệch (giây) đã phát hiện, chờ báo cáo
        self._reported_skew = 0.0
        self.server_synced_at = 0.0
        w = wall()
        last = store.get("last_trusted") if store else None
        if last is not None and w < float(last) - skew_threshold:    # chỉnh lùi rồi khởi động lại
            self.anchor_wall = float(last)
            self.tamper.append(int(w - float(last)))
            self._reported_skew = w - float(last)
        else:
            self.anchor_wall = w
        self.anchor_mono = mono()
        self._last_persist = 0.0

    def now(self) -> float:
        trusted = self.anchor_wall + (self.mono() - self.anchor_mono)
        skew = self.wall() - trusted
        if abs(skew) > self.threshold and abs(skew - self._reported_skew) > self.threshold:
            self.tamper.append(int(skew))
            self._reported_skew = skew
        elif abs(skew) <= self.threshold:
            self._reported_skew = 0.0
        if self.store and trusted - self._last_persist > 30:
            self.store.set("last_trusted", trusted)
            self._last_persist = trusted
        return trusted

    def sync_server(self, server_time: float) -> None:
        """Mỗi nhịp tim: neo lại theo giờ máy chủ; lệch > ngưỡng so với giờ tin cậy hiện tại => ghi nhận."""
        trusted = self.anchor_wall + (self.mono() - self.anchor_mono)
        diff = server_time - trusted
        if abs(diff) > self.threshold:
            self.tamper.append(int(diff))
        self.anchor_wall, self.anchor_mono = float(server_time), self.mono()
        self._reported_skew = self.wall() - server_time if abs(self.wall() - server_time) > self.threshold else 0.0
        self.server_synced_at = self.anchor_mono

    def pop_tamper(self) -> list[int]:
        out, self.tamper = self.tamper, []
        return out

    def last_server_sync_age(self) -> float | None:
        return None if not self.server_synced_at else self.mono() - self.server_synced_at
