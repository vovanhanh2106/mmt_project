import _path  # noqa
import copy, datetime
from ogk_agent.app_control import ProcInfo
from ogk_agent.enforcer import Enforcer
from ogk_agent.store import Store
from ogk_agent.timeguard import TimeGuard
from ogk_common.policy import default_policy

MONDAY_10AM = datetime.datetime(2026, 11, 16, 10, 0, 0).timestamp()   # thứ Hai


class FakeClock:
    def __init__(self, start=MONDAY_10AM):
        self.m, self.w = 1000.0, start
    def mono(self): return self.m
    def wall(self): return self.w
    def advance(self, s): self.m += s; self.w += s
    def set_wall(self, w): self.w = w          # người dùng chỉnh đồng hồ: đồng hồ đơn điệu không đổi


class FakePlatform:
    def __init__(self):
        self.procs, self.killed, self.locks, self.notes = [], [], 0, []
        self.idle, self.locked = 0.0, False
    def list_processes(self): return [p for p in self.procs if p.pid not in self.killed]
    def kill(self, pid): self.killed.append(pid); return True
    def lock(self): self.locks += 1
    def notify(self, title, text, kind="info"): self.notes.append((kind, title, text))
    def idle_seconds(self): return self.idle
    def session_locked(self): return self.locked


def make_env(policy_changes=None, start=MONDAY_10AM):
    clk = FakeClock(start)
    store = Store(":memory:")
    tg = TimeGuard(store, mono=clk.mono, wall=clk.wall)
    plat = FakePlatform()
    enf = Enforcer(store, tg, plat, device_id=1, child_id=1)
    pol = default_policy(1)
    pol["grace_sec"] = 0
    pol.update(policy_changes or {})
    enf.set_policy(pol)
    return clk, store, plat, enf


def run(clk, enf, seconds, step=1):
    last = None
    for _ in range(int(seconds / step)):
        clk.advance(step)
        last = enf.tick()
    return last


def types(store):
    return [r[1] + ":" + r[2] for r in store.recent_events(1000)][::-1]
