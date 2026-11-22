"""5+ kịch bản tích hợp phía agent (bộ điều phối + DNS proxy thật qua UDP loopback)."""
import _path  # noqa
import os, socket, tempfile, threading, unittest
from helpers import make_env, run, types, MONDAY_10AM
from ogk_agent import dnspacket as P
from ogk_agent.app_control import ProcInfo, sha256_file
from ogk_agent.dnsfilter import DnsFilter
from ogk_agent.dnsproxy import DnsProxy
from ogk_common.classify import load_classification


class S1_QuotaLock(unittest.TestCase):
    def test_quota_3_minutes_warns_then_locks_on_time(self):
        clk, store, plat, enf = make_env({"daily_quota_min": {"weekday": 3, "weekend": 3}})
        enf.tick(); r = run(clk, enf, 122)
        self.assertEqual(r["state"], "warn")                   # còn <= 1 phút
        self.assertIn("quota_warning:warn_1m", types(store))
        self.assertEqual(plat.locks, 0)
        r = run(clk, enf, 60)
        self.assertEqual(r["state"], "locked"); self.assertGreaterEqual(plat.locks, 1)
        self.assertIn("locked:quota", types(store))
        used = enf.used_today(); self.assertAlmostEqual(used, 180, delta=3)   # sai số << ±30s

    def test_grace_period_gives_60s_before_lock(self):
        clk, store, plat, enf = make_env({"daily_quota_min": {"weekday": 1, "weekend": 1}, "grace_sec": 60})
        enf.tick(); r = run(clk, enf, 62)
        self.assertEqual(r["state"], "grace"); self.assertEqual(plat.locks, 0)
        self.assertTrue(any(k == "grace" for k, _, _ in plat.notes))
        r = run(clk, enf, 60); self.assertEqual(r["state"], "locked"); self.assertGreaterEqual(plat.locks, 1)

    def test_idle_time_not_counted(self):
        clk, store, plat, enf = make_env(); plat.idle = 600
        enf.tick(); run(clk, enf, 120); self.assertEqual(enf.used_today(), 0)
        plat.idle = 0; run(clk, enf, 60); self.assertAlmostEqual(enf.used_today(), 60, delta=2)

    def test_locked_session_not_counted(self):
        clk, store, plat, enf = make_env(); plat.locked = True
        enf.tick(); run(clk, enf, 120); self.assertEqual(enf.used_today(), 0)


class S2_ScheduleLock(unittest.TestCase):
    def test_start_in_blocked_slot_locks_within_5_seconds(self):
        sched = ["0" * 48] * 7
        clk, store, plat, enf = make_env({"schedule": sched, "grace_sec": 60})
        r = run(clk, enf, 5)
        self.assertEqual(r["state"], "locked"); self.assertGreaterEqual(plat.locks, 1)
        self.assertIn("locked:schedule", types(store))


class S3_RenamedApp(unittest.TestCase):
    def test_renamed_binary_is_killed_and_explained(self):
        d = tempfile.mkdtemp(); f = os.path.join(d, "game.exe")
        with open(f, "wb") as fh: fh.write(b"fake-notepad")
        clk, store, plat, enf = make_env({"app_rules": [{"name": "notepad.exe", "sha256": sha256_file(f), "action": "block", "set_by": "Mẹ"}]})
        plat.procs = [ProcInfo(10, "game.exe", f)]
        enf.tick(); r = run(clk, enf, 1)
        self.assertEqual(plat.killed, [10])
        self.assertIn("blocked_app:game.exe", types(store))
        self.assertTrue(any(k == "blocked" and "Mẹ" in txt for k, _, txt in plat.notes))   # NT4: có lý do + người đặt luật


class S4_DnsProxyOverUdp(unittest.TestCase):
    def test_block_forward_and_safesearch(self):
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); up.bind(("127.0.0.1", 0)); up_port = up.getsockname()[1]
        def fake_upstream():
            while True:
                try: data, a = up.recvfrom(512)
                except OSError: return
                q = P.parse_question(data)
                ans = P.rr(b"\xc0\x0c", 1, 60, bytes([93, 184, 216, 34]))
                up.sendto(P._header(q, 0, 1) + q.raw + ans, a)
        threading.Thread(target=fake_upstream, daemon=True).start()

        class U:   # upstream trỏ vào máy chủ giả trên cổng cao
            def query(self, raw):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(raw, ("127.0.0.1", up_port)); d = s.recvfrom(4096)[0]; s.close(); return d
        clk, store, plat, enf = make_env()
        proxy = DnsProxy(DnsFilter(load_classification()), U(), lambda: enf.policy, lambda: enf.exhausted, enf.on_dns_decision, port=0)
        proxy.sock = None
        # dùng handle() trực tiếp qua socket thật: bind cổng ngẫu nhiên
        proxy.port = 0
        t = proxy.start()
        import time; time.sleep(0.3); port = proxy.sock.getsockname()[1]

        def ask(name, qt=1):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
            s.sendto(P.build_query(4242, name, qt), ("127.0.0.1", port)); d = s.recvfrom(4096)[0]; s.close(); return d
        try:
            self.assertEqual(ask("www.facebook.com")[3] & 0x0F, 3)                  # NXDOMAIN
            ok = ask("vnexpress.net"); self.assertEqual(ok[3] & 0x0F, 0); self.assertEqual(P.parse_answers(ok)[1][0][2], bytes([93, 184, 216, 34]))
            ss = ask("www.google.com"); rc, ans = P.parse_answers(ss)
            self.assertEqual(rc, 0); self.assertEqual(ans[0][0], P.CNAME); self.assertIn(b"forcesafesearch", ss)
        finally:
            proxy.stop(); up.close()
        ev = types(store)
        self.assertIn("blocked_domain:facebook.com", ev); self.assertIn("domain_query:vnexpress.net", ev)


class S5_ClockTamper(unittest.TestCase):
    def test_rewind_3_hours_does_not_grant_time_and_is_recorded(self):
        clk, store, plat, enf = make_env({"daily_quota_min": {"weekday": 5, "weekend": 5}})
        enf.tick(); run(clk, enf, 200)
        used_before = enf.used_today()
        clk.set_wall(clk.w - 3 * 3600)
        run(clk, enf, 5)
        self.assertGreaterEqual(enf.used_today(), used_before)                   # quota không tăng
        self.assertIn("quota_warning:clock_changed", types(store))
        r = run(clk, enf, 120); self.assertEqual(r["state"], "locked")           # vẫn khóa đúng hạn


class S6_OfflineModes(unittest.TestCase):
    def test_fail_open_after_n_days_and_fail_closed(self):
        for mode, expect_lock in (("fail_open", False), ("fail_closed", True)):
            clk, store, plat, enf = make_env({"fail_mode": mode, "offline_max_days": 1, "app_rules": [{"name": "x.exe", "action": "block"}]})
            enf.tick(); clk.advance(86400 + 10); r = enf.tick()
            self.assertEqual(r["state"], "locked" if expect_lock else "degraded_open")
            self.assertEqual(plat.locks > 0, expect_lock)

    def test_offline_events_buffered_then_synced_once(self):
        clk, store, plat, enf = make_env(); enf.tick(); enf.emit("domain_query", "a.com"); enf.emit("domain_query", "b.com")
        b1, rows = store.freeze_batch(); self.assertEqual(len(rows), 2)
        b1b, _ = store.freeze_batch(); self.assertEqual(b1, b1b)                  # gửi lại (mất ACK) => cùng batch_id
        store.ack_batch(b1); self.assertEqual(store.pending_events(), 0)


class S7_ParentCommands(unittest.TestCase):
    def test_lock_addtime_unlock(self):
        clk, store, plat, enf = make_env({"daily_quota_min": {"weekday": 1, "weekend": 1}})
        enf.tick(); run(clk, enf, 70); self.assertEqual(enf.state, "locked")
        enf.apply_command("add_time", 15); r = run(clk, enf, 2); self.assertNotEqual(r["state"], "locked")
        enf.apply_command("lock"); r = run(clk, enf, 2); self.assertEqual(r["state"], "locked")
        enf.apply_command("unlock"); r = run(clk, enf, 2); self.assertNotEqual(r["state"], "locked")
        ev = types(store); self.assertIn("override_granted:add_time", ev); self.assertIn("locked:parent_command", ev)


if __name__ == "__main__":
    unittest.main()
