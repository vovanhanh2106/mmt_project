import _path  # noqa
import os, tempfile, unittest
from ogk_common.domains import registered_domain, host_matches, longest_suffix_lookup
from ogk_common.events import validate_event
from ogk_common.policy import (default_policy, validate_policy, sign_envelope, verify_envelope, seconds_until_blocked,
                               slot_allowed, quota_for)
from ogk_common.classify import load_classification, category_of
from ogk_agent import dnspacket as P
from ogk_agent.dnsfilter import DnsFilter
from ogk_agent.app_control import ProcInfo, decide_app, sha256_file, HashCache
from ogk_agent.timeeval import evaluate_time
from ogk_agent.timeguard import TimeGuard
from ogk_agent.store import Store
from helpers import FakeClock, MONDAY_10AM

T = load_classification()


class TestDomains(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("M.Facebook.com."), "facebook.com")
        self.assertEqual(registered_domain("a.b.hcmus.edu.vn"), "hcmus.edu.vn")
    def test_host_matches_subdomain_only_on_label_boundary(self):
        self.assertTrue(host_matches("www.x.com", "x.com"))
        self.assertFalse(host_matches("notx.com", "x.com"))
    def test_longest_suffix(self):
        self.assertEqual(longest_suffix_lookup("a.b.c", {"b.c": 1, "c": 2})[1], 1)


class TestEvents(unittest.TestCase):
    base = {"ts": 1700000000, "type": "domain_query", "subject": "youtube.com", "duration_sec": 0}
    def test_ok(self): self.assertEqual(validate_event(self.base), [])
    def test_full_url_rejected(self):
        self.assertTrue(validate_event({**self.base, "subject": "https://youtube.com/watch?v=1"}))
    def test_subdomain_rejected_for_domain_event(self):
        self.assertTrue(validate_event({**self.base, "subject": "www.youtube.com"}))
    def test_extra_field_rejected(self):
        self.assertTrue(validate_event({**self.base, "window_title": "x"}))
    def test_app_path_rejected(self):
        self.assertTrue(validate_event({**self.base, "type": "app_start", "subject": "C:\\Users\\a\\game.exe"}))


class TestPolicy(unittest.TestCase):
    def test_default_valid(self): self.assertEqual(validate_policy(default_policy(1)), [])
    def test_bad_schedule(self):
        p = default_policy(1); p["schedule"][0] = "1" * 47
        self.assertTrue(validate_policy(p))
    def test_signature_detects_tampering_and_wrong_device(self):
        key = b"k" * 32; env = sign_envelope(7, default_policy(1), key)
        self.assertTrue(verify_envelope(env, key, 7))
        self.assertFalse(verify_envelope(env, key, 8))
        env["policy"]["daily_quota_min"]["weekday"] = 999
        self.assertFalse(verify_envelope(env, key, 7))
    def test_seconds_until_blocked_across_midnight(self):
        p = default_policy(1)
        p["schedule"] = ["1" * 48] * 7; p["schedule"][1] = "0" * 48   # thứ Ba cấm cả ngày
        self.assertEqual(seconds_until_blocked(p, 0, 23 * 3600 + 30 * 60), 1800)
    def test_weekend_quota(self):
        p = default_policy(1); self.assertEqual(quota_for(p, 5), 120); self.assertEqual(quota_for(p, 0), 90)


class TestTimeEval(unittest.TestCase):
    def test_warning_levels(self):
        p = default_policy(1)
        self.assertEqual(evaluate_time(p, MONDAY_10AM, 90 * 60 - 590).warn_level, 10)
        self.assertEqual(evaluate_time(p, MONDAY_10AM, 90 * 60 - 250).warn_level, 5)
        self.assertEqual(evaluate_time(p, MONDAY_10AM, 90 * 60 - 30).warn_level, 1)
        self.assertEqual(evaluate_time(p, MONDAY_10AM, 0).state, "ok")
    def test_quota_expired_and_bonus(self):
        p = default_policy(1)
        self.assertEqual(evaluate_time(p, MONDAY_10AM, 90 * 60).state, "expired")
        self.assertNotEqual(evaluate_time(p, MONDAY_10AM, 90 * 60, bonus_sec=900).state, "expired")


class TestAppControl(unittest.TestCase):
    def test_rename_detected_by_hash(self):
        d = tempfile.mkdtemp(); f = os.path.join(d, "game.exe")
        with open(f, "wb") as fh: fh.write(b"MZ-fake-notepad-binary")
        h = sha256_file(f)
        p = default_policy(1); p["app_rules"] = [{"name": "notepad.exe", "sha256": h, "action": "block"}]
        dec = decide_app(ProcInfo(1, "game.exe", f), HashCache().get(f), p)
        self.assertEqual(dec.action, "block")
        self.assertEqual(decide_app(ProcInfo(2, "other.exe", f.replace("game", "x")), None, p).action, "allow")
    def test_system_process_never_blocked(self):
        p = default_policy(1); p["app_rules"] = [{"name": "explorer.exe", "action": "block"}]
        self.assertEqual(decide_app(ProcInfo(1, "explorer.exe", "C:\\Windows\\explorer.exe"), None, p).action, "allow")


class TestDns(unittest.TestCase):
    def test_packet_roundtrip(self):
        q = P.parse_question(P.build_query(99, "Www.Example.COM", P.A))
        self.assertEqual((q.txid, q.name, q.qtype), (99, "www.example.com", 1))
    def test_nxdomain_flags(self):
        q = P.parse_question(P.build_query(5, "a.com", 1)); r = P.build_rcode(q, 3)
        self.assertEqual(r[3] & 0x0F, 3); self.assertEqual(r[:2], q.txid.to_bytes(2, "big"))
    def test_filter_basics(self):
        f, p = DnsFilter(T), default_policy(1)
        self.assertEqual(f.decide("m.facebook.com", p).action, "block")        # tên miền con bị chặn theo
        self.assertEqual(f.decide("hcmus.edu.vn", p).action, "forward")
        self.assertEqual(f.decide("www.google.com", p).target, "forcesafesearch.google.com")
        self.assertEqual(f.decide("dns.google", p).rule, "doh_endpoint")
        self.assertEqual(f.decide("use-application-dns.net", p).action, "block")
    def test_parent_rule_beats_category(self):
        f, p = DnsFilter(T), default_policy(1)
        p["domain_rules"] = [{"domain": "facebook.com", "action": "allow"}]
        self.assertEqual(f.decide("www.facebook.com", p).action, "forward")
    def test_games_budget_exhausted(self):
        f, p = DnsFilter(T), default_policy(1)
        self.assertEqual(f.decide("roblox.com", p).action, "forward")
        self.assertEqual(f.decide("roblox.com", p, frozenset({"games"})).action, "block")
    def test_acceptance_block_50_allow_20(self):
        f, p = DnsFilter(T), default_policy(1)
        social = [d for d, c in T.items() if c == "social"][:25]
        demo = [f"blocked-demo-{i:02d}.example" for i in range(1, 11)]
        blocked = social + demo + ["m." + d for d in social[:15]]
        self.assertEqual(len(blocked), 50)
        hit = sum(f.decide(d, p).action == "block" for d in blocked)
        self.assertGreaterEqual(hit / 50, 0.95)
        edu = ["moet.gov.vn", "hcmus.edu.vn", "vnu.edu.vn", "hust.edu.vn", "hocmai.vn", "vietjack.com", "olm.vn", "violet.vn", "loigiaihay.com",
               "azota.vn", "khanacademy.org", "wikipedia.org", "duolingo.com", "coursera.org", "scratch.mit.edu", "code.org", "tuoitre.vn",
               "vnexpress.net", "dictionary.cambridge.org", "classroom.google.com"]
        self.assertEqual(sum(f.decide(d, p).action == "block" for d in edu), 0)
    def test_classification_has_200_entries_and_6_groups(self):
        self.assertGreaterEqual(len(T), 200)
        self.assertEqual(set(T.values()), {"education", "entertainment", "social", "games", "inappropriate"})


class TestStoreAndTime(unittest.TestCase):
    def test_batch_is_idempotent_until_ack(self):
        s = Store()
        for i in range(3): s.enqueue_event({"ts": 1 + i, "type": "domain_query", "subject": "a.com"})
        b1, rows1 = s.freeze_batch(); b2, rows2 = s.freeze_batch()
        self.assertEqual((b1, rows1), (b2, rows2)); self.assertEqual(len(rows1), 3)
        s.ack_batch(b1); self.assertEqual(s.pending_events(), 0); self.assertEqual(s.freeze_batch(), (None, []))
    def test_clock_rollback_does_not_move_trusted_time(self):
        c = FakeClock(); tg = TimeGuard(Store(), c.mono, c.wall)
        c.advance(60); before = tg.now()
        c.set_wall(c.w - 3 * 3600)
        self.assertAlmostEqual(tg.now(), before, delta=1)
        self.assertEqual(len(tg.pop_tamper()), 1)
    def test_rollback_across_reboot_detected(self):
        s = Store(); c = FakeClock(); tg = TimeGuard(s, c.mono, c.wall); c.advance(100); tg.now(); s.set("last_trusted", c.w)
        c2 = FakeClock(c.w - 3 * 3600); tg2 = TimeGuard(s, c2.mono, c2.wall)
        self.assertTrue(tg2.pop_tamper()); self.assertGreaterEqual(tg2.now(), c.w - 1)
    def test_server_sync_reanchors(self):
        c = FakeClock(); tg = TimeGuard(Store(), c.mono, c.wall)
        tg.sync_server(c.w + 7200); self.assertTrue(tg.pop_tamper()); self.assertAlmostEqual(tg.now(), c.w + 7200, delta=1)


if __name__ == "__main__":
    unittest.main()
