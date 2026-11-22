"""Kịch bản tích hợp phía server (cần: pip install -r server/requirements.txt). Tự bỏ qua nếu thiếu FastAPI."""
import _path  # noqa
import os, tempfile, unittest

try:
    from fastapi.testclient import TestClient
    HAVE = True
except Exception:
    HAVE = False

if HAVE:
    from ogk_server.app import Settings, create_app
    from ogk_common.policy import verify_envelope
    import base64


@unittest.skipUnless(HAVE, "thiếu fastapi/httpx")
class ServerApi(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.app = create_app(Settings(data_dir=d, db_url=f"sqlite:///{d}/t.db", dev=True))
        self.c = TestClient(self.app)

    def parent(self, email="a@x.vn", name="Mẹ"):
        c = TestClient(self.app)
        self.assertEqual(c.post("/api/auth/register", json={"email": email, "password": "MatKhau12345", "display_name": name}).status_code, 201)
        csrf = c.post("/api/auth/login", json={"email": email, "password": "MatKhau12345"}).json()["csrf"]
        return c, {"X-CSRF-Token": csrf}

    def enroll(self, c, h, cid):
        code = c.post(f"/api/children/{cid}/pairing-code", headers=h).json()["code"]
        r = TestClient(self.app).post("/api/enroll", json={"code": code, "fingerprint": "f" * 32, "hostname": "PC-BE-AN"})
        self.assertEqual(r.status_code, 200); return r.json()

    def test_01_weak_password_and_lockout(self):
        self.assertEqual(self.c.post("/api/auth/register", json={"email": "w@x.vn", "password": "yeu", "display_name": "x"}).status_code, 422)
        self.parent("l@x.vn")
        for _ in range(5): self.assertEqual(self.c.post("/api/auth/login", json={"email": "l@x.vn", "password": "sai-sai-sai"}).status_code, 401)
        self.assertEqual(self.c.post("/api/auth/login", json={"email": "l@x.vn", "password": "MatKhau12345"}).status_code, 429)  # khóa 15 phút

    def test_02_csrf_required_for_writes(self):
        c, h = self.parent()
        self.assertEqual(c.post("/api/children", json={"name": "An", "age_band": "6-11"}).status_code, 403)
        self.assertEqual(c.post("/api/children", json={"name": "An", "age_band": "6-11"}, headers=h).status_code, 201)

    def test_03_idor_other_parent_cannot_touch_child(self):
        a, ha = self.parent("a@x.vn"); b, hb = self.parent("b@x.vn", "Bố")
        cid = a.post("/api/children", json={"name": "An"}, headers=ha).json()["id"]
        for path in (f"/api/children/{cid}/policy", f"/api/children/{cid}/report", f"/api/children/{cid}/audit"):
            self.assertEqual(b.get(path).status_code, 404)
        self.assertEqual(b.put(f"/api/children/{cid}/policy", json={}, headers=hb).status_code, 404)
        self.assertEqual(b.delete(f"/api/children/{cid}/data", headers=hb).status_code, 404)

    def test_04_enroll_signed_policy_and_expired_code(self):
        a, ha = self.parent(); cid = a.post("/api/children", json={"name": "An"}, headers=ha).json()["id"]
        e = self.enroll(a, ha, cid); dc = TestClient(self.app); dh = {"Authorization": "Bearer " + e["access_token"]}
        env = dc.get("/api/device/policy", headers=dh).json()
        self.assertTrue(verify_envelope(env, base64.b64decode(e["policy_key"]), e["device_id"]))
        env["policy"]["daily_quota_min"]["weekday"] = 1440
        self.assertFalse(verify_envelope(env, base64.b64decode(e["policy_key"]), e["device_id"]))
        self.assertEqual(dc.post("/api/enroll", json={"code": "AAAAAAAA", "fingerprint": "f" * 32, "hostname": "x"}).status_code, 400)

    def test_05_events_idempotent_and_minimisation(self):
        a, ha = self.parent(); cid = a.post("/api/children", json={"name": "An"}, headers=ha).json()["id"]
        e = self.enroll(a, ha, cid); dc = TestClient(self.app); dh = {"Authorization": "Bearer " + e["access_token"]}
        batch = {"batch_id": "a" * 32, "events": [{"ts": 1_700_000_000, "type": "domain_query", "subject": "youtube.com"},
                                                  {"ts": 1_700_000_001, "type": "domain_query", "subject": "https://x.com/path?q=1"},   # URL đầy đủ -> bị từ chối
                                                  {"ts": 1_700_000_002, "type": "app_stop", "subject": "game.exe", "duration_sec": 60, "window_title": "x"}]}
        r1 = dc.post("/api/device/events", json=batch, headers=dh).json(); self.assertEqual((r1["accepted"], r1["rejected"]), (1, 2))
        r2 = dc.post("/api/device/events", json=batch, headers=dh).json(); self.assertTrue(r2["duplicate"])

    def test_06_request_flow_unblock_updates_policy_and_child_sees_audit(self):
        a, ha = self.parent(); cid = a.post("/api/children", json={"name": "An"}, headers=ha).json()["id"]
        e = self.enroll(a, ha, cid); dc = TestClient(self.app); dh = {"Authorization": "Bearer " + e["access_token"]}
        self.assertEqual(dc.post("/api/device/requests", json={"kind": "unblock", "subject": "https://vietjack.com/abc"}, headers=dh).status_code, 200)
        rid = a.get(f"/api/children/{cid}/requests").json()["items"][0]["id"]
        self.assertEqual(a.post(f"/api/requests/{rid}/resolve", json={"approve": True}, headers=ha).status_code, 200)
        pol = a.get(f"/api/children/{cid}/policy").json()
        self.assertTrue(any(r["domain"] == "vietjack.com" and r["action"] == "allow" for r in pol["domain_rules"]))
        items = dc.get("/api/device/audit", headers=dh).json()["items"]; self.assertTrue(items)                  # NT5
        self.assertEqual(dc.get("/api/device/requests", headers=dh).json()["items"][0]["status"], "approved")     # NT3

    def test_07_command_delivered_by_heartbeat_then_acked(self):
        a, ha = self.parent(); cid = a.post("/api/children", json={"name": "An"}, headers=ha).json()["id"]
        e = self.enroll(a, ha, cid); dc = TestClient(self.app); dh = {"Authorization": "Bearer " + e["access_token"]}
        r = a.post(f"/api/devices/{e['device_id']}/commands", json={"kind": "lock"}, headers=ha).json(); self.assertFalse(r["pushed"])
        hb = dc.post("/api/device/heartbeat", json={"status": "ok", "quota_used_sec": 10, "policy_version": 1, "acked": []}, headers=dh).json()
        self.assertEqual(hb["commands"][0]["kind"], "lock")
        hb2 = dc.post("/api/device/heartbeat", json={"status": "locked", "quota_used_sec": 10, "policy_version": 1, "acked": [r["id"]]}, headers=dh).json()
        self.assertEqual(hb2["commands"], [])

    def test_08_revoked_device_rejected_and_data_deletion(self):
        a, ha = self.parent(); cid = a.post("/api/children", json={"name": "An"}, headers=ha).json()["id"]
        e = self.enroll(a, ha, cid); dc = TestClient(self.app); dh = {"Authorization": "Bearer " + e["access_token"]}
        self.assertEqual(a.delete(f"/api/children/{cid}/data", headers=ha).status_code, 200)
        a.delete(f"/api/devices/{e['device_id']}", headers=ha)
        self.assertEqual(dc.get("/api/device/policy", headers=dh).status_code, 401)

    def test_09_retention_job_deletes_old_events(self):
        from ogk_server.app import purge_old
        from ogk_server.db import Event
        SF = self.app.state.SF
        with SF() as db:
            db.add(Event(ts=1_000, device_id=1, child_id=1, type="domain_query", subject="a.com")); db.commit()
        purge_old(SF)
        with SF() as db: self.assertEqual(db.query(Event).count(), 0)


if __name__ == "__main__":
    unittest.main()
