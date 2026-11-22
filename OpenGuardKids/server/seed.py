"""Tạo dữ liệu mẫu: phụ huynh demo + 1 trẻ + mã ghép. Chạy: python server/scripts_seed.py"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "common"), os.path.join(ROOT, "server")]
os.environ.setdefault("OGK_DEV", "1")
from fastapi.testclient import TestClient
from ogk_server.app import create_app

app = create_app(); c = TestClient(app)
r = c.post("/api/auth/register", json={"email": "phuhuynh@demo.vn", "password": "MatKhauDemo2026", "display_name": "Mẹ Lan"})
print("register:", r.status_code)
r = c.post("/api/auth/login", json={"email": "phuhuynh@demo.vn", "password": "MatKhauDemo2026"}); csrf = r.json()["csrf"]
h = {"X-CSRF-Token": csrf}
cid = c.post("/api/children", json={"name": "Bé An", "age_band": "6-11"}, headers=h).json()["id"]
print("Tài khoản demo: phuhuynh@demo.vn / MatKhauDemo2026 ; child_id =", cid)
print("Mã ghép (hết hạn sau 10 phút):", c.post(f"/api/children/{cid}/pairing-code", headers=h).json()["code"])
