"""OGK-Server (FastAPI). Chạy: uvicorn ogk_server.app:app --ssl-keyfile data/server.key --ssl-certfile data/server.crt"""
# from __future__ import annotations
import asyncio, base64, json, os, re, time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import delete, select, func

from ogk_common.events import validate_event
from ogk_common.policy import default_policy, sign_envelope, validate_policy
from . import security as S
from .db import (AuditLog, Base, Child, ChildRequest, Command, DailyUsage, Device, Event, IngestBatch, PairingCode,
                 Parent, PolicyRec, RefreshToken, SessionRec, make_engine, make_session_factory, now)
from .reports import build_report

RETENTION_DAYS = 90
SESSION_TTL = 12 * 3600
ACCESS_TTL = 15 * 60
REFRESH_TTL = 90 * 86400
DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")
BASE_DIR = Path(__file__).resolve().parents[2]


class Settings:
    def __init__(self, **kw):
        self.data_dir = kw.get("data_dir") or os.environ.get("OGK_DATA_DIR", str(BASE_DIR / "server" / "data"))
        self.db_url = kw.get("db_url") or os.environ.get("OGK_DB_URL", f"sqlite:///{self.data_dir}/ogk.db")
        self.dev = kw.get("dev", os.environ.get("OGK_DEV") == "1")                      # dev: cho phép HTTP, cookie không Secure
        self.allow_registration = kw.get("allow_registration", os.environ.get("OGK_ALLOW_REGISTRATION", "1") == "1")
        self.dashboard_dir = kw.get("dashboard_dir") or str(BASE_DIR / "dashboard")


class Manager:
    """Các kết nối WebSocket của agent (lệnh khẩn < 5 s)."""
    def __init__(self): self.conns: dict[int, WebSocket] = {}
    async def send(self, device_id: int, msg: dict) -> bool:
        ws = self.conns.get(device_id)
        if not ws: return False
        try: await ws.send_json(msg); return True
        except Exception: self.conns.pop(device_id, None); return False


# ---------------- tiện ích ----------------
def purge_old(SF, retention_days: int = RETENTION_DAYS) -> dict:
    """Tác vụ tự động xóa dữ liệu quá hạn lưu trữ (F3)."""
    t = now(); cutoff = t - retention_days * 86400
    day_cut = time.strftime("%Y-%m-%d", time.localtime(cutoff))
    with SF() as db:
        n = {"events": db.execute(delete(Event).where(Event.ts < cutoff)).rowcount,
             "usage": db.execute(delete(DailyUsage).where(DailyUsage.day < day_cut)).rowcount,
             "requests": db.execute(delete(ChildRequest).where(ChildRequest.created_at < cutoff)).rowcount,
             "batches": db.execute(delete(IngestBatch).where(IngestBatch.received_at < t - 7 * 86400)).rowcount}
        db.execute(delete(SessionRec).where(SessionRec.expires_at < t))
        db.execute(delete(PairingCode).where(PairingCode.expires_at < t - 86400))
        db.execute(delete(RefreshToken).where(RefreshToken.expires_at < t))
        db.commit()
    return n


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings()
    os.makedirs(cfg.data_dir, exist_ok=True)
    engine = make_engine(cfg.db_url); Base.metadata.create_all(engine)
    SF = make_session_factory(engine)
    secret = S.load_or_create_key("OGK_SECRET", os.path.join(cfg.data_dir, ".secret"))
    cipher = S.FieldCipher(S.load_or_create_key("OGK_DATA_KEY", os.path.join(cfg.data_dir, ".datakey")))
    limiter, manager = S.RateLimiter(), Manager()

    @asynccontextmanager
    async def lifespan(app):
        async def janitor():
            while True:
                try: await asyncio.to_thread(purge_old, SF)
                except Exception: pass
                await asyncio.sleep(3600)
        task = asyncio.create_task(janitor())
        yield
        task.cancel()

    app = FastAPI(title="OpenGuard Kids Server", version="1.0.0", lifespan=lifespan, docs_url="/api/docs" if cfg.dev else None, redoc_url=None, openapi_url="/api/openapi.json" if cfg.dev else None)
    app.state.SF, app.state.cipher, app.state.manager, app.state.cfg = SF, cipher, manager, cfg
    templates = Jinja2Templates(directory=os.path.join(cfg.dashboard_dir, "templates"))
    app.mount("/static", StaticFiles(directory=os.path.join(cfg.dashboard_dir, "static")), name="static")

    @app.middleware("http")
    async def sec_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"; resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
        if request.url.path.startswith("/api"): resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------------- phụ thuộc ----------------
    def get_db():
        db = SF()
        try: yield db
        finally: db.close()

    def ip_of(request: Request) -> str: return request.client.host if request.client else "?"

    def audit(db, child_id, actor, ip, action, summary="", old=None, new=None):
        db.add(AuditLog(child_id=child_id, actor=actor, ip=ip, action=action, summary=summary[:300],
                        old_value=json.dumps(old, ensure_ascii=False) if old is not None else None,
                        new_value=json.dumps(new, ensure_ascii=False) if new is not None else None))

    def current_session(request: Request, db=Depends(get_db)):
        tok = request.cookies.get("ogk_session")
        if not tok: raise HTTPException(401, "Chưa đăng nhập")
        rec = db.get(SessionRec, S.sha256_hex(tok))
        if not rec or rec.expires_at < now(): raise HTTPException(401, "Phiên hết hạn")
        if request.method not in ("GET", "HEAD", "OPTIONS"):           # CSRF cho mọi thao tác ghi
            if not S.hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), rec.csrf):
                raise HTTPException(403, "CSRF token không hợp lệ")
        return rec

    def current_parent(rec=Depends(current_session), db=Depends(get_db)) -> Parent:
        p = db.get(Parent, rec.parent_id)
        if not p: raise HTTPException(401, "Tài khoản không tồn tại")
        return p

    def own_child(db, parent: Parent, child_id: int) -> Child:
        """Kiểm tra quyền sở hữu Ở TẦNG TRUY VẤN (chống IDOR). admin được xem mọi trẻ."""
        q = select(Child).where(Child.id == child_id)
        if parent.role != "admin": q = q.where(Child.parent_id == parent.id)
        c = db.scalars(q).first()
        if not c: raise HTTPException(404, "Không tìm thấy")
        return c

    def own_device(db, parent: Parent, device_id: int) -> Device:
        q = select(Device).join(Child, Device.child_id == Child.id).where(Device.id == device_id)
        if parent.role != "admin": q = q.where(Child.parent_id == parent.id)
        d = db.scalars(q).first()
        if not d: raise HTTPException(404, "Không tìm thấy")
        return d

    def current_device(request: Request, db=Depends(get_db)) -> Device:
        h = request.headers.get("Authorization", "")
        p = S.verify_token(secret, h[7:]) if h.startswith("Bearer ") else None
        if not p or p.get("k") != "a": raise HTTPException(401, "Token không hợp lệ")
        d = db.get(Device, p["d"])
        if not d or d.revoked: raise HTTPException(401, "Thiết bị đã bị thu hồi")
        return d

    def latest_policy(db, child_id: int) -> tuple[int, dict]:
        r = db.scalars(select(PolicyRec).where(PolicyRec.child_id == child_id).order_by(PolicyRec.version.desc())).first()
        if not r:
            child = db.get(Child, child_id)
            pol = default_policy(child_id, child.age_band if child else "6-11")
            db.add(PolicyRec(child_id=child_id, version=1, body=json.dumps(pol, ensure_ascii=False))); db.commit()
            return 1, pol
        return r.version, json.loads(r.body)

    async def save_policy(db, child: Child, new_body: dict, actor: str, ip: str, action: str, summary: str) -> int:
        ver, old = latest_policy(db, child.id)
        body = {**new_body, "version": ver + 1, "child_id": child.id}
        errs = validate_policy(body)
        if errs: raise HTTPException(422, errs)
        db.add(PolicyRec(child_id=child.id, version=ver + 1, body=json.dumps(body, ensure_ascii=False)))
        audit(db, child.id, actor, ip, action, summary, old, body)
        db.commit()
        for d in child.devices:
            await manager.send(d.id, {"type": "policy_changed", "version": ver + 1})
        return ver + 1

    def issue_tokens(db, dev: Device) -> dict:
        refresh = S.random_token()
        db.add(RefreshToken(device_id=dev.id, token_hash=S.sha256_hex(refresh), expires_at=now() + REFRESH_TTL))
        return {"access_token": S.make_token(secret, {"d": dev.id, "k": "a"}, ACCESS_TTL), "refresh_token": refresh}

    def rate(request: Request, name: str, limit: int, window: int):
        if not limiter.allow(f"{name}:{ip_of(request)}", limit, window): raise HTTPException(429, "Quá nhiều yêu cầu, thử lại sau")

    # ---------------- xác thực phụ huynh ----------------
    class RegisterIn(BaseModel):
        email: str = Field(max_length=200, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        password: str = Field(max_length=200)
        display_name: str = Field(min_length=1, max_length=100)

    class LoginIn(BaseModel):
        email: str = Field(max_length=200)
        password: str = Field(max_length=200)
        totp: str | None = None

    @app.post("/api/auth/register", status_code=201)
    async def register(body: RegisterIn, request: Request, db=Depends(get_db)):
        if not cfg.allow_registration: raise HTTPException(403, "Đăng ký đang đóng")
        rate(request, "register", 5, 3600)
        errs = S.password_problems(body.password)
        if errs: raise HTTPException(422, errs)
        email = body.email.strip().lower()
        if db.scalars(select(Parent).where(Parent.email == email)).first(): raise HTTPException(409, "Email đã được dùng")
        first = db.scalar(select(func.count()).select_from(Parent)) == 0
        p = Parent(email=email, display_name=body.display_name.strip(), pw_hash=S.hash_password(body.password), role="admin" if first else "parent")
        db.add(p); audit(db, None, f"parent:{email}", ip_of(request), "register"); db.commit()
        return {"id": p.id}

    @app.post("/api/auth/login")
    async def login(body: LoginIn, request: Request, response: Response, db=Depends(get_db)):
        rate(request, "login", 20, 600)
        p = db.scalars(select(Parent).where(Parent.email == body.email.strip().lower())).first()
        if p and p.locked_until > now():
            raise HTTPException(429, f"Tài khoản bị khóa tạm thời, thử lại sau {max(1, (p.locked_until - now()) // 60)} phút")
        ok = S.verify_password(body.password, p.pw_hash if p else S.DUMMY_HASH) and p is not None
        if ok and p.totp_enabled:
            ok = bool(body.totp) and S.totp_verify(cipher.decrypt_str(p.totp_secret_enc), body.totp)
        if not ok:
            if p:
                p.failed_count += 1
                if p.failed_count >= 5: p.locked_until, p.failed_count = now() + 900, 0       # khóa 15 phút sau 5 lần sai
                audit(db, None, f"parent:{p.email}", ip_of(request), "login_failed"); db.commit()
            raise HTTPException(401, "Email, mật khẩu hoặc mã 2FA không đúng")
        p.failed_count = 0
        tok, csrf = S.random_token(), S.random_token(16)
        db.add(SessionRec(token_hash=S.sha256_hex(tok), parent_id=p.id, csrf=csrf, expires_at=now() + SESSION_TTL))
        audit(db, None, f"parent:{p.email}", ip_of(request), "login"); db.commit()
        response.set_cookie("ogk_session", tok, max_age=SESSION_TTL, httponly=True, secure=not cfg.dev, samesite="lax", path="/")
        return {"csrf": csrf, "display_name": p.display_name, "role": p.role}

    @app.post("/api/auth/logout")
    async def logout(response: Response, rec=Depends(current_session), db=Depends(get_db)):
        db.delete(rec); db.commit()                                                              # hủy phiên phía máy chủ
        response.delete_cookie("ogk_session", path="/")
        return {"ok": True}

    @app.get("/api/me")
    async def me(rec=Depends(current_session), p=Depends(current_parent)):
        return {"id": p.id, "email": p.email, "display_name": p.display_name, "role": p.role, "csrf": rec.csrf, "totp_enabled": p.totp_enabled}

    @app.post("/api/auth/totp/setup")
    async def totp_setup(p=Depends(current_parent), db=Depends(get_db)):
        sec = S.totp_new_secret(); p.totp_secret_enc, p.totp_enabled = cipher.encrypt(sec), False; db.commit()
        return {"secret": sec, "uri": f"otpauth://totp/OpenGuardKids:{p.email}?secret={sec}&issuer=OpenGuardKids"}

    @app.post("/api/auth/totp/enable")
    async def totp_enable(body: dict = Body(...), p=Depends(current_parent), db=Depends(get_db)):
        if not p.totp_secret_enc or not S.totp_verify(cipher.decrypt_str(p.totp_secret_enc), str(body.get("code", ""))): raise HTTPException(400, "Mã không đúng")
        p.totp_enabled = True; db.commit(); return {"ok": True}

    # ---------------- trẻ, thiết bị, ghép đôi ----------------
    class ChildIn(BaseModel):
        name: str = Field(min_length=1, max_length=50)
        age_band: str = Field(default="6-11", pattern=r"^(6-11|12-14|15-17)$")

    @app.get("/api/children")
    async def list_children(p=Depends(current_parent), db=Depends(get_db)):
        q = select(Child) if p.role == "admin" else select(Child).where(Child.parent_id == p.id)
        out = []
        for c in db.scalars(q.order_by(Child.id)).all():
            out.append({"id": c.id, "name": cipher.decrypt_str(c.name_enc), "age_band": c.age_band,
                        "devices": [{"id": d.id, "hostname": d.hostname, "last_seen": d.last_seen, "state": d.state, "revoked": d.revoked} for d in c.devices],
                        "pending_requests": db.scalar(select(func.count()).where(ChildRequest.child_id == c.id, ChildRequest.status == "pending")) or 0})
        return out

    @app.post("/api/children", status_code=201)
    async def create_child(body: ChildIn, request: Request, p=Depends(current_parent), db=Depends(get_db)):
        c = Child(parent_id=p.id, name_enc=cipher.encrypt(body.name.strip()), age_band=body.age_band)
        db.add(c); db.flush()
        pol = default_policy(c.id, c.age_band, set_by=f"{p.display_name} (mặc định theo độ tuổi {c.age_band})")
        db.add(PolicyRec(child_id=c.id, version=1, body=json.dumps(pol, ensure_ascii=False)))
        audit(db, c.id, f"parent:{p.email}", ip_of(request), "child_created", f"Tạo hồ sơ cho trẻ, độ tuổi {c.age_band}", None, pol); db.commit()
        return {"id": c.id}

    @app.post("/api/children/{child_id}/pairing-code")
    async def pairing(child_id: int, request: Request, p=Depends(current_parent), db=Depends(get_db)):
        c = own_child(db, p, child_id); code = S.pairing_code()
        db.add(PairingCode(child_id=c.id, code_hash=S.sha256_hex(code), expires_at=now() + 600))
        audit(db, c.id, f"parent:{p.email}", ip_of(request), "pairing_code_created"); db.commit()
        return {"code": code, "expires_in": 600}

    @app.delete("/api/devices/{device_id}")
    async def revoke_device(device_id: int, request: Request, p=Depends(current_parent), db=Depends(get_db)):
        d = own_device(db, p, device_id); d.revoked = True
        db.execute(delete(RefreshToken).where(RefreshToken.device_id == d.id))
        audit(db, d.child_id, f"parent:{p.email}", ip_of(request), "device_revoked", d.hostname); db.commit()
        return {"ok": True}

    @app.delete("/api/children/{child_id}/data")
    async def delete_child_data(child_id: int, request: Request, p=Depends(current_parent), db=Depends(get_db)):
        """'Xóa toàn bộ dữ liệu của con tôi': server + yêu cầu agent xóa bộ đệm."""
        c = own_child(db, p, child_id); dev_ids = [d.id for d in c.devices]
        for model in (Event, DailyUsage, ChildRequest):
            db.execute(delete(model).where(model.child_id == c.id))
        if dev_ids: db.execute(delete(IngestBatch).where(IngestBatch.device_id.in_(dev_ids)))
        cmds = [Command(device_id=i, kind="purge_data") for i in dev_ids]; db.add_all(cmds)
        audit(db, c.id, f"parent:{p.email}", ip_of(request), "data_deleted", "Xóa toàn bộ dữ liệu sử dụng"); db.commit()
        for cm in cmds: await manager.send(cm.device_id, {"type": "command", "id": cm.id, "kind": "purge_data"})
        return {"ok": True, "devices_notified": len(dev_ids)}

    # ---------------- chính sách, nhật ký, báo cáo, yêu cầu ----------------
    @app.get("/api/children/{child_id}/policy")
    async def get_policy_parent(child_id: int, p=Depends(current_parent), db=Depends(get_db)):
        c = own_child(db, p, child_id); v, pol = latest_policy(db, c.id); return pol

    @app.put("/api/children/{child_id}/policy")
    async def put_policy(child_id: int, request: Request, body: dict = Body(...), p=Depends(current_parent), db=Depends(get_db)):
        c = own_child(db, p, child_id)
        _, old = latest_policy(db, c.id)
        keys = [k for k in body if k not in ("version", "child_id", "set_by") and body.get(k) != old.get(k)]
        body["set_by"] = p.display_name                                                      # NT4: ai đặt luật
        v = await save_policy(db, c, body, f"parent:{p.email}", ip_of(request), "policy_updated", "Đổi: " + ", ".join(keys or ["(không đổi)"]))
        return {"version": v}

    @app.get("/api/children/{child_id}/audit")
    async def audit_parent(child_id: int, p=Depends(current_parent), db=Depends(get_db)):
        c = own_child(db, p, child_id)
        rows = db.scalars(select(AuditLog).where(AuditLog.child_id == c.id).order_by(AuditLog.id.desc()).limit(200)).all()
        return {"items": [{"ts": r.ts, "actor": r.actor, "ip": r.ip, "action": r.action, "summary": r.summary, "old": r.old_value, "new": r.new_value} for r in rows]}

    @app.get("/api/children/{child_id}/report")
    async def report_parent(child_id: int, days: int = 7, p=Depends(current_parent), db=Depends(get_db)):
        return build_report(db, own_child(db, p, child_id).id, days)

    @app.get("/api/children/{child_id}/requests")
    async def requests_parent(child_id: int, p=Depends(current_parent), db=Depends(get_db)):
        c = own_child(db, p, child_id)
        rows = db.scalars(select(ChildRequest).where(ChildRequest.child_id == c.id).order_by(ChildRequest.id.desc()).limit(100)).all()
        return {"items": [{"id": r.id, "kind": r.kind, "subject": r.subject, "note": r.note, "status": r.status, "response_text": r.response_text, "created_at": r.created_at} for r in rows]}

    class ResolveIn(BaseModel):
        approve: bool
        response_text: str = Field(default="", max_length=300)
        minutes: int = Field(default=15, ge=1, le=240)

    @app.post("/api/requests/{req_id}/resolve")
    async def resolve_request(req_id: int, body: ResolveIn, request: Request, p=Depends(current_parent), db=Depends(get_db)):
        r = db.get(ChildRequest, req_id)
        if not r: raise HTTPException(404, "Không tìm thấy")
        c = own_child(db, p, r.child_id)
        if r.status != "pending": raise HTTPException(409, "Yêu cầu đã được xử lý")
        if body.approve and r.kind == "unblock" and not DOMAIN_RE.match(r.subject.strip().lower()):
            raise HTTPException(422, "Tên miền trong yêu cầu không hợp lệ")
        r.status, r.resolved_at = ("approved" if body.approve else "denied"), now()
        r.response_text = body.response_text or ("Bố/Mẹ đồng ý." if body.approve else "Bố/Mẹ chưa đồng ý lần này.")
        audit(db, c.id, f"parent:{p.email}", ip_of(request), "request_resolved", f"{r.kind} {r.subject}: {r.status}")
        db.commit()
        if body.approve and r.kind == "more_time":
            cm = Command(device_id=r.device_id, kind="add_time", minutes=body.minutes); db.add(cm); db.commit()
            await manager.send(cm.device_id, {"type": "command", "id": cm.id, "kind": "add_time", "minutes": cm.minutes})
        elif body.approve and r.kind == "unblock":
            subj = r.subject.strip().lower()
            _, pol = latest_policy(db, c.id)
            pol["domain_rules"] = [x for x in pol["domain_rules"] if x["domain"] != subj] + [{"domain": subj, "action": "allow", "set_by": p.display_name, "reason": "Bố/Mẹ đã duyệt yêu cầu của con"}]
            pol["set_by"] = p.display_name
            await save_policy(db, c, pol, f"parent:{p.email}", ip_of(request), "policy_updated", f"Mở chặn {subj} theo yêu cầu của trẻ")
        return {"ok": True}

    class CommandIn(BaseModel):
        kind: str = Field(pattern=r"^(lock|unlock|add_time|pause)$")
        minutes: int = Field(default=15, ge=1, le=240)

    @app.post("/api/devices/{device_id}/commands")
    async def send_command(device_id: int, body: CommandIn, request: Request, p=Depends(current_parent), db=Depends(get_db)):
        d = own_device(db, p, device_id)
        cm = Command(device_id=d.id, kind=body.kind, minutes=body.minutes); db.add(cm)
        audit(db, d.child_id, f"parent:{p.email}", ip_of(request), "command", f"{body.kind} {body.minutes if body.kind in ('add_time', 'pause') else ''}".strip()); db.commit()
        pushed = await manager.send(d.id, {"type": "command", "id": cm.id, "kind": cm.kind, "minutes": cm.minutes})
        return {"id": cm.id, "pushed": pushed}

    # ---------------- API cho agent ----------------
    class EnrollIn(BaseModel):
        code: str = Field(min_length=8, max_length=8)
        fingerprint: str = Field(min_length=16, max_length=128)
        hostname: str = Field(max_length=100)

    @app.post("/api/enroll")
    async def enroll(body: EnrollIn, request: Request, db=Depends(get_db)):
        rate(request, "enroll", 10, 600)
        pc = db.scalars(select(PairingCode).where(PairingCode.code_hash == S.sha256_hex(body.code.upper()))).first()
        if not pc or pc.used or pc.expires_at < now(): raise HTTPException(400, "Mã ghép không đúng hoặc đã hết hạn")
        pc.used = True
        key = os.urandom(32)
        dev = Device(child_id=pc.child_id, hostname=body.hostname, fingerprint_hash=S.sha256_hex(body.fingerprint), policy_key_enc=cipher.encrypt(key))
        db.add(dev); db.flush()
        toks = issue_tokens(db, dev)
        audit(db, pc.child_id, "agent", ip_of(request), "device_enrolled", f"Ghép đôi máy {body.hostname} (sự kiện đồng ý của phụ huynh – NĐ 13/2023)")
        db.commit()
        return {"device_id": dev.id, "child_id": pc.child_id, "policy_key": base64.b64encode(key).decode(), **toks}

    @app.post("/api/device/refresh")
    async def refresh(request: Request, body: dict = Body(...), db=Depends(get_db)):
        rate(request, "refresh", 30, 600)
        rt = db.scalars(select(RefreshToken).where(RefreshToken.token_hash == S.sha256_hex(str(body.get("refresh_token", ""))))).first()
        if not rt or rt.revoked or rt.expires_at < now(): raise HTTPException(401, "Refresh token không hợp lệ")
        dev = db.get(Device, rt.device_id)
        if not dev or dev.revoked: raise HTTPException(401, "Thiết bị đã bị thu hồi")
        rt.revoked = True                                                                    # xoay vòng refresh token
        toks = issue_tokens(db, dev); db.commit(); return toks

    @app.post("/api/device/heartbeat")
    async def heartbeat(body: dict = Body(...), dev=Depends(current_device), db=Depends(get_db)):
        dev.last_seen = now(); dev.state = str(body.get("status", ""))[:20]; dev.policy_version_ack = int(body.get("policy_version", 0))
        day = str(body.get("day", time.strftime("%Y-%m-%d")))
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
            du = db.get(DailyUsage, (dev.id, day))
            used = max(0, min(int(body.get("quota_used_sec", 0)), 86400))
            if du: du.used_sec = max(du.used_sec, used)
            else: db.add(DailyUsage(device_id=dev.id, day=day, used_sec=used, child_id=dev.child_id))
        acked = [int(x) for x in body.get("acked", []) if isinstance(x, int)]
        if acked:
            for cm in db.scalars(select(Command).where(Command.device_id == dev.id, Command.id.in_(acked))).all(): cm.acked_at = now()
        pending = db.scalars(select(Command).where(Command.device_id == dev.id, Command.acked_at.is_(None), Command.created_at > now() - 3600).order_by(Command.id)).all()
        ver, _ = latest_policy(db, dev.child_id); db.commit()
        return {"server_time": time.time(), "policy_version": ver, "commands": [{"id": c.id, "kind": c.kind, "minutes": c.minutes} for c in pending]}

    @app.get("/api/device/policy")
    async def device_policy(dev=Depends(current_device), db=Depends(get_db)):
        _, pol = latest_policy(db, dev.child_id)
        return sign_envelope(dev.id, pol, cipher.decrypt(dev.policy_key_enc))

    @app.post("/api/device/events")
    async def device_events(request: Request, body: dict = Body(...), dev=Depends(current_device), db=Depends(get_db)):
        if not limiter.allow(f"ev:{dev.id}", 60, 60): raise HTTPException(429, "Quá nhiều yêu cầu")
        bid, evs = str(body.get("batch_id", "")), body.get("events", [])
        if not re.fullmatch(r"[0-9a-f]{32}", bid) or not isinstance(evs, list) or len(evs) > 1000: raise HTTPException(422, "Lô sự kiện không hợp lệ")
        if db.get(IngestBatch, (dev.id, bid)): return {"accepted": 0, "duplicate": True}      # idempotent: gửi lại không bị đếm hai lần
        ok = bad = 0
        for e in evs:
            if validate_event({k: v for k, v in e.items()} if isinstance(e, dict) else {"x": 1}):
                bad += 1; continue
            db.add(Event(ts=e["ts"], device_id=dev.id, child_id=dev.child_id, type=e["type"], subject=e["subject"], duration_sec=e.get("duration_sec", 0), policy_id=e.get("policy_id")))
            ok += 1
        db.add(IngestBatch(device_id=dev.id, batch_id=bid)); db.commit()
        return {"accepted": ok, "rejected": bad, "duplicate": False}

    @app.post("/api/device/requests")
    async def device_request(request: Request, body: dict = Body(...), dev=Depends(current_device), db=Depends(get_db)):
        if not limiter.allow(f"rq:{dev.id}", 10, 3600): raise HTTPException(429, "Em gửi nhiều quá, đợi một lát nhé")
        kind, subj = body.get("kind"), str(body.get("subject", ""))[:120]
        if kind not in ("more_time", "unblock"): raise HTTPException(422, "Loại yêu cầu không hợp lệ")
        if kind == "unblock":
            subj = subj.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
            if not DOMAIN_RE.match(subj): raise HTTPException(422, "Hãy nhập tên trang web, ví dụ vietjack.com")
        db.add(ChildRequest(child_id=dev.child_id, device_id=dev.id, kind=kind, subject=subj, note=str(body.get("note", ""))[:300])); db.commit()
        return {"ok": True}

    @app.get("/api/device/requests")
    async def device_requests(dev=Depends(current_device), db=Depends(get_db)):
        rows = db.scalars(select(ChildRequest).where(ChildRequest.child_id == dev.child_id).order_by(ChildRequest.id.desc()).limit(20)).all()
        return {"items": [{"kind": r.kind, "subject": r.subject, "status": r.status, "response_text": r.response_text} for r in rows]}

    @app.get("/api/device/summary")
    async def device_summary(days: int = 1, dev=Depends(current_device), db=Depends(get_db)):
        return build_report(db, dev.child_id, days)                                          # NT5: cùng bộ báo cáo với phụ huynh

    @app.get("/api/device/audit")
    async def device_audit(dev=Depends(current_device), db=Depends(get_db)):
        rows = db.scalars(select(AuditLog).where(AuditLog.child_id == dev.child_id, AuditLog.action.in_(("policy_updated", "command", "request_resolved", "child_created"))).order_by(AuditLog.id.desc()).limit(50)).all()
        return {"items": [{"ts": r.ts, "actor": "Bố/Mẹ" if r.actor.startswith("parent:") else r.actor, "summary": r.summary} for r in rows]}

    @app.post("/api/device/uninstall")
    async def device_uninstall(request: Request, body: dict = Body(...), dev=Depends(current_device), db=Depends(get_db)):
        rate(request, "uninstall", 5, 600)
        child = db.get(Child, dev.child_id); par = db.get(Parent, child.parent_id)
        if par.locked_until > now() or par.email != str(body.get("email", "")).strip().lower() or not S.verify_password(str(body.get("password", "")), par.pw_hash):
            par.failed_count += 1
            if par.failed_count >= 5: par.locked_until, par.failed_count = now() + 900, 0
            db.commit(); raise HTTPException(403, "Xác thực phụ huynh thất bại")
        dev.revoked = True; db.execute(delete(RefreshToken).where(RefreshToken.device_id == dev.id))
        db.add(Event(ts=now(), device_id=dev.id, child_id=dev.child_id, type="quota_warning", subject="agent_uninstalled", duration_sec=0))
        audit(db, dev.child_id, f"parent:{par.email}", ip_of(request), "device_uninstalled", dev.hostname); db.commit()
        return {"ok": True}

    @app.websocket("/ws/device")
    async def ws_device(ws: WebSocket):
        h = ws.headers.get("authorization", "")
        p = S.verify_token(secret, h[7:]) if h.startswith("Bearer ") else None
        if not p or p.get("k") != "a": await ws.close(code=4401); return
        with SF() as db:
            d = db.get(Device, p["d"])
            if not d or d.revoked: await ws.close(code=4401); return
            pending = [(c.id, c.kind, c.minutes) for c in db.scalars(select(Command).where(Command.device_id == d.id, Command.acked_at.is_(None), Command.created_at > now() - 3600)).all()]
        await ws.accept(); manager.conns[p["d"]] = ws
        try:
            for cid, kind, minutes in pending: await ws.send_json({"type": "command", "id": cid, "kind": kind, "minutes": minutes})
            while True:
                m = await ws.receive_json()
                if m.get("type") == "ack" and isinstance(m.get("id"), int):
                    with SF() as db:
                        cm = db.get(Command, m["id"])
                        if cm and cm.device_id == p["d"]: cm.acked_at = now(); db.commit()
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            if manager.conns.get(p["d"]) is ws: manager.conns.pop(p["d"], None)

    # ---------------- giao diện web ----------------
    @app.get("/", response_class=HTMLResponse)
    async def page_index(request: Request): return templates.TemplateResponse(request, "index.html", {})
    @app.get("/login", response_class=HTMLResponse)
    async def page_login(request: Request): return templates.TemplateResponse(request, "login.html", {})
    @app.get("/children/{child_id}", response_class=HTMLResponse)
    async def page_child(request: Request, child_id: int): return templates.TemplateResponse(request, "child.html", {"child_id": child_id})

    return app

