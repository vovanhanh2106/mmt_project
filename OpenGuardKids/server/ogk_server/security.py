"""Bảo mật (F5): băm mật khẩu scrypt, token HMAC, mã hoá trường AES-GCM, TOTP, giới hạn tần suất."""
from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, struct, threading, time
from collections import defaultdict, deque
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
MIN_PASSWORD = 10


def b64(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def unb64(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def sha256_hex(s: str | bytes) -> str: return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()


# ---- mật khẩu ----
def password_problems(pw: str) -> list[str]:
    errs = []
    if len(pw) < MIN_PASSWORD: errs.append(f"Mật khẩu tối thiểu {MIN_PASSWORD} ký tự")
    if pw.lower() == pw or pw.upper() == pw or not any(c.isdigit() for c in pw): errs.append("Cần chữ hoa, chữ thường và số")
    return errs


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(h)}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=unb64(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, unb64(h))
    except Exception:
        return False


DUMMY_HASH = hash_password("dummy-password-for-timing")   # chống dò tài khoản qua thời gian phản hồi


# ---- token truy cập (HMAC) ----
def make_token(secret: bytes, payload: dict, ttl: int) -> str:
    body = b64(json.dumps({**payload, "exp": int(time.time()) + ttl}, separators=(",", ":")).encode())
    return body + "." + b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())


def verify_token(secret: bytes, token: str) -> dict | None:
    try:
        body, sig = token.split(".")
        if not hmac.compare_digest(b64(hmac.new(secret, body.encode(), hashlib.sha256).digest()), sig):
            return None
        p = json.loads(unb64(body))
        return p if p["exp"] >= time.time() else None
    except Exception:
        return None


def random_token(n: int = 32) -> str: return secrets.token_urlsafe(n)


PAIR_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
def pairing_code() -> str: return "".join(secrets.choice(PAIR_ALPHABET) for _ in range(8))


# ---- mã hoá trường nhạy cảm (AES-GCM) ----
class FieldCipher:
    def __init__(self, key: bytes):
        assert len(key) == 32
        self.aes = AESGCM(key)

    def encrypt(self, plain: str | bytes) -> str:
        nonce = os.urandom(12)
        data = plain.encode() if isinstance(plain, str) else plain
        return b64(nonce + self.aes.encrypt(nonce, data, None))

    def decrypt(self, token: str) -> bytes:
        raw = unb64(token)
        return self.aes.decrypt(raw[:12], raw[12:], None)

    def decrypt_str(self, token: str) -> str: return self.decrypt(token).decode()


def load_or_create_key(env_name: str, path: str) -> bytes:
    """Khoá lấy từ biến môi trường (base64); nếu chưa có, tạo tệp quyền 0600 (chỉ cho phát triển – production đặt biến môi trường)."""
    v = os.environ.get(env_name)
    if v: return unb64(v)
    if os.path.exists(path):
        return open(path, "rb").read()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    k = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f: f.write(k)
    return k


# ---- TOTP (RFC 6238) – điểm cộng ----
def totp_new_secret() -> str: return base64.b32encode(os.urandom(10)).decode()

def totp_code(secret_b32: str, t: float | None = None, step: int = 30, digits: int = 6) -> str:
    counter = int((t if t is not None else time.time()) // step)
    h = hmac.new(base64.b32decode(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)

def totp_verify(secret_b32: str, code: str, window: int = 1) -> bool:
    now = time.time()
    return any(hmac.compare_digest(totp_code(secret_b32, now + d * 30), code) for d in range(-window, window + 1))


# ---- giới hạn tần suất (cửa sổ trượt, theo khoá) ----
class RateLimiter:
    def __init__(self):
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > window: q.popleft()
            if len(q) >= limit: return False
            q.append(now); return True
