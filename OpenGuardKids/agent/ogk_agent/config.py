"""Cấu hình & bí mật của agent. Thư mục dữ liệu: %ProgramData%\\OpenGuardKids (ACL: chỉ SYSTEM/Administrators được ghi)."""
from __future__ import annotations
import base64, json, os
from pathlib import Path


def home() -> Path:
    p = Path(os.environ.get("OGK_HOME") or (Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "OpenGuardKids"))
    p.mkdir(parents=True, exist_ok=True)
    return p


DEFAULTS = {"server_url": "", "pin_sha256": "", "device_id": 0, "child_id": 0, "upstream": ["1.1.1.1", "8.8.8.8"],
            "dns_port": 53, "local_port": 47600, "heartbeat_sec": 60}


def load_config() -> dict:
    f = home() / "config.json"
    cfg = dict(DEFAULTS)
    if f.exists():
        cfg.update(json.loads(f.read_text(encoding="utf-8")))
    return cfg


def save_config(cfg: dict) -> None:
    (home() / "config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def _protect(b: bytes) -> bytes:
    try:
        import win32crypt   # DPAPI, phạm vi máy: tài khoản trẻ không đọc được vì tệp có ACL
        return win32crypt.CryptProtectData(b, "ogk", None, None, None, 4)   # CRYPTPROTECT_LOCAL_MACHINE
    except Exception:
        return b


def _unprotect(b: bytes) -> bytes:
    try:
        import win32crypt
        return win32crypt.CryptUnprotectData(b, None, None, None, 4)[1]
    except Exception:
        return b


def save_secrets(sec: dict) -> None:
    f = home() / "secrets.bin"
    f.write_bytes(_protect(json.dumps(sec).encode()))
    try: os.chmod(f, 0o600)
    except OSError: pass


def load_secrets() -> dict:
    f = home() / "secrets.bin"
    return json.loads(_unprotect(f.read_bytes())) if f.exists() else {}


def policy_key(sec: dict) -> bytes:
    return base64.b64decode(sec.get("policy_key", ""))
