"""CLI: python -m ogk_agent <run|enroll|tray|service|status|uninstall>"""
import argparse, getpass, hashlib, logging, socket, sys, uuid
from . import config as C


def fingerprint() -> str:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
            guid = winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception:
        guid = str(uuid.getnode())
    return hashlib.sha256((guid + socket.gethostname()).encode()).hexdigest()     # chỉ lưu băm, không lưu GUID thô


def main():
    ap = argparse.ArgumentParser(prog="ogk_agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll"); e.add_argument("--server", required=True); e.add_argument("--pin", required=True, help="SHA-256 chứng chỉ máy chủ (hex)"); e.add_argument("--code", required=True)
    for n in ("run", "tray", "status", "uninstall"): sub.add_parser(n)
    s = sub.add_parser("service"); s.add_argument("action", choices=["install", "start", "stop", "remove", "restart"])
    a = ap.parse_args()

    if a.cmd == "enroll":
        from .sync import ApiClient
        cl = ApiClient(a.server, a.pin, {})
        res = cl.enroll(a.code.strip().upper(), fingerprint(), socket.gethostname())
        cfg = C.load_config(); cfg.update(server_url=a.server, pin_sha256=a.pin, device_id=res["device_id"], child_id=res["child_id"]); C.save_config(cfg)
        C.save_secrets({"access_token": res["access_token"], "refresh_token": res["refresh_token"], "policy_key": res["policy_key"]})
        print(f"Đã ghép đôi thành công (device_id={res['device_id']}). Việc ghép đôi là sự đồng ý của phụ huynh theo Nghị định 13/2023/NĐ-CP.")
    elif a.cmd == "run":
        logging.basicConfig(level=logging.INFO)
        from .runtime import AgentRuntime
        AgentRuntime().run()
    elif a.cmd == "tray":
        from .tray import main as tray_main; tray_main()
    elif a.cmd == "service":
        from .service import main as svc_main; svc_main([sys.argv[0], a.action])
    elif a.cmd == "status":
        cfg = C.load_config(); print({k: cfg[k] for k in ("server_url", "device_id", "child_id")})
    elif a.cmd == "uninstall":   # quy trình gỡ cài đặt hợp pháp: phụ huynh nhập mật khẩu trên máy trẻ
        from .sync import ApiClient
        cfg, sec = C.load_config(), C.load_secrets()
        cl = ApiClient(cfg["server_url"], cfg["pin_sha256"], sec)
        cl.uninstall_auth(input("Email phụ huynh: "), getpass.getpass("Mật khẩu phụ huynh: "))
        from . import netenforce as N
        N.restore_dns(); N.remove_dns_firewall()
        print("Đã xác thực. Sự kiện gỡ cài đặt đã được ghi lại. Chạy 'python -m ogk_agent service remove' để gỡ dịch vụ.")


if __name__ == "__main__":
    main()
