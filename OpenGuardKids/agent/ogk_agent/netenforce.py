"""Cưỡng chế phía mạng (cần quyền Administrator, chạy lúc cài đặt và bởi service): trỏ DNS về 127.0.0.1, canh gác cấu hình DNS,
chặn cổng 53 ra ngoài trừ máy chủ upstream, và đặt chính sách trình duyệt tắt DoH. Mọi lệnh đều minh bạch & có thể hoàn tác."""
from __future__ import annotations
import ipaddress, subprocess

FW_RULE = "OGK-Block-DNS"


def complement_ranges(allowed: list[str], v6: bool = False) -> list[str]:
    """Các dải CIDR bao phủ mọi địa chỉ NGOẠI TRỪ allowed (+loopback) – để tạo luật firewall 'chặn tất cả trừ upstream'."""
    root = ipaddress.ip_network("::/0" if v6 else "0.0.0.0/0")
    nets = [root]
    skip = [ipaddress.ip_network("::1/128" if v6 else "127.0.0.0/8")]
    skip += [ipaddress.ip_network(a + ("/128" if v6 else "/32")) for a in allowed if (":" in a) == v6]
    for s in skip:
        nxt = []
        for n in nets:
            if n.overlaps(s):
                nxt.extend(n.address_exclude(s) if n != s and s.subnet_of(n) else [])
            else:
                nxt.append(n)
        nets = nxt
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


def ps(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True, text=True, timeout=60)


def set_dns_to_loopback() -> None:
    ps("Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses 127.0.0.1 }")


def dns_is_loopback() -> bool:
    r = ps("(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0 -and $_.ServerAddresses[0] -ne '127.0.0.1' -and $_.InterfaceAlias -notmatch 'Loopback'}).Count")
    return r.stdout.strip() in ("0", "")


def restore_dns() -> None:
    ps("Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }")


def install_dns_firewall(upstream: list[str]) -> None:
    v4 = ",".join(complement_ranges(upstream))
    ps(f"Remove-NetFirewallRule -DisplayName '{FW_RULE}' -ErrorAction SilentlyContinue; "
       f"New-NetFirewallRule -DisplayName '{FW_RULE}' -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -RemoteAddress {v4}; "
       f"New-NetFirewallRule -DisplayName '{FW_RULE}' -Direction Outbound -Action Block -Protocol TCP -RemotePort 53 -RemoteAddress {v4}")


def remove_dns_firewall() -> None:
    ps(f"Remove-NetFirewallRule -DisplayName '{FW_RULE}' -ErrorAction SilentlyContinue")


def set_browser_doh_policies() -> None:
    """Chrome/Edge: DnsOverHttpsMode=off (chính sách doanh nghiệp). Firefox: policies.json (DNSOverHTTPS Enabled=false, Locked)."""
    import winreg
    for key in (r"SOFTWARE\Policies\Google\Chrome", r"SOFTWARE\Policies\Microsoft\Edge"):
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "DnsOverHttpsMode", 0, winreg.REG_SZ, "off")
