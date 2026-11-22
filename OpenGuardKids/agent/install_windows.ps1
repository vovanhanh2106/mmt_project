# OpenGuard Kids – cài đặt agent (chạy bằng PowerShell "Run as Administrator").
# Điều kiện: Windows 10/11 x64, Python 3.11+, tài khoản của trẻ KHÔNG thuộc nhóm Administrators.
param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Pin, [Parameter(Mandatory)][string]$Code)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")) { throw "Cần quyền Administrator" }
$data = Join-Path $env:ProgramData "OpenGuardKids"
New-Item -ItemType Directory -Force $data | Out-Null
# ACL: chỉ SYSTEM + Administrators được ghi; Users chỉ đọc (Tray cần đọc local_token)
icacls $data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null
python -m venv "$data\venv"
& "$data\venv\Scripts\pip.exe" install -r "$PSScriptRoot\requirements.txt"
$py = "$data\venv\Scripts\python.exe"
& $py -m ogk_agent enroll --server $Server --pin $Pin --code $Code
& $py -m ogk_agent service install
sc.exe failure OpenGuardKids reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null   # tự khởi động lại khi bị kết thúc
sc.exe config OpenGuardKids start= auto | Out-Null
# Tray tự chạy khi trẻ đăng nhập (hiển thị rõ ràng – KHÔNG ẩn)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OpenGuardKidsTray" -Value "`"$py`" -m ogk_agent tray"
& $py -c "from ogk_agent import netenforce as N, config as C; N.set_browser_doh_policies(); N.set_dns_to_loopback(); N.install_dns_firewall(C.load_config()['upstream'])"
Start-Service OpenGuardKids
Write-Host "Đã cài đặt. Hãy báo cho con biết: biểu tượng OGK ở khay hệ thống cho em xem chương trình ghi nhận gì."
