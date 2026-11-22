# Gỡ cài đặt hợp pháp: yêu cầu mật khẩu phụ huynh (xác thực với máy chủ) rồi hoàn tác DNS/firewall/dịch vụ.
$data = Join-Path $env:ProgramData "OpenGuardKids"; $py = "$data\venv\Scripts\python.exe"
& $py -m ogk_agent uninstall
if ($LASTEXITCODE -eq 0) {
  Stop-Service OpenGuardKids -ErrorAction SilentlyContinue
  & $py -m ogk_agent service remove
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OpenGuardKidsTray" -ErrorAction SilentlyContinue
  Write-Host "Đã gỡ. Dữ liệu còn lại ở $data (có thể xóa)."
}
