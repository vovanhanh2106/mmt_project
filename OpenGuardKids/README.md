# OpenGuard Kids – Công cụ đồng hành, không phải phần mềm theo dõi lén

Ứng dụng hỗ trợ phụ huynh và trẻ em cùng thống nhất thời gian dùng máy Windows 10/11. Kiến trúc client–server: **OGK-Agent** (dịch vụ Windows + Tray) ↔ **OGK-Server** (FastAPI + SQLite) ↔ **Dashboard** web (dùng được trên điện thoại).

```
/common      mã dùng chung: chính sách + chữ ký HMAC, lược đồ sự kiện, phân loại (216 tên miền / 5 nhóm có dữ liệu + "chưa phân loại")
/agent       OGK-Agent: enforcer, DNS proxy 127.0.0.1:53, kiểm soát ứng dụng (SHA-256), Tray, dịch vụ Windows, script cài đặt
/server      OGK-Server: FastAPI, SQLAlchemy, WebSocket lệnh khẩn, báo cáo, nhật ký kiểm toán, tác vụ xóa sau 90 ngày
/dashboard   giao diện phụ huynh (Jinja2 + JS thuần, CSP chặt) – màn hình minh bạch của trẻ nằm ở agent (kidpages.py)
/tests       57 test: unit + 7 kịch bản tích hợp agent + 9 kịch bản tích hợp API server
/docs        PRIVACY.md, PRIVACY_TRE_EM.md, THREATMODEL.md, BaoCaoKyThuatMang.md (M1–M6), AI_USAGE.md
/demo        kịch bản video
/tools       đo hiệu năng DNS/CPU/RAM, nhập danh sách chặn
```

## Trạng thái kiểm chứng (đọc trước khi nộp)

| Thành phần | Trạng thái |
|---|---|
| Logic lõi (thời gian, hạn mức, lịch 7×48, ân hạn, chống chỉnh giờ, chặn app theo hash, lọc DNS + SafeSearch + DoH, DNS proxy qua UDP thật, hàng đợi sự kiện idempotent, bảo mật server) | **Đã chạy: 48 test đạt** |
| Server FastAPI/SQLAlchemy + 9 test API | Đã viết, **chưa chạy** (cần `pip install`); chạy `pytest tests` trên máy nhóm |
| Windows service, Tray, `netenforce`, script PowerShell | Đã viết, **chưa chạy trên Windows** – cần thử trên máy sạch |
| Báo cáo chính, M1–M6 số liệu, ảnh Wireshark, video, phân công % | **Nhóm tự thực hiện** (có khung sẵn trong `docs/`) |

## Cài đặt trong 15 phút

### 1. Máy chủ (Windows/Linux, Python 3.11+)
```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r server/requirements.txt
python server/gen_cert.py <IP-hoặc-hostname-máy-chủ>      # in ra MÃ GHIM SHA-256 – lưu lại cho agent
python server/seed.py                                    # tài khoản demo + mã ghép (hoặc tự đăng ký ở /login)
cd server && uvicorn ogk_server.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile data/server.key --ssl-certfile data/server.crt
```
Mở `https://<máy chủ>:8443/login`. **Tài khoản demo:** `phuhuynh@demo.vn` / `MatKhauDemo2026`.
Biến môi trường (production): `OGK_SECRET`, `OGK_DATA_KEY` (base64 32 byte), `OGK_ALLOW_REGISTRATION=0` sau khi tạo xong tài khoản. `OGK_DEV=1` chỉ dùng khi phát triển (cho HTTP).

### 2. Máy của trẻ (Windows 10/11 x64, PowerShell *Run as Administrator*)
Điều kiện: tài khoản của trẻ **không** thuộc nhóm Administrators; trẻ đã được thông báo và đồng ý đồng hành.
```powershell
cd agent
.\install_windows.ps1 -Server https://<máy chủ>:8443 -Pin <MÃ GHIM> -Code <MÃ GHÉP 8 KÝ TỰ>
```
Script tạo thư mục `%ProgramData%\OpenGuardKids` (ACL), venv, ghép đôi (= ghi nhận sự đồng ý của phụ huynh), cài dịch vụ + tự khởi động lại, Tray tự chạy, trỏ DNS về 127.0.0.1, đặt chính sách tắt DoH của trình duyệt và luật firewall chặn cổng 53 ra ngoài. Gỡ: `.\uninstall_windows.ps1` (hỏi mật khẩu phụ huynh).

Chạy thử không cần dịch vụ (cổng DNS cao, không cần admin): đặt `dns_port` trong `config.json` rồi `python -m ogk_agent run`.

### 3. Kiểm thử
```bash
pip install -r server/requirements.txt -e common
python -m unittest discover -s tests -v        # hoặc: pytest tests
```

## Quyết định thiết kế chính
- **DNS proxy cục bộ** làm cơ chế lọc web (so sánh 4 phương án ở `docs/BaoCaoKyThuatMang.md`): chặn HTTPS không cần giải mã TLS, hợp NT2.
- **Chính sách ký HMAC gắn `device_id`**; agent từ chối chính sách sai chữ ký hoặc phiên bản thấp hơn.
- **Giờ tin cậy = neo máy chủ + đồng hồ đơn điệu** (chống chỉnh giờ).
- **fail-open sau 7 ngày mất liên lạc** (cấu hình được; lý do ở M5).
- Sự kiện đúng **7 trường**, `subject` là tên miền cấp hai/tên ứng dụng; máy chủ từ chối URL đầy đủ. Quy ước token hệ thống cho sự kiện `quota_warning`/`locked`/`override_granted` nêu ở `ogk_common/events.py`.
- Không có chế độ ẩn: nếu Tray không hiển thị được, agent **tự dừng** (chống stalkerware).

## Giới hạn đã biết
Không có DNS-over-TCP phía proxy (phản hồi nhỏ, hiếm khi cần); không lọc URL theo đường dẫn; truy cập bằng IP trực tiếp, VPN và quản trị viên cục bộ không bị chặn được (xem M3); chỉnh giờ *tiến* khi ngoại tuyến lâu chỉ được phát hiện ở lần đồng bộ kế tiếp; bộ phân loại 216 mục chỉ là khởi đầu – dùng `tools/import_blocklist.py` để nạp danh sách riêng (không dùng tên miền người lớn trong bộ test nộp bài).
