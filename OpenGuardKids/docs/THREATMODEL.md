# THREATMODEL.md – STRIDE + checklist ASVS

Ranh giới tin cậy: (1) máy của trẻ [agent SYSTEM | tray user | **tài khoản trẻ = không tin cậy**], (2) mạng, (3) máy chủ, (4) trình duyệt phụ huynh.

## Bảng STRIDE (12 mối đe dọa)

| # | Loại | Mối đe dọa | Tác nhân | Biện pháp trong mã | Rủi ro còn lại |
|---|---|---|---|---|---|
| T1 | S | Giả mạo máy chủ (sửa hosts/DNS/ARP để trỏ agent tới máy chủ giả, phát chính sách "không giới hạn") | Trẻ/mạng LAN | TLS1.2+, **ghim chứng chỉ SHA-256** (`sync.PinnedHTTPSConnection`), chính sách còn **ký HMAC** gắn `device_id` | Mất khoá HMAC = mất bảo vệ; khoá nằm trong ProgramData (ACL) |
| T2 | S | Đánh cắp/dùng lại token thiết bị | Trẻ/malware | Access 15 phút, refresh **xoay vòng** & lưu băm, thu hồi khi gỡ thiết bị; bí mật lưu DPAPI máy | Admin cục bộ đọc được bí mật |
| T3 | T | **Chính trẻ sửa chính sách/CSDL cục bộ** để nới luật | Trẻ | ACL SYSTEM/Administrators ghi; agent **từ chối chính sách sai chữ ký** và chính sách phiên bản thấp hơn (chống rollback); tài khoản trẻ không thuộc Administrators | Nếu trẻ có quyền admin thì vô hiệu (ngoài phạm vi, nêu trong M3) |
| T4 | T | **Chỉnh đồng hồ hệ thống** để kéo dài giờ | Trẻ | `TimeGuard`: đồng hồ đơn điệu + neo giờ máy chủ mỗi nhịp tim; lùi giờ không tăng quota; ghi `clock_changed` | Chỉnh *tiến* khi ngoại tuyến kéo dài có thể reset sớm; được sửa ở lần đồng bộ kế tiếp (M6) |
| T5 | R | Chối bỏ thay đổi luật ("con không biết", "mẹ không đổi") | Phụ huynh/trẻ | Nhật ký kiểm toán: ai, lúc nào, **IP**, giá trị cũ/mới; trẻ xem được tóm tắt (NT5) | Nhật ký trong cùng CSDL – quản trị DB sửa được |
| T6 | I | IDOR: phụ huynh A đọc/sửa trẻ của B | Phụ huynh xấu | Kiểm tra sở hữu **ở tầng truy vấn** (`own_child`, `own_device`) – trả 404; có test | — |
| T7 | I | Lộ CSDL → lộ hoạt động của trẻ | Kẻ tấn công máy chủ | Tối thiểu dữ liệu (không URL/tiêu đề/ảnh), mã hoá AES-GCM tên trẻ/khoá, băm scrypt, lưu 90 ngày rồi xóa | Metadata (tên miền, giờ) vẫn nhạy cảm |
| T8 | I | Chiếm phiên/CSRF trên dashboard | Kẻ tấn công web | Cookie HttpOnly+Secure+SameSite=Lax, phiên 12 giờ huỷ phía máy chủ, **CSRF token** cho mọi thao tác ghi, CSP `default-src 'self'`, JS chỉ dùng `textContent` | — |
| T9 | D | **Trẻ kết thúc agent/dịch vụ** | Trẻ (không admin) | Dịch vụ LocalSystem – tài khoản thường không dừng được; Service Recovery tự khởi động lại; Tray bị tắt → service dựng lại | Admin cục bộ dừng được; phụ huynh thấy "mất liên lạc" trên dashboard |
| T10 | D | Làm ngập máy chủ/dò mật khẩu | Bất kỳ | Giới hạn tần suất theo IP/thiết bị, khóa tài khoản 15 phút sau 5 lần sai, lô sự kiện ≤ 1000 | DoS mạng ở tầng thấp cần WAF/reverse proxy |
| T11 | E | Nâng quyền: DLL hijacking/ghi vào thư mục agent | Trẻ | Thư mục cài đặt/ProgramData ACL chỉ SYSTEM/Admin ghi; agent chạy từ venv trong ProgramData | Phụ thuộc cấu hình Windows đúng |
| T12 | — | **Kịch bản "chính trẻ là kẻ tấn công"** (vượt DNS/VPN/Safe Mode…) | Trẻ | Xem phân tích 9 kỹ thuật ở `BaoCaoKyThuatMang.md` mục M3, có nêu giới hạn | Không có biện pháp kỹ thuật tuyệt đối; kết hợp giáo dục & thoả thuận |
| T13 | — | **Stalkerware: lạm dụng sản phẩm để theo dõi người lớn** | Người dùng xấu | Không có chế độ ẩn; biểu tượng khay luôn hiện + thông báo khi khởi động; **agent tự dừng nếu không hiển thị được biểu tượng** (`runtime._tray_watchdog`); không thu nội dung/vị trí; sự kiện `agent_stopped`; tài liệu nêu phạm vi hợp pháp (con chưa thành niên, có sự đồng ý của phụ huynh, trẻ biết) | Người có quyền admin trên máy người khác vẫn có thể cài; chỉ giảm được, không chặn tuyệt đối. **Cấm cài trên máy người lớn khi họ không biết.** |

## Checklist ASVS (rút gọn, tự đánh giá – điền cột "Đã kiểm chứng" khi nghiệm thu)

| ASVS | Yêu cầu | Hiện thực | Đã kiểm chứng |
|---|---|---|---|
| V2.1 | Mật khẩu ≥ 10 ký tự, băm bằng hàm chậm | scrypt N=2^14, độ dài tối thiểu 10 + độ phức tạp | `test_server_security`, `test_01` |
| V2.2 | Chống brute-force | Khóa 15 phút sau 5 lần sai + rate limit IP | `test_01` |
| V2.8 | TOTP | RFC 6238 (khớp vector chuẩn) | `test_totp_rfc6238_vector` |
| V3.2–3.4 | Quản lý phiên | Token ngẫu nhiên, lưu băm, cookie cờ an toàn, huỷ khi đăng xuất | `test_02` |
| V4.1–4.2 | Kiểm soát truy cập, chống IDOR | `own_child`/`own_device` | `test_03` |
| V5.1 | Kiểm tra đầu vào | Pydantic + `validate_event` + `validate_policy` | `test_05`, `test_unit` |
| V6.2 | Mã hoá dữ liệu nhạy cảm | AES-GCM; khoá từ biến môi trường/DPAPI | `test_aes_gcm_*` |
| V8.3 | Bảo vệ dữ liệu cá nhân, tối thiểu hoá, hết hạn | Lược đồ 7 trường, 90 ngày, nút xoá | `test_09`, `TestEvents` |
| V9.1 | TLS | TLS1.2+, ghim chứng chỉ | `TestPinning` |
| V13 | API | JSON, CSRF, giới hạn tần suất, header bảo mật | `test_02` |
| V14.4 | Header HTTP | CSP, nosniff, X-Frame-Options, no-store | (kiểm tra thủ công bằng DevTools) |
