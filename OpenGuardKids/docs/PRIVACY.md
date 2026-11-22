# PRIVACY.md – Bảng dữ liệu ↔ mục đích ↔ thời hạn ↔ người xem

Nguyên tắc: **tối thiểu dữ liệu (NT2)**. Trường nào không giải thích được mục đích thì không có trong lược đồ.
Căn cứ: Nghị định 13/2023/NĐ-CP (bảo vệ dữ liệu cá nhân – dữ liệu của trẻ em cần sự đồng ý của cha mẹ/người giám hộ), Luật Trẻ em 2016.
Sự đồng ý của phụ huynh được ghi nhận tại bước **ghép đôi** (mã 8 ký tự, hiệu lực 10 phút, có dòng `device_enrolled` trong nhật ký kiểm toán).

## A. Sự kiện hoạt động (bảng `events`, lược đồ đúng 7 trường)

| Trường | Mục đích | Thời hạn lưu | Ai xem được |
|---|---|---|---|
| `ts` (epoch giây) | Dựng biểu đồ theo ngày/tuần, sắp xếp sự kiện | 90 ngày, tự xóa | Phụ huynh sở hữu hồ sơ; trẻ (qua màn hình "Hôm nay em đã dùng gì") |
| `device_id` | Biết sự kiện đến từ máy nào (1 phụ huynh : n trẻ : m máy) | 90 ngày | Phụ huynh sở hữu; không hiển thị cho trẻ |
| `child_id` | Gom báo cáo theo trẻ | 90 ngày | Phụ huynh sở hữu |
| `type` ∈ {app_start, app_stop, domain_query, blocked_app, blocked_domain, quota_warning, locked, unlock_request, override_granted} | Phân loại báo cáo, đếm số lần chặn | 90 ngày | Phụ huynh; trẻ |
| `subject` = tên ứng dụng *hoặc* tên miền **cấp hai** (ví dụ `youtube.com`) hoặc token hệ thống cố định (`warn_5m`, `clock_changed`…) | Top 10 ứng dụng/tên miền; giải thích lý do chặn. **Không bao giờ** là URL đầy đủ (máy chủ từ chối) | 90 ngày | Phụ huynh; trẻ |
| `duration_sec` | Tính thời lượng sử dụng ứng dụng | 90 ngày | Phụ huynh; trẻ |
| `policy_id` | Truy vết luật nào đang áp dụng khi chặn (NT4) | 90 ngày | Phụ huynh; trẻ |

## B. Dữ liệu vận hành khác

| Dữ liệu | Mục đích | Thời hạn | Ai xem |
|---|---|---|---|
| `daily_usage` (thiết bị, ngày, số giây) | Biểu đồ thời gian dùng máy; đối chiếu hạn mức | 90 ngày | Phụ huynh; trẻ |
| Tên trẻ (mã hoá AES-GCM) | Hiển thị trên dashboard | Đến khi xóa hồ sơ | Phụ huynh |
| Độ tuổi (khoảng 6-11/12-14/15-17) | Chọn luật mặc định | Đến khi xóa hồ sơ | Phụ huynh |
| Email, tên hiển thị, băm mật khẩu (scrypt), bí mật TOTP (mã hoá) | Đăng nhập phụ huynh | Đến khi xóa tài khoản | Chủ tài khoản (băm không ai đọc được) |
| Băm vân tay thiết bị (SHA-256 của MachineGuid+hostname) | Nhận diện thiết bị khi ghép đôi, không lưu GUID thô | Đến khi thu hồi thiết bị | Phụ huynh (chỉ thấy hostname) |
| Hostname máy | Phân biệt máy với nhau | Đến khi thu hồi | Phụ huynh |
| Khoá HMAC chính sách (mã hoá AES-GCM) | Ký chính sách để agent từ chối chính sách bị sửa | Đến khi thu hồi | Không ai (chỉ máy chủ và agent) |
| Nhật ký kiểm toán (ai, lúc nào, IP, giá trị cũ/mới) | Trách nhiệm giải trình; trẻ được xem (NT5) – **trẻ không thấy IP và giá trị chi tiết, chỉ thấy tóm tắt** | Không tự xóa cùng sự kiện; xóa khi xóa hồ sơ | Phụ huynh (đầy đủ); trẻ (tóm tắt) |
| Yêu cầu của trẻ (xin giờ/báo chặn nhầm) + phản hồi | NT3: trẻ có tiếng nói | 90 ngày | Phụ huynh; trẻ |
| Phiên đăng nhập (băm token) | Duy trì phiên 12 giờ | Hết hạn tự xóa | Hệ thống |

## C. Dữ liệu KHÔNG thu thập
Nội dung phím gõ, tin nhắn/email/tài liệu, ảnh chụp màn hình, tiêu đề cửa sổ, URL đầy đủ/đường dẫn/tham số truy vấn, lịch sử tìm kiếm, vị trí, camera/micro. Không gửi dữ liệu tới bên thứ ba.

## D. Quyền của chủ thể dữ liệu
- **Xem**: dashboard phụ huynh + màn hình của trẻ dùng *cùng một hàm báo cáo*.
- **Xóa**: nút "Xóa toàn bộ dữ liệu của con tôi" xóa trên máy chủ và gửi lệnh `purge_data` để agent xóa bộ đệm cục bộ; tác vụ nền tự xóa sau 90 ngày.
- **Rút lại đồng ý**: thu hồi thiết bị / gỡ cài đặt bằng mật khẩu phụ huynh (có ghi sự kiện).
