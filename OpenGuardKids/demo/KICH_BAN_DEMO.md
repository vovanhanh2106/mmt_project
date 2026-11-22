# Kịch bản video demo 5–7 phút (có thuyết minh tiếng Việt)

1. (0:00) Dashboard: tạo hồ sơ "Bé An", tạo mã ghép 8 ký tự; cài agent trên máy Windows sạch; biểu tượng OGK + thông báo khởi động (NT1).
2. **D1 – Thời gian:** đặt quota 3 phút → cảnh báo 10/5/1 phút, ân hạn 60 s, máy khóa đúng hạn. Lịch tuần: đặt ô hiện tại là "khóa" → máy khóa trong 5 s.
3. Đổi tên `notepad.exe` thành `game.exe`, luật chặn theo SHA-256 → tiến trình bị đóng + cửa sổ giải thích lý do và người đặt luật (NT4).
4. **DNS:** mở `facebook.com` (NXDOMAIN + lý do), `vietjack.com` (mở được); `nslookup www.google.com` thấy forcesafesearch; Wireshark minh họa (M1).
5. Đổi DNS sang 8.8.8.8 / bật DoH trong Chrome → nêu kết quả và cách xử lý (M3).
6. Lùi đồng hồ 3 giờ → quota không tăng, sự kiện `clock_changed` hiện trên dashboard.
7. Tray: "Xin thêm giờ", "Em nghĩ trang này bị chặn nhầm" → phụ huynh duyệt trên điện thoại → hiệu lực ≤ 60 s; lệnh khóa ngay < 5 s.
8. Màn hình trẻ: "Ứng dụng này ghi nhận gì về em", "Hôm nay em đã dùng gì", "Ai đã đổi luật". Nút "Xóa toàn bộ dữ liệu của con tôi".
9. Ngắt mạng/tắt server → agent vẫn đếm giờ; bật lại → đồng bộ không trùng sự kiện.
