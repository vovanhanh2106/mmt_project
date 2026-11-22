# Báo cáo kỹ thuật hệ thống & mạng (Phụ lục M1–M6)

> **Cách dùng:** các phần *thiết kế/phân tích* đã được soạn theo đúng mã nguồn. Các ô **[ĐIỀN]** là **kết quả đo/thử thực tế** mà nhóm phải tự thực hiện trên máy Windows của mình – không được điền số liệu chưa đo. Khi hoàn tất, xuất file này ra PDF thành `BaoCaoKyThuatMang.pdf`.

## M1. Sơ đồ luồng gói tin khi trẻ mở trang bị chặn

```
 Trình duyệt ──(1) getaddrinfo("m.facebook.com")──▶ Stub resolver (Dnscache) ──(2) UDP/53 → 127.0.0.1──▶ DNS proxy của agent (dnsproxy.py)
                                                                                                             │ (3) parse_question()
                                                                                                             ▼
                                                                            DnsFilter.decide(): miễn chặn → DoH/canary → SafeSearch → luật phụ huynh → nhóm phân loại
                                                                                                             │
                              ┌──────────────── block ───────────────────────────────┬──────────── forward ───────────────┐
                              ▼                                                       ▼                                    ▼
                (4a) phản hồi NXDOMAIN (RCODE=3)                          (4b) UDP/53 → upstream (hoặc DoH của agent)   (4c) rewrite: CNAME → forcesafesearch…
                (5a) sự kiện blocked_domain + cửa sổ Tray                    (5b) trả lời nguyên văn                        + bản ghi A/AAAA của đích
                     "Trang facebook.com bị chặn – nhóm Mạng xã hội, luật do Mẹ Lan đặt" (NT4)
```

Bằng chứng cần nộp: (a) `tcpdump`/Wireshark với bộ lọc `udp.port == 53` chụp được truy vấn A của `facebook.com` từ stub resolver tới `127.0.0.1` và phản hồi RCODE=3: **[ĐIỀN ảnh chụp #1]**; (b) truy vấn của trang được phép đi tiếp tới upstream, thấy gói thứ hai ra card mạng: **[ĐIỀN ảnh #2]**; (c) `nslookup www.google.com 127.0.0.1` thấy CNAME `forcesafesearch.google.com`: **[ĐIỀN ảnh #3]**.
Lệnh gợi ý: `tshark -i "Loopback" -f "udp port 53" -Y dns -T fields -e frame.time_relative -e dns.qry.name -e dns.flags.rcode`.

## M2. So sánh phương án chặn

| Tiêu chí | Tệp `hosts` | **DNS proxy cục bộ (chọn)** | Proxy HTTP(S) | Bộ lọc WFP |
|---|---|---|---|---|
| Độ chính xác | Thấp: khớp từng tên đầy đủ, không có ký tự đại diện cho tên miền con | **Cao**: khớp tên miền + mọi tên miền con; phân loại 6 nhóm; luật dài nhất thắng | Rất cao (thấy cả đường dẫn nếu giải mã) | Trung bình: lọc theo IP/cổng; IP của CDN dùng chung nhiều trang |
| Chặn HTTPS | Có (chặn ở bước phân giải) | **Có, không cần giải mã TLS** (chặn trước khi kết nối) | Chỉ chặn theo tên miền (CONNECT) trừ khi cài CA giả mạo – xâm phạm riêng tư, trái NT2 | Có theo IP, không thấy tên miền |
| Chi phí hiện thực | Rất thấp | **Thấp–vừa** (≈ 200 dòng, chỉ stdlib) | Vừa–cao (xử lý HTTP/1.1, HTTP/2, WebSocket, chứng chỉ) | Cao (API C, driver/callout, ký mã) |
| Khả năng bị vượt | Cao (sửa hosts, DoH, IP trực tiếp) | Trung bình: DoH/đổi DNS/VPN – có biện pháp đối phó (M3) | Trung bình: ứng dụng bỏ qua proxy hệ thống | Thấp hơn (tầng nhân) nhưng vẫn vượt được bằng VPN |
| Ảnh hưởng hiệu năng | Không | **Rất thấp** (đo ở M4: [ĐIỀN]) | Cao hơn (mọi byte đi qua proxy) | Thấp |

**Lý do chọn DNS proxy:** cân bằng giữa độ chính xác, chặn được HTTPS mà không giải mã nội dung (phù hợp nguyên tắc tối thiểu dữ liệu NT2 và danh mục cấm), chi phí hiện thực hợp lý trong 6 tuần, và cho phép SafeSearch bằng CNAME. Giới hạn: không lọc được theo đường dẫn (URL) – nằm ở hạng mục "có thì tốt".

## M3. Phân tích đường vòng (bypass) – mỗi kỹ thuật phải có kết quả thử thật

| # | Kỹ thuật | Mô tả | Kết quả mong đợi theo thiết kế | **Kết quả thử thực tế** | Biện pháp đối phó / chấp nhận rủi ro |
|---|---|---|---|---|---|
| 1 | Đổi DNS thủ công (8.8.8.8) | Trẻ đặt DNS card mạng sang máy chủ khác | Tài khoản thường **không có quyền** đổi; nếu có, `netenforce.dns_is_loopback()` khôi phục; firewall `OGK-Block-DNS` chặn UDP/TCP 53 tới mọi máy chủ ngoài upstream | **[ĐIỀN]** | Đối phó: quyền chuẩn + watchdog + firewall. Giới hạn: admin cục bộ vượt được |
| 2 | DNS-over-HTTPS (trình duyệt) | Chrome/Edge/Firefox gửi DNS qua 443 | Đặt chính sách `DnsOverHttpsMode=off` (Chrome/Edge); NXDOMAIN cho `use-application-dns.net` (Firefox); chặn tên miền các điểm cuối DoH | **[ĐIỀN – bật DoH trong Chrome, nêu rõ kết quả]** | Đối phó như bên trái. Giới hạn: DoH tới **địa chỉ IP** cố định (vd. 1.1.1.1:443) không đi qua DNS → cần luật firewall chặn IP DoH hoặc proxy |
| 3 | DNS-over-TLS | Cổng 853 | Chưa có trong Windows 10/11 cho ứng dụng thường; chặn cổng 853 ra ngoài bằng firewall (nên bổ sung) | **[ĐIỀN]** | Chấp nhận rủi ro thấp / bổ sung luật firewall |
| 4 | VPN/proxy công cộng | Cài app VPN, dùng web proxy | Cài app cần quyền admin → trẻ không cài được; web proxy: tên miền proxy thuộc nhóm "không phù hợp" nếu có trong danh sách | **[ĐIỀN]** | Chấp nhận rủi ro: không thể chặn mọi VPN bằng DNS. Kết hợp thoả thuận gia đình |
| 5 | Truy cập trực tiếp bằng địa chỉ IP | Gõ `http://157.240.x.x` | DNS proxy không thấy → **không chặn được** | **[ĐIỀN]** | Chấp nhận/đề xuất WFP hoặc proxy HTTP(S) (hạng mục "có thì tốt"). Ghi rõ giới hạn |
| 6 | Safe Mode | Khởi động chế độ an toàn | Dịch vụ không chạy trong Safe Mode thường; tài khoản trẻ không có quyền vào cấu hình khởi động | **[ĐIỀN]** | Đối phó ngoài phạm vi: mật khẩu BIOS/BitLocker, tài khoản chuẩn. Chấp nhận rủi ro |
| 7 | Khởi động từ USB | Boot Linux live | Không thể chặn bằng phần mềm | **[ĐIỀN – ghi "không áp dụng"]** | Mật khẩu BIOS/UEFI, Secure Boot, BitLocker. Chấp nhận rủi ro |
| 8 | Tài khoản Windows khác | Đăng nhập tài khoản admin/khách | DNS và dịch vụ áp dụng toàn máy (không theo người dùng) nên vẫn bị lọc; hạn mức thời gian tính theo máy | **[ĐIỀN]** | Vô hiệu tài khoản Khách; không chia sẻ mật khẩu admin |
| 9 | Kết thúc tiến trình | Task Manager / `taskkill` | Tray (quyền người dùng) có thể bị tắt → service dựng lại; service là SYSTEM nên trẻ không dừng được; nếu **không dựng lại được Tray → agent tự dừng và báo** (chống stalkerware) | **[ĐIỀN]** | Service Recovery + watchdog; đây là đánh đổi có chủ đích giữa "không ẩn" và "chống gỡ" |

## M4. Đo hiệu năng (mỗi phép đo ≥ 30 mẫu)

Phương pháp: máy Windows [ĐIỀN cấu hình]; công cụ `tools/measure_agent_resources.py` (psutil, 60 mẫu × 2 s) và `tools/measure_dns_latency.py` (50 truy vấn/phía). *Rảnh* = không thao tác 5 phút; *cao điểm* = mở 10 tab + chạy bộ 50 tên miền + bảng điều khiển đang cấu hình lại.

| Phép đo | Rảnh | Cao điểm |
|---|---|---|
| CPU agent trung bình (%) | [ĐIỀN] | [ĐIỀN] |
| RAM agent (MB) | [ĐIỀN] | [ĐIỀN] |

| Độ trễ DNS | p50 (ms) | p95 (ms) |
|---|---|---|
| Không có agent (trực tiếp upstream) | [ĐIỀN] | [ĐIỀN] |
| Có agent (qua proxy 127.0.0.1) | [ĐIỀN] | [ĐIỀN] |

Độ trễ áp dụng chính sách: đổi luật trên dashboard → đo thời điểm `policy_changed` (ws) / heartbeat kế tiếp tới khi agent đổi hành vi, ≥ 30 lần: p50 [ĐIỀN] s, p95 [ĐIỀN] s (yêu cầu ≤ 60 s). Lệnh khẩn (khóa ngay): p50 [ĐIỀN] s, p95 [ĐIỀN] s (yêu cầu < 5 s).

## M5. Khả năng chịu lỗi

| Kịch bản | Hành vi mong đợi (theo mã) | Hành vi thực tế | Thời gian phục hồi |
|---|---|---|---|
| Mất mạng | Agent tiếp tục đếm giờ, áp chính sách đã lưu (đã xác minh chữ ký), **đệm sự kiện** trong SQLite; khi có mạng gửi theo lô với `batch_id` cố định ⇒ gửi lại không bị đếm hai lần. Quá `offline_max_days` thì theo `fail_mode` (mặc định *fail-open*: lý do ở báo cáo chính) | [ĐIỀN] | [ĐIỀN] |
| Máy chủ ngừng | Như trên; WebSocket tự kết nối lại (backoff 2→60 s); lệnh khẩn đang chờ được gửi ở nhịp tim/kết nối lại | [ĐIỀN] | [ĐIỀN] |
| Agent bị kết thúc | Service Recovery khởi động lại sau 5 s (`sc failure`); trạng thái khóa/ưu tiên (`force_lock`, `override_until`, quota trong ngày) được **nạp lại từ SQLite**; Tray bị tắt → dựng lại trong ≤ ~1 phút | [ĐIỀN] | [ĐIỀN] |

**Quyết định fail-open (cần bảo vệ khi vấn đáp):** sản phẩm chạy trên máy gia đình; máy chủ lab có thể hỏng nhiều ngày và không được làm trẻ mất khả năng học bài. Rủi ro (trẻ cắt kết nối máy chủ để hết hạn chính sách) giảm vì: không có Internet thì cũng không giải trí trực tuyến; dashboard cảnh báo "mất liên lạc"; chỉ sau N ngày (mặc định 7); phụ huynh có thể chọn *fail-closed* cho từng trẻ.

## M6. Đồng bộ thời gian

Cơ chế (`agent/ogk_agent/timeguard.py`): `thời_gian_tin_cậy = mốc_neo + (mono_now − mono_neo)`; mốc neo là **giờ máy chủ** ở mỗi nhịp tim 60 s (hoặc giờ máy lúc khởi động, không bao giờ lùi so với `last_trusted` đã lưu). Độ lệch `|giờ_máy − tin_cậy| > 120 s` ⇒ ghi sự kiện `quota_warning/clock_changed`; quota và ngày chỉ tính theo thời gian tin cậy nên **lùi 3 giờ không tăng quota** (có test `S5_ClockTamper`). Giới hạn đã biết: chỉnh *tiến* khi đang ngoại tuyến có thể làm sang ngày sớm; được phát hiện và sửa ở lần đồng bộ máy chủ kế tiếp; đồng hồ đơn điệu có thể không tăng khi máy ngủ → neo lại theo máy chủ khi có mạng. Số liệu thử: lùi giờ 3 giờ **[ĐIỀN ảnh/nhật ký]**.
