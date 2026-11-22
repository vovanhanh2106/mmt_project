# AI_USAGE.md – Khai báo sử dụng công cụ AI

> Tệp này phải được nhóm rà soát và chỉnh sửa cho đúng với thực tế làm bài. Dưới đây là bản nháp **trung thực về nguồn gốc mã ban đầu**.

| Phần | Công cụ AI | Mức độ | Đã kiểm chứng ra sao |
|---|---|---|---|
| Bộ khung toàn dự án (agent, server, dashboard, tài liệu mẫu) | Claude (Anthropic) | Sinh bản nháp đầu tiên theo đề bài | Xem cột bên dưới |
| Logic lõi: `ogk_common/*`, `timeeval`, `timeguard`, `enforcer`, `app_control`, `dns*`, `store`, `security`, `netenforce.complement_ranges` | Claude | Sinh mã + bộ test | **Đã chạy**: 48 test (unit + 7 kịch bản tích hợp agent, gồm DNS proxy qua UDP loopback thật) đạt trong môi trường kiểm thử của công cụ |
| Server FastAPI/SQLAlchemy (`app.py`, `db.py`), `test_server_api.py` | Claude | Sinh mã | **Chưa chạy được trong môi trường của công cụ** (thiếu thư viện). Nhóm phải chạy `pytest tests` và sửa lỗi nếu có |
| Windows: `winplatform`, `tray`, `service`, `netenforce` (PowerShell/WTS/registry), `install_windows.ps1` | Claude | Sinh mã | **Chưa chạy trên Windows**. Nhóm phải thử trên máy Windows 10/11 sạch |
| Số liệu M1, M3–M6, ảnh chụp, video, báo cáo chính | — | Không do AI tạo | Nhóm tự đo/tự viết |

Nhóm cần bổ sung: những chỗ đã đọc hiểu và sửa, lỗi AI gây ra đã phát hiện, và phần nào nhóm tự viết. Mỗi thành viên phải giải thích được mọi dòng mã khi vấn đáp.
