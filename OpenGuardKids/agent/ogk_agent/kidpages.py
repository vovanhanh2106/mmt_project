"""Màn hình minh bạch cho trẻ (NT1, NT3, NT5). Ngôn ngữ đơn giản cho học sinh cấp 1; HTML thuần, không gọi dịch vụ ngoài."""
from __future__ import annotations
import html, time

CSS = """body{font-family:'Segoe UI',Arial,sans-serif;background:#fff8e7;color:#2b2b2b;margin:0;padding:16px;max-width:720px;margin:auto;font-size:20px}
h1{color:#d9480f;font-size:30px}.card{background:#fff;border-radius:16px;padding:16px;margin:12px 0;box-shadow:0 2px 6px #0002}
.big{font-size:44px;font-weight:700;color:#2b8a3e}button,a.btn{background:#1c7ed6;color:#fff;border:0;border-radius:12px;padding:12px 18px;font-size:20px;text-decoration:none;display:inline-block;margin:4px}
nav a{margin-right:12px;font-size:18px}.no{color:#c92a2a}.yes{color:#2b8a3e}.bar{background:#ffd8a8;border-radius:8px;height:18px}.bar>i{display:block;background:#f76707;height:18px;border-radius:8px}"""


def page(title: str, body: str, token: str = "") -> str:
    q = f"?t={html.escape(token)}" if token else ""
    nav = f'<nav><a href="/{q}">🏠 Trang chủ</a><a href="/what{q}">🔍 Máy ghi gì?</a><a href="/today{q}">📊 Hôm nay</a><a href="/rules{q}">📜 Luật</a></nav>'
    return f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title><style>{CSS}</style>{nav}<h1>{html.escape(title)}</h1>{body}"


def fmt_min(sec) -> str:
    sec = int(sec or 0)
    return f"{sec // 3600} giờ {sec % 3600 // 60} phút" if sec >= 3600 else f"{sec // 60} phút"


def home(status: dict, requests: list, token: str) -> str:
    rem = status.get("remaining_sec")
    left = "không giới hạn hôm nay" if rem is None else fmt_min(rem)
    reqs = "".join(f"<li>{html.escape(r.get('kind',''))} {html.escape(r.get('subject',''))}: <b>{html.escape(r.get('status',''))}</b> {html.escape(r.get('response_text') or '')}</li>" for r in requests[:8]) or "<li>Em chưa gửi yêu cầu nào.</li>"
    js = """<script>
async function send(kind,subject){const note=prompt('Em muốn nhắn gì cho Bố/Mẹ? (không bắt buộc)')||'';
const r=await fetch('/api/request'+location.search,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind,subject,note})});
alert(r.ok?'Đã gửi cho Bố/Mẹ rồi nhé!':'Chưa gửi được, em thử lại sau nhé.');location.reload()}</script>"""
    return page("Chào em!", f"""<div class=card>Em còn được dùng máy: <div class=big>{left}</div>Hôm nay em đã dùng: {fmt_min(status.get('used_sec'))}</div>
<div class=card><button onclick="send('more_time','more_time')">⏰ Xin thêm giờ</button>
<button onclick="const d=prompt('Trang nào bị chặn nhầm? (ví dụ: vietjack.com)');if(d)send('unblock',d)">🙋 Em nghĩ trang này bị chặn nhầm</button></div>
<div class=card><b>Yêu cầu của em</b><ul>{reqs}</ul></div>
<div class=card>Cần người giúp đỡ? Gọi tổng đài bảo vệ trẻ em <b>111</b> (miễn phí).</div>{js}""", token)


def what() -> str:
    return page("Ứng dụng này ghi nhận gì về em?", """
<div class=card><b class=yes>✔ Máy CÓ ghi:</b><ul><li>Tên chương trình em mở (ví dụ: <i>Minecraft</i>)</li>
<li>Tên chính của trang web em vào (ví dụ: <i>youtube.com</i>)</li><li>Em dùng trong bao lâu</li><li>Lúc nào</li></ul></div>
<div class=card><b class=no>✘ Máy KHÔNG ghi:</b><ul><li>Em gõ chữ gì trên bàn phím</li><li>Tin nhắn, thư, bài làm của em</li>
<li>Hình chụp màn hình</li><li>Địa chỉ đầy đủ của trang web, tiêu đề trang</li></ul></div>
<div class=card>Bố/Mẹ xem được đúng những điều này – em cũng xem được ở mục “Hôm nay”. Dữ liệu tự xóa sau 90 ngày.<br>
Biểu tượng của chương trình luôn hiện ở góc màn hình để em biết chương trình đang chạy.</div>""")


def today(summary: dict, token: str = "") -> str:
    apps = summary.get("top_apps", []); doms = summary.get("top_domains", [])
    mx = max([a["seconds"] for a in apps] + [1])
    arows = "".join(f"<div>{html.escape(a['name'])} – {fmt_min(a['seconds'])}<div class=bar><i style='width:{int(100*a['seconds']/mx)}%'></i></div></div>" for a in apps) or "Chưa có gì."
    drows = "".join(f"<li>{html.escape(d['name'])} ({d['count']} lần)</li>" for d in doms) or "<li>Chưa có gì.</li>"
    return page("Hôm nay em đã dùng gì?", f"""<div class=card>Thời gian dùng máy: <b>{fmt_min(summary.get('total_sec'))}</b><br>Số lần bị chặn: <b>{summary.get('blocked', 0)}</b></div>
<div class=card><b>Chương trình em dùng nhiều</b>{arows}</div><div class=card><b>Trang web em hay vào</b><ul>{drows}</ul></div>""", token)


def rules(audit: list, token: str = "") -> str:
    rows = "".join(f"<li>{time.strftime('%d/%m %H:%M', time.localtime(a['ts']))} – <b>{html.escape(a['actor'])}</b>: {html.escape(a['summary'])}</li>" for a in audit) or "<li>Chưa có thay đổi nào.</li>"
    return page("Ai đã đổi luật?", f"<div class=card>Em được biết mỗi lần Bố/Mẹ thay đổi luật:<ul>{rows}</ul></div>", token)
