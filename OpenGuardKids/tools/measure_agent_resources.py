"""M4 – Đo CPU/RAM của agent (>= 30 mẫu). Dùng: python tools/measure_agent_resources.py --name python.exe --cmdline ogk_agent --n 60 --interval 2 > res.csv
Đo 2 lần: lúc rảnh (không dùng máy) và lúc cao điểm (mở nhiều tab/ứng dụng + chạy bộ truy vấn DNS)."""
import argparse, time, psutil
ap = argparse.ArgumentParser(); ap.add_argument("--cmdline", default="ogk_agent"); ap.add_argument("--n", type=int, default=60); ap.add_argument("--interval", type=float, default=2.0)
a = ap.parse_args()
procs = [p for p in psutil.process_iter(["cmdline"]) if a.cmdline in " ".join(p.info["cmdline"] or [])]
if not procs: raise SystemExit("Không thấy tiến trình agent")
for p in procs: p.cpu_percent(None)
print("t,cpu_percent,rss_mb")
for i in range(a.n):
    time.sleep(a.interval)
    print(f"{i*a.interval:.0f},{sum(p.cpu_percent(None) for p in procs):.2f},{sum(p.memory_info().rss for p in procs)/2**20:.1f}")
