"""M4 – Đo độ trễ phân giải DNS (p50/p95, >= 30 mẫu): trực tiếp tới upstream vs qua DNS proxy của agent.
Dùng: python tools/measure_dns_latency.py --proxy 127.0.0.1 --upstream 1.1.1.1 --n 50 > dns_latency.csv"""
import argparse, os, random, socket, statistics, sys, time
sys.path[:0] = [os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), d) for d in ("agent", "common")]
from ogk_agent import dnspacket as P

NAMES = ["vnexpress.net", "tuoitre.vn", "wikipedia.org", "hcmus.edu.vn", "olm.vn", "vietjack.com", "khanacademy.org", "duolingo.com", "example.com", "moet.gov.vn"]


def one(server, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    t0 = time.perf_counter(); s.sendto(P.build_query(random.randint(1, 65535), name, 1), (server, 53))
    try: s.recvfrom(4096); dt = (time.perf_counter() - t0) * 1000
    except socket.timeout: dt = None
    s.close(); return dt


def pct(v, p): v = sorted(v); return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))]


ap = argparse.ArgumentParser(); ap.add_argument("--proxy", default="127.0.0.1"); ap.add_argument("--upstream", default="1.1.1.1"); ap.add_argument("--n", type=int, default=50)
a = ap.parse_args()
print("target,p50_ms,p95_ms,mean_ms,samples,timeouts")
for label, srv in (("direct_upstream", a.upstream), ("via_agent_proxy", a.proxy)):
    xs, to = [], 0
    for i in range(a.n):
        dt = one(srv, random.choice(NAMES)); (xs.append(dt) if dt is not None else None); to += dt is None; time.sleep(0.05)
    print(f"{label},{pct(xs,50):.2f},{pct(xs,95):.2f},{statistics.mean(xs):.2f},{len(xs)},{to}" if xs else f"{label},NA,NA,NA,0,{to}")
