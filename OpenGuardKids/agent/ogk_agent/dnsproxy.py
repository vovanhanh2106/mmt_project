"""DNS proxy cục bộ 127.0.0.1:53 (UDP). Đường đi gói tin: stub resolver -> proxy -> DnsFilter -> upstream/NXDOMAIN (M1)."""
from __future__ import annotations
import logging, random, socket, threading
from concurrent.futures import ThreadPoolExecutor
from . import dnspacket as P
from .dnsfilter import DnsFilter

log = logging.getLogger("ogk.dns")


class DnsProxy:
    def __init__(self, flt: DnsFilter, upstream, get_policy, get_exhausted, on_decision=None, host="127.0.0.1", port=53):
        self.flt, self.up, self.get_policy, self.get_exhausted, self.on_decision = flt, upstream, get_policy, get_exhausted, on_decision
        self.host, self.port = host, port
        self.sock: socket.socket | None = None
        self._stop = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=16)

    def handle(self, data: bytes) -> bytes | None:
        try:
            q = P.parse_question(data)
        except ValueError:
            return None
        policy = self.get_policy()
        if q.qtype not in (P.A, P.AAAA) and policy is not None:
            # loại bản ghi khác (MX, TXT, HTTPS…) vẫn phải qua bộ lọc theo tên
            pass
        dec = self.flt.decide(q.name, policy or {}, self.get_exhausted()) if policy else None
        if dec is None:
            return self._forward(data, q)
        if self.on_decision:
            try: self.on_decision(dec)
            except Exception: log.exception("on_decision")
        if dec.action == "block":
            return P.build_rcode(q, 3)                     # NXDOMAIN + hiển thị lý do qua Tray (NT4)
        if dec.action == "rewrite" and q.qtype in (P.A, P.AAAA):
            try:
                up = self.up.query(P.build_query(random.randint(0, 65535), dec.target, q.qtype))
                rcode, ans = P.parse_answers(up)
                recs = [a for a in ans if a[0] == q.qtype]
                if rcode == 0 and recs:
                    return P.build_rewrite(q, dec.target, recs)
            except Exception:
                log.exception("rewrite thất bại")
            return P.build_rcode(q, 2)
        return self._forward(data, q)

    def _forward(self, data: bytes, q) -> bytes:
        try:
            return self.up.query(data)
        except Exception:
            return P.build_rcode(q, 2)                      # SERVFAIL

    def serve_forever(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            self.pool.submit(self._work, data, addr)

    def _work(self, data, addr):
        resp = self.handle(data)
        if resp and self.sock:
            try: self.sock.sendto(resp, addr)
            except OSError: pass

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True, name="ogk-dns")
        t.start()
        return t

    def stop(self):
        self._stop.set()
        if self.sock:
            self.sock.close()
