"""Truy vấn DNS phía trên (UDP có fallback TCP, hoặc DoH do chính agent thực hiện để có thể khóa cổng 53 ra ngoài)."""
from __future__ import annotations
import socket, struct, urllib.request


class UdpUpstream:
    def __init__(self, servers: list[str], timeout: float = 2.0):
        self.servers, self.timeout = servers, timeout

    def query(self, raw: bytes) -> bytes:
        last = None
        for s in self.servers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(raw, (s, 53))
                    data, _ = sock.recvfrom(4096)
                if data[:2] != raw[:2]:
                    continue
                if data[2] & 0x02:   # TC => thử TCP
                    return self._tcp(s, raw)
                return data
            except OSError as e:
                last = e
        raise TimeoutError(f"upstream không phản hồi: {last}")

    def _tcp(self, server: str, raw: bytes) -> bytes:
        with socket.create_connection((server, 53), timeout=self.timeout) as s:
            s.sendall(struct.pack("!H", len(raw)) + raw)
            n = struct.unpack("!H", s.recv(2))[0]
            buf = b""
            while len(buf) < n:
                buf += s.recv(n - len(buf))
            return buf


class DohUpstream:
    def __init__(self, url: str = "https://1.1.1.1/dns-query", timeout: float = 3.0):
        self.url, self.timeout = url, timeout

    def query(self, raw: bytes) -> bytes:
        req = urllib.request.Request(self.url, data=raw, headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return r.read()
