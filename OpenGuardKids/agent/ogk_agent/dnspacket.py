"""Phân tích/tạo gói DNS tối thiểu bằng struct (RFC 1035) – không cần thư viện ngoài. Dùng cho M1."""
from __future__ import annotations
import struct
from dataclasses import dataclass

A, CNAME, AAAA = 1, 5, 28


@dataclass
class Question:
    txid: int
    flags: int
    name: str
    qtype: int
    qclass: int
    raw: bytes   # phần question gốc (để chép vào phản hồi)


def read_name(data: bytes, off: int):
    labels, jumped, end, hops = [], False, None, 0
    while True:
        if off >= len(data):
            raise ValueError("gói bị cắt")
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("con trỏ nén hỏng")
            if not jumped:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            jumped = True
            hops += 1
            if hops > 20:
                raise ValueError("vòng lặp nén")
            continue
        off += 1
        labels.append(data[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels).lower(), (end if jumped else off)


def encode_name(name: str) -> bytes:
    out = b""
    for lab in name.rstrip(".").split("."):
        b = lab.encode("ascii")
        if not 0 < len(b) < 64:
            raise ValueError("nhãn không hợp lệ")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def parse_question(data: bytes) -> Question:
    if len(data) < 12:
        raise ValueError("gói quá ngắn")
    txid, flags, qd = struct.unpack("!HHH", data[:6])
    if flags & 0x8000 or qd != 1:
        raise ValueError("không phải truy vấn đơn giản")
    name, off = read_name(data, 12)
    if off + 4 > len(data):
        raise ValueError("thiếu QTYPE/QCLASS")
    qtype, qclass = struct.unpack("!HH", data[off:off + 4])
    return Question(txid, flags, name, qtype, qclass, data[12:off + 4])


def build_query(txid: int, name: str, qtype: int) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, 1)


def _header(q: Question, rcode: int, an: int) -> bytes:
    flags = 0x8000 | 0x0080 | (q.flags & 0x0100) | rcode
    return struct.pack("!HHHHHH", q.txid, flags, 1, an, 0, 0)


def build_rcode(q: Question, rcode: int) -> bytes:
    """rcode=3 -> NXDOMAIN; rcode=2 -> SERVFAIL."""
    return _header(q, rcode, 0) + q.raw


def rr(owner: bytes, rtype: int, ttl: int, rdata: bytes) -> bytes:
    return owner + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def build_rewrite(q: Question, target: str, records: list[tuple[int, int, bytes]]) -> bytes:
    """CNAME name->target kèm các bản ghi A/AAAA của target (records = [(type, ttl, rdata)])."""
    ans = [rr(b"\xc0\x0c", CNAME, 60, encode_name(target))]
    t = encode_name(target)
    ans += [rr(t, rt, min(ttl, 300), rd) for rt, ttl, rd in records]
    return _header(q, 0, len(ans)) + q.raw + b"".join(ans)


def parse_answers(data: bytes) -> tuple[int, list[tuple[int, int, bytes]]]:
    """Trả về (rcode, [(type, ttl, rdata)]) của phần Answer."""
    txid, flags, qd, an = struct.unpack("!HHHH", data[:8])
    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    out = []
    for _ in range(an):
        _, off = read_name(data, off)
        rtype, _, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        out.append((rtype, ttl, data[off:off + rdlen]))
        off += rdlen
    return flags & 0x000F, out
