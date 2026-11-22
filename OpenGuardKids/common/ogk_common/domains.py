"""Xử lý tên miền: chuẩn hoá, rút tên miền cấp hai, so khớp tên miền + toàn bộ tên miền con."""
from __future__ import annotations

# Hậu tố nhiều nhãn thường gặp (đủ cho đồ án; production nên dùng Public Suffix List)
MULTI_LABEL_SUFFIXES = {
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "ac.vn", "info.vn", "biz.vn", "name.vn", "pro.vn", "health.vn",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.kr", "com.sg", "com.cn", "com.br", "co.in",
}


def normalize_host(name: str) -> str:
    return (name or "").strip().lower().rstrip(".")


def registered_domain(host: str) -> str:
    """'m.facebook.com' -> 'facebook.com'; 'sub.hcmus.edu.vn' -> 'hcmus.edu.vn'."""
    h = normalize_host(host)
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_matches(host: str, rule: str) -> bool:
    """True nếu host == rule hoặc host là tên miền con của rule."""
    h, r = normalize_host(host), normalize_host(rule)
    return bool(r) and (h == r or h.endswith("." + r))


def suffixes(host: str):
    """Sinh các hậu tố từ dài đến ngắn: a.b.c -> a.b.c, b.c, c."""
    labels = normalize_host(host).split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


def longest_suffix_lookup(host: str, table: dict):
    """Trả về (khoá, giá trị) khớp dài nhất, hoặc (None, None)."""
    for s in suffixes(host):
        if s in table:
            return s, table[s]
    return None, None
