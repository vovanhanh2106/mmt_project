"""F2 – Quyết định lọc DNS: miễn chặn (NT6) > DoH/canary > SafeSearch > luật phụ huynh > nhóm phân loại > mặc định."""
from __future__ import annotations
from dataclasses import dataclass
from ogk_common.domains import host_matches, longest_suffix_lookup, normalize_host, registered_domain
from ogk_common.classify import category_of
from ogk_common.policy import ALWAYS_ALLOW, CATEGORY_VI

DOH_ENDPOINTS = (
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com", "dns.google", "dns64.dns.google",
    "dns.quad9.net", "doh.opendns.com", "dns.adguard.com", "dns.adguard-dns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
    "doh.libredns.gr", "dns.cloudflare.com",
)
CANARY = ("use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com")   # Firefox/Apple: NXDOMAIN => tắt DoH/Private Relay
SAFESEARCH = {
    "google.com": "forcesafesearch.google.com", "www.google.com": "forcesafesearch.google.com",
    "google.com.vn": "forcesafesearch.google.com", "www.google.com.vn": "forcesafesearch.google.com",
    "www.google.vn": "forcesafesearch.google.com",
    "www.bing.com": "strict.bing.com", "bing.com": "strict.bing.com",
    "www.youtube.com": "restrict.youtube.com", "m.youtube.com": "restrict.youtube.com", "youtube.com": "restrict.youtube.com",
    "youtubei.googleapis.com": "restrict.youtube.com", "youtube.googleapis.com": "restrict.youtube.com",
    "www.youtube-nocookie.com": "restrict.youtube.com",
    "duckduckgo.com": "safe.duckduckgo.com", "www.duckduckgo.com": "safe.duckduckgo.com",
}


@dataclass
class DnsDecision:
    action: str                 # forward | block | rewrite
    qname: str = ""
    domain: str = ""            # tên miền cấp hai (để ghi sự kiện)
    category: str = ""
    target: str = ""            # cho rewrite
    rule: str = ""              # mã luật khớp
    reason: str = ""            # NT4: giải thích cho trẻ


class DnsFilter:
    def __init__(self, classification: dict[str, str], extra_allow: tuple[str, ...] = ()):
        self.table = classification
        self.extra_allow = tuple(extra_allow)

    def decide(self, qname: str, policy: dict, exhausted_groups=frozenset()) -> DnsDecision:
        host = normalize_host(qname)
        dom = registered_domain(host)
        d = DnsDecision("forward", host, dom)
        if any(host_matches(host, a) for a in (*ALWAYS_ALLOW, *self.extra_allow)):
            d.rule = "always_allow"
            return d
        if policy.get("paused_until", 0) and policy["paused_until"] > __import__("time").time():
            return d
        who = policy.get("set_by", "Bố/Mẹ")
        if any(host_matches(host, e) for e in (*DOH_ENDPOINTS, *CANARY)):
            return DnsDecision("block", host, dom, "doh", rule="doh_endpoint",
                               reason="Dịch vụ DNS mã hoá bị chặn để bộ lọc hoạt động đúng.")
        if policy.get("safesearch", True):
            tgt = SAFESEARCH.get(host)
            if tgt:
                return DnsDecision("rewrite", host, dom, target=tgt, rule="safesearch")
        # luật của phụ huynh: khớp dài nhất thắng
        best = None
        for r in policy.get("domain_rules", []):
            if host_matches(host, r["domain"]) and (best is None or len(r["domain"]) > len(best["domain"])):
                best = r
        if best:
            d.rule = f"parent:{best['domain']}"
            if best["action"] == "block":
                d.action, d.reason = "block", best.get("reason") or f"Trang này bị chặn (luật do {best.get('set_by', who)} đặt)."
            return d
        cat = category_of(host, self.table)
        d.category = cat
        mode = policy.get("categories", {}).get(cat, "allow")
        d.rule = f"category:{cat}"
        if mode == "block":
            d.action, d.reason = "block", f"Trang này thuộc nhóm '{CATEGORY_VI[cat]}' – luật do {who} đặt."
        elif mode.startswith("budget:"):
            g = mode.split(":", 1)[1]
            if g in exhausted_groups:
                d.action, d.reason = "block", f"Em đã dùng hết thời gian nhóm '{CATEGORY_VI[cat]}' hôm nay (luật do {who} đặt)."
        return d
