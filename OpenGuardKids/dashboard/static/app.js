"use strict";
const OGK = {
  csrf: "",
  async api(method, path, body) {
    const opt = { method, headers: { "Content-Type": "application/json", "X-CSRF-Token": OGK.csrf }, credentials: "same-origin" };
    if (body !== undefined) opt.body = JSON.stringify(body);
    const r = await fetch(path, opt);
    let data = {}; try { data = await r.json(); } catch (e) { /* trống */ }
    if (r.status === 401 && !location.pathname.startsWith("/login")) { location.href = "/login"; throw new Error("401"); }
    if (!r.ok) { const d = data.detail; throw new Error(Array.isArray(d) ? d.map(x => x.msg || x).join("; ") : (d || r.statusText)); }
    return data;
  },
  el(tag, props, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) { if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v); }
    for (const k of kids.flat()) e.append(k instanceof Node ? k : document.createTextNode(String(k ?? "")));
    return e;                                  // chỉ dùng textContent/Text node => chống XSS
  },
  fmt(sec) { sec = Math.round(sec || 0); return sec >= 3600 ? Math.floor(sec / 3600) + " giờ " + Math.floor(sec % 3600 / 60) + " phút" : Math.floor(sec / 60) + " phút"; },
  when(ts) { return ts ? new Date(ts * 1000).toLocaleString("vi-VN") : "—"; },
  async init() {
    if (location.pathname.startsWith("/login")) return;
    const me = await OGK.api("GET", "/api/me"); OGK.csrf = me.csrf;
    document.getElementById("who").textContent = me.display_name;
    const lo = document.getElementById("logout"); lo.classList.remove("hidden");
    lo.addEventListener("click", async () => { await OGK.api("POST", "/api/auth/logout"); location.href = "/login"; });
  }
};
