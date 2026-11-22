"use strict";
(async () => {
  await OGK.init();
  const $ = id => document.getElementById(id), id = $("title").dataset.child, base = "/api/children/" + id;
  let policy = null;
  const CAT = { education: "Học tập", entertainment: "Giải trí", social: "Mạng xã hội", games: "Trò chơi", inappropriate: "Không phù hợp lứa tuổi", unclassified: "Chưa phân loại" };
  const DAYS = ["T2", "T3", "T4", "T5", "T6", "T7", "CN"];

  document.querySelectorAll(".tabs button").forEach(b => b.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach(x => x.classList.toggle("on", x === b));
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("hidden", t.id !== "tab-" + b.dataset.tab));
    ({ report: loadReport, devices: loadDevices, requests: loadReqs, audit: loadAudit })[b.dataset.tab]?.();
  }));

  // ---- báo cáo ----
  let lastReport = null;
  async function loadReport() {
    const r = lastReport = await OGK.api("GET", base + "/report?days=" + $("days").value);
    const mx = Math.max(1, ...r.daily.map(d => d.seconds)), ch = $("chart"); ch.replaceChildren();
    r.daily.forEach(d => { const b = OGK.el("div", { class: "bar", title: d.day + ": " + OGK.fmt(d.seconds) }, OGK.el("b", {}, Math.round(d.seconds / 60)), OGK.el("span", {}, d.day.slice(5))); b.style.height = Math.max(2, 100 * d.seconds / mx) + "%"; ch.append(b); });
    $("total").textContent = "Tổng: " + OGK.fmt(r.total_sec) + " (phút mỗi ngày hiển thị trên cột)";
    const fill = (t, rows, f) => { t.replaceChildren(...(rows.length ? rows.map(f) : [OGK.el("tr", {}, OGK.el("td", {}, "Chưa có dữ liệu"))])); };
    fill($("apps"), r.top_apps, a => OGK.el("tr", {}, OGK.el("td", {}, a.name), OGK.el("td", {}, OGK.fmt(a.seconds))));
    fill($("domains"), r.top_domains, d => OGK.el("tr", {}, OGK.el("td", {}, d.name), OGK.el("td", {}, d.count + " lần")));
    $("blocked").textContent = r.blocked;
    $("pend").textContent = r.pending_requests; $("pend").classList.toggle("hidden", !r.pending_requests);
  }
  $("days").addEventListener("change", loadReport);
  $("print").addEventListener("click", () => window.print());
  $("csv").addEventListener("click", () => {
    if (!lastReport) return;
    const rows = [["loai", "ten", "giá_tri"], ...lastReport.daily.map(d => ["ngay", d.day, d.seconds]), ...lastReport.top_apps.map(a => ["ung_dung", a.name, a.seconds]), ...lastReport.top_domains.map(d => ["ten_mien", d.name, d.count])];
    const esc = v => { v = String(v); if (/^[=+\-@]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };    // chống CSV injection
    const url = URL.createObjectURL(new Blob(["\ufeff" + rows.map(r => r.map(esc).join(",")).join("\n")], { type: "text/csv" }));
    OGK.el("a", { href: url, download: "bao-cao-tuan.csv" }).click(); URL.revokeObjectURL(url);
  });

  // ---- luật ----
  function renderGrid() {
    const g = $("grid"); g.replaceChildren(OGK.el("div", {}, ""));
    for (let h = 0; h < 48; h++) g.append(OGK.el("div", {}, h % 4 === 0 ? String(h / 2) : ""));
    policy.schedule.forEach((row, d) => {
      g.append(OGK.el("div", {}, DAYS[d]));
      for (let s = 0; s < 48; s++) { const c = OGK.el("div", { class: "cell" + (row[s] === "1" ? " on" : ""), title: DAYS[d] + " " + String(Math.floor(s / 2)).padStart(2, "0") + ":" + (s % 2 ? "30" : "00") }); c.dataset.d = d; c.dataset.s = s; g.append(c); }
    });
  }
  let painting = null;
  const toggle = (c, v) => { const d = +c.dataset.d, s = +c.dataset.s, r = policy.schedule[d].split(""); r[s] = v; policy.schedule[d] = r.join(""); c.classList.toggle("on", v === "1"); };
  $("grid").addEventListener("pointerdown", e => { const c = e.target.closest(".cell"); if (!c) return; painting = c.classList.contains("on") ? "0" : "1"; toggle(c, painting); });
  $("grid").addEventListener("pointerover", e => { const c = e.target.closest(".cell"); if (painting && c) toggle(c, painting); });
  window.addEventListener("pointerup", () => painting = null);
  $("all-on").addEventListener("click", () => { policy.schedule = Array(7).fill("1".repeat(48)); renderGrid(); });
  $("all-off").addEventListener("click", () => { policy.schedule = Array(7).fill("0".repeat(48)); renderGrid(); });

  function renderRules() {
    const dl = $("dr-list"), al = $("ar-list");
    dl.replaceChildren(...policy.domain_rules.map((r, i) => OGK.el("tr", {}, OGK.el("td", {}, r.domain), OGK.el("td", {}, r.action === "block" ? "Chặn" : "Cho phép"), OGK.el("td", {}, OGK.el("button", { class: "ghost", onclick: () => { policy.domain_rules.splice(i, 1); renderRules(); } }, "Xóa")))));
    al.replaceChildren(...policy.app_rules.map((r, i) => OGK.el("tr", {}, OGK.el("td", {}, r.name || "(theo hash)"), OGK.el("td", {}, (r.sha256 || "").slice(0, 12)), OGK.el("td", {}, r.action === "block" ? "Chặn" : "Cho phép"), OGK.el("td", {}, r.group || ""), OGK.el("td", {}, OGK.el("button", { class: "ghost", onclick: () => { policy.app_rules.splice(i, 1); renderRules(); } }, "Xóa")))));
  }
  $("dr-add").addEventListener("click", () => { const d = $("dr-domain").value.trim().toLowerCase(); if (!d) return; policy.domain_rules.push({ domain: d, action: $("dr-action").value }); $("dr-domain").value = ""; renderRules(); });
  $("ar-add").addEventListener("click", () => {
    const n = $("ar-name").value.trim(), h = $("ar-sha").value.trim().toLowerCase(); if (!n && !h) return;
    if (h && !/^[0-9a-f]{64}$/.test(h)) return alert("SHA-256 phải gồm 64 ký tự hex");
    policy.app_rules.push({ name: n || undefined, sha256: h || undefined, action: $("ar-action").value, group: $("ar-group").value || null }); renderRules();
  });

  async function loadPolicy() {
    policy = await OGK.api("GET", base + "/policy");
    $("q-wd").value = policy.daily_quota_min.weekday; $("q-we").value = policy.daily_quota_min.weekend; $("grace").value = policy.grace_sec; $("idle").value = policy.idle_timeout_sec;
    $("g-games").value = policy.groups.games?.limit_min ?? ""; $("g-social").value = policy.groups.social?.limit_min ?? "";
    $("safesearch").checked = policy.safesearch; $("app-mode").value = policy.app_mode; $("off-days").value = policy.offline_max_days; $("fail").value = policy.fail_mode;
    const cats = $("cats"); cats.replaceChildren();
    for (const [k, v] of Object.entries(CAT)) {
      const sel = OGK.el("select", { id: "cat-" + k }, ...[["allow", "Cho phép"], ["block", "Chặn"], ["budget:games", "Tính vào ngân sách Trò chơi"], ["budget:social", "Tính vào ngân sách Mạng xã hội"]].map(([val, txt]) => OGK.el("option", { value: val }, txt)));
      sel.value = policy.categories[k]; cats.append(OGK.el("label", {}, v, sel));
    }
    renderGrid(); renderRules();
  }
  $("save").addEventListener("click", async () => {
    const m = $("pmsg"); m.className = "msg";
    const lim = v => v === "" ? null : parseInt(v, 10);
    policy.daily_quota_min = { weekday: +$("q-wd").value, weekend: +$("q-we").value }; policy.grace_sec = +$("grace").value; policy.idle_timeout_sec = +$("idle").value;
    policy.groups = {}; if ($("g-games").value !== "") policy.groups.games = { limit_min: lim($("g-games").value) }; if ($("g-social").value !== "") policy.groups.social = { limit_min: lim($("g-social").value) };
    for (const k of Object.keys(CAT)) policy.categories[k] = $("cat-" + k).value;
    policy.safesearch = $("safesearch").checked; policy.app_mode = $("app-mode").value; policy.offline_max_days = +$("off-days").value; policy.fail_mode = $("fail").value;
    try { const r = await OGK.api("PUT", base + "/policy", policy); m.textContent = "Đã lưu – phiên bản " + r.version; m.className = "msg ok"; loadPolicy(); }
    catch (e) { m.textContent = e.message; }
  });

  // ---- thiết bị ----
  async function loadDevices() {
    const kids = await OGK.api("GET", "/api/children"), me = kids.find(k => String(k.id) === id), box = $("devs"); box.replaceChildren();
    const cmd = (d, kind, minutes) => async () => { try { const r = await OGK.api("POST", "/api/devices/" + d.id + "/commands", { kind, minutes: minutes || 15 }); alert(r.pushed ? "Đã gửi tới máy con." : "Máy con chưa kết nối, lệnh sẽ được gửi ở nhịp tim kế tiếp (≤ 60 giây)."); } catch (e) { alert(e.message); } };
    for (const d of (me?.devices || [])) box.append(OGK.el("div", { class: "card" }, OGK.el("h3", {}, d.hostname), OGK.el("p", {}, d.revoked ? "Đã thu hồi" : "Thấy lần cuối: " + OGK.when(d.last_seen) + " – trạng thái: " + d.state),
      d.revoked ? "" : OGK.el("div", { class: "row" }, OGK.el("button", { onclick: cmd(d, "lock") }, "🔒 Khóa ngay"), OGK.el("button", { onclick: cmd(d, "unlock") }, "🔓 Mở khóa"), OGK.el("button", { onclick: cmd(d, "add_time", 15) }, "➕ Cộng 15 phút"),
        OGK.el("button", { class: "ghost", onclick: cmd(d, "pause", 120) }, "⏸ Tạm nghỉ 2 giờ"), OGK.el("button", { class: "ghost", onclick: async () => { if (confirm("Thu hồi thiết bị này?")) { await OGK.api("DELETE", "/api/devices/" + d.id); loadDevices(); } } }, "Thu hồi"))));
  }
  $("pair").addEventListener("click", async () => { const r = await OGK.api("POST", base + "/pairing-code"); $("code").textContent = r.code; });
  $("wipe").addEventListener("click", async () => { if (confirm("Xóa TOÀN BỘ dữ liệu sử dụng của con? Không thể khôi phục.")) { const r = await OGK.api("DELETE", base + "/data"); alert("Đã xóa. Đã báo " + r.devices_notified + " máy xóa bộ đệm."); } });

  // ---- yêu cầu & nhật ký ----
  async function loadReqs() {
    const box = $("reqs"); box.replaceChildren();
    for (const r of (await OGK.api("GET", base + "/requests")).items) {
      const label = r.kind === "more_time" ? "Xin thêm giờ" : "Báo chặn nhầm: " + r.subject;
      const act = ok => async () => { const t = prompt("Lời nhắn cho con (tuỳ chọn)") || ""; try { await OGK.api("POST", "/api/requests/" + r.id + "/resolve", { approve: ok, response_text: t, minutes: 15 }); loadReqs(); } catch (e) { alert(e.message); } };
      box.append(OGK.el("div", { class: "card" }, OGK.el("b", {}, label), OGK.el("p", {}, OGK.when(r.created_at) + (r.note ? " – “" + r.note + "”" : "")),
        r.status === "pending" ? OGK.el("div", { class: "row" }, OGK.el("button", { onclick: act(true) }, "Đồng ý"), OGK.el("button", { class: "ghost", onclick: act(false) }, "Từ chối")) : OGK.el("p", {}, r.status === "approved" ? "✅ Đã đồng ý. " : "❌ Đã từ chối. ", r.response_text)));
    }
    if (!box.children.length) box.append(OGK.el("p", {}, "Con chưa gửi yêu cầu nào."));
  }
  async function loadAudit() {
    const t = $("auditt"); t.replaceChildren(OGK.el("tr", {}, ...["Thời điểm", "Ai", "IP", "Hành động", "Chi tiết"].map(h => OGK.el("th", {}, h))));
    for (const a of (await OGK.api("GET", base + "/audit")).items) t.append(OGK.el("tr", {}, OGK.el("td", {}, OGK.when(a.ts)), OGK.el("td", {}, a.actor), OGK.el("td", {}, a.ip), OGK.el("td", {}, a.action), OGK.el("td", {}, a.summary)));
  }

  const kids = await OGK.api("GET", "/api/children"); const me = kids.find(k => String(k.id) === id);
  $("title").textContent = "Bảng điều khiển của " + (me ? me.name : "con");
  await Promise.all([loadPolicy(), loadReport()]);
})();
