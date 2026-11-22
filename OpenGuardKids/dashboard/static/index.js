"use strict";
(async () => {
  await OGK.init();
  const box = document.getElementById("children");
  async function load() {
    box.replaceChildren();
    for (const c of await OGK.api("GET", "/api/children")) {
      const devs = c.devices.length ? c.devices.map(d => OGK.el("li", {}, d.hostname + " – " + (d.revoked ? "đã thu hồi" : "thấy lần cuối " + OGK.when(d.last_seen) + " (" + d.state + ")"))) : [OGK.el("li", {}, "Chưa ghép đôi máy nào")];
      box.append(OGK.el("div", { class: "card" }, OGK.el("h3", {}, c.name, " ", OGK.el("small", {}, "(" + c.age_band + " tuổi)")),
        OGK.el("ul", {}, devs), c.pending_requests ? OGK.el("p", {}, OGK.el("span", { class: "badge" }, c.pending_requests), " yêu cầu đang chờ") : "",
        OGK.el("a", { href: "/children/" + c.id }, OGK.el("button", {}, "Mở bảng điều khiển"))));
    }
  }
  document.getElementById("addchild").addEventListener("click", async () => {
    const m = document.getElementById("msg");
    try { await OGK.api("POST", "/api/children", { name: document.getElementById("cname").value, age_band: document.getElementById("cage").value }); m.textContent = ""; document.getElementById("cname").value = ""; load(); }
    catch (e) { m.textContent = e.message; }
  });
  load();
})();
