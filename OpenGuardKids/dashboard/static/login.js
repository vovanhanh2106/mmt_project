"use strict";
const $ = id => document.getElementById(id), msg = (t, ok) => { $("msg").textContent = t; $("msg").className = "msg" + (ok ? " ok" : ""); };
$("login").addEventListener("click", async () => {
  try { await OGK.api("POST", "/api/auth/login", { email: $("email").value, password: $("password").value, totp: $("totp").value || null }); location.href = "/"; }
  catch (e) { msg(e.message); }
});
$("register").addEventListener("click", async () => {
  try {
    if (!$("dname").value) { document.querySelector("details").open = true; return msg("Nhập tên hiển thị rồi bấm lại"); }
    await OGK.api("POST", "/api/auth/register", { email: $("email").value, password: $("password").value, display_name: $("dname").value });
    msg("Đã tạo tài khoản, hãy đăng nhập.", true);
  } catch (e) { msg(e.message); }
});
