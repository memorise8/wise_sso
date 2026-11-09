(() => {
  const form = document.querySelector("[data-employee-invite]");
  const list = document.querySelector("[data-invitation-list]");
  const status = document.querySelector("[data-invitation-status]");
  const csrf = document.querySelector("meta[name='admin-session-csrf']").content;
  let busy = false;
  async function request(path, method = "GET", body) {
    const response = await fetch("/oauth2/admin/api/invitations" + path, {
      method, credentials: "same-origin",
      headers: { "content-type": "application/json", "x-admin-csrf": csrf },
      ...(body ? { body: JSON.stringify(body) } : {})
    });
    if (response.status === 401) window.location.assign("/oauth2/admin/login?reauth=1");
    if (!response.ok) throw new Error("초대 처리 실패: 권한·중복 계정·메일 설정을 확인하세요.");
    return response.status === 204 ? null : response.json();
  }
  async function refresh() {
    const result = await request("");
    list.replaceChildren();
    for (const row of result.items) {
      const box = document.createElement("p");
      box.textContent = `${row.email} · ${row.name} · ${row.status} · 만료 ${row.expiresAt} · ${row.deliveredAt ? "발송 완료" : "미발송"} `;
      if (row.status === "PENDING") {
        for (const [action, text] of [["resend", "재발송"], ["cancel", "취소"]]) {
          const button = document.createElement("button");
          button.type = "button"; button.textContent = text;
          button.addEventListener("click", () => run(async () => {
            if (!window.confirm(`${row.email} 초대를 ${text}할까요?`)) return;
            await request(`/${encodeURIComponent(row.id)}/${action}`, "POST", {});
            await refresh();
          }));
          box.append(button);
        }
      }
      list.append(box);
    }
  }
  async function run(work) {
    if (busy) return;
    busy = true;
    try { await work(); status.textContent = "처리 완료"; }
    catch (error) { status.textContent = error.message || "요청 실패"; }
    finally { busy = false; }
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void run(async () => {
      const data = new FormData(form);
      const roles = String(data.get("roles")).split(",").map((part) => {
        const pair = part.trim().split(":");
        if (pair.length !== 2 || !pair.every(Boolean)) throw new Error("역할은 service:user 형식으로 입력하세요.");
        return { serviceKey: pair[0], name: pair[1] };
      });
      await request("", "POST", { email: data.get("email"), name: data.get("name"), roles });
      form.reset(); await refresh();
    });
  });
  document.querySelector("[data-invitation-refresh]").addEventListener("click", () => run(refresh));
})();
