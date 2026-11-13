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
      const kind = row.kind === "EXTERNAL" ? `외부 · 계정 기한 ${row.accountExpiresAt}` : "직원";
      box.textContent = `${row.email} · ${row.name} · ${kind} · ${row.status} · 링크 만료 ${row.expiresAt} · ${row.deliveredAt ? "전달 완료" : "미발송"} `;
      if (row.status === "PENDING") {
        for (const [action, text] of [["resend", "재발송"], ["relink", "새 링크"], ["cancel", "취소"]]) {
          const button = document.createElement("button");
          button.type = "button"; button.textContent = text;
          button.addEventListener("click", () => run(async () => {
            if (!window.confirm(`${row.email} 초대를 ${text}할까요?`)) return;
            const path = `/${encodeURIComponent(row.id)}/${action === "relink" ? "resend" : action}`;
            const result = await request(path, "POST", action === "relink" ? { delivery: "link" } : {});
            await refresh();
            if (result && result.invitationUrl) showLink(result.invitationUrl);
          }));
          box.append(button);
        }
      }
      list.append(box);
    }
  }
  function showLink(url) {
    const box = document.createElement("p");
    const field = document.createElement("input");
    field.readOnly = true; field.value = url; field.setAttribute("aria-label", "초대 링크");
    const copy = document.createElement("button");
    copy.type = "button"; copy.textContent = "링크 복사";
    copy.addEventListener("click", () => run(() => navigator.clipboard.writeText(url)));
    box.append(field, copy);
    list.prepend(box);
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
      const roles = data.getAll("role").map((value) => {
        const [serviceKey, name] = String(value).split(":");
        return { serviceKey, name };
      });
      if (!roles.length) throw new Error("줄 서비스 권한을 하나 이상 고르세요.");
      const created = await request("", "POST", {
        email: data.get("email"), name: data.get("name"), roles, delivery: data.get("delivery")
      });
      form.reset(); await refresh();
      if (created.invitationUrl) showLink(created.invitationUrl);
    });
  });
  document.querySelector("[data-invitation-refresh]").addEventListener("click", () => run(refresh));

  // Employee invitations pick roles from the catalogue; sso:admin is granted deliberately later.
  const SERVICE_NAMES = { gitlab: "GitLab", "agent-hub": "에이전트 허브", temis: "TEMIS", fantra: "Fantra" };
  const choices = form.querySelector("[data-invite-roles]");
  void (async () => {
    try {
      const response = await fetch("/oauth2/admin/api/roles?page=1&pageSize=100", { credentials: "same-origin" });
      if (!response.ok) throw new Error();
      const items = (await response.json()).items
        .filter((role) => !(role.serviceKey === "sso" && role.name === "admin"))
        .filter((role) => !(role.serviceKey === "temis" && role.name === "admin"));
      const legend = choices.querySelector("legend");
      choices.replaceChildren(legend);
      for (const role of items) {
        const label = document.createElement("label");
        const box = document.createElement("input");
        box.type = "checkbox"; box.name = "role"; box.value = `${role.serviceKey}:${role.name}`;
        const service = SERVICE_NAMES[role.serviceKey] ?? role.serviceKey;
        label.append(box, ` ${service} (${role.serviceKey}:${role.name})`);
        choices.append(label);
      }
    } catch {
      const note = choices.querySelector("p");
      if (note) note.textContent = "역할 목록을 불러오지 못했습니다. 새로고침해 주세요.";
    }
  })();
})();
