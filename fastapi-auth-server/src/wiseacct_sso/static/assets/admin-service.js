(() => {
  const panel = document.querySelector("[data-service-panel]");
  if (!panel || document.querySelector("meta[name='admin-auth-mode']")?.getAttribute("content") !== "session") return;
  const base = document.querySelector("meta[name='admin-api-base']").getAttribute("content");
  const csrf = document.querySelector("meta[name='admin-session-csrf']").getAttribute("content");
  const tabs = panel.querySelector("[data-service-tabs]");
  const note = panel.querySelector("[data-service-note]");
  const policy = panel.querySelector("[data-service-policy]");
  const count = panel.querySelector("[data-service-count]");
  const members = panel.querySelector("[data-service-members]");
  const pager = panel.querySelector("[data-service-pager]");
  const form = panel.querySelector("[data-service-add]");
  const roleSelect = form.querySelector("select[name='role']");
  const pageSize = 25;
  const labels = { "gitlab-temis": "GitLab", "agent-hub-dash": "에이전트 허브", "fantra-oidc": "Fantra" };
  const notes = {
    "gitlab-temis": "gitlab:user가 있어야 GitLab에 로그인할 수 있습니다. 외부 계정도 받을 수 있는 유일한 권한입니다.",
    "agent-hub-dash": "SSO 로그인은 누구나 통과하고, 허브가 자체 명단·초대로 입장을 정합니다. agent-hub:user가 있으면 초대 없이 들어갑니다."
  };
  const typeLabels = { EMPLOYEE: "직원", CUSTOMER: "고객", EXTERNAL: "외부", UNCLASSIFIED: "미분류" };
  let clients = [];
  let current = null;
  let page = 1;
  let busy = false;

  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  };
  const roleName = (role) => `${role.serviceKey}:${role.name}`;
  const label = (client) => labels[client.clientId] ?? client.clientId;
  const askReason = () => window.prompt("변경 사유를 입력하세요. (감사 기록에 남습니다)")?.trim();

  async function api(path, method = "GET", body) {
    const response = await fetch(base + path, {
      method,
      credentials: "same-origin",
      headers: { "content-type": "application/json", ...(method === "GET" ? {} : { "x-admin-csrf": csrf }) },
      ...(body ? { body: JSON.stringify(body) } : {})
    });
    if (response.status === 401) window.location.assign("/oauth2/admin/login?reauth=1");
    const text = await response.text();
    const payload = text ? JSON.parse(text) : null;
    if (!response.ok) {
      const code = payload?.error?.code ?? payload?.code ?? response.status;
      const messages = {
        EMPLOYEE_REQUIRED: "직원으로 분류된 사용자만 받을 수 있는 권한입니다. 먼저 사용자 유형을 '직원'으로 바꾸세요.",
        EXTERNAL_ROLE_NOT_ALLOWED: "외부 계정에는 이 권한을 줄 수 없습니다 (외부 계정은 gitlab:user만 가능).",
        LAST_SSO_ADMIN: "마지막 SSO 관리자의 권한은 뺄 수 없습니다. 다른 관리자를 먼저 지정하세요.",
        USER_CHANGED: "그사이 사용자 정보가 바뀌었습니다. 새로고침 후 다시 시도하세요.",
        INVALID_ROLE: "역할 형식이 올바르지 않습니다.",
        FORBIDDEN: "이 작업을 할 권한이 없습니다. 자기 자신의 관리자 권한은 바꿀 수 없습니다."
      };
      throw new Error(messages[code] ?? payload?.error?.message ?? `처리하지 못했습니다 (${code}).`);
    }
    return payload;
  }

  const status = (message, tone = "info") => {
    count.textContent = message;
    count.dataset.tone = tone;
  };

  function renderPolicy() {
    const types = current.allowedUserTypes?.map((type) => typeLabels[type] ?? type).join(", ") || "전체";
    const list = element("dl", "client-access-policy");
    for (const [name, value] of [
      [current.allowWithoutRequiredRole ? "SSO 로그인 통과" : "이용 가능", `${current.eligibleCount}명`],
      ["필요 역할", current.requiredRoles.map(roleName).join(", ") || "없음"],
      ["허용 유형", types],
      ["역할 없이 로그인", current.allowWithoutRequiredRole ? "가능 (서비스가 초대로 거름)" : "불가"],
      ["자동 로그인", current.ssoAutoLogin ? "켜짐" : "꺼짐"]
    ]) {
      const item = element("div");
      item.append(element("dt", "", name), element("dd", "", value));
      list.append(item);
    }
    policy.replaceChildren(list);
    note.textContent = notes[current.clientId] ?? "";
    roleSelect.replaceChildren(...current.requiredRoles.map((role, index) => {
      const option = element("option", "", roleName(role));
      option.value = String(index);
      return option;
    }));
  }

  async function load() {
    members.replaceChildren(element("p", "type-fixed", "불러오는 중…"));
    const result = await api(`/clients/${encodeURIComponent(current.clientId)}/members?page=${page}&pageSize=${pageSize}`);
    if (!result.items.length && result.page > 1) {
      page = Math.max(1, Math.ceil(result.total / result.pageSize));
      return load();
    }
    status(current.allowWithoutRequiredRole
      ? `SSO 로그인을 통과하는 사람 ${result.total}명 · 실제 입장은 '역할 있음'이거나 ${label(current)}에서 초대받은 사람만`
      : `${label(current)}에 로그인할 수 있는 사람 ${result.total}명`);
    members.replaceChildren();
    if (!result.items.length) members.append(element("p", "type-fixed", "아직 이용할 수 있는 사람이 없습니다."));
    for (const member of result.items) {
      const row = element("div", "service-member");
      const who = element("div", "user-main");
      const name = element("a", "user-name", member.name ?? member.email);
      name.href = `/oauth2/admin/users/${encodeURIComponent(member.id)}`;
      who.append(name, element("span", "user-email", member.email));
      const tags = element("div", "access-list");
      if (member.userType === "EXTERNAL") tags.append(element("span", "type-tag", "외부"));
      tags.append(member.requiredRoleMatched
        ? element("span", "access-chip", "역할 있음")
        : element("span", "access-none", "역할 없음 · 서비스 초대 필요"));
      const actions = element("div", "member-actions");
      for (const role of member.matchedRoles) {
        const remove = element("button", "danger-button", `${roleName(role)} 빼기`);
        remove.type = "button";
        remove.addEventListener("click", () => run(async () => {
          const reasonCode = askReason();
          if (!reasonCode) return;
          await api(`/users/${encodeURIComponent(member.id)}/roles/${encodeURIComponent(role.id)}`, "DELETE", { reasonCode });
          await refresh();
          status(`${member.email}: ${roleName(role)}을 뺐습니다.`, "success");
        }));
        actions.append(remove);
      }
      row.append(who, tags, actions);
      members.append(row);
    }
    pager.replaceChildren();
    const last = Math.ceil(result.total / result.pageSize);
    if (last > 1) {
      const move = (next) => run(async () => { page = next; await load(); });
      if (result.page > 1) pager.append(button("이전", () => move(result.page - 1)));
      pager.append(element("span", "type-fixed", `${result.page} / ${last}`));
      if (result.page < last) pager.append(button("다음", () => move(result.page + 1)));
    }
  }

  const button = (text, action) => {
    const control = element("button", "secondary-button", text);
    control.type = "button";
    control.addEventListener("click", action);
    return control;
  };

  async function run(work) {
    if (busy) return;
    busy = true;
    try { await work(); }
    catch (error) { status(error.message || "요청 실패", "error"); }
    finally { busy = false; }
  }

  async function refresh() {
    const result = await api("/clients?page=1&pageSize=100");
    clients = result.items.filter((client) =>
      client.requiredRoles.length && !client.requiredRoles.some((role) => role.serviceKey === "temis"));
    current = clients.find((client) => client.clientId === current?.clientId) ?? clients[0] ?? null;
    if (!current) return;
    renderPolicy();
    await load();
  }

  function select(client) {
    current = client;
    page = 1;
    for (const tab of tabs.children) tab.setAttribute("aria-selected", String(tab.dataset.clientId === client.clientId));
    renderPolicy();
    void run(load);
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void run(async () => {
      const email = String(new FormData(form).get("email") ?? "").trim().toLowerCase();
      const role = current.requiredRoles[Number(roleSelect.value)];
      if (!email || !role) return;
      const found = await api(`/users?${new URLSearchParams({ page: "1", pageSize: "100", email })}`);
      const user = found.items.find((u) => (u.email ?? "").toLowerCase() === email);
      if (!user) throw new Error(`${email} 계정이 없습니다. 먼저 초대(직원 초대·외부 계정)로 계정을 만드세요.`);
      const reasonCode = askReason();
      if (!reasonCode) return;
      await api(`/users/${encodeURIComponent(user.id)}/roles`, "POST",
        { serviceKey: role.serviceKey, name: role.name, reasonCode });
      form.reset();
      await refresh();
      status(`${email}: ${label(current)} 권한(${roleName(role)})을 주었습니다.`, "success");
    });
  });

  void (async () => {
    try {
      await refresh();
    } catch {
      return;
    }
    if (!clients.length) return;
    for (const client of clients) {
      const tab = element("button", "secondary-button", label(client));
      tab.type = "button";
      tab.setAttribute("role", "tab");
      tab.dataset.clientId = client.clientId;
      tab.addEventListener("click", () => select(client));
      tabs.append(tab);
    }
    tabs.firstElementChild?.setAttribute("aria-selected", "true");
    panel.hidden = false;
  })();
})();
