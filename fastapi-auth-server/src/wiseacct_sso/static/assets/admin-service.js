(() => {
  const panel = document.querySelector("[data-service-panel]");
  if (!panel || document.querySelector("meta[name='admin-auth-mode']")?.getAttribute("content") !== "session") return;
  const base = document.querySelector("meta[name='admin-api-base']").getAttribute("content");
  const csrf = document.querySelector("meta[name='admin-session-csrf']").getAttribute("content");
  const tabs = panel.querySelector("[data-service-tabs]");
  const note = panel.querySelector("[data-service-note]");
  const count = panel.querySelector("[data-service-count]");
  const members = panel.querySelector("[data-service-members]");
  const form = panel.querySelector("[data-service-add]");
  let services = [];
  let current = null;
  let busy = false;

  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  };

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
        EXTERNAL_ACCOUNT_MANAGED: "외부 계정의 유형은 바꿀 수 없습니다. 기한·정지는 '외부 계정' 패널에서 관리하세요.",
        NOT_EXTERNAL_ACCOUNT: "외부 계정에서만 할 수 있는 작업입니다.",
        LEGACY_ADMIN_ROLE_DISABLED: "temis:admin은 더 이상 줄 수 없습니다. 관리자는 sso:admin을 쓰세요.",
        LAST_SSO_ADMIN: "마지막 SSO 관리자의 권한은 뺄 수 없습니다. 다른 관리자를 먼저 지정하세요.",
        USER_CHANGED: "그사이 사용자 정보가 바뀌었습니다. 새로고침 후 다시 시도하세요.",
        INVALID_USER_TYPE: "지원하지 않는 사용자 유형입니다.",
        INVALID_USER_STATUS: "지원하지 않는 상태입니다.",
        INVALID_ROLE: "역할 형식이 올바르지 않습니다.",
        INVALID_ACCOUNT_TERM: "기한은 1~365일 사이 정수로 입력하세요.",
        FORBIDDEN: "이 작업을 할 권한이 없습니다. 자기 자신의 관리자 권한·세션·상태는 바꿀 수 없습니다."
      };
      throw new Error(messages[code] ?? `처리하지 못했습니다 (${code}).`);
    }
    return payload;
  }

  const status = (message, tone = "info") => {
    count.textContent = message;
    count.dataset.tone = tone;
  };

  async function load() {
    const [service, name] = current.roles[0].split(":");
    note.textContent = current.note;
    members.replaceChildren(element("p", "type-fixed", "불러오는 중…"));
    const page = await api(`/users?${new URLSearchParams({ page: "1", pageSize: "100", role: `${service}:${name}` })}`);
    members.replaceChildren();
    count.textContent = `${current.roles[0]} 보유 ${page.total}명${page.total > page.items.length ? ` (앞 ${page.items.length}명 표시)` : ""}`;
    if (!page.items.length) {
      members.append(element("p", "type-fixed", "아직 권한을 받은 사람이 없습니다."));
      return;
    }
    for (const user of page.items) {
      const role = user.roles.find((r) => r.serviceKey === service && r.name === name);
      const row = element("div", "service-member");
      const who = element("div", "user-main");
      who.append(element("span", "user-email", user.email ?? user.id), element("span", "", user.name ?? ""));
      const tags = element("div", "access-list");
      if (user.userType === "EXTERNAL") tags.append(element("span", "access-chip", "외부"));
      if (user.status !== "ACTIVE") tags.append(element("span", "access-none", user.status));
      const remove = element("button", "danger-button", "권한 빼기");
      remove.type = "button";
      remove.addEventListener("click", () => run(async () => {
        if (!window.confirm(`${user.email}의 ${current.label} 권한(${current.roles[0]})을 뺄까요?`)) return;
        await api(`/users/${encodeURIComponent(user.id)}/roles/${encodeURIComponent(role.id)}`, "DELETE",
          { reasonCode: "ADMIN_SERVICE_PANEL_ROLE_REMOVE" });
        await load();
        status(`${user.email}: ${current.label} 권한을 뺐습니다.`, "success");
      }));
      row.append(who, tags, remove);
      members.append(row);
    }
  }

  async function run(work) {
    if (busy) return;
    busy = true;
    try { await work(); }
    catch (error) { status(error.message || "요청 실패", "error"); }
    finally { busy = false; }
  }

  function select(service) {
    current = service;
    for (const tab of tabs.children) tab.setAttribute("aria-selected", String(tab.dataset.clientId === service.clientId));
    void run(load);
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void run(async () => {
      const email = String(new FormData(form).get("email") ?? "").trim().toLowerCase();
      if (!email) return;
      const found = await api(`/users?${new URLSearchParams({ page: "1", pageSize: "100", email })}`);
      const user = found.items.find((u) => (u.email ?? "").toLowerCase() === email);
      if (!user) throw new Error(`${email} 계정이 없습니다. 먼저 초대(직원 초대·외부 계정)로 계정을 만드세요.`);
      const [service, name] = current.roles[0].split(":");
      await api(`/users/${encodeURIComponent(user.id)}/roles`, "POST",
        { serviceKey: service, name, reasonCode: "ADMIN_SERVICE_PANEL_ROLE_ASSIGN" });
      form.reset();
      await load();
      status(`${email}: ${current.label} 권한(${current.roles[0]})을 주었습니다.`, "success");
    });
  });

  void (async () => {
    try {
      services = (await api("/services")).items;
    } catch {
      return;
    }
    if (!services.length) return;
    for (const service of services) {
      const tab = element("button", "secondary-button", service.label);
      tab.type = "button";
      tab.setAttribute("role", "tab");
      tab.dataset.clientId = service.clientId;
      tab.addEventListener("click", () => select(service));
      tabs.append(tab);
    }
    panel.hidden = false;
    select(services[0]);
  })();
})();
