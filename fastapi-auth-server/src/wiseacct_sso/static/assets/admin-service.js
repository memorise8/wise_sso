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
        EXTERNAL_ROLE_NOT_ALLOWED: "외부 계정에는 이 권한을 줄 수 없습니다 (외부 계정은 gitlab:user만 가능).",
        ROLE_ALREADY_ASSIGNED: "이미 권한이 있습니다."
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
