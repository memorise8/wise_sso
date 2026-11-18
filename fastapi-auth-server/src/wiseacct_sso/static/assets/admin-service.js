(() => {
  const panel = document.querySelector("[data-service-panel]");
  if (!panel || document.querySelector("meta[name='admin-auth-mode']")?.getAttribute("content") !== "session") return;
  const readOnly = document.querySelector("meta[name='admin-access']")?.getAttribute("content") === "viewer";
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
  if (readOnly) form.hidden = true;
  const pageSize = 25;
  const labels = { "gitlab-temis": "GitLab", "agent-hub-dash": "에이전트 허브", "fantra-oidc": "Fantra" };
  const typeLabels = { EMPLOYEE: "직원", CUSTOMER: "고객", EXTERNAL: "외부", UNCLASSIFIED: "미분류" };
  let clients = [];
  let current = null;
  let page = 1;
  let busy = false;
  let memberSequence = 0;

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
    if (readOnly && !["GET", "HEAD"].includes(method.toUpperCase())) {
      throw new Error("읽기 전용 계정으로는 변경할 수 없습니다.");
    }
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
      ["역할 없이 로그인", current.allowWithoutRequiredRole ? "허용" : "불가"],
      ["자동 로그인", current.ssoAutoLogin ? "켜짐" : "꺼짐"]
    ]) {
      const item = element("div");
      item.append(element("dt", "", name), element("dd", "", value));
      list.append(item);
    }
    policy.replaceChildren(list);
    if (typeof window.CustomEvent === "function" && typeof document.dispatchEvent === "function") {
      document.dispatchEvent(new window.CustomEvent("admin-service-selected", {
        detail: { clientId: current.clientId }
      }));
    }
    const roleRule = current.allowWithoutRequiredRole
      ? "필요 역할이 없어도 SSO 로그인을 허용합니다."
      : "필요 역할 조건을 충족해야 SSO 로그인이 가능합니다.";
    note.textContent = `허용 유형: ${types}. ${roleRule} 그 밖의 SSO 로그인 조건도 적용됩니다. 서비스 내부 권한과 초대 여부는 해당 서비스에서 별도로 확인합니다.`;
    roleSelect.replaceChildren(...current.requiredRoles.map((role, index) => {
      const option = element("option", "", roleName(role));
      option.value = String(index);
      return option;
    }));
  }

  async function load() {
    if (!current) return;
    const selected = current;
    const requestedPage = page;
    const requestId = ++memberSequence;
    const isCurrent = () => requestId === memberSequence
      && current?.clientId === selected.clientId && page === requestedPage;
    members.replaceChildren(element("p", "type-fixed", "불러오는 중…"));
    pager.replaceChildren();
    status(`${label(selected)} 구성원을 불러오는 중…`);
    let result;
    try {
      result = await api(`/clients/${encodeURIComponent(selected.clientId)}/members?page=${requestedPage}&pageSize=${pageSize}`);
    } catch (error) {
      if (!isCurrent()) return;
      members.replaceChildren(element("p", "type-fixed", "구성원 목록을 불러오지 못했습니다."));
      status(error.message || "구성원 조회 실패", "error");
      return;
    }
    if (!isCurrent()) return;
    if (!result.items.length && result.page > 1) {
      page = Math.max(1, Math.ceil(result.total / result.pageSize));
      return load();
    }
    status(`${label(selected)}의 SSO 로그인 조건을 충족하는 사람 ${result.total}명`);
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
        : element("span", "access-none", "역할 없음 · SSO 로그인 허용"));
      const actions = element("div", "member-actions");
      for (const role of (readOnly ? [] : member.matchedRoles)) {
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
      const move = (next) => {
        if (current?.clientId !== selected.clientId) return;
        page = next;
        void load();
      };
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
    void load();
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (readOnly) return;
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

  document.addEventListener?.("admin-policy-applied", () => { void run(refresh); });

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

(() => {
  if (document.querySelector("meta[name='admin-auth-mode']")?.getAttribute("content") !== "session") return;
  if (document.querySelector("meta[name='admin-access']")?.getAttribute("content") === "viewer") return;
  const panel = document.querySelector("[data-service-panel]");
  if (!panel) return;
  const base = document.querySelector("meta[name='admin-api-base']").getAttribute("content");
  const csrf = document.querySelector("meta[name='admin-session-csrf']").getAttribute("content");
  const root = document.createElement("section");
  root.dataset.policyEditor = "";
  root.hidden = true;
  panel.append(root);
  let sequence = 0;
  let clientId = "";
  let current = null;
  let page = 1;
  let busy = false;

  const node = (tag, text) => {
    const result = document.createElement(tag);
    if (text !== undefined) result.textContent = String(text);
    return result;
  };
  const kst = (value) => {
    if (!value) return "기록 없음";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "시각 확인 불가";
    const parts = Object.fromEntries(new Intl.DateTimeFormat("ko-KR", {
      timeZone: "Asia/Seoul", calendar: "gregory", numberingSystem: "latn",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23"
    }).formatToParts(date).map((part) => [part.type, part.value]));
    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second} (KST)`;
  };
  async function api(path, method = "GET", body) {
    const response = await fetch(base + path, {
      method, credentials: "same-origin",
      headers: {
        "content-type": "application/json",
        ...(method === "GET" ? {} : { "x-admin-csrf": csrf })
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    if (response.status === 401) window.location.assign("/oauth2/admin/login?reauth=1");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message || "정책 요청을 처리하지 못했습니다.");
    return payload;
  }
  const endpoint = () => `/clients/${encodeURIComponent(clientId)}`;
  const message = node("p");
  message.setAttribute("role", "status");
  const reason = () => window.prompt("변경 또는 결정 사유를 입력하세요. (최대 128자)")?.trim();

  async function run(work) {
    if (busy) return;
    busy = true;
    const buttons = [...root.querySelectorAll("button")].map((button) => [button, button.disabled]);
    for (const [button] of buttons) button.disabled = true;
    try { await work(); }
    catch (error) { message.textContent = error.message || "처리하지 못했습니다."; }
    finally {
      busy = false;
      for (const [button, disabled] of buttons) button.disabled = disabled;
    }
  }
  function button(text, action) {
    const control = node("button", text);
    control.type = "button";
    control.className = "secondary-button";
    control.addEventListener("click", () => { void run(action); });
    return control;
  }
  function input(label, value, type = "text") {
    const wrapper = node("label", label + " ");
    const control = node("input");
    control.type = type;
    if (type === "checkbox") control.checked = Boolean(value);
    else control.value = value;
    wrapper.append(control);
    return { wrapper, control };
  }
  const typeNames = {
    EMPLOYEE: "직원", CUSTOMER: "고객", EXTERNAL: "외부", UNCLASSIFIED: "미분류"
  };
  const describe = (policy) => [
    `허용 유형: ${policy.allowedUserTypes?.map((type) => typeNames[type] ?? type).join(", ") || "전체"}`,
    `필요 역할: ${policy.requiredRoles.map((role) => `${role.serviceKey}:${role.name}`).join(", ")}`,
    `역할 없이 로그인: ${policy.allowWithoutRequiredRole ? "허용" : "불가"}`,
    `그룹으로 전달할 서비스: ${policy.groupsServiceKeys.join(", ")}`,
    `자동 로그인: ${policy.ssoAutoLogin ? "켜짐" : "꺼짐"}`
  ].join("\n");

  async function load() {
    const id = ++sequence;
    const selected = clientId;
    const path = endpoint();
    let policy, history;
    try {
      [policy, history] = await Promise.all([
        api(path + "/policy"),
        api(path + `/policy-changes?page=${page}&pageSize=25`)
      ]);
    } catch (error) {
      if (id !== sequence || selected !== clientId) return;
      throw error;
    }
    if (id !== sequence || selected !== clientId) return;
    current = policy;
    render(history);
  }

  function render(history) {
    root.hidden = false;
    root.replaceChildren(node("h3", "접근 정책 변경"), message);
    message.textContent = "";
    root.append(
      node("p", `현재 버전 ${current.version} · 마지막 변경 ${kst(current.updatedAt)}`),
      node("p", "요청한 관리자와 다른 관리자 한 명의 승인이 필요합니다.")
    );
    const form = node("form");
    form.className = "form-grid";
    const allTypes = input("모든 사용자 유형 허용", current.policy.allowedUserTypes === null, "checkbox");
    form.append(allTypes.wrapper);
    const types = Object.entries(typeNames).map(([key, label]) => {
      const field = input(label, current.policy.allowedUserTypes?.includes(key), "checkbox");
      form.append(field.wrapper);
      return { key, ...field };
    });
    const syncTypes = () => {
      for (const field of types) field.control.disabled = allTypes.control.checked;
    };
    allTypes.control.addEventListener("change", syncTypes);
    syncTypes();
    const roles = input("필요 역할 (쉼표로 구분)", current.policy.requiredRoles.map(
      (role) => `${role.serviceKey}:${role.name}`
    ).join(", "));
    const groups = input("그룹으로 전달할 서비스 (쉼표로 구분)", current.policy.groupsServiceKeys.join(", "));
    const withoutRole = input("필요 역할 없이 로그인 허용", current.policy.allowWithoutRequiredRole, "checkbox");
    const auto = input("자동 로그인 허용", current.policy.ssoAutoLogin, "checkbox");
    form.append(roles.wrapper, groups.wrapper, withoutRole.wrapper, auto.wrapper);
    const submit = node("button", "변경 요청");
    submit.type = "submit";
    submit.className = "primary-button";
    form.append(submit);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      let requiredRoles;
      try {
        requiredRoles = roles.control.value.split(",").map((value) => {
          const parts = value.trim().split(":");
          if (parts.length !== 2 || !parts[0] || !parts[1]) {
            throw new Error("필요 역할을 서비스:역할 형식으로 입력하세요.");
          }
          return { serviceKey: parts[0], name: parts[1] };
        });
      } catch (error) {
        message.textContent = error.message;
        return;
      }
      const proposed = {
        allowedUserTypes: allTypes.control.checked ? null : types.filter(
          (field) => field.control.checked
        ).map((field) => field.key),
        requiredRoles,
        groupsServiceKeys: groups.control.value.split(",").map((value) => value.trim()),
        allowWithoutRequiredRole: withoutRole.control.checked,
        ssoAutoLogin: auto.control.checked
      };
      const path = endpoint();
      const expectedVersion = current.version;
      void run(async () => {
        const reasonCode = reason();
        if (!reasonCode) return;
        await api(path + "/policy-changes", "POST", { expectedVersion, proposed, reasonCode });
        page = 1;
        await load();
        message.textContent = "변경을 요청했습니다. 다른 관리자의 승인을 기다립니다.";
      });
    });
    root.append(form);

    if (current.version > 1) {
      const target = input("되돌릴 버전", String(current.version - 1), "number");
      target.control.min = "1";
      target.control.max = String(current.version - 1);
      target.control.step = "1";
      root.append(target.wrapper, button("이전 버전 복원 요청", async () => {
        const rollbackToVersion = Number(target.control.value);
        if (!Number.isInteger(rollbackToVersion) || rollbackToVersion < 1 || rollbackToVersion >= current.version) {
          throw new Error("현재보다 작은 이전 버전을 입력하세요.");
        }
        const reasonCode = reason();
        if (!reasonCode) return;
        await api(endpoint() + "/policy-changes", "POST", {
          expectedVersion: current.version, rollbackToVersion, reasonCode
        });
        page = 1;
        await load();
        message.textContent = "복원을 요청했습니다. 다른 관리자의 승인이 필요합니다.";
      }));
    }

    root.append(node("h3", "정책 변경 요청 이력"));
    if (!history.items.length) root.append(node("p", "변경 요청이 없습니다."));
    const statuses = { PENDING: "승인 대기", APPLIED: "적용 완료", REJECTED: "거절" };
    for (const change of history.items) {
      const card = node("article");
      card.className = "panel";
      card.append(
        node("h4", `${statuses[change.status] ?? change.status} · 기준 버전 ${change.baseVersion}`),
        node("p", `요청자: ${change.requestedByEmail || "이메일 기록 없음"} · ${kst(change.requestedAt)}`),
        node("p", `요청 사유: ${change.reasonCode}`),
        node("p", `처리 시각: ${kst(change.resolvedAt)}`)
      );
      const before = node("pre", describe(change.beforePolicy));
      const after = node("pre", describe(change.proposedPolicy));
      before.style.whiteSpace = "pre-wrap";
      after.style.whiteSpace = "pre-wrap";
      card.append(node("h4", "변경 전"), before, node("h4", "요청 정책"), after);
      const decisionInfo = node("p");
      decisionInfo.dataset.policyDecision = "";
      decisionInfo.setAttribute("role", "status");
      decisionInfo.hidden = true;
      const decisionPath = endpoint() + `/policy-changes/${encodeURIComponent(change.id)}`;
      card.append(button("승인·거절 기록 보기", async () => {
        decisionInfo.hidden = false;
        decisionInfo.textContent = "결정 기록을 불러오는 중…";
        try {
          const detail = await api(decisionPath);
          const decision = detail.decision;
          decisionInfo.textContent = decision
            ? `${decision.decision === "APPROVE" ? "승인" : "거절"} · ${decision.decidedByEmail || "이메일 기록 없음"} · ${kst(decision.decidedAt)} · ${decision.reasonCode}`
            : "아직 결정되지 않은 요청입니다.";
        } catch (error) {
          decisionInfo.textContent = error.message || "결정 기록을 불러오지 못했습니다.";
        }
      }), decisionInfo);
      if (change.status === "PENDING") {
        for (const [decision, label] of [["APPROVE", "승인"], ["REJECT", "거절"]]) {
          const control = button(label, async () => {
            const reasonCode = reason();
            if (!reasonCode) return;
            await api(endpoint() + `/policy-changes/${encodeURIComponent(change.id)}/decision`, "POST", {
              decision, reasonCode
            });
            await load();
            if (decision === "APPROVE") document.dispatchEvent(new CustomEvent("admin-policy-applied"));
            message.textContent = `${label} 처리를 완료했습니다.`;
          });
          control.disabled = change.requestedById === current.actorUserId
            || (decision === "APPROVE" && change.baseVersion !== current.version);
          card.append(control);
        }
        if (change.requestedById === current.actorUserId) {
          card.append(node("p", "본인이 요청한 정책은 다른 관리자가 결정해야 합니다."));
        }
      }
      root.append(card);
    }
    const pager = node("div");
    if (page > 1) pager.append(button("이전", async () => { page -= 1; await load(); }));
    pager.append(node("span", ` ${page}페이지 `));
    if (history.hasMore) pager.append(button("다음", async () => { page += 1; await load(); }));
    root.append(pager);
  }

  document.addEventListener("admin-service-selected", (event) => {
    clientId = event.detail.clientId;
    page = 1;
    root.hidden = true;
    void load().catch((error) => {
      root.hidden = false;
      root.replaceChildren(message);
      message.textContent = error.message || "정책을 불러오지 못했습니다.";
    });
  });
})();
