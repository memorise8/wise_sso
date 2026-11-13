const tokenStorageKey = "wise_sso_admin_access_token";
const userStatuses = ["ACTIVE", "PENDING_EMAIL_VERIFICATION", "SUSPENDED", "DELETED"];

const tokenForm = document.querySelector("[data-token-form]");
const filterForm = document.querySelector("[data-filter-form]");
const userTable = document.querySelector("[data-users]");
const summary = document.querySelector("[data-summary]");
const notice = document.querySelector("[data-notice]");
const health = document.querySelector("[data-health]");
const auditList = document.querySelector("[data-audit]");
const adminApiBase = document.querySelector("meta[name='admin-api-base']")?.getAttribute("content") ?? "/admin";

const sessionAuth = document.querySelector("meta[name='admin-auth-mode']")?.getAttribute("content") === "session";
const adminCsrf = document.querySelector("meta[name='admin-session-csrf']")?.getAttribute("content") ?? "";
if (sessionAuth) window.sessionStorage.removeItem(tokenStorageKey);

const bulkForm = document.querySelector("[data-bulk-type-form]");
const bulkType = document.querySelector("[data-bulk-type]");
const bulkSubmit = document.querySelector("[data-bulk-submit]");
const selectedCount = document.querySelector("[data-selected-count]");
const selectAll = document.querySelector("[data-select-all]");
const selectedUserIds = new Set();
let visibleUserIds = new Set();
let adminBusy = false;

const syncSelection = () => {
  if (selectedCount) selectedCount.textContent = `선택 ${selectedUserIds.size}명`;
  if (selectAll instanceof HTMLInputElement) {
    selectAll.checked = visibleUserIds.size > 0 && selectedUserIds.size === visibleUserIds.size;
    selectAll.indeterminate = selectedUserIds.size > 0 && selectedUserIds.size < visibleUserIds.size;
    selectAll.disabled = adminBusy || visibleUserIds.size === 0;
  }
  if (bulkSubmit instanceof HTMLButtonElement) {
    bulkSubmit.disabled = adminBusy || selectedUserIds.size === 0;
  }
  for (const input of userTable?.querySelectorAll("input[data-select-user]") ?? []) {
    if (input instanceof HTMLInputElement) input.checked = selectedUserIds.has(input.dataset.selectUser);
  }
};

const clearSelection = () => {
  selectedUserIds.clear();
  syncSelection();
};

const tokenInput = tokenForm?.querySelector("input[name='token']");

const setNotice = (tone, message) => {
  if (!(notice instanceof HTMLElement)) {
    return;
  }
  notice.hidden = false;
  notice.dataset.tone = tone;
  notice.textContent = message;
  window.setTimeout(() => {
    notice.hidden = true;
  }, 4200);
};

const authToken = () => sessionAuth ? "" : window.sessionStorage.getItem(tokenStorageKey) ?? "";

const setBusy = (busy) => {
  adminBusy = busy;
  for (const control of document.querySelectorAll("button, input, select")) {
    if (control instanceof HTMLButtonElement || control instanceof HTMLInputElement || control instanceof HTMLSelectElement) {
      control.disabled = busy || control.dataset.typeChangeBlocked === "true";
    }
  }
  syncSelection();
};

const apiPath = (path) => `${adminApiBase}${path}`;

const apiFetch = async (path, options = {}) => {
  const token = authToken();
  if (!sessionAuth && !token) {
    throw new Error("관리자 Access Token을 먼저 저장하세요.");
  }

  const response = await fetch(apiPath(path), {
    ...options,
    credentials: "same-origin",
    headers: {
      ...(sessionAuth ? {} : { authorization: `Bearer ${token}` }),
      "content-type": "application/json",
      ...(options.headers ?? {}),
      ...(sessionAuth && !["GET", "HEAD"].includes((options.method ?? "GET").toUpperCase()) ? { "x-admin-csrf": adminCsrf } : {})
    }
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (!response.ok) {
    if (sessionAuth && response.status === 401) {
      window.location.assign("/oauth2/admin/login?reauth=1");
      throw new Error("관리자 로그인이 만료됐습니다. 다시 로그인하세요.");
    }
    throw new Error(payload?.error?.message ?? "요청을 처리하지 못했습니다.");
  }
  return payload;
};

const formatDate = (value) => new Intl.DateTimeFormat("ko-KR", {
  timeZone: "Asia/Seoul",
  dateStyle: "medium",
  timeStyle: "short"
}).format(new Date(value));

const roleLabel = (role) => `${role.serviceKey}:${role.name}`;

const element = (tagName, { className, text } = {}) => {
  const node = document.createElement(tagName);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = String(text);
  }
  return node;
};

const renderEmptyUsers = (message) => {
  visibleUserIds = new Set();
  clearSelection();
  if (userTable) {
    const row = element("tr");
    const cell = element("td", { className: "empty-cell", text: message });
    cell.colSpan = 7;
    row.append(cell);
    userTable.replaceChildren(row);
  }
};

let userPage = 1;
let auditPage = 1;

const renderDashboardPager = (selector, result, onPage) => {
  const pager = document.querySelector(selector);
  if (!pager) return;
  pager.replaceChildren();
  if (!result || result.total <= result.pageSize) return;
  const last = Math.ceil(result.total / result.pageSize);
  if (result.page > 1) {
    pager.append(accessButton("이전", () => onPage(result.page - 1)));
  }
  pager.append(element("span", { text: `${result.page} / ${last} 페이지` }));
  if (result.page < last) {
    pager.append(accessButton("다음", () => onPage(result.page + 1)));
  }
};

const userQueryString = () => {
  if (!(filterForm instanceof HTMLFormElement)) {
    return "";
  }
  const values = new FormData(filterForm);
  const params = new URLSearchParams({ page: String(userPage), pageSize: "50" });
  for (const name of ["email", "status", "role", "userType"]) {
    const value = values.get(name);
    if (typeof value === "string" && value.trim()) {
      params.set(name, value.trim());
    }
  }
  return params.toString();
};

const setSummary = (message) => {
  if (summary) {
    summary.textContent = message;
  }
};

const statusSelect = (user) => {
  const label = element("label", { className: "compact-label" });
  label.append(element("span", { className: "sr-only", text: "상태 변경" }));
  const select = element("select");
  select.dataset.statusSelect = String(user.id);
  for (const status of userStatuses) {
    const option = element("option", { text: status });
    option.value = status;
    option.selected = status === user.status;
    select.append(option);
  }
  label.append(select);
  return label;
};

const userTypeSelect = (user) => {
  if (user.userType === "EXTERNAL") {
    return element("span", { text: "외부" });
  }
  const select = element("select");
  select.dataset.userTypeSelect = String(user.id);
  select.setAttribute("aria-label", "사용자 유형 변경");
  for (const [value, text] of [["UNCLASSIFIED", "미분류"], ["EMPLOYEE", "직원"], ["CUSTOMER", "고객"]]) {
    const option = element("option", { text });
    option.value = value;
    option.selected = value === (user.userType ?? "UNCLASSIFIED");
    select.append(option);
  }
  return select;
};

const actionButton = (className, text, datasetName, datasetValue) => {
  const button = element("button", { className, text });
  button.type = "button";
  button.dataset[datasetName] = String(datasetValue);
  return button;
};

const renderUsers = (page) => {
  if (!userTable) {
    return;
  }
  if (!page.items.length) {
    renderEmptyUsers("조회 결과가 없습니다.");
    setSummary("0명");
    return;
  }

  visibleUserIds = new Set(
    page.items.filter((user) => user.userType !== "EXTERNAL").map((user) => String(user.id))
  );
  selectedUserIds.clear();
  const rows = page.items.map((user) => {
    const row = element("tr");
    const selectionCell = element("td");
    const checkbox = element("input");
    checkbox.type = "checkbox";
    checkbox.dataset.selectUser = String(user.id);
    if (user.userType === "EXTERNAL") {
      checkbox.dataset.typeChangeBlocked = "true";
      checkbox.disabled = true;
      checkbox.title = "외부 계정은 유형을 변경할 수 없습니다.";
    }
    checkbox.setAttribute("aria-label", `${user.email ?? user.id} 선택`);
    selectionCell.append(checkbox);

    const identityCell = element("td");
    const identity = element("div", { className: "user-main" });
    const emailLabel = element(sessionAuth ? "a" : "span", {
      className: "user-email",
      text: user.email ?? "이메일 없음",
    });
    if (sessionAuth) emailLabel.href = `/oauth2/admin/users/${encodeURIComponent(user.id)}`;
    identity.append(
      emailLabel,
      element("span", { text: user.name ?? "이름 없음" }),
      element("span", { className: "user-id", text: user.id })
    );
    identityCell.append(identity);

    const statusCell = element("td");
    const status = element("span", { className: "badge", text: user.status });
    status.dataset.status = String(user.status);
    statusCell.append(status);

    const roleCell = element("td");
    const roles = element("div", { className: "role-list" });
    if (user.roles.length) {
      for (const role of user.roles) {
        const button = actionButton("role-chip", `${roleLabel(role)} 제거`, "removeRole", user.id);
        button.dataset.roleId = String(role.id);
        roles.append(button);
      }
    } else {
      roles.append(element("span", { className: "role-chip", text: "역할 없음" }));
    }
    roleCell.append(roles);

    const createdCell = element("td", { text: formatDate(user.createdAt) });
    const actionCell = element("td");
    const actions = element("div", { className: "action-list" });
    actions.append(
      statusSelect(user),
      ...(sessionAuth && document.querySelector("[data-client-access]")
        ? [rolePicker(user)]
        : [
          actionButton("secondary-button", "user 부여", "addUserRole", user.id),
          actionButton("secondary-button", "admin 부여", "addAdminRole", user.id),
        ]),
      actionButton("danger-button", "세션 폐기", "revoke", user.id)
    );
    actionCell.append(actions);

    const typeCell = element("td");
    typeCell.append(userTypeSelect(user));
    row.append(selectionCell, identityCell, statusCell, typeCell, roleCell, createdCell, actionCell);
    return row;
  });
  userTable.replaceChildren(...rows);
  syncSelection();
  setSummary(`총 ${page.total}명 중 ${page.items.length}명 표시`);
};

const loadUsers = async () => {
  if (adminBusy) return;
  const query = userQueryString();
  setBusy(true);
  try {
    let page = await apiFetch(`/users?${query}`);
    const last = Math.max(1, Math.ceil(page.total / page.pageSize));
    if (userPage > last) {
      userPage = last;
      const corrected = new URLSearchParams(query);
      corrected.set("page", String(last));
      page = await apiFetch(`/users?${corrected}`);
    }
    renderUsers(page);
    renderDashboardPager("[data-user-pager]", page, (next) => {
      if (adminBusy) return;
      userPage = next;
      void loadUsers();
    });
  } catch (error) {
    renderDashboardPager("[data-user-pager]", null);
    renderEmptyUsers(error instanceof Error ? error.message : "조회 실패");
    setNotice("error", error instanceof Error ? error.message : "조회 실패");
  } finally {
    setBusy(false);
  }
};

const patchStatus = async (userId, status, reasonCode) => {
  await apiFetch(`/users/${encodeURIComponent(userId)}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status, reasonCode })
  });
};

const assignRole = (userId, serviceKey, name, reasonCode) =>
  apiFetch(`/users/${encodeURIComponent(userId)}/roles`, {
    method: "POST",
    body: JSON.stringify({ serviceKey, name, reasonCode })
  });

const addRole = (userId, name) =>
  assignRole(userId, name === "admin" ? "sso" : "temis", name, "ADMIN_DASHBOARD_ROLE_ASSIGN");

const removeRole = async (userId, roleId, reasonCode) => {
  if (reasonCode === undefined) {
    reasonCode = sessionAuth ? roleReason() : "ADMIN_DASHBOARD_ROLE_REMOVE";
  }
  if (!reasonCode) return false;
  await apiFetch(`/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(roleId)}`, {
    method: "DELETE",
    body: JSON.stringify({ reasonCode })
  });
};

const revokeSessions = async (userId) => {
  const reasonCode = roleReason();
  if (!reasonCode) return false;
  await apiFetch(`/users/${encodeURIComponent(userId)}/revoke-sessions`, {
    method: "POST",
    body: JSON.stringify({ reasonCode })
  });
};

let roleCatalog = [];
let clientPage = 1;
let memberPage = 1;
let selectedClientId = null;
let clientAccessRequest = 0;

const accessButton = (label, action) => {
  const button = element("button", { className: "secondary-button", text: label });
  button.type = "button";
  button.addEventListener("click", action);
  return button;
};

const fillRoleOptions = (select, roles) => {
  const placeholder = element("option", { text: "역할 선택" });
  placeholder.value = "";
  select.replaceChildren(placeholder, ...roles.map((role, index) => {
    const option = element("option", { text: `${role.serviceKey}:${role.name}` });
    option.value = String(index);
    return option;
  }));
};

const roleReason = () => window.prompt("변경 사유를 입력하세요.")?.trim();

const rolePicker = (user) => {
  const wrapper = element("div");
  const select = element("select");
  select.setAttribute("aria-label", "부여할 역할");
  fillRoleOptions(select, roleCatalog);
  wrapper.append(select, accessButton("부여", () => {
    const role = select.value === "" ? null : roleCatalog[Number(select.value)];
    if (!role) return;
    const reason = roleReason();
    if (!reason) return;
    void runUserAction(
      () => assignRole(user.id, role.serviceKey, role.name, reason),
      "역할을 부여했습니다."
    );
  }));
  return wrapper;
};

const loadRoleCatalog = async () => {
  const roles = [];
  let page = 1;
  while (true) {
    const result = await apiFetch(`/roles?page=${page}&pageSize=100`);
    roles.push(...result.items);
    if (roles.length >= result.total || result.items.length === 0) break;
    page += 1;
  }
  roleCatalog = roles;
};

const accessPager = (result, onPage) => {
  const controls = element("div");
  if (result.page > 1) {
    controls.append(accessButton("이전", () => onPage(result.page - 1)));
  }
  if (result.page * result.pageSize < result.total) {
    controls.append(accessButton("다음", () => onPage(result.page + 1)));
  }
  return controls;
};

const memberGrantForm = (client) => {
  const form = element("form");
  const email = element("input");
  email.type = "email";
  email.required = true;
  email.setAttribute("aria-label", "추가할 사용자의 이메일");
  email.placeholder = "사용자 이메일";
  const roles = element("select");
  roles.required = true;
  roles.setAttribute("aria-label", "부여할 서비스 역할");
  fillRoleOptions(roles, client.requiredRoles);
  const submit = element("button", { className: "secondary-button", text: "역할 부여" });
  submit.type = "submit";
  form.append(email, roles, submit);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const address = email.value.trim();
    const role = roles.value === "" ? null : client.requiredRoles[Number(roles.value)];
    if (!address || !role) return;
    const reason = roleReason();
    if (!reason) return;
    void runUserAction(async () => {
      const query = new URLSearchParams({ email: address, pageSize: "100" });
      const result = await apiFetch(`/users?${query}`);
      const user = result.items.find((item) => item.email === address);
      if (!user) throw new Error("이메일이 정확히 일치하는 사용자를 찾지 못했습니다.");
      await assignRole(user.id, role.serviceKey, role.name, reason);
    }, "서비스 역할을 부여했습니다.");
  });
  return form;
};

const renderClientMembers = (container, client, result) => {
  const list = element("ul");
  for (const member of result.items) {
    const entry = element("li", {
      text: `${member.email} · ${member.requiredRoleMatched ? "필요 역할 충족" : "역할 없이 허용"}`
    });
    for (const role of member.matchedRoles) {
      entry.append(accessButton(`${role.serviceKey}:${role.name} 회수`, () => {
        const reason = roleReason();
        if (!reason) return;
        void runUserAction(
          () => removeRole(member.id, role.id, reason),
          "서비스 역할을 회수했습니다."
        );
      }));
    }
    list.append(entry);
  }
  container.replaceChildren(
    element("h3", { text: `${client.clientId} 이용 가능자 (${result.total}명)` }),
    result.items.length ? list : element("p", { text: "표시할 이용 가능자가 없습니다." }),
    accessPager(result, (page) => {
      memberPage = page;
      void refreshClientAccess();
    }),
    element("h4", { text: "역할 부여" }),
    memberGrantForm(client)
  );
};

const refreshClientAccess = async () => {
  const panel = document.querySelector("[data-client-access]");
  if (!sessionAuth || !panel) return;
  const status = panel.querySelector("[data-client-access-status]");
  const catalog = panel.querySelector("[data-client-catalog]");
  const members = panel.querySelector("[data-client-members]");
  if (!status || !catalog || !members) return;

  const request = ++clientAccessRequest;
  panel.hidden = false;
  status.textContent = "서비스 정책을 불러오는 중입니다.";
  try {
    const result = await apiFetch(`/clients?page=${clientPage}&pageSize=25`);
    if (request !== clientAccessRequest) return;
    const typeLabels = {
      EMPLOYEE: "직원",
      CUSTOMER: "고객",
      EXTERNAL: "외부",
      UNCLASSIFIED: "미분류",
    };
    const number = new Intl.NumberFormat("ko-KR");
    const rows = result.items.map((client) => {
      const card = element("article", { className: "client-access-card" });
      const header = element("div", { className: "client-access-card-header" });
      header.append(
        element("h3", { text: client.clientId }),
        element("strong", { text: `이용 가능 ${number.format(client.eligibleCount)}명` })
      );

      const types = client.allowedUserTypes
        ?.map((type) => typeLabels[type] ?? type).join(", ") || "전체";
      const roles = client.requiredRoles
        .map((role) => `${role.serviceKey}:${role.name}`).join(", ") || "없음";
      const policy = element("dl", { className: "client-access-policy" });
      for (const [label, value] of [
        ["허용 유형", types],
        ["필요 역할", roles],
        ["역할 없이 로그인", client.allowWithoutRequiredRole ? "가능" : "불가"],
        ["자동 로그인", client.ssoAutoLogin ? "켜짐" : "꺼짐"],
      ]) {
        policy.append(element("dt", { text: label }), element("dd", { text: value }));
      }

      const details = accessButton("이용 가능자 보기", () => {
        selectedClientId = client.clientId;
        memberPage = 1;
        void refreshClientAccess();
      });
      details.setAttribute("aria-label", `${client.clientId} 이용 가능자 보기`);
      card.append(header, policy, details);
      return card;
    });
    const grid = element("div", { className: "client-access-grid" });
    grid.append(...rows);
    catalog.replaceChildren(grid, accessPager(result, (page) => {
      clientPage = page;
      selectedClientId = null;
      void refreshClientAccess();
    }));
    const client = result.items.find((item) => item.clientId === selectedClientId);
    if (client) {
      const id = encodeURIComponent(client.clientId);
      const page = await apiFetch(`/clients/${id}/members?page=${memberPage}&pageSize=25`);
      if (request !== clientAccessRequest) return;
      if (!page.items.length && page.page > 1) {
        memberPage = Math.max(1, Math.ceil(page.total / page.pageSize));
        await refreshClientAccess();
        return;
      }
      renderClientMembers(members, client, page);
    } else {
      members.replaceChildren();
    }
    status.textContent = result.total === 0 ? "등록된 서비스가 없습니다." : "";
  } catch (error) {
    if (request !== clientAccessRequest) return;
    members.replaceChildren();
    status.textContent = error instanceof Error ? error.message : "서비스 조회 실패";
  }
};

const runUserAction = async (task, successMessage) => {
  if (adminBusy) return;
  setBusy(true);
  try {
    if ((await task()) === false) return;
    setNotice("success", successMessage);
  } catch (error) {
    setNotice("error", error instanceof Error ? error.message : "요청 실패");
    return;
  } finally {
    setBusy(false);
  }
  await loadUsers();
  if (sessionAuth) await refreshClientAccess();
};

const renderAudit = (page) => {
  if (!auditList) {
    return;
  }
  if (!page.items.length) {
    auditList.replaceChildren(element("p", { className: "empty-cell", text: "감사 로그가 없습니다." }));
    return;
  }

  const items = page.items.map((item) => {
    const article = element("article", { className: "audit-item" });
    article.append(
      element("strong", { text: item.eventType }),
      element("span", { text: `${item.outcome}${item.reasonCode ? ` / ${item.reasonCode}` : ""}` }),
      element("span", { text: item.userId ?? item.targetUserId ?? "사용자 없음" }),
      element("time", { text: formatDate(item.createdAt) })
    );
    return article;
  });
  auditList.replaceChildren(...items);
};

const loadAudit = async () => {
  if (adminBusy) return;
  setBusy(true);
  try {
    let page = await apiFetch(`/audit-logs?page=${auditPage}&pageSize=20`);
    const last = Math.max(1, Math.ceil(page.total / page.pageSize));
    if (auditPage > last) {
      auditPage = last;
      page = await apiFetch(`/audit-logs?page=${auditPage}&pageSize=20`);
    }
    renderAudit(page);
    renderDashboardPager("[data-audit-pager]", page, (next) => {
      if (adminBusy) return;
      auditPage = next;
      void loadAudit();
    });
  } catch (error) {
    renderDashboardPager("[data-audit-pager]", null);
    if (auditList) {
      auditList.replaceChildren(element("p", {
        className: "empty-cell",
        text: error instanceof Error ? error.message : "조회 실패"
      }));
    }
    setNotice("error", error instanceof Error ? error.message : "조회 실패");
  } finally {
    setBusy(false);
  }
};

tokenForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!(tokenInput instanceof HTMLInputElement) || !tokenInput.value.trim()) {
    setNotice("error", "Access Token을 입력하세요.");
    return;
  }
  clearSelection();
  window.sessionStorage.setItem(tokenStorageKey, tokenInput.value.trim());
  tokenInput.value = "";
  setNotice("success", "관리자 토큰을 저장했습니다.");
  void loadUsers();
});

document.querySelector("[data-clear-token]")?.addEventListener("click", () => {
  window.sessionStorage.removeItem(tokenStorageKey);
  renderEmptyUsers("토큰을 저장한 뒤 조회하세요.");
  setSummary("토큰을 저장한 뒤 조회하세요.");
  setNotice("success", "관리자 토큰을 삭제했습니다.");
});

filterForm?.addEventListener("input", () => {
  userPage = 1;
  clearSelection();
  renderDashboardPager("[data-user-pager]", null);
});

selectAll?.addEventListener("change", () => {
  if (!(selectAll instanceof HTMLInputElement) || adminBusy) return;
  selectedUserIds.clear();
  if (selectAll.checked) for (const userId of visibleUserIds) selectedUserIds.add(userId);
  syncSelection();
});

bulkForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  if (adminBusy || !(bulkType instanceof HTMLSelectElement)) return;
  const ids = Array.from(selectedUserIds);
  const selectedType = bulkType.value;
  if (!ids.length || !["EMPLOYEE", "CUSTOMER", "UNCLASSIFIED"].includes(selectedType)) {
    setNotice("error", "사용자와 변경할 유형을 선택하세요.");
    return;
  }
  const label = { EMPLOYEE: "직원", CUSTOMER: "고객", UNCLASSIFIED: "미분류" }[selectedType];
  if (!window.confirm(`${ids.length}명의 사용자 유형을 ${label}(으)로 변경합니다. 변경된 사용자의 기존 인증 세션이 폐기됩니다. 계속하시겠습니까?`)) return;
  const reasonCode = roleReason();
  if (!reasonCode) return;
  setBusy(true);
  void (async () => {
    try {
      const result = await apiFetch("/users/type", {
        method: "PATCH",
        body: JSON.stringify({ userIds: ids, userType: selectedType === "UNCLASSIFIED" ? null : selectedType,
          reasonCode })
      });
      clearSelection();
      setNotice("success", `${result.changedCount}명 변경, ${result.unchangedCount}명은 기존 유형과 같습니다.`);
    } catch (error) {
      setNotice("error", error instanceof Error ? error.message : "일괄 변경 실패");
      return;
    } finally {
      setBusy(false);
    }
    await loadUsers();
  })();
});

filterForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  userPage = 1;
  void loadUsers();
});

document.querySelector("[data-refresh]")?.addEventListener("click", () => {
  void loadUsers();
});

document.querySelector("[data-load-audit]")?.addEventListener("click", () => {
  void loadAudit();
});

userTable?.addEventListener("change", (event) => {
  const target = event.target;
  if (target instanceof HTMLInputElement && target.dataset.selectUser) {
    const id = target.dataset.selectUser;
    if (!adminBusy && visibleUserIds.has(id)) {
      if (target.checked) selectedUserIds.add(id);
      else selectedUserIds.delete(id);
    }
    syncSelection();
    return;
  }
  if (!(target instanceof HTMLSelectElement) || adminBusy) {
    return;
  }
  const typeUserId = target.dataset.userTypeSelect;
  if (typeUserId) {
    const reasonCode = roleReason();
    if (!reasonCode) {
      void loadUsers();
      return;
    }
    void runUserAction(() => apiFetch(`/users/${encodeURIComponent(typeUserId)}/type`, {
      method: "PATCH",
      body: JSON.stringify({ userType: target.value === "UNCLASSIFIED" ? null : target.value,
                             reasonCode })
    }), "사용자 유형을 변경했습니다.");
    return;
  }
  const userId = target.dataset.statusSelect;
  if (!userId) {
    return;
  }
  const reasonCode = roleReason();
  if (!reasonCode) {
    void loadUsers();
    return;
  }
  void runUserAction(() => patchStatus(userId, target.value, reasonCode), "상태를 변경했습니다.");
});

userTable?.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  const userRoleTarget = target.dataset.addUserRole;
  if (userRoleTarget) {
    void runUserAction(() => addRole(userRoleTarget, "user"), "temis:user 역할을 부여했습니다.");
    return;
  }
  const adminRoleTarget = target.dataset.addAdminRole;
  if (adminRoleTarget) {
    void runUserAction(() => addRole(adminRoleTarget, "admin"), "sso:admin 역할을 부여했습니다.");
    return;
  }
  const revokeTarget = target.dataset.revoke;
  if (revokeTarget) {
    void runUserAction(() => revokeSessions(revokeTarget), "세션을 폐기했습니다.");
    return;
  }
  const removeRoleTarget = target.dataset.removeRole;
  const roleId = target.dataset.roleId;
  if (removeRoleTarget && roleId) {
    void runUserAction(() => removeRole(removeRoleTarget, roleId), "역할을 제거했습니다.");
  }
});

void fetch("/healthz")
  .then((response) => {
    if (!health) {
      return;
    }
    health.textContent = response.ok ? "서버 정상" : "서버 확인 필요";
  })
  .catch(() => {
    if (health) {
      health.textContent = "서버 확인 필요";
    }
  });

if (sessionAuth || authToken()) {
  void loadUsers();
}

const loadAdminOverview = async () => {
  const panel = document.querySelector("[data-admin-overview]");
  const status = panel?.querySelector("[data-admin-overview-status]");
  const content = panel?.querySelector("[data-admin-overview-content]");
  if (!sessionAuth || !(panel instanceof HTMLElement) || !status || !content) return;

  panel.hidden = false;
  try {
    const data = await apiFetch("/summary");
    const groups = [
      ["사용자 유형", [
        ["직원", data.usersByType.EMPLOYEE],
        ["고객", data.usersByType.CUSTOMER],
        ["외부", data.usersByType.EXTERNAL],
        ["미분류", data.usersByType.UNCLASSIFIED],
      ]],
      ["사용자 상태", [
        ["활성", data.usersByStatus.ACTIVE],
        ["이메일 인증 대기", data.usersByStatus.PENDING_EMAIL_VERIFICATION],
        ["정지", data.usersByStatus.SUSPENDED],
        ["삭제", data.usersByStatus.DELETED],
      ]],
      ["외부 계정 만료 예정", [
        ["7일 이내", data.externalExpiring.within7Days],
        ["30일 이내", data.externalExpiring.within30Days],
      ]],
      ["초대", [
        ["대기 중", data.invitations.pending],
        ["만료", data.invitations.expired],
      ]],
      ["로그인", [
        ["최근 24시간 성공", data.logins24h.success],
        ["최근 24시간 실패", data.logins24h.failure],
        ["현재 잠긴 계정", data.lockedAccounts],
      ]],
      ["최근 7일 서비스별 로그인 사용자", Object.entries(data.serviceLoginUsers7d)],
    ];

    const number = new Intl.NumberFormat("ko-KR");
    content.replaceChildren(...groups.map(([title, rows]) => {
      const group = element("div", { className: "admin-overview-group" });
      group.append(element("h3", { text: title }));
      if (!rows.length) {
        group.append(element("p", { text: "집계 기간에 로그인 기록이 없습니다." }));
        return group;
      }
      const list = element("dl");
      for (const [label, value] of rows) {
        list.append(
          element("dt", { text: label }),
          element("dd", { text: number.format(value) }),
        );
      }
      group.append(list);
      return group;
    }));
    status.hidden = true;
  } catch {
    status.textContent = "요약을 불러오지 못했습니다. 페이지를 새로고침해 주세요.";
  }
};

void loadAdminOverview();

if (sessionAuth && document.querySelector("[data-client-access]")) {
  void refreshClientAccess();
  void loadRoleCatalog()
    .then(() => loadUsers())
    .catch(() => setNotice("error", "역할 목록을 불러오지 못했습니다."));
}
