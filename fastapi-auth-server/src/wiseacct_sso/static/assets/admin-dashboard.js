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

const overview = document.querySelector("[data-overview]");
// Token mode (legacy /manage-api) has no role catalogue endpoint; keep its two original grants.
let roleCatalogue = [
  { serviceKey: "temis", name: "user", externalAllowed: false },
  { serviceKey: "sso", name: "admin", externalAllowed: false }
];

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

// Server error codes shown to administrators in Korean; other codes keep the server message.
const adminErrorMessages = {
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

const authToken = () => sessionAuth ? "" : window.sessionStorage.getItem(tokenStorageKey) ?? "";

const setBusy = (busy) => {
  adminBusy = busy;
  for (const control of document.querySelectorAll("button, input, select")) {
    if (control instanceof HTMLButtonElement || control instanceof HTMLInputElement || control instanceof HTMLSelectElement) {
      control.disabled = busy;
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
    const code = payload?.error?.code;
    throw new Error(adminErrorMessages[code] ?? payload?.error?.message ?? "요청을 처리하지 못했습니다.");
  }
  return payload;
};

const formatDate = (value) => new Intl.DateTimeFormat("ko-KR", {
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
    cell.colSpan = 8;
    row.append(cell);
    userTable.replaceChildren(row);
  }
};

const userQueryString = () => {
  if (!(filterForm instanceof HTMLFormElement)) {
    return "";
  }
  const values = new FormData(filterForm);
  const params = new URLSearchParams({ page: "1", pageSize: "50" });
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

const typeCellContent = (user) => user.userType === "EXTERNAL"
  ? element("span", { className: "type-fixed", text: "외부 (기한·정지는 외부 계정 패널)" })
  : userTypeSelect(user);

const roleAssign = (user) => {
  const wrap = element("div", { className: "role-assign" });
  const select = element("select");
  select.dataset.roleSelect = String(user.id);
  select.setAttribute("aria-label", "부여할 역할");
  const held = new Set(user.roles.map(roleLabel));
  const assignable = roleCatalogue.filter((role) =>
    (user.userType !== "EXTERNAL" || role.externalAllowed) && !held.has(roleLabel(role)));
  for (const role of assignable) {
    const option = element("option", { text: roleLabel(role) });
    option.value = roleLabel(role);
    select.append(option);
  }
  const button = actionButton("secondary-button", "역할 부여", "assignRole", user.id);
  if (!assignable.length) {
    select.append(element("option", { text: "부여할 역할 없음" }));
    select.disabled = true;
    button.disabled = true;
  }
  wrap.append(select, button);
  return wrap;
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

  // External accounts keep their type; they are not selectable for bulk type changes.
  visibleUserIds = new Set(page.items.filter((user) => user.userType !== "EXTERNAL").map((user) => String(user.id)));
  selectedUserIds.clear();
  const rows = page.items.map((user) => {
    const row = element("tr");
    const selectionCell = element("td");
    const checkbox = element("input");
    checkbox.type = "checkbox";
    checkbox.dataset.selectUser = String(user.id);
    checkbox.setAttribute("aria-label", `${user.email ?? user.id} 선택`);
    checkbox.disabled = user.userType === "EXTERNAL";
    selectionCell.append(checkbox);

    const identityCell = element("td");
    const identity = element("div", { className: "user-main" });
    identity.append(
      element("span", { className: "user-email", text: user.email ?? "(email 없음)" }),
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

    const accessCell = element("td");
    accessCell.dataset.accessFor = String(user.id);
    accessCell.append(element("span", { className: "type-fixed", text: sessionAuth ? "확인 중…" : "-" }));

    const createdCell = element("td", { text: formatDate(user.createdAt) });
    const actionCell = element("td");
    const actions = element("div", { className: "action-list" });
    actions.append(
      statusSelect(user),
      roleAssign(user),
      actionButton("danger-button", "세션 폐기", "revoke", user.id)
    );
    actionCell.append(actions);

    const typeCell = element("td");
    typeCell.append(typeCellContent(user));
    row.append(selectionCell, identityCell, statusCell, typeCell, roleCell, accessCell, createdCell, actionCell);
    return row;
  });
  userTable.replaceChildren(...rows);
  syncSelection();
  void loadServiceAccess(page.items.map((user) => String(user.id)));
  setSummary(`총 ${page.total}명 중 ${page.items.length}명 표시`);
};

const loadUsers = async () => {
  // Read the filters before setBusy: disabled controls are left out of FormData.
  const query = userQueryString();
  setBusy(true);
  try {
    const page = await apiFetch(`/users?${query}`);
    renderUsers(page);
  } catch (error) {
    renderEmptyUsers(error instanceof Error ? error.message : "조회 실패");
    setNotice("error", error instanceof Error ? error.message : "조회 실패");
  } finally {
    setBusy(false);
  }
};

const patchStatus = async (userId, status) => {
  await apiFetch(`/users/${encodeURIComponent(userId)}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status, reasonCode: "ADMIN_DASHBOARD_STATUS_CHANGE" })
  });
};

const addRole = async (userId, serviceKey, name) => {
  await apiFetch(`/users/${encodeURIComponent(userId)}/roles`, {
    method: "POST",
    body: JSON.stringify({ serviceKey, name, reasonCode: "ADMIN_DASHBOARD_ROLE_ASSIGN" })
  });
};

const setStat = (name, value) => {
  const node = overview?.querySelector(`[data-stat='${name}']`);
  if (node) node.textContent = value;
};

const loadOverview = async () => {
  if (!sessionAuth || !overview) return;
  try {
    const data = await apiFetch("/summary");
    for (const [type, count] of Object.entries(data.activeUsersByType)) setStat(type, `${count}명`);
    setStat("expiring30", `${data.external.expiringIn30Days}명`);
    setStat("expiring7", `7일 안: ${data.external.expiringIn7Days}명`);
    setStat("pendingInvitations", `${data.invitations.pending}건`);
    setStat("expiredInvitations", `링크 만료: ${data.invitations.expiredUnaccepted}건`);
    setStat("loginFailures", `${data.last24Hours.loginFailures}건`);
    setStat("locked", `잠긴 계정: ${data.lockedAccounts}개`);
    for (const card of overview.querySelectorAll("[data-tone='warn']")) {
      const value = Number.parseInt(card.querySelector("dd")?.textContent ?? "0", 10);
      card.dataset.alert = String(value > 0);
    }
    overview.hidden = false;
  } catch {
    overview.hidden = true;
  }
};

const renderAccess = (cell, entries) => {
  const allowed = entries.filter((entry) => entry.allowed);
  const denied = entries.filter((entry) => !entry.allowed);
  const list = element("div", { className: "access-list" });
  if (!allowed.length) list.append(element("span", { className: "access-none", text: "사용 가능한 서비스 없음" }));
  for (const entry of allowed) {
    const chip = element("span", { className: "access-chip", text: entry.service });
    chip.title = entry.reason;
    list.append(chip);
  }
  cell.replaceChildren(list);
  if (denied.length) {
    const detail = element("details", { className: "access-denied" });
    detail.append(element("summary", { text: `불가 ${denied.length}개` }));
    for (const entry of denied) detail.append(element("p", { text: `${entry.service}: ${entry.reason}` }));
    cell.append(detail);
  }
};

const loadServiceAccess = async (ids) => {
  if (!sessionAuth || !ids.length || !userTable) return;
  try {
    const params = new URLSearchParams(ids.map((id) => ["id", id]));
    const data = await apiFetch(`/service-access?${params.toString()}`);
    for (const cell of userTable.querySelectorAll("td[data-access-for]")) {
      const entries = data.users[cell.dataset.accessFor];
      if (entries) renderAccess(cell, entries);
    }
  } catch {
    for (const cell of userTable.querySelectorAll("td[data-access-for]")) {
      cell.replaceChildren(element("span", { className: "type-fixed", text: "확인 실패" }));
    }
  }
};

const loadRoles = async () => {
  if (!sessionAuth) return;
  try {
    roleCatalogue = (await apiFetch("/roles")).items;
  } catch {
    // Keep the built-in grants when the catalogue is unavailable.
  }
};

const removeRole = async (userId, roleId) => {
  await apiFetch(`/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(roleId)}`, {
    method: "DELETE",
    body: JSON.stringify({ reasonCode: "ADMIN_DASHBOARD_ROLE_REMOVE" })
  });
};

const revokeSessions = async (userId) => {
  await apiFetch(`/users/${encodeURIComponent(userId)}/revoke-sessions`, {
    method: "POST",
    body: JSON.stringify({ reasonCode: "ADMIN_DASHBOARD_SESSION_REVOKE" })
  });
};

const runUserAction = async (task, successMessage) => {
  setBusy(true);
  try {
    await task();
    setNotice("success", successMessage);
    await loadUsers();
    void loadOverview();
  } catch (error) {
    setNotice("error", error instanceof Error ? error.message : "요청 실패");
  } finally {
    setBusy(false);
  }
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
  setBusy(true);
  try {
    const page = await apiFetch("/audit-logs?page=1&pageSize=20");
    renderAudit(page);
  } catch (error) {
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

filterForm?.addEventListener("input", clearSelection);

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
  setBusy(true);
  void (async () => {
    try {
      const result = await apiFetch("/users/type", {
        method: "PATCH",
        body: JSON.stringify({ userIds: ids, userType: selectedType === "UNCLASSIFIED" ? null : selectedType,
          reasonCode: "ADMIN_DASHBOARD_BULK_USER_TYPE_CHANGE" })
      });
      clearSelection();
      setNotice("success", `${result.changedCount}명 변경, ${result.unchangedCount}명은 기존 유형과 같습니다.`);
      await loadUsers();
    } catch (error) {
      setNotice("error", error instanceof Error ? error.message : "일괄 변경 실패");
    } finally {
      setBusy(false);
    }
  })();
});

filterForm?.addEventListener("submit", (event) => {
  event.preventDefault();
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
    void runUserAction(() => apiFetch(`/users/${encodeURIComponent(typeUserId)}/type`, {
      method: "PATCH",
      body: JSON.stringify({ userType: target.value === "UNCLASSIFIED" ? null : target.value,
                             reasonCode: "ADMIN_DASHBOARD_USER_TYPE_CHANGE" })
    }), "사용자 유형을 변경했습니다.");
    return;
  }
  const userId = target.dataset.statusSelect;
  if (!userId) {
    return;
  }
  void runUserAction(() => patchStatus(userId, target.value), "상태를 변경했습니다.");
});

userTable?.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  const assignTarget = target.dataset.assignRole;
  if (assignTarget) {
    const select = userTable.querySelector(`select[data-role-select='${CSS.escape(assignTarget)}']`);
    const value = select instanceof HTMLSelectElement ? select.value : "";
    const [serviceKey, name] = value.split(":");
    if (!serviceKey || !name) return;
    if (serviceKey === "sso" && !window.confirm(`${value}는 관리자 권한입니다. 부여할까요?`)) return;
    void runUserAction(() => addRole(assignTarget, serviceKey, name), `${value} 역할을 부여했습니다.`);
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

document.querySelector("[data-overview-refresh]")?.addEventListener("click", () => {
  void loadOverview();
});

if (sessionAuth) {
  void loadOverview();
  void loadRoles().then(loadUsers);
} else if (authToken()) {
  void loadUsers();
}
