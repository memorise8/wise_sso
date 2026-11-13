const tokenStorageKey = "wise_sso_admin_access_token";
const userStatuses = ["ACTIVE", "PENDING_EMAIL_VERIFICATION", "SUSPENDED", "DELETED"];
const statusLabels = { ACTIVE: "활성", PENDING_EMAIL_VERIFICATION: "인증 대기", SUSPENDED: "정지", DELETED: "삭제" };
const serviceLabels = { "gitlab-temis": "GitLab", "agent-hub-dash": "에이전트 허브", "fantra-oidc": "Fantra" };

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
    const code = payload?.error?.code;
    throw new Error(adminErrorMessages[code] ?? payload?.error?.message ?? "요청을 처리하지 못했습니다.");
  }
  return payload;
};

const formatDate = (value) => new Intl.DateTimeFormat("ko-KR", {
  timeZone: "Asia/Seoul",
  dateStyle: "medium",
  timeStyle: "short"
}).format(new Date(value));

const formatDay = (value) => new Intl.DateTimeFormat("ko-KR", { timeZone: "Asia/Seoul", dateStyle: "medium" }).format(new Date(value));

// Every change asks why; the answer is stored as the audit reason.
const askReason = () => window.prompt("변경 사유를 입력하세요. (감사 기록에 남습니다)")?.trim();

let userPage = 1;
let auditPage = 1;

const renderPager = (selector, result, onPage) => {
  const pager = document.querySelector(selector);
  if (!pager) return;
  pager.replaceChildren();
  if (!result || result.total <= result.pageSize) return;
  const last = Math.ceil(result.total / result.pageSize);
  const step = (text, page) => {
    const button = element("button", { className: "secondary-button", text });
    button.type = "button";
    button.addEventListener("click", () => {
      if (!adminBusy) onPage(page);
    });
    return button;
  };
  if (result.page > 1) pager.append(step("이전", result.page - 1));
  pager.append(element("span", { text: `${result.page} / ${last}` }));
  if (result.page < last) pager.append(step("다음", result.page + 1));
};

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
    const option = element("option", { text: statusLabels[status] ?? status });
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

const typeCellContent = (user) => {
  if (user.userType !== "EXTERNAL") return userTypeSelect(user);
  const tag = element("span", { className: "type-tag", text: "외부" });
  tag.title = "기한·정지는 '외부 계정' 메뉴에서 관리합니다.";
  return tag;
};

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
    identity.append(
      (() => {
        const name = element(sessionAuth ? "a" : "span", { className: "user-name", text: user.name ?? "이름 없음" });
        if (sessionAuth) name.href = `/oauth2/admin/users/${encodeURIComponent(user.id)}`;
        return name;
      })(),
      element("span", { className: "user-email", text: user.email ?? "(email 없음)" }),
      element("span", { className: "user-id", text: user.id })
    );
    const avatar = element("span", { className: "avatar", text: (user.name ?? user.email ?? "?").trim().charAt(0).toUpperCase() || "?" });
    avatar.setAttribute("aria-hidden", "true");
    const who = element("div", { className: "user-cell" });
    who.append(avatar, identity);
    identityCell.append(who);

    const statusCell = element("td");
    const status = element("span", { className: "badge", text: statusLabels[user.status] ?? user.status });
    status.dataset.status = String(user.status);
    statusCell.append(status);

    const roleCell = element("td");
    const roles = element("div", { className: "role-list" });
    if (user.roles.length) {
      for (const role of user.roles) {
        const button = actionButton("role-chip", `${roleLabel(role)} ×`, "removeRole", user.id);
        button.dataset.roleId = String(role.id);
        button.title = "누르면 이 역할을 뺍니다";
        button.setAttribute("aria-label", `${roleLabel(role)} 역할 빼기`);
        roles.append(button);
      }
    } else {
      roles.append(element("span", { className: "muted", text: "역할 없음" }));
    }
    roleCell.append(roles);

    const accessCell = element("td");
    accessCell.dataset.accessFor = String(user.id);
    accessCell.append(element("span", { className: "type-fixed", text: sessionAuth ? "확인 중…" : "-" }));

    const createdCell = element("td", { className: "nowrap muted", text: formatDay(user.createdAt) });
    const actionCell = element("td", { className: "col-menu" });
    const menu = element("details", { className: "row-menu" });
    const trigger = element("summary", { text: "⋯" });
    trigger.setAttribute("aria-label", `${user.email ?? user.id} 관리`);
    const actions = element("div", { className: "action-list" });
    actions.append(
      element("span", { className: "menu-label", text: "상태" }),
      statusSelect(user),
      element("span", { className: "menu-label", text: "역할 주기" }),
      roleAssign(user),
      actionButton("danger-button", "로그인 세션 끊기", "revoke", user.id)
    );
    menu.append(trigger, actions);
    actionCell.append(menu);

    const typeCell = element("td");
    typeCell.append(typeCellContent(user));
    row.append(selectionCell, identityCell, statusCell, typeCell, roleCell, accessCell, createdCell, actionCell);
    return row;
  });
  userTable.replaceChildren(...rows);
  syncSelection();
  void loadServiceAccess(page.items);
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
    renderPager("[data-user-pager]", page, (next) => {
      userPage = next;
      void loadUsers();
    });
  } catch (error) {
    renderPager("[data-user-pager]", null);
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

const addRole = async (userId, serviceKey, name, reasonCode) => {
  await apiFetch(`/users/${encodeURIComponent(userId)}/roles`, {
    method: "POST",
    body: JSON.stringify({ serviceKey, name, reasonCode })
  });
};

const accessReasons = {
  OIDC_USER_INACTIVE: "정지·삭제됐거나 이메일 인증 전",
  OIDC_ACCOUNT_EXPIRED: "외부 계정 기한 지남",
  OIDC_EMAIL_UNVERIFIED: "이메일 인증 전",
  OIDC_USER_TYPE_DENIED: "이 서비스가 받지 않는 사용자 유형",
  OIDC_REQUIRED_ROLE_MISSING: "필요한 역할 없음",
  OIDC_GROUPS_INVALID: "역할 구성 오류",
  OIDC_INVITATION_REQUIRED: "역할 없음 (서비스에서 초대받아야 입장)"
};

// Fantra·TEMIS and the SSO admin portal are not OIDC clients; their access follows the role alone.
const roleServices = [
  ["temis", "user", "Fantra·TEMIS"],
  ["sso", "admin", "SSO 관리자"]
];

const renderAccess = (cell, entries, user) => {
  const active = user?.status === "ACTIVE";
  const named = entries.map((entry) => ({
    service: serviceLabels[entry.clientId] ?? entry.clientId,
    allowed: entry.allowed,
    reason: entry.allowed ? "로그인 가능" : accessReasons[entry.reason] ?? entry.reason
  }));
  for (const [serviceKey, name, service] of roleServices) {
    const held = user?.roles.some((role) => role.serviceKey === serviceKey && role.name === name);
    named.push({ service, allowed: Boolean(active && held), reason: held ? (active ? "로그인 가능" : "계정 비활성") : `${serviceKey}:${name} 없음` });
  }
  const allowed = named.filter((entry) => entry.allowed);
  const denied = named.filter((entry) => !entry.allowed);
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

const loadServiceAccess = async (users) => {
  if (!sessionAuth || !users.length || !userTable) return;
  try {
    const params = new URLSearchParams(users.map((user) => ["id", String(user.id)]));
    const data = await apiFetch(`/service-access?${params.toString()}`);
    const byId = new Map(users.map((user) => [String(user.id), user]));
    for (const cell of userTable.querySelectorAll("td[data-access-for]")) {
      const entries = data.users[cell.dataset.accessFor];
      if (entries) renderAccess(cell, entries, byId.get(cell.dataset.accessFor));
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
    const roles = [];
    for (let page = 1; ; page += 1) {
      const result = await apiFetch(`/roles?page=${page}&pageSize=100`);
      roles.push(...result.items);
      if (roles.length >= result.total || !result.items.length) break;
    }
    roleCatalogue = roles;
  } catch {
    // Keep the built-in grants when the catalogue is unavailable.
  }
};

const removeRole = async (userId, roleId, reasonCode) => {
  await apiFetch(`/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(roleId)}`, {
    method: "DELETE",
    body: JSON.stringify({ reasonCode })
  });
};

const revokeSessions = async (userId, reasonCode) => {
  await apiFetch(`/users/${encodeURIComponent(userId)}/revoke-sessions`, {
    method: "POST",
    body: JSON.stringify({ reasonCode })
  });
};

const runUserAction = async (task, successMessage) => {
  setBusy(true);
  try {
    await task();
    setNotice("success", successMessage);
  } catch (error) {
    setNotice("error", error instanceof Error ? error.message : "요청 실패");
    return;
  } finally {
    setBusy(false);
  }
  // loadUsers skips while busy, so refresh only after the controls are released.
  await loadUsers();
  void loadAdminOverview();
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
    renderPager("[data-audit-pager]", page, (next) => {
      auditPage = next;
      void loadAudit();
    });
  } catch (error) {
    renderPager("[data-audit-pager]", null);
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
  renderPager("[data-user-pager]", null);
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
  const reasonCode = askReason();
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
  const userId = target.dataset.statusSelect;
  if (!typeUserId && !userId) {
    return;
  }
  const reasonCode = askReason();
  if (!reasonCode) {
    void loadUsers(); // put the select back
    return;
  }
  if (typeUserId) {
    void runUserAction(() => apiFetch(`/users/${encodeURIComponent(typeUserId)}/type`, {
      method: "PATCH",
      body: JSON.stringify({ userType: target.value === "UNCLASSIFIED" ? null : target.value, reasonCode })
    }), "사용자 유형을 변경했습니다.");
    return;
  }
  void runUserAction(() => patchStatus(userId, target.value, reasonCode), "상태를 변경했습니다.");
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
    const reasonCode = askReason();
    if (!reasonCode) return;
    void runUserAction(() => addRole(assignTarget, serviceKey, name, reasonCode), `${value} 역할을 부여했습니다.`);
    return;
  }
  const revokeTarget = target.dataset.revoke;
  if (revokeTarget) {
    const reasonCode = askReason();
    if (!reasonCode) return;
    void runUserAction(() => revokeSessions(revokeTarget, reasonCode), "로그인 세션을 끊었습니다.");
    return;
  }
  const removeRoleTarget = target.dataset.removeRole;
  const roleId = target.dataset.roleId;
  if (removeRoleTarget && roleId) {
    const reasonCode = askReason();
    if (!reasonCode) return;
    void runUserAction(() => removeRole(removeRoleTarget, roleId, reasonCode), "역할을 뺐습니다.");
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

if (sessionAuth) {
  void loadRoles().then(loadUsers);
} else if (authToken()) {
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
    const number = new Intl.NumberFormat("ko-KR");
    const types = data.usersByType;
    const total = Object.values(types).reduce((sum, value) => sum + value, 0);
    const expiring = data.externalExpiring;
    const cards = [
      ["전체 사용자", total, `활성 ${number.format(data.usersByStatus.ACTIVE)} · 정지 ${number.format(data.usersByStatus.SUSPENDED)}`],
      ["직원", types.EMPLOYEE, `고객 ${number.format(types.CUSTOMER)} · 미분류 ${number.format(types.UNCLASSIFIED)}`],
      ["외부 계정", types.EXTERNAL, `7일 안 만료 ${number.format(expiring.within7Days)} · 30일 ${number.format(expiring.within30Days)}`, expiring.within7Days > 0],
      ["대기 중인 초대", data.invitations.pending, `링크 만료 ${number.format(data.invitations.expired)}`],
      ["24시간 로그인", data.logins24h.success, `실패 ${number.format(data.logins24h.failure)} · 잠긴 계정 ${number.format(data.lockedAccounts)}`, data.lockedAccounts > 0]
    ];
    const grid = element("dl", { className: "stat-strip" });
    for (const [label, value, detail, warn] of cards) {
      const card = element("div", { className: "stat" });
      if (warn) card.dataset.tone = "warn";
      card.append(
        element("dt", { text: label }),
        element("dd", { text: number.format(value) }),
        element("p", { text: detail })
      );
      grid.append(card);
    }
    const services = Object.entries(data.serviceLoginUsers7d)
      .map(([id, count]) => `${serviceLabels[id] ?? id} ${number.format(count)}명`);
    const line = element("p", {
      className: "stat-foot",
      text: services.length
        ? `최근 7일 서비스별 로그인 사용자 · ${services.join(" · ")}`
        : "최근 7일 서비스 로그인 기록이 없습니다."
    });
    content.replaceChildren(grid, line);
    status.hidden = true;

    const attention = document.querySelector("[data-attention]");
    const notes = [];
    if (expiring.within7Days > 0) notes.push(`7일 안에 기한이 끝나는 외부 계정 ${expiring.within7Days}개`);
    if (data.lockedAccounts > 0) notes.push(`잠긴 계정 ${data.lockedAccounts}개`);
    if (data.invitations.expired > 0) notes.push(`링크가 만료된 초대 ${data.invitations.expired}건`);
    if (attention instanceof HTMLElement) {
      attention.textContent = notes.length ? `확인이 필요합니다 · ${notes.join(", ")}` : "";
      attention.hidden = notes.length === 0;
    }
  } catch {
    status.textContent = "요약을 불러오지 못했습니다. 페이지를 새로고침해 주세요.";
  }
};

void loadAdminOverview();
