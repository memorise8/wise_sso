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

const authToken = () => window.sessionStorage.getItem(tokenStorageKey) ?? "";

const setBusy = (busy) => {
  for (const button of document.querySelectorAll("button")) {
    if (button instanceof HTMLButtonElement) {
      button.disabled = busy;
    }
  }
};

const apiPath = (path) => `${adminApiBase}${path}`;

const apiFetch = async (path, options = {}) => {
  const token = authToken();
  if (!token) {
    throw new Error("관리자 Access Token을 먼저 저장하세요.");
  }

  const response = await fetch(apiPath(path), {
    ...options,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      ...(options.headers ?? {})
    }
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(payload?.error?.message ?? "요청을 처리하지 못했습니다.");
  }
  return payload;
};

const formatDate = (value) => new Intl.DateTimeFormat("ko-KR", {
  dateStyle: "medium",
  timeStyle: "short"
}).format(new Date(value));

const roleLabel = (role) => `${role.serviceKey}:${role.name}`;

const renderEmptyUsers = (message) => {
  if (userTable) {
    userTable.innerHTML = `<tr><td colspan="5" class="empty-cell">${message}</td></tr>`;
  }
};

const userQueryString = () => {
  if (!(filterForm instanceof HTMLFormElement)) {
    return "";
  }
  const values = new FormData(filterForm);
  const params = new URLSearchParams({ page: "1", pageSize: "50" });
  for (const name of ["email", "status", "role"]) {
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

const statusSelect = (user) => `
  <label class="compact-label">
    <span class="sr-only">상태 변경</span>
    <select data-status-select="${user.id}">
      ${userStatuses.map((status) => `<option value="${status}" ${status === user.status ? "selected" : ""}>${status}</option>`).join("")}
    </select>
  </label>
`;

const renderUsers = (page) => {
  if (!userTable) {
    return;
  }
  if (!page.items.length) {
    renderEmptyUsers("조회 결과가 없습니다.");
    setSummary("0명");
    return;
  }

  userTable.innerHTML = page.items.map((user) => `
    <tr>
      <td>
        <div class="user-main">
          <span class="user-email">${user.email ?? "(email 없음)"}</span>
          <span>${user.name ?? "이름 없음"}</span>
          <span class="user-id">${user.id}</span>
        </div>
      </td>
      <td><span class="badge" data-status="${user.status}">${user.status}</span></td>
      <td>
        <div class="role-list">
          ${user.roles.length ? user.roles.map((role) => `
            <button class="role-chip" type="button" data-remove-role="${user.id}" data-role-id="${role.id}">${roleLabel(role)} 제거</button>
          `).join("") : "<span class=\"role-chip\">역할 없음</span>"}
        </div>
      </td>
      <td>${formatDate(user.createdAt)}</td>
      <td>
        <div class="action-list">
          ${statusSelect(user)}
          <button class="secondary-button" type="button" data-add-user-role="${user.id}">user 부여</button>
          <button class="secondary-button" type="button" data-add-admin-role="${user.id}">admin 부여</button>
          <button class="danger-button" type="button" data-revoke="${user.id}">세션 폐기</button>
        </div>
      </td>
    </tr>
  `).join("");
  setSummary(`총 ${page.total}명 중 ${page.items.length}명 표시`);
};

const loadUsers = async () => {
  setBusy(true);
  try {
    const page = await apiFetch(`/users?${userQueryString()}`);
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

const addRole = async (userId, name) => {
  await apiFetch(`/users/${encodeURIComponent(userId)}/roles`, {
    method: "POST",
    body: JSON.stringify({ serviceKey: "temis", name, reasonCode: "ADMIN_DASHBOARD_ROLE_ASSIGN" })
  });
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
    auditList.innerHTML = "<p class=\"empty-cell\">감사 로그가 없습니다.</p>";
    return;
  }

  auditList.innerHTML = page.items.map((item) => `
    <article class="audit-item">
      <strong>${item.eventType}</strong>
      <span>${item.outcome}${item.reasonCode ? ` / ${item.reasonCode}` : ""}</span>
      <span>${item.userId ?? item.targetUserId ?? "사용자 없음"}</span>
      <time>${formatDate(item.createdAt)}</time>
    </article>
  `).join("");
};

const loadAudit = async () => {
  setBusy(true);
  try {
    const page = await apiFetch("/audit-logs?page=1&pageSize=20");
    renderAudit(page);
  } catch (error) {
    if (auditList) {
      auditList.innerHTML = `<p class="empty-cell">${error instanceof Error ? error.message : "조회 실패"}</p>`;
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
  if (!(target instanceof HTMLSelectElement)) {
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
  const userRoleTarget = target.dataset.addUserRole;
  if (userRoleTarget) {
    void runUserAction(() => addRole(userRoleTarget, "user"), "temis:user 역할을 부여했습니다.");
    return;
  }
  const adminRoleTarget = target.dataset.addAdminRole;
  if (adminRoleTarget) {
    void runUserAction(() => addRole(adminRoleTarget, "admin"), "temis:admin 역할을 부여했습니다.");
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

if (authToken()) {
  void loadUsers();
}
