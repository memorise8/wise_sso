"use strict";

const userId = decodeURIComponent(location.pathname.split("/").at(-1));
const userPath = `/users/${encodeURIComponent(userId)}`;
const csrf = document.querySelector('meta[name="admin-csrf"]').content;
const statusLine = document.querySelector("#detail-status");
const pageSize = 25;
const pages = { roles: 1, access: 1, sessions: 1, lastLogin: 1, history: 1, audit: 1 };
const clock = new Intl.DateTimeFormat("ko-KR", {
  timeZone: "Asia/Seoul", dateStyle: "medium", timeStyle: "short",
});
const typeLabels = { EMPLOYEE: "직원", CUSTOMER: "고객", EXTERNAL: "외부", UNCLASSIFIED: "미분류" };
const stateLabels = {
  ACTIVE: "활성", SUSPENDED: "정지", PENDING_EMAIL_VERIFICATION: "인증 대기", DELETED: "삭제",
};
let busy = false;
let roleCatalog = [];

function node(tag, text) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = String(text);
  return result;
}

function formatDate(value) {
  return value ? clock.format(new Date(value)) : "—";
}

function roleName(role) {
  return `${role.serviceKey}:${role.name}`;
}

async function api(path, method = "GET", body) {
  const response = await fetch(`/oauth2/admin/api${path}`, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    ...(body === undefined ? {} : {
      headers: { "Content-Type": "application/json", "X-Admin-CSRF": csrf },
      body: JSON.stringify(body),
    }),
  });
  if (response.status === 401) {
    location.assign("/oauth2/admin/login");
    throw new Error("다시 로그인해 주세요.");
  }
  if (response.status === 204) return null;
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error?.message ?? `요청 실패 (${response.status})`);
  }
  return data;
}

function button(label, action) {
  const control = node("button", label);
  control.type = "button";
  control.className = "secondary-button";
  control.addEventListener("click", () => {
    if (!busy) void action();
  });
  return control;
}

function section(id, title, ...content) {
  document.querySelector(`#detail-${id}`).replaceChildren(node("h2", title), ...content);
}

function table(headers, rows) {
  if (rows.length === 0) return node("p", "표시할 기록이 없습니다.");
  const wrapper = node("div");
  wrapper.className = "table-wrap";
  const result = node("table");
  const head = result.createTHead().insertRow();
  for (const label of headers) {
    const header = node("th", label);
    header.scope = "col";
    head.append(header);
  }
  const body = result.createTBody();
  for (const values of rows) {
    const row = body.insertRow();
    for (const value of values) row.append(node("td", value ?? "—"));
  }
  wrapper.append(result);
  return wrapper;
}

function pager(key, result) {
  const controls = node("div");
  if (result.total <= result.pageSize) return controls;
  const move = (page) => {
    pages[key] = page;
    return load();
  };
  if (result.page > 1) controls.append(button("이전", () => move(result.page - 1)));
  controls.append(node("span", ` ${result.page} / ${Math.ceil(result.total / result.pageSize)} `));
  if (result.page * result.pageSize < result.total) {
    controls.append(button("다음", () => move(result.page + 1)));
  }
  return controls;
}

async function mutate(path, method, payload, reasonField = "reasonCode") {
  const reason = window.prompt("변경 사유를 입력하세요.")?.trim();
  if (!reason) return;
  busy = true;
  statusLine.textContent = "변경 중입니다.";
  try {
    await api(path, method, { ...payload, [reasonField]: reason });
  } catch (error) {
    statusLine.textContent = error.message;
    return;
  } finally {
    busy = false;
  }
  pages.roles = 1;
  pages.audit = 1;
  pages.sessions = 1;
  await load("변경을 저장했습니다.");
}

function renderProfile(profile) {
  const fields = node("dl");
  fields.className = "client-access-policy";
  const data = [
    ["이메일", profile.email],
    ["이름", profile.name],
    ["유형", typeLabels[profile.userType ?? "UNCLASSIFIED"]],
    ["상태", stateLabels[profile.status] ?? profile.status],
    ["가입일 (KST)", formatDate(profile.createdAt)],
  ];
  if (profile.userType === "EXTERNAL") {
    data.push(["외부 계정 만료 (KST)", formatDate(profile.accountExpiresAt)]);
  }
  for (const [label, value] of data) fields.append(node("dt", label), node("dd", value ?? "—"));

  const actions = node("div");
  actions.className = "row-actions";
  if (profile.status === "ACTIVE" || profile.status === "SUSPENDED") {
    const next = profile.status === "ACTIVE" ? "SUSPENDED" : "ACTIVE";
    actions.append(button(next === "ACTIVE" ? "활성화" : "정지", () =>
      mutate(`${userPath}/status`, "PATCH", { status: next })
    ));
  }
  actions.append(button("세션 끊기", () => mutate(`${userPath}/revoke-sessions`, "POST", {})));
  if (profile.userType === "EXTERNAL") {
    actions.append(button("기한 연장", () => {
      const raw = window.prompt("연장할 일수를 입력하세요 (1–365일).");
      if (raw === null) return;
      const days = Number(raw);
      if (!Number.isInteger(days) || days < 1 || days > 365) {
        statusLine.textContent = "연장 일수는 1–365일이어야 합니다.";
        return;
      }
      return mutate(`/external-accounts/${encodeURIComponent(userId)}/extend`, "POST", { days }, "reason");
    }));
  }
  section("profile", "기본 정보", fields, actions);
}

function renderRoles(profile) {
  const list = node("ul");
  for (const role of profile.roles.items) {
    const item = node("li", `${roleName(role)} `);
    item.append(button("회수", () =>
      mutate(`${userPath}/roles/${encodeURIComponent(role.id)}`, "DELETE", {})
    ));
    list.append(item);
  }

  const select = node("select");
  select.setAttribute("aria-label", "부여할 역할");
  const placeholder = node("option", "역할 선택");
  placeholder.value = "";
  select.append(placeholder);
  for (const [index, role] of roleCatalog.entries()) {
    const option = node("option", roleName(role));
    option.value = String(index);
    select.append(option);
  }

  section(
    "roles", "역할",
    profile.roles.items.length ? list : node("p", "부여된 역할이 없습니다."),
    pager("roles", profile.roles),
    select,
    button("역할 부여", () => {
      const role = select.value === "" ? null : roleCatalog[Number(select.value)];
      if (role) return mutate(`${userPath}/roles`, "POST", {
        serviceKey: role.serviceKey, name: role.name,
      });
    })
  );
}

async function load(message = "") {
  if (busy) return;
  busy = true;
  statusLine.textContent = "사용자 정보를 불러오는 중입니다.";
  try {
    const detailQuery = new URLSearchParams({
      page: String(pages.access), historyPage: String(pages.history),
      servicePage: String(pages.lastLogin), rolePage: String(pages.roles),
      pageSize: String(pageSize),
    });
    const auditQuery = new URLSearchParams({
      targetUserId: userId, page: String(pages.audit), pageSize: String(pageSize),
    });
    const [profile, sessions, audit] = await Promise.all([
      api(`${userPath}?${detailQuery}`),
      api(`${userPath}/sessions?page=${pages.sessions}&pageSize=${pageSize}`),
      api(`/audit-logs?${auditQuery}`),
    ]);

    renderProfile(profile);
    renderRoles(profile);
    const access = profile.eligibleServices;
    section("access", "로그인 가능 서비스",
      table(["서비스", "접근 근거"], access.items.map((item) => [
        item.clientId, item.requiredRoleMatched ? "필요 역할 충족" : "역할 없이 허용",
      ])),
      pager("access", access)
    );
    section("sessions", `살아 있는 세션 (${sessions.activeSessionCount}개)`,
      table(["서비스", "개수", "가장 이른 만료 (KST)", "가장 늦은 만료 (KST)"],
        sessions.items.map((item) => [
          item.audience, item.count, formatDate(item.earliestExpiresAt), formatDate(item.latestExpiresAt),
        ])),
      pager("sessions", sessions)
    );
    const last = profile.lastLoginByService;
    section("last-login", "서비스별 마지막 성공 로그인",
      table(["서비스", "시각 (KST)", "IP"], last.items.map((item) => [
        item.service, formatDate(item.createdAt), item.ipAddress,
      ])),
      pager("lastLogin", last)
    );
    const history = profile.loginHistory;
    section("history", "최근 로그인 이력",
      table(["시각 (KST)", "서비스", "IP", "결과"], history.items.map((item) => [
        formatDate(item.createdAt), item.service, item.ipAddress, item.outcome === "success" ? "성공" : "실패",
      ])),
      pager("history", history)
    );
    section("audit", "대상 사용자 감사 기록",
      table(["시각 (KST)", "이벤트", "결과", "사유"], audit.items.map((item) => [
        formatDate(item.createdAt), item.eventType, item.outcome, item.reasonCode,
      ])),
      pager("audit", audit)
    );
    statusLine.textContent = message;
  } catch (error) {
    statusLine.textContent = error.message;
  } finally {
    busy = false;
  }
}

async function start() {
  let page = 1;
  let catalogError = false;
  try {
    while (true) {
      const result = await api(`/roles?page=${page}&pageSize=100`);
      roleCatalog.push(...result.items);
      if (roleCatalog.length >= result.total || result.items.length === 0) break;
      page += 1;
    }
  } catch {
    catalogError = true;
  }
  await load(catalogError ? "역할 목록을 불러오지 못했습니다." : "");
}

void start();
