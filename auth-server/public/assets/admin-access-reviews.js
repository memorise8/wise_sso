(() => {
  "use strict";
  const panel = document.querySelector("[data-review-panel]");
  const nav = document.querySelector('[data-nav="reviews"]');
  const access = document.querySelector('meta[name="admin-access"]')?.content;
  if (!panel) return;
  if (access !== "admin") {
    panel.remove();
    nav?.remove();
    return;
  }

  const startForm = panel.querySelector("[data-review-start]");
  const status = panel.querySelector("[data-review-status]");
  const list = panel.querySelector("[data-review-list]");
  const listPager = panel.querySelector("[data-review-list-pager]");
  const detail = panel.querySelector("[data-review-detail]");
  const heading = panel.querySelector("[data-review-title]");
  const metadata = panel.querySelector("[data-review-metadata]");
  const counts = panel.querySelector("[data-review-counts]");
  const filter = panel.querySelector("[data-review-filter]");
  const rows = panel.querySelector("[data-review-items]");
  const itemPager = panel.querySelector("[data-review-item-pager]");
  const complete = panel.querySelector("[data-review-complete]");
  const csrf = document.querySelector('meta[name="admin-session-csrf"]').content;
  const clock = new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    calendar: "gregory",
    numberingSystem: "latn",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hourCycle: "h23",
  });
  const labels = {
    PENDING: "미결정", KEEP: "유지", REVOKE: "회수", ALREADY_REMOVED: "이미 제거됨",
  };
  const errors = {
    ACCESS_REVIEW_CLOSED: "이미 완료된 점검입니다.",
    ACCESS_REVIEW_ITEM_DECIDED: "다른 관리자가 이미 결정했습니다. 최신 내용을 확인하세요.",
    ACCESS_REVIEW_NOT_READY: "미결정 항목이 있거나 이미 완료된 점검입니다.",
    LAST_SSO_ADMIN: "마지막 활성 관리자의 권한은 회수할 수 없습니다.",
    FORBIDDEN: "관리자 권한이 없거나 본인의 관리자 권한 회수처럼 금지된 작업입니다.",
  };
  let busy = false;
  let reviewPage = 1;
  let itemPage = 1;
  let selected = null;

  function element(tag, text) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    return node;
  }

  function time(value) {
    if (!value) return "—";
    const parts = Object.fromEntries(
      clock.formatToParts(new Date(value)).map((part) => [part.type, part.value])
    );
    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second} (KST)`;
  }

  function controls() {
    for (const node of panel.querySelectorAll("button, input, select")) {
      node.disabled = busy || node.dataset.reviewBlocked === "true";
    }
  }

  async function api(path, method = "GET", body) {
    const response = await fetch(`/oauth2/admin/api/access-reviews${path}`, {
      method, credentials: "same-origin", cache: "no-store",
      ...(body === undefined ? {} : {
        headers: { "Content-Type": "application/json", "x-admin-csrf": csrf },
        body: JSON.stringify(body),
      }),
    });
    if (response.status === 401) {
      location.assign("/oauth2/admin/login?reauth=1");
      throw new Error("로그인이 만료됐습니다.");
    }
    const result = await response.json();
    if (!response.ok) {
      const error = new Error(
        errors[result.error?.code] ?? result.error?.message ?? `요청 실패 (${response.status})`
      );
      error.status = response.status;
      throw error;
    }
    return result;
  }

  async function run(work) {
    if (busy) return;
    busy = true;
    controls();
    status.textContent = "처리 중입니다.";
    try {
      await work();
      status.textContent = "";
    } catch (error) {
      if (error.status === 409 && selected) {
        try { await loadDetail(); } catch {}
      }
      status.textContent = error.message ?? "요청에 실패했습니다.";
    } finally {
      busy = false;
      controls();
    }
  }

  function button(text, action) {
    const node = element("button", text);
    node.type = "button";
    node.className = "secondary-button";
    node.addEventListener("click", () => void run(action));
    return node;
  }

  function pager(container, result, move) {
    container.replaceChildren();
    if (result.page > 1) {
      container.append(button("이전", () => move(result.page - 1)));
    }
    container.append(element("span", `${result.page} 페이지`));
    if (result.hasMore) {
      container.append(button("다음", () => move(result.page + 1)));
    }
  }

  async function loadList() {
    const result = await api(`?page=${reviewPage}&pageSize=25`);
    if (!result.items.length && reviewPage > 1) {
      reviewPage -= 1;
      return loadList();
    }
    list.replaceChildren();
    for (const review of result.items) {
      const item = element("li");
      item.append(
        button(review.title, async () => {
          selected = review.id;
          itemPage = 1;
          filter.value = "";
          await loadDetail();
        }),
        element("span", ` ${review.status === "OPEN" ? "진행 중" : "완료"} · 시작 ${time(review.startedAt)}`)
      );
      list.append(item);
    }
    if (!result.items.length) list.append(element("li", "점검 회차가 없습니다."));
    pager(listPager, result, async (page) => {
      reviewPage = page;
      await loadList();
    });
  }

  async function decide(item, decision) {
    if (decision === "REVOKE" && !window.confirm(
      `${item.userEmail ?? item.userId}의 ${item.serviceKey}:${item.roleName} 역할을 즉시 회수합니다. 계속할까요?`
    )) return;
    const payload = { decision };
    if (decision === "REVOKE") {
      const reason = window.prompt("회수 사유를 입력하세요. (감사 기록에 남습니다)")?.trim();
      if (!reason) return;
      if (reason.length > 128) throw new Error("사유는 128자 이내로 입력하세요.");
      payload.reasonCode = reason;
    }
    await api(
      `/${encodeURIComponent(selected)}/items/${encodeURIComponent(item.id)}/decision`,
      "POST", payload
    );
    await loadDetail();
  }

  async function loadItems(review) {
    const query = new URLSearchParams({ page: String(itemPage), pageSize: "25" });
    if (filter.value) query.set("decision", filter.value);
    const result = await api(`/${encodeURIComponent(selected)}/items?${query}`);
    if (!result.items.length && itemPage > 1) {
      itemPage -= 1;
      return loadItems(review);
    }

    const table = element("table");
    const header = table.createTHead().insertRow();
    for (const label of ["사용자·시작 시 상태", "역할", "결정", "결정자", "결정 시각 (KST)", "사유", "작업"]) {
      const cell = element("th", label);
      cell.scope = "col";
      header.append(cell);
    }
    const body = table.createTBody();
    for (const item of result.items) {
      const row = body.insertRow();
      const user = element("td");
      user.append(
        element("p", item.userName ?? item.userEmail ?? item.userId),
        element("p", item.userEmail ?? item.userId),
        element("p", `${item.userType ?? "미분류"} · ${item.userStatus}`),
      );
      if (item.accountExpiresAt) {
        user.append(element("p", `계정 기한 ${time(item.accountExpiresAt)}`));
      }
      row.append(
        user,
        element("td", `${item.serviceKey}:${item.roleName}`),
        element("td", labels[item.decision] ?? item.decision),
        element("td", item.decidedByEmail ?? (item.decidedById ? "삭제되었거나 이메일 없는 계정" : "—")),
        element("td", time(item.decidedAt)),
        element("td", item.reasonCode ?? "—"),
      );
      const actions = element("td");
      if (review.status === "OPEN" && item.decision === "PENDING") {
        actions.append(
          button("유지", () => decide(item, "KEEP")),
          button("회수", () => decide(item, "REVOKE")),
        );
      }
      row.append(actions);
    }
    rows.replaceChildren(table);
    if (!result.items.length) rows.append(element("p", "해당 항목이 없습니다."));
    pager(itemPager, result, async (page) => {
      itemPage = page;
      await loadItems(review);
    });
  }

  async function loadDetail() {
    if (!selected) return;
    const review = await api(`/${encodeURIComponent(selected)}`);
    detail.hidden = false;
    heading.textContent = review.title;
    const starter = review.startedByEmail ?? "삭제되었거나 이메일 없는 계정";
    const completer = review.completedByEmail ?? "삭제되었거나 이메일 없는 계정";
    metadata.textContent =
      `${review.status === "OPEN" ? "진행 중" : "완료"} · 시작자 ${starter} · 시작 ${time(review.startedAt)}` +
      (review.completedAt
        ? `${review.completedById !== review.startedById ? ` · 완료자 ${completer}` : ""} · 완료 ${time(review.completedAt)}`
        : "");
    counts.textContent = `전체 ${review.total} · ` +
      Object.entries(labels).map(([key, label]) => `${label} ${review.counts[key] ?? 0}`).join(" · ");
    complete.dataset.reviewBlocked = String(
      review.status !== "OPEN" || review.counts.PENDING > 0
    );
    await loadItems(review);
    controls();
  }

  startForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy) return;
    const data = new FormData(startForm);
    const raw = String(data.get("serviceKeys") ?? "").trim();
    const serviceKeys = raw
      ? raw.split(",").map((value) => value.trim()).filter(Boolean)
      : null;
    const payload = {
      title: String(data.get("title") ?? "").trim(),
      reasonCode: String(data.get("reasonCode") ?? "").trim(),
      serviceKeys,
    };
    void run(async () => {
      const review = await api("", "POST", payload);
      selected = review.id;
      reviewPage = 1;
      itemPage = 1;
      filter.value = "";
      startForm.reset();
      await loadList();
      await loadDetail();
    });
  });

  filter.addEventListener("change", () => void run(async () => {
    itemPage = 1;
    await loadDetail();
  }));
  complete.addEventListener("click", () => void run(async () => {
    const reason = window.prompt("점검 완료 사유를 입력하세요.")?.trim();
    if (!reason) return;
    if (reason.length > 128) throw new Error("사유는 128자 이내로 입력하세요.");
    await api(`/${encodeURIComponent(selected)}/complete`, "POST", { reasonCode: reason });
    await loadDetail();
    await loadList();
  }));
  panel.querySelector("[data-review-refresh]").addEventListener("click", () =>
    void run(async () => {
      await loadList();
      await loadDetail();
    })
  );
  nav?.addEventListener("click", () => void run(loadList));
  if (location.hash === "#reviews") void run(loadList);
})();
