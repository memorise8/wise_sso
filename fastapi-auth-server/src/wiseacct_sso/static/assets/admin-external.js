(() => {
  const form = document.querySelector("[data-external-create]");
  const list = document.querySelector("[data-external-list]");
  const status = document.querySelector("[data-external-status]");
  const daysLabel = document.querySelector("[data-external-days]");
  const preview = document.querySelector("[data-external-preview]");
  const linkBox = document.querySelector("[data-external-link]");
  const linkValue = document.querySelector("[data-external-link-value]");
  const csrf = document.querySelector("meta[name='admin-session-csrf']").content;
  const MAX_DAYS = 365;
  const DAY_MS = 24 * 60 * 60 * 1000;
  let busy = false;

  async function request(path, method = "GET", body) {
    const response = await fetch("/oauth2/admin/api/external-accounts" + path, {
      method, credentials: "same-origin",
      headers: { "content-type": "application/json", "x-admin-csrf": csrf },
      ...(body ? { body: JSON.stringify(body) } : {})
    });
    if (response.status === 401) window.location.assign("/oauth2/admin/login?reauth=1");
    if (!response.ok) {
      let code = "";
      try { code = (await response.json()).error?.code || ""; } catch { code = ""; }
      throw new Error(`처리하지 못했습니다${code ? ` (${code})` : ""}. 중복 계정·기한·권한을 확인하세요.`);
    }
    return response.status === 204 ? null : response.json();
  }

  function formatDate(iso) {
    return new Date(iso).toLocaleString("ko-KR", { timeZone: "Asia/Seoul", dateStyle: "medium", timeStyle: "short" });
  }

  function remaining(iso) {
    const left = Math.ceil((new Date(iso).getTime() - Date.now()) / DAY_MS);
    return left <= 0 ? "만료됨" : `D-${left}`;
  }

  function selectedDays() {
    const data = new FormData(form);
    const value = data.get("preset") === "custom" ? Number(data.get("days")) : Number(data.get("preset"));
    if (!Number.isInteger(value) || value < 1 || value > MAX_DAYS) throw new Error("기한은 1~365일 사이 정수로 입력하세요.");
    return value;
  }

  function updatePreview() {
    daysLabel.hidden = new FormData(form).get("preset") !== "custom";
    try {
      const days = selectedDays();
      const end = new Date(Date.now() + days * DAY_MS);
      preview.textContent = `${days}일 · ${end.toLocaleDateString("ko-KR", { timeZone: "Asia/Seoul" })} 23:59까지 사용`;
    } catch { preview.textContent = ""; }
  }

  function askReason(text) {
    const reason = window.prompt(`${text} 사유를 입력하세요.`);
    if (reason === null) return null;
    if (!reason.trim()) throw new Error("사유를 입력해야 합니다.");
    return reason.trim().slice(0, 128);
  }

  function actionButton(text, handler) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = text;
    button.addEventListener("click", () => run(handler));
    return button;
  }

  async function refresh() {
    const result = await request("");
    list.replaceChildren();
    if (result.items.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "외부 계정이 없습니다.";
      list.append(empty);
      return;
    }
    for (const row of result.items) {
      const box = document.createElement("p");
      const state = row.status !== "ACTIVE" ? "정지" : row.expired ? "만료" : remaining(row.accountExpiresAt);
      const roles = row.roles.length ? row.roles.join(", ") : "역할 없음";
      box.textContent = `${row.email} · ${row.name ?? ""} · ${state} · ${formatDate(row.accountExpiresAt)}까지 · ${roles} `;
      const id = encodeURIComponent(row.id);
      box.append(actionButton("연장", async () => {
        const input = window.prompt("연장할 일수 (1~365). 남은 기한 뒤에 더해집니다.", "90");
        if (input === null) return;
        const days = Number(input);
        if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) throw new Error("일수는 1~365 사이 정수입니다.");
        const reason = askReason("연장");
        if (reason === null) return;
        const extended = await request(`/${id}/extend`, "POST", { days, reason });
        status.textContent = `${row.email}: ${formatDate(extended.accountExpiresAt)}까지 연장`;
        await refresh();
      }));
      if (row.status === "ACTIVE") {
        box.append(actionButton("즉시 정지", async () => {
          if (!window.confirm(`${row.email} 계정을 바로 정지할까요? 로그인 세션이 모두 끊깁니다.`)) return;
          const reason = askReason("정지");
          if (reason === null) return;
          await request(`/${id}/suspend`, "POST", { reason });
          await refresh();
        }));
      } else if (row.status === "SUSPENDED") {
        box.append(actionButton("정지 해제", async () => {
          const reason = askReason("정지 해제");
          if (reason === null) return;
          await request(`/${id}/reactivate`, "POST", { reason });
          await refresh();
        }));
      }
      list.append(box);
    }
  }

  async function run(work) {
    if (busy) return;
    busy = true;
    try { await work(); if (!status.textContent) status.textContent = "처리 완료"; }
    catch (error) { status.textContent = error.message || "요청 실패"; }
    finally { busy = false; }
  }

  form.addEventListener("change", updatePreview);
  form.addEventListener("input", updatePreview);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void run(async () => {
      status.textContent = "";
      const data = new FormData(form);
      const delivery = String(data.get("delivery"));
      const created = await request("", "POST", {
        email: data.get("email"),
        name: data.get("name"),
        days: selectedDays(),
        roles: data.get("gitlab") ? [{ serviceKey: "gitlab", name: "user" }] : [],
        delivery
      });
      linkBox.hidden = !created.invitationUrl;
      linkValue.value = created.invitationUrl || "";
      status.textContent = `${formatDate(created.accountExpiresAt)}까지 쓸 수 있는 외부 계정 초대를 만들었습니다${delivery === "mail" ? " (메일 발송)" : ""}.`;
      form.reset(); updatePreview();
      await refresh();
    });
  });
  document.querySelector("[data-external-copy]").addEventListener("click", () => run(async () => {
    await navigator.clipboard.writeText(linkValue.value);
    status.textContent = "링크를 복사했습니다.";
  }));
  document.querySelector("[data-external-refresh]").addEventListener("click", () => run(refresh));
  updatePreview();
})();
