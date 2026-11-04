(() => {
  let token = new URLSearchParams(window.location.hash.slice(1)).get("token");
  window.history.replaceState(null, "", window.location.pathname);
  const form = document.querySelector("[data-invitation-accept]");
  const notice = document.querySelector("[data-invitation-notice]");
  let busy = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    const data = new FormData(form);
    if (!token || data.get("password") !== data.get("confirmation")) {
      notice.textContent = "초대 링크와 비밀번호 확인을 확인하세요.";
      return;
    }
    busy = true;
    form.querySelector("button").disabled = true;
    try {
      const response = await fetch("/oauth2/invitations/accept", {
        method: "POST", credentials: "same-origin",
        body: new URLSearchParams({ token, password: data.get("password"), csrf_token: data.get("csrf_token") })
      });
      if (!response.ok) throw new Error("초대가 만료·취소·사용되었거나 비밀번호 정책에 맞지 않습니다.");
      token = null;
      form.reset(); form.hidden = true;
      notice.textContent = "직원 계정이 활성화되었습니다. 승인된 서비스에서 로그인하세요.";
    } catch (error) { notice.textContent = error.message || "잠시 후 다시 시도하세요."; }
    finally { busy = false; form.querySelector("button").disabled = false; }
  });
})();
