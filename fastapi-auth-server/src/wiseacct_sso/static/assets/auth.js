// allow: SIZE_OK - Temporarily kept intact for P0 auth hardening because storage, callback, and login flows share browser state and QA harness coverage; split after P0 frontend cleanup.
const pageByPath = new Map([
  ["/", "login"],
  ["/login", "login"],
  ["/signup", "signup"],
  ["/auth/callback", "callback"],
  ["/password-reset", "password-reset"],
  ["/verify-email", "verify-email"]
]);

const accessTokenStorageKey = "wise_sso_access_token";
const legacyRefreshTokenStorageKey = "wise_sso_refresh_token";
const browserTokenUrlParams = ["accessToken", "refreshToken", "access_token", "refresh_token"];

const relyingClient = {
  clientId: "temis",
  redirectUri: "https://financenow.kr/auth/callback"
};

const oauthSessionKeys = {
  state: "wise_sso_oauth_state",
  codeVerifier: "wise_sso_oauth_code_verifier",
  signupHandoff: "wise_sso_signup_handoff"
};
const handoffParamNames = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method"];

const notice = document.querySelector("[data-notice]");
window.localStorage.removeItem(legacyRefreshTokenStorageKey);

const activePage = pageByPath.get(window.location.pathname) ?? "login";
document.querySelector(".auth-shell")?.setAttribute("data-view", activePage);
for (const view of document.querySelectorAll("[data-page]")) {
  view.hidden = view.getAttribute("data-page") !== activePage;
}

const setNotice = (tone, message) => {
  if (!(notice instanceof HTMLElement)) {
    return;
  }

  notice.hidden = false;
  notice.dataset.tone = tone;
  notice.textContent = message;
};

const clearNotice = () => {
  if (!(notice instanceof HTMLElement)) {
    return;
  }

  notice.hidden = true;
  notice.textContent = "";
  delete notice.dataset.tone;
};

const submitJson = async (path, body) => {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const message = payload?.error?.message ?? "요청을 처리하지 못했습니다.";
    throw new Error(message);
  }
  return payload;
};

const formValues = (form) => Object.fromEntries(new FormData(form).entries());

const withSubmitting = async (form, task) => {
  const button = form.querySelector("button[type='submit']");
  if (button instanceof HTMLButtonElement) {
    button.disabled = true;
  }
  clearNotice();
  try {
    await task();
  } catch (error) {
    setNotice("error", error instanceof Error ? error.message : "요청을 처리하지 못했습니다.");
  } finally {
    if (button instanceof HTMLButtonElement) {
      button.disabled = false;
    }
  }
};

const storeAccessToken = (tokens) => {
  window.localStorage.removeItem(legacyRefreshTokenStorageKey);
  if (typeof tokens?.accessToken !== "string") {
    throw new Error("토큰 응답이 올바르지 않습니다.");
  }

  window.sessionStorage.setItem(accessTokenStorageKey, tokens.accessToken);
};

const stripBrowserTokensFromUrl = () => {
  const url = new URL(window.location.href);
  let changed = false;
  for (const paramName of browserTokenUrlParams) {
    if (url.searchParams.has(paramName)) {
      url.searchParams.delete(paramName);
      changed = true;
    }
  }

  if (url.hash) {
    const hashParams = new URLSearchParams(url.hash.slice(1));
    let hashChanged = false;
    for (const paramName of browserTokenUrlParams) {
      if (hashParams.has(paramName)) {
        hashParams.delete(paramName);
        hashChanged = true;
      }
    }
    if (hashChanged) {
      const cleanedHash = hashParams.toString();
      url.hash = cleanedHash ? `#${cleanedHash}` : "";
      changed = true;
    }
  }

  if (changed) {
    window.history.replaceState({}, document.title, `${url.pathname}${url.search}${url.hash}`);
  }
};

const isDevelopmentOrigin = () => {
  const hostname = window.location.hostname;
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname.endsWith(".localhost");
};

const clearOAuthSession = () => {
  window.sessionStorage.removeItem(oauthSessionKeys.state);
  window.sessionStorage.removeItem(oauthSessionKeys.codeVerifier);
};

const clearSignupHandoff = () => {
  window.sessionStorage.removeItem(oauthSessionKeys.signupHandoff);
};

const parseHandoffFromUrl = () => {
  const params = new URLSearchParams(window.location.search);
  const clientId = params.get("client_id");
  const redirectUri = params.get("redirect_uri");
  const state = params.get("state");
  const codeChallenge = params.get("code_challenge");
  const codeChallengeMethod = params.get("code_challenge_method");
  if (!clientId && !redirectUri && !state && !codeChallenge && !codeChallengeMethod) {
    return null;
  }
  if (!clientId || !redirectUri || !codeChallenge || codeChallengeMethod !== "S256") {
    setNotice("error", "회원가입 요청 정보가 올바르지 않습니다.");
    return null;
  }

  return {
    clientId,
    redirectUri,
    state,
    codeChallenge,
    codeChallengeMethod
  };
};

const rememberHandoff = () => {
  if (activePage !== "login" && activePage !== "signup") {
    return;
  }

  const handoff = parseHandoffFromUrl();
  if (handoff) {
    window.sessionStorage.setItem(oauthSessionKeys.signupHandoff, JSON.stringify(handoff));
  }
};

const readSignupHandoff = () => {
  const stored = window.sessionStorage.getItem(oauthSessionKeys.signupHandoff);
  if (!stored) {
    return null;
  }
  try {
    const parsed = JSON.parse(stored);
    if (
      typeof parsed.clientId === "string" &&
      typeof parsed.redirectUri === "string" &&
      typeof parsed.codeChallenge === "string" &&
      parsed.codeChallengeMethod === "S256"
    ) {
      return {
        clientId: parsed.clientId,
        redirectUri: parsed.redirectUri,
        state: typeof parsed.state === "string" ? parsed.state : undefined,
        codeChallenge: parsed.codeChallenge,
        codeChallengeMethod: parsed.codeChallengeMethod
      };
    }
  } catch {
    clearSignupHandoff();
  }
  return null;
};

const handoffQueryString = () => {
  const currentParams = new URLSearchParams(window.location.search);
  const nextParams = new URLSearchParams();
  for (const name of handoffParamNames) {
    const value = currentParams.get(name);
    if (value) {
      nextParams.set(name, value);
    }
  }
  return nextParams.toString();
};

const preserveHandoffLinks = () => {
  const query = handoffQueryString();
  if (!query) {
    return;
  }
  for (const link of document.querySelectorAll("a[href^='/']")) {
    const href = link.getAttribute("href");
    if (!href || href.includes("?")) {
      continue;
    }
    link.setAttribute("href", `${href}?${query}`);
  }
};

const base64Url = (bytes) => {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return window.btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
};

const randomBase64Url = (byteLength) => {
  const bytes = new Uint8Array(byteLength);
  window.crypto.getRandomValues(bytes);
  return base64Url(bytes);
};

const sha256Base64Url = async (value) => {
  const bytes = new TextEncoder().encode(value);
  const digest = await window.crypto.subtle.digest("SHA-256", bytes);
  return base64Url(new Uint8Array(digest));
};

const startOAuthLogin = async (provider) => {
  const handoff = readSignupHandoff();
  const state = handoff?.state ?? randomBase64Url(24);
  const codeVerifier = handoff ? null : randomBase64Url(48);
  const codeChallenge = handoff?.codeChallenge ?? await sha256Base64Url(codeVerifier);
  window.sessionStorage.setItem(oauthSessionKeys.state, state);
  if (codeVerifier) {
    window.sessionStorage.setItem(oauthSessionKeys.codeVerifier, codeVerifier);
  } else {
    window.sessionStorage.removeItem(oauthSessionKeys.codeVerifier);
  }

  const startUrl = new URL(`/auth/${provider}`, window.location.origin);
  startUrl.searchParams.set("client_id", handoff?.clientId ?? relyingClient.clientId);
  startUrl.searchParams.set("redirect_uri", handoff?.redirectUri ?? relyingClient.redirectUri);
  startUrl.searchParams.set("state", state);
  startUrl.searchParams.set("code_challenge", codeChallenge);
  startUrl.searchParams.set("code_challenge_method", handoff?.codeChallengeMethod ?? "S256");
  window.location.assign(startUrl.toString());
};

for (const link of document.querySelectorAll("a[href='/auth/google']")) {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    void startOAuthLogin("google").catch((error) => {
      setNotice("error", error instanceof Error ? error.message : "소셜 로그인을 시작하지 못했습니다.");
    });
  });
}

document.querySelector("[data-form='login']")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  void withSubmitting(form, async () => {
    const values = formValues(form);
    const handoff = readSignupHandoff();
    const tokens = await submitJson("/auth/login", {
      email: values.email,
      password: values.password,
      ...(handoff ?? {})
    });
    if (typeof tokens?.redirectUrl === "string") {
      window.location.assign(tokens.redirectUrl);
      return;
    }
    storeAccessToken(tokens);
    setNotice("success", "로그인했습니다.");
  });
});

document.querySelector("[data-form='signup']")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  void withSubmitting(form, async () => {
    const values = formValues(form);
    await submitJson("/auth/register", {
      email: values.email,
      password: values.password,
      name: values.name
    });
    const handoff = readSignupHandoff();
    await submitJson("/auth/email-verification/request", {
      email: values.email,
      ...(handoff ?? {})
    });
    setNotice("success", "가입 요청을 받았습니다. 이메일 인증 링크를 확인하세요.");
  });
});

document.querySelector("[data-form='password-reset-request']")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  void withSubmitting(form, async () => {
    const values = formValues(form);
    await submitJson("/auth/password-reset/request", {
      email: values.email
    });
    setNotice("success", "비밀번호 재설정 링크를 보냈습니다.");
  });
});

document.querySelector("[data-form='password-reset-confirm']")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  void withSubmitting(form, async () => {
    const token = new URLSearchParams(window.location.search).get("token");
    if (!token) {
      throw new Error("비밀번호 재설정 토큰이 없습니다.");
    }

    const values = formValues(form);
    await submitJson("/auth/password-reset/confirm", {
      token,
      password: values.password
    });
    window.history.replaceState({}, document.title, "/password-reset");
    setNotice("success", "비밀번호를 변경했습니다. 새 비밀번호로 로그인하세요.");
  });
});

const configurePasswordResetView = () => {
  const hasToken = Boolean(new URLSearchParams(window.location.search).get("token"));
  const mode = hasToken ? "confirm" : "request";
  for (const element of document.querySelectorAll("[data-reset-mode]")) {
    if (element instanceof HTMLElement) {
      element.hidden = element.dataset.resetMode !== mode;
    }
  }
};

const exchangeAuthCode = async () => {
  stripBrowserTokensFromUrl();
  if (!isDevelopmentOrigin()) {
    clearOAuthSession();
    window.history.replaceState({}, document.title, "/auth/callback");
    setNotice("success", "로그인이 완료되었습니다. 서비스로 돌아가세요.");
    return;
  }

  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const state = params.get("state");
  if (!code) {
    window.history.replaceState({}, document.title, "/auth/callback");
    setNotice("error", "인증 코드가 없습니다. 로그인부터 다시 시작하세요.");
    return;
  }

  const expectedState = window.sessionStorage.getItem(oauthSessionKeys.state);
  const codeVerifier = window.sessionStorage.getItem(oauthSessionKeys.codeVerifier);
  if (!expectedState || !codeVerifier || state !== expectedState) {
    clearOAuthSession();
    window.history.replaceState({}, document.title, "/auth/callback");
    setNotice("error", "로그인 요청을 확인하지 못했습니다. 로그인부터 다시 시작하세요.");
    return;
  }

  try {
    window.history.replaceState({}, document.title, "/auth/callback");
    const tokens = await submitJson("/auth/exchange", {
      code,
      clientId: relyingClient.clientId,
      redirectUri: relyingClient.redirectUri,
      codeVerifier
    });
    storeAccessToken(tokens);
    clearOAuthSession();
    setNotice("success", "로그인했습니다. 이 창을 닫거나 서비스로 돌아가세요.");
  } catch (error) {
    setNotice("error", error instanceof Error ? error.message : "로그인 처리를 완료하지 못했습니다.");
  }
};

const confirmEmail = async () => {
  const token = new URLSearchParams(window.location.search).get("token");
  if (!token) {
    setNotice("error", "이메일 인증 토큰이 없습니다.");
    return;
  }

  try {
    const result = await submitJson("/auth/email-verification/confirm", { token });
    window.history.replaceState({}, document.title, "/verify-email");
    clearSignupHandoff();
    if (typeof result?.redirectUrl === "string") {
      window.location.assign(result.redirectUrl);
      return;
    }
    setNotice("success", "이메일 인증이 완료되었습니다. 로그인할 수 있습니다.");
  } catch (error) {
    setNotice("error", error instanceof Error ? error.message : "이메일 인증에 실패했습니다.");
  }
};

rememberHandoff();
preserveHandoffLinks();

if (activePage === "callback") {
  void exchangeAuthCode();
}

if (activePage === "password-reset") {
  configurePasswordResetView();
}

if (activePage === "verify-email") {
  void confirmEmail();
}
