#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

class Element {
  constructor(attributes = {}) {
    this.attributes = new Map(Object.entries(attributes));
    this.dataset = {};
    this.hidden = false;
    this.textContent = "";
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  querySelector() {
    return null;
  }

  addEventListener() {}
}

class HTMLFormElement extends Element {}
class HTMLButtonElement extends Element {}

const createStorage = (entries = {}) => {
  const values = new Map(Object.entries(entries));
  return {
    getItem: (key) => values.get(key) ?? null,
    removeItem: (key) => {
      values.delete(key);
    },
    setItem: (key, value) => {
      values.set(key, String(value));
    }
  };
};

const waitForAsyncScriptWork = async () => {
  await new Promise((resolve) => {
    setImmediate(resolve);
  });
  await new Promise((resolve) => {
    setImmediate(resolve);
  });
};

const runPortalScript = async ({ url, fetchPayload, sessionEntries = {} }) => {
  const script = await readFile(new URL("../public/assets/auth.js", import.meta.url), "utf8");
  const locationUrl = new URL(url);
  const notice = new Element();
  const authShell = new Element();
  const views = [
    new Element({ "data-page": "login" }),
    new Element({ "data-page": "signup" }),
    new Element({ "data-page": "callback" }),
    new Element({ "data-page": "password-reset" }),
    new Element({ "data-page": "verify-email" })
  ];
  const fetchCalls = [];
  const localStorage = createStorage({ wise_sso_refresh_token: "stale-refresh-token" });
  const sessionStorage = createStorage(sessionEntries);
  const document = {
    title: "Wise SSO",
    querySelector: (selector) => {
      if (selector === "[data-notice]") {
        return notice;
      }
      if (selector === ".auth-shell") {
        return authShell;
      }
      return null;
    },
    querySelectorAll: (selector) => {
      if (selector === "[data-page]") {
        return views;
      }
      return [];
    }
  };
  const location = {
    get hash() {
      return locationUrl.hash;
    },
    set hash(value) {
      locationUrl.hash = value;
    },
    get hostname() {
      return locationUrl.hostname;
    },
    get href() {
      return locationUrl.href;
    },
    get origin() {
      return locationUrl.origin;
    },
    get pathname() {
      return locationUrl.pathname;
    },
    get search() {
      return locationUrl.search;
    },
    assign(nextUrl) {
      const parsedUrl = new URL(nextUrl, locationUrl.href);
      locationUrl.href = parsedUrl.href;
    }
  };
  const fetch = async (path, init) => {
    fetchCalls.push({ path, body: init?.body ?? null });
    return {
      ok: true,
      text: async () => JSON.stringify(fetchPayload)
    };
  };
  const window = {
    crypto: {
      getRandomValues: (bytes) => bytes.fill(1),
      subtle: {
        digest: async () => new Uint8Array([1, 2, 3]).buffer
      }
    },
    document,
    fetch,
    history: {
      replaceState: (_state, _title, nextUrl) => {
        const parsedUrl = new URL(nextUrl, locationUrl.href);
        locationUrl.href = parsedUrl.href;
      }
    },
    localStorage,
    location,
    sessionStorage,
    TextEncoder,
    URL,
    URLSearchParams,
    btoa: (value) => Buffer.from(value, "binary").toString("base64")
  };

  const context = vm.createContext({
    document,
    Error,
    fetch,
    FormData: class FormData {},
    HTMLButtonElement,
    HTMLElement: Element,
    HTMLFormElement,
    TextEncoder,
    URL,
    URLSearchParams,
    window
  });

  vm.runInContext(script, context, { filename: "auth.js" });
  await waitForAsyncScriptWork();

  return {
    accessToken: localStorage.getItem("wise_sso_access_token"),
    refreshToken: localStorage.getItem("wise_sso_refresh_token"),
    fetchCalls,
    href: location.href,
    notice: {
      hidden: notice.hidden,
      text: notice.textContent,
      tone: notice.dataset.tone ?? null
    }
  };
};

const sessionEntries = {
  wise_sso_oauth_code_verifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
  wise_sso_oauth_state: "expected-state"
};

const devResult = await runPortalScript({
  url: "http://localhost:3000/auth/callback?code=handoff-code&state=expected-state&accessToken=leaked&refreshToken=leaked#access_token=leaked&refresh_token=leaked",
  fetchPayload: { accessToken: "browser-dev-access-token", refreshToken: "server-refresh-token" },
  sessionEntries
});

assert.equal(devResult.fetchCalls.length, 1, "dev callback should exchange the handoff code once");
assert.equal(devResult.accessToken, "browser-dev-access-token", "dev callback may store only the Access Token");
assert.equal(devResult.refreshToken, null, "dev callback must not persist the Refresh Token");
assert.match(devResult.href, /^http:\/\/localhost:3000\/auth\/callback$/, "dev callback should scrub token-bearing URL data");

const productionResult = await runPortalScript({
  url: "https://auth.financenow.kr/auth/callback?code=handoff-code&state=expected-state&refreshToken=leaked#accessToken=leaked",
  fetchPayload: { accessToken: "must-not-be-used", refreshToken: "must-not-be-used" },
  sessionEntries
});

assert.equal(productionResult.fetchCalls.length, 0, "production callback must leave code exchange to TEMIS BFF");
assert.equal(productionResult.accessToken, null, "production callback must not persist Access Token");
assert.equal(productionResult.refreshToken, null, "production callback must not persist Refresh Token");
assert.match(productionResult.href, /^https:\/\/auth\.financenow\.kr\/auth\/callback$/, "production callback should scrub URL handoff data");

const staleStateResult = await runPortalScript({
  url: "http://localhost:3000/auth/callback?code=handoff-code&state=attacker-state&refreshToken=leaked#accessToken=leaked",
  fetchPayload: { accessToken: "must-not-be-used", refreshToken: "must-not-be-used" },
  sessionEntries
});

assert.equal(staleStateResult.fetchCalls.length, 0, "stale state must not call the exchange endpoint");
assert.equal(staleStateResult.accessToken, null, "stale state must not persist an Access Token");
assert.equal(staleStateResult.refreshToken, null, "stale state must not persist a Refresh Token");
assert.match(staleStateResult.href, /^http:\/\/localhost:3000\/auth\/callback$/, "stale state should scrub URL data");
assert.equal(staleStateResult.notice.tone, "error", "stale state should surface an error state");

const malformedResult = await runPortalScript({
  url: "http://localhost:3000/auth/callback?code=handoff-code&state=expected-state",
  fetchPayload: { refreshToken: "refresh-without-access" },
  sessionEntries
});

assert.equal(malformedResult.accessToken, null, "malformed exchange response must not store an Access Token");
assert.equal(malformedResult.refreshToken, null, "malformed exchange response must not store a Refresh Token");
assert.equal(malformedResult.notice.tone, "error", "malformed exchange response should surface an error state");

console.log(JSON.stringify({
  dev: devResult,
  malformed: malformedResult,
  production: productionResult,
  staleState: staleStateResult
}, null, 2));
