import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_REQUEST_BYTES = 8 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024;

export const endpoints = Object.freeze({
  google: Object.freeze({
    issuer: "https://accounts.google.com",
    token: "https://oauth2.googleapis.com/token",
    userInfo: "https://openidconnect.googleapis.com/v1/userinfo"
  }),
  naver: Object.freeze({
    issuer: "https://nid.naver.com",
    token: "https://nid.naver.com/oauth2.0/token",
    userInfo: "https://openapi.naver.com/v1/nid/me"
  }),
  kakao: Object.freeze({
    issuer: "https://kauth.kakao.com",
    token: "https://kauth.kakao.com/oauth/token",
    userInfo: "https://kapi.kakao.com/v2/user/me"
  })
});

const fail = message => {
  throw new TypeError(`test-only provider transport: ${message}`);
};

const exactObject = (value, fields, name) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${name} must be an object`);
  const keys = Object.keys(value).sort();
  if (keys.join("\0") !== [...fields].sort().join("\0")) fail(`${name} fields are not exact`);
};

export const validateConfig = config => {
  exactObject(config, ["scenarios"], "config");
  if (!Array.isArray(config.scenarios) || config.scenarios.length < 1 || config.scenarios.length > 3) {
    fail("scenarios must contain one to three providers");
  }
  const seen = new Set();
  for (const scenario of config.scenarios) {
    exactObject(
      scenario,
      ["provider", "issuer", "code", "accessToken", "profile", "clientId", "clientSecret", "redirectUri", "tokenOutcome", "userOutcome"],
      "scenario"
    );
    const fixed = endpoints[scenario.provider];
    if (!fixed || seen.has(scenario.provider)) fail("provider is unknown or duplicated");
    seen.add(scenario.provider);
    if (scenario.issuer !== fixed.issuer) fail("provider issuer does not match the fixed identity");
    for (const field of ["code", "accessToken", "clientId", "clientSecret", "redirectUri"]) {
      if (typeof scenario[field] !== "string" || scenario[field].length < 1 || Buffer.byteLength(scenario[field]) > MAX_REQUEST_BYTES) {
        fail(`${field} is empty or too large`);
      }
    }
    for (const field of ["tokenOutcome", "userOutcome"]) {
      if (!["success", "timeout", "malformed-json", "redirect", "invalid-payload"].includes(scenario[field])) {
        fail(`${field} is invalid`);
      }
    }
  }
  return config;
};

export const readConfig = file => {
  if (typeof constants.O_NOFOLLOW !== "number" || typeof process.getuid !== "function") {
    fail("config requires no-follow and owner identity support");
  }
  let descriptor;
  try {
    descriptor = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(descriptor);
    const wrongOwner = stat.uid !== process.getuid();
    if (!stat.isFile() || stat.size > MAX_CONFIG_BYTES || (stat.mode & 0o777) !== 0o600 || wrongOwner) {
      fail("config must be an owned, private, bounded regular file");
    }
    return validateConfig(JSON.parse(readBoundedConfigBytes(descriptor).toString("utf8")));
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
};

export const readBoundedConfigBytes = descriptor => {
  const buffer = Buffer.alloc(MAX_CONFIG_BYTES + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const count = readSync(descriptor, buffer, offset, buffer.length - offset, null);
    if (count === 0) break;
    offset += count;
  }
  if (offset > MAX_CONFIG_BYTES) fail("provider config is too large");
  return buffer.subarray(0, offset);
};

const responseFor = (outcome, payload, signal) => {
  if (outcome === "timeout") {
    return new Promise((_resolve, reject) => {
      const abort = () => reject(signal?.reason ?? new DOMException("Aborted", "AbortError"));
      if (signal?.aborted) abort();
      else signal?.addEventListener("abort", abort, { once: true });
    });
  }
  if (outcome === "redirect") fail("provider redirects are not allowed");
  if (outcome === "malformed-json") return new Response("{", { headers: { "content-type": "application/json" } });
  const body = JSON.stringify(outcome === "invalid-payload" ? { unexpected: true } : payload);
  if (Buffer.byteLength(body) > MAX_RESPONSE_BYTES) fail("provider response body is too large");
  return new Response(body, { headers: { "content-type": "application/json" } });
};

const readBoundedBody = async request => {
  if (!request.body) return Buffer.alloc(0);
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_REQUEST_BYTES) {
      await reader.cancel();
      fail("provider request body is too large");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, size);
};

export const installProviderTransport = configValue => {
  const config = validateConfig(configValue);
  const routes = new Map();
  for (const scenario of config.scenarios) {
    const fixed = endpoints[scenario.provider];
    routes.set(fixed.token, { scenario, operation: "token" });
    routes.set(fixed.userInfo, { scenario, operation: "user-info" });
  }
  const records = [];
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const route = routes.get(request.url);
    if (!route) fail("provider request is outside the fixed allowlist");
    const expectedMethod = route.operation === "token" ? "POST" : "GET";
    if (request.method !== expectedMethod) fail("provider request method is not allowed");
    const parsed = new URL(request.url);
    if (parsed.username || parsed.password || parsed.search || parsed.hash) fail("provider URL decorations are not allowed");
    const body = await readBoundedBody(request);
    const scenario = route.scenario;
    if (route.operation === "token") {
      if ((request.headers.get("content-type") ?? "").split(";", 1)[0].trim().toLowerCase() !== "application/x-www-form-urlencoded") {
        fail("provider token content type is not allowed");
      }
      const form = new URLSearchParams(body.toString("utf8"));
      const names = [...form.keys()];
      const required = ["grant_type", "client_id", "client_secret", "redirect_uri", "code"];
      if (names.length !== required.length || new Set(names).size !== required.length || required.some(name => !form.has(name))) {
        fail("provider token form fields are not exact");
      }
      const expected = {
        grant_type: "authorization_code",
        client_id: scenario.clientId,
        client_secret: scenario.clientSecret,
        redirect_uri: scenario.redirectUri,
        code: scenario.code
      };
      for (const [name, value] of Object.entries(expected)) if (form.get(name) !== value) fail(`provider token ${name} does not match`);
    } else {
      if (body.length) fail("provider user-info request body is not allowed");
      if (request.headers.get("authorization") !== `Bearer ${scenario.accessToken}`) fail("provider bearer token does not match");
    }
    records.push(Object.freeze({ provider: scenario.provider, operation: route.operation, method: request.method, url: request.url }));
    const outcome = route.operation === "token" ? scenario.tokenOutcome : scenario.userOutcome;
    const payload = route.operation === "token" ? { access_token: scenario.accessToken } : scenario.profile;
    return responseFor(outcome, payload, request.signal);
  };
  return records;
};
