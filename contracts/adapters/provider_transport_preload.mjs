import { closeSync, constants, fstatSync, openSync, readSync, writeSync } from "node:fs";

const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_REQUEST_BYTES = 8 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_FDINFO_BYTES = 4 * 1024;
const LINUX_O_ACCMODE = 3;

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

const readLinuxDescriptorFlags = descriptor => {
  if (process.platform !== "linux" || typeof constants.O_NONBLOCK !== "number") {
    fail("provider record descriptor flag inspection requires Linux");
  }
  let fdinfo;
  try {
    fdinfo = openSync(`/proc/self/fdinfo/${descriptor}`, constants.O_RDONLY | constants.O_NOFOLLOW);
    const buffer = Buffer.alloc(MAX_FDINFO_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const count = readSync(fdinfo, buffer, offset, buffer.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    if (offset > MAX_FDINFO_BYTES) fail("provider record descriptor metadata is too large");
    const matches = [...buffer.subarray(0, offset).toString("ascii").matchAll(/^flags:\s*([0-7]+)$/gm)];
    if (matches.length !== 1 || !matches[0][1]) fail("provider record descriptor flags are unavailable");
    return Number.parseInt(matches[0][1], 8);
  } catch (error) {
    if (error instanceof TypeError && String(error).includes("test-only provider transport")) throw error;
    fail("provider record descriptor flags are unavailable");
  } finally {
    if (fdinfo !== undefined) closeSync(fdinfo);
  }
};

export const createProviderRecordWriterFromEnvironment = () => {
  const names = [
    "WISEACCT_TEST_PROVIDER_RECORD_FD",
    "WISEACCT_TEST_PROVIDER_RUN_ID",
    "WISEACCT_TEST_PROVIDER_RUNTIME"
  ];
  const values = names.map(name => process.env[name]);
  if (values.every(value => value === undefined)) return null;
  if (values.some(value => value === undefined)) fail("provider record environment binding is incomplete");
  const [fdText, runId, runtime] = values;
  if (!/^(?:[3-9]|[1-9][0-9]+)$/.test(fdText)) fail("provider record descriptor is invalid");
  if (!/^[A-Za-z0-9._-]{8,64}$/.test(runId)) fail("provider record runId is invalid");
  if (runtime !== "express" && runtime !== "fastapi") fail("provider record runtime is invalid");
  const descriptor = Number(fdText);
  let identity;
  try {
    const details = fstatSync(descriptor);
    if (!details.isFIFO() || details.uid !== process.getuid() || (details.mode & 0o777) !== 0o600) {
      fail("provider record descriptor is not an owned write pipe");
    }
    const flags = readLinuxDescriptorFlags(descriptor);
    if ((flags & LINUX_O_ACCMODE) !== constants.O_WRONLY || (flags & constants.O_NONBLOCK) === 0) {
      fail("provider record descriptor must be a nonblocking write pipe");
    }
    identity = Object.freeze({
      dev: details.dev,
      ino: details.ino,
      mode: details.mode,
      uid: details.uid
    });
  } catch (error) {
    if (error instanceof TypeError && String(error).includes("test-only provider transport")) throw error;
    fail("provider record descriptor is unavailable");
  }
  let sequence = 0;
  let closed = false;
  const currentIdentityMatches = () => {
    try {
      const details = fstatSync(descriptor);
      return details.dev === identity.dev && details.ino === identity.ino && details.mode === identity.mode && details.uid === identity.uid;
    } catch {
      return false;
    }
  };
  return Object.freeze({
    emit(provider, operation) {
      if (!endpoints[provider] || (operation !== "token" && operation !== "user-info")) {
        fail("provider record value is invalid");
      }
      if (closed) fail("provider record writer is closed");
      if (!currentIdentityMatches()) fail("provider record descriptor identity changed");
      sequence += 1;
      if (sequence > 16) fail("provider record count is exhausted");
      const encoded = Buffer.from(`${JSON.stringify({
        schemaVersion: 1,
        runId,
        runtime,
        source: "provider-transport",
        provider,
        operation,
        sequence
      })}\n`);
      if (encoded.length > 512) fail("provider record is too large");
      let written;
      try {
        written = writeSync(descriptor, encoded);
      } catch {
        fail("provider record emission failed");
      }
      if (written !== encoded.length) fail("provider record emission was incomplete");
    },
    close() {
      if (closed) return;
      closed = true;
      if (currentIdentityMatches()) closeSync(descriptor);
    }
  });
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

export const installProviderTransport = (configValue, recorder = null) => {
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
    if (recorder) recorder.emit(scenario.provider, route.operation);
    const outcome = route.operation === "token" ? scenario.tokenOutcome : scenario.userOutcome;
    const payload = route.operation === "token" ? { access_token: scenario.accessToken } : scenario.profile;
    return responseFor(outcome, payload, request.signal);
  };
  return records;
};
