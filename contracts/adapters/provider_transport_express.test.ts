import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { execFileSync } from "node:child_process";
import { appendFileSync, chmodSync, closeSync, fstatSync, mkdtempSync, openSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { endpoints, installProviderTransport, readBoundedConfigBytes, readConfig, validateConfig } from "./provider_transport_preload.mjs";
import type { ProviderScenario } from "./provider_transport_preload.mjs";

process.env["DATABASE_URL"] = "postgresql://user:password@127.0.0.1:5432/provider_contract";
process.env["JWT_REFRESH_SECRET"] = "provider-contract-refresh-secret";
process.env["JWT_ISSUER"] = "https://auth.temis.co.kr";
process.env["JWT_AUDIENCE"] = "temis";
process.env["REDIS_URL"] = "redis://127.0.0.1:6379/14";
process.env["FRONTEND_REDIRECT_URL"] = "https://financenow.kr/auth/callback";
process.env["OAUTH_ENABLED_PROVIDERS"] = "google,naver,kakao";
process.env["GOOGLE_CLIENT_ID"] = "google-client";
process.env["GOOGLE_CLIENT_SECRET"] = "google-secret";
process.env["GOOGLE_REDIRECT_URI"] = "http://127.0.0.1:4000/auth/google/callback";
process.env["NAVER_CLIENT_ID"] = "naver-client";
process.env["NAVER_CLIENT_SECRET"] = "naver-secret";
process.env["NAVER_REDIRECT_URI"] = "http://127.0.0.1:4000/auth/naver/callback";
process.env["KAKAO_CLIENT_ID"] = "kakao-client";
process.env["KAKAO_CLIENT_SECRET"] = "kakao-secret";
process.env["KAKAO_REDIRECT_URI"] = "http://127.0.0.1:4000/auth/kakao/callback";
process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([
  {
    clientId: "temis",
    audience: "temis",
    allowedRedirectUris: [
      "https://financenow.kr/auth/callback",
      "https://temis.me/auth/callback",
      "https://ti.temis.me/auth/callback"
    ],
    allowedOrigins: ["https://financenow.kr"],
    defaultRole: { serviceKey: "temis", name: "user" }
  }
]);

const mocks = vi.hoisted(() => ({
  findOrCreateUserBySocialProfile: vi.fn(),
  consume: vi.fn()
}));

vi.mock("../../auth-server/src/services/oauth-state.store.js", () => ({
  oauthStateStore: { create: vi.fn(), consume: mocks.consume }
}));
vi.mock("../../auth-server/src/services/user.service.js", () => ({
  findOrCreateUserBySocialProfile: mocks.findOrCreateUserBySocialProfile
}));

const scenarios = [
  {
    provider: "google",
    issuer: endpoints.google.issuer,
    code: "google-code",
    accessToken: "google-access",
    profile: { sub: "google-subject", email: "google@example.com", email_verified: true },
    clientId: "google-client",
    clientSecret: "google-secret",
    redirectUri: "http://127.0.0.1:4000/auth/google/callback",
    tokenOutcome: "success",
    userOutcome: "success"
  },
  {
    provider: "naver",
    issuer: endpoints.naver.issuer,
    code: "naver-code",
    accessToken: "naver-access",
    profile: { response: { id: "naver-subject", email: "naver@example.com" } },
    clientId: "naver-client",
    clientSecret: "naver-secret",
    redirectUri: "http://127.0.0.1:4000/auth/naver/callback",
    tokenOutcome: "success",
    userOutcome: "success"
  },
  {
    provider: "kakao",
    issuer: endpoints.kakao.issuer,
    code: "kakao-code",
    accessToken: "kakao-access",
    profile: { id: 42, kakao_account: { email: "kakao@example.com" } },
    clientId: "kakao-client",
    clientSecret: "kakao-secret",
    redirectUri: "http://127.0.0.1:4000/auth/kakao/callback",
    tokenOutcome: "success",
    userOutcome: "success"
  }
] as const satisfies readonly ProviderScenario[];

describe("test-only provider transport against the actual Express ky boundary", () => {
  const originalFetch = globalThis.fetch;
  const records = installProviderTransport({ scenarios: scenarios.map(value => ({ ...value })) });

  beforeAll(() => {
    mocks.consume.mockImplementation(async () => ({
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      callerState: null,
      codeChallenge: "contract-challenge",
      codeChallengeMethod: "S256"
    }));
    mocks.findOrCreateUserBySocialProfile.mockImplementation(async (profile: { provider: string }) => ({
      id: `user-${profile.provider}`,
      status: "ACTIVE"
    }));
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
  });

  it.each(scenarios)("intercepts the fixed $provider token and user-info calls", async scenario => {
    const { handleOAuthCallback } = await import("../../auth-server/src/services/oauth.service.js");
    const result = await handleOAuthCallback(scenario.provider, scenario.code, `${scenario.provider}-state`);

    expect(result.userId).toBe(`user-${scenario.provider}`);
    expect(records.slice(-2)).toEqual([
      { provider: scenario.provider, operation: "token", method: "POST", url: endpoints[scenario.provider].token },
      { provider: scenario.provider, operation: "user-info", method: "GET", url: endpoints[scenario.provider].userInfo }
    ]);
    expect(mocks.findOrCreateUserBySocialProfile).toHaveBeenLastCalledWith(
      expect.objectContaining({ provider: scenario.provider }),
      "temis"
    );
  });

  it("blocks any non-allowlisted origin without calling the original fetch", async () => {
    await expect(fetch("https://example.com/not-a-provider")).rejects.toThrow("outside the fixed allowlist");
  });

  it("rejects a mismatched provider issuer before installing a transport", () => {
    expect(() => validateConfig({
      scenarios: [{ ...scenarios[0], issuer: "https://issuer.invalid" }]
    })).toThrow("issuer does not match");
  });

  it("loads only a private regular config descriptor and rejects symlink substitution", () => {
    const directory = mkdtempSync(join(tmpdir(), "provider-transport-"));
    try {
      const configPath = join(directory, "scenario.json");
      writeFileSync(configPath, JSON.stringify({ scenarios: [{ ...scenarios[0] }] }), { mode: 0o600 });
      expect(readConfig(configPath).scenarios).toHaveLength(1);
      chmodSync(configPath, 0o640);
      expect(() => readConfig(configPath)).toThrow("owned, private");
      chmodSync(configPath, 0o400);
      expect(() => readConfig(configPath)).toThrow("owned, private");
      chmodSync(configPath, 0o600);
      const linkPath = join(directory, "scenario-link.json");
      symlinkSync(configPath, linkPath);
      expect(() => readConfig(linkPath)).toThrow();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects config growth beyond the read cap after an earlier bounded stat", () => {
    const directory = mkdtempSync(join(tmpdir(), "provider-growth-"));
    let descriptor: number | undefined;
    try {
      const configPath = join(directory, "scenario.json");
      writeFileSync(configPath, JSON.stringify({ scenarios: [{ ...scenarios[0] }] }), { mode: 0o600 });
      const openDescriptor = openSync(configPath, "r");
      descriptor = openDescriptor;
      expect(fstatSync(openDescriptor).size).toBeLessThan(64 * 1024);
      appendFileSync(configPath, "x".repeat(64 * 1024));
      expect(() => readBoundedConfigBytes(openDescriptor)).toThrow("config is too large");
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("keeps the library side-effect free and activates only the process preload entrypoint", () => {
    const directory = mkdtempSync(join(tmpdir(), "provider-preload-"));
    try {
      const configPath = join(directory, "scenario.json");
      writeFileSync(configPath, JSON.stringify({ scenarios: [{ ...scenarios[0] }] }), { mode: 0o600 });
      const adapterDirectory = fileURLToPath(new URL(".", import.meta.url));
      const libraryUrl = pathToFileURL(join(adapterDirectory, "provider_transport_preload.mjs")).href;
      const entryUrl = pathToFileURL(join(adapterDirectory, "provider_transport_preload_entry.mjs")).href;
      const childEnvironment = { WISEACCT_TEST_PROVIDER_CONFIG: configPath };

      execFileSync(
        process.execPath,
        [
          "--input-type=module",
          "--eval",
          `const original = globalThis.fetch; await import(${JSON.stringify(libraryUrl)}); if (globalThis.fetch !== original) throw new Error("library import mutated fetch");`
        ],
        { env: childEnvironment, stdio: "pipe", timeout: 5_000 }
      );

      execFileSync(
        process.execPath,
        [
          "--import",
          entryUrl,
          "--input-type=module",
          "--eval",
          `
            const token = await fetch("${endpoints.google.token}", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "google-client",
                client_secret: "google-secret",
                redirect_uri: "http://127.0.0.1:4000/auth/google/callback",
                code: "google-code"
              })
            });
            if ((await token.json()).access_token !== "google-access") throw new Error("token response mismatch");
            const profile = await fetch("${endpoints.google.userInfo}", {
              headers: { authorization: "Bearer google-access" }
            });
            if ((await profile.json()).sub !== "google-subject") throw new Error("profile response mismatch");
            try {
              await fetch("https://example.com/not-allowed");
              throw new Error("external request unexpectedly succeeded");
            } catch (error) {
              if (!String(error).includes("outside the fixed allowlist")) throw error;
            }
          `
        ],
        { env: childEnvironment, stdio: "pipe", timeout: 5_000 }
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects redirects and oversized synthetic provider payloads", async () => {
    const redirectRecords = installProviderTransport({
      scenarios: [{ ...scenarios[0], tokenOutcome: "redirect" }]
    });
    const { handleOAuthCallback } = await import("../../auth-server/src/services/oauth.service.js");
    await expect(handleOAuthCallback("google", "google-code", "redirect-state")).rejects.toThrow(
      "provider redirects are not allowed"
    );
    expect(redirectRecords).toHaveLength(1);

    installProviderTransport({
      scenarios: [{ ...scenarios[0], profile: { value: "x".repeat(64 * 1024) } }]
    });
    await expect(handleOAuthCallback("google", "google-code", "large-state")).rejects.toThrow(
      "provider response body is too large"
    );
  });

  it("surfaces malformed token payloads through the actual Express schema boundary", async () => {
    installProviderTransport({
      scenarios: [{ ...scenarios[0], tokenOutcome: "invalid-payload" }]
    });
    const { handleOAuthCallback } = await import("../../auth-server/src/services/oauth.service.js");
    await expect(handleOAuthCallback("google", "google-code", "payload-state")).rejects.toMatchObject({
      name: "ZodError"
    });
  });

  it("honors ky's fixed timeout when the synthetic provider does not answer", async () => {
    vi.useFakeTimers();
    try {
      installProviderTransport({
        scenarios: [{ ...scenarios[0], tokenOutcome: "timeout" }]
      });
      const { handleOAuthCallback } = await import("../../auth-server/src/services/oauth.service.js");
      const rejection = expect(
        handleOAuthCallback("google", "google-code", "timeout-state")
      ).rejects.toMatchObject({ name: "TimeoutError" });
      await vi.advanceTimersByTimeAsync(10_001);
      await rejection;
    } finally {
      vi.useRealTimers();
    }
  });
});
