// allow: SIZE_OK - security-critical parser matrix for AUTH_CLIENTS_JSON, provider secrets, and localhost behavior kept together for P0 final gate.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";

const temisClientPolicy = {
  clientId: "temis",
  audience: "temis",
  allowedRedirectUris: ["https://financenow.kr/auth/callback", "https://temis.me/auth/callback", "https://ti.temis.me/auth/callback"],
  allowedOrigins: ["https://financenow.kr"],
  defaultRole: { serviceKey: "temis", name: "user" }
};
const authClientsJson = (clients: readonly object[]): string => JSON.stringify(clients);
const temisClientJson = (override: object): string => authClientsJson([{ ...temisClientPolicy, ...override }]);
const localClientPolicy = {
  clientId: "local-dev",
  audience: "local-dev",
  allowedRedirectUris: ["http://localhost:3000/auth/callback"],
  allowedOrigins: ["http://localhost:3000"],
  defaultRole: { serviceKey: "temis", name: "pending" }
};

const createAccessKeyEnv = (): Record<string, string> => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  if (publicJwk.kty !== "RSA" || typeof publicJwk.n !== "string" || typeof publicJwk.e !== "string") {
    throw new Error("Generated RSA key did not export a public JWK");
  }
  const publicJwkWithMetadata = {
    kty: "RSA",
    n: publicJwk.n,
    e: publicJwk.e,
    alg: "RS256",
    use: "sig",
    kid: "temis-access-key-1"
  } as const;

  return {
    JWT_ACCESS_ALGORITHM: "RS256",
    JWT_ACCESS_PRIVATE_KEY: privateKey.export({ format: "pem", type: "pkcs8" }).toString().replace(/\n/g, "\\n"),
    JWT_ACCESS_PUBLIC_JWK: JSON.stringify(publicJwkWithMetadata),
    JWT_ACCESS_KEY_ID: publicJwkWithMetadata.kid
  };
};

const baseEnv = {
  ...createAccessKeyEnv(),
  DATABASE_URL: "postgresql://user:password@localhost:5432/auth_db",
  JWT_REFRESH_SECRET: "test-refresh-secret-long",
  JWT_ISSUER: "https://auth.temis.co.kr",
  JWT_AUDIENCE: "temis",
  REDIS_URL: "redis://localhost:6379",
  OAUTH_ENABLED_PROVIDERS: "google,naver,kakao",
  FRONTEND_REDIRECT_URL: "https://app.temis.co.kr/auth/callback",
  GOOGLE_CLIENT_ID: "google",
  GOOGLE_CLIENT_SECRET: "google-secret",
  GOOGLE_REDIRECT_URI: "http://localhost:4000/auth/google/callback",
  NAVER_CLIENT_ID: "naver",
  NAVER_CLIENT_SECRET: "naver-secret",
  NAVER_REDIRECT_URI: "http://localhost:4000/auth/naver/callback",
  KAKAO_CLIENT_ID: "kakao",
  KAKAO_CLIENT_SECRET: "kakao-secret",
  KAKAO_REDIRECT_URI: "http://localhost:4000/auth/kakao/callback",
  AUTH_CLIENTS_JSON: authClientsJson([temisClientPolicy]),
  MAIL_PROVIDER: "dev"
} satisfies Record<string, string>;

const productionSmtpEnv = {
  ...baseEnv,
  NODE_ENV: "production",
  MAIL_PROVIDER: "smtp",
  SMTP_HOST: "smtp.example.com",
  SMTP_USERNAME: "mailer",
  SMTP_PASSWORD: "mailer-password"
} satisfies Record<string, string>;

const expectTemisClientOverrideRejected = async (override: object, message: RegExp = /required TEMIS/i): Promise<void> => {
  const { parseEnv } = await import("./env.js");

  expect(() => parseEnv({
    ...baseEnv,
    AUTH_CLIENTS_JSON: temisClientJson(override)
  })).toThrow(message);
};

describe("parseEnv CORS allowlist", () => {
  beforeEach(() => {
    vi.resetModules();
    Object.assign(process.env, baseEnv);
  });

  it("Given production env without local origins When env is parsed Then localhost is not added implicitly", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...productionSmtpEnv,
      CORS_ALLOWED_ORIGINS: "https://admin.temis.co.kr"
    });

    expect(parsed.CORS_ALLOWED_ORIGINS).toEqual([
      "https://admin.temis.co.kr",
      "https://app.temis.co.kr"
    ]);
  });

  it("Given production env with explicit localhost origin When env is parsed Then localhost remains allowed", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...productionSmtpEnv,
      CORS_ALLOWED_ORIGINS: "https://admin.temis.co.kr,http://localhost:3000"
    });

    expect(parsed.CORS_ALLOWED_ORIGINS).toContain("http://localhost:3000");
  });

  it("Given test env without local origins When env is parsed Then local development origins are added", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...baseEnv,
      NODE_ENV: "test",
      CORS_ALLOWED_ORIGINS: "https://admin.temis.co.kr"
    });

    expect(parsed.CORS_ALLOWED_ORIGINS).toEqual([
      "https://admin.temis.co.kr",
      "https://app.temis.co.kr",
      "http://localhost:3000",
      "http://127.0.0.1:3000"
    ]);
  });

  it("Given only Google OAuth is enabled When env is parsed Then Naver and Kakao secrets are not required", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...baseEnv,
      OAUTH_ENABLED_PROVIDERS: "google",
      NAVER_CLIENT_ID: "",
      NAVER_CLIENT_SECRET: "",
      KAKAO_CLIENT_ID: "",
      KAKAO_CLIENT_SECRET: ""
    });

    expect(parsed.OAUTH_ENABLED_PROVIDERS).toEqual(["google"]);
    expect(parsed.NAVER_CLIENT_ID).toBeUndefined();
    expect(parsed.KAKAO_CLIENT_ID).toBeUndefined();
  });

  it("Given Naver OAuth is enabled without secrets When env is parsed Then it rejects the missing provider settings", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...baseEnv,
      OAUTH_ENABLED_PROVIDERS: "google,naver",
      NAVER_CLIENT_ID: "",
      NAVER_CLIENT_SECRET: ""
    })).toThrow(/NAVER_CLIENT_ID/);
  });

  it("Given production env with dev mail provider When env is parsed Then it rejects the dev provider", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...baseEnv,
      NODE_ENV: "production",
      MAIL_PROVIDER: "dev"
    })).toThrow();
  });

  it("Given production smtp env without smtp credentials When env is parsed Then it rejects missing smtp settings", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...baseEnv,
      NODE_ENV: "production",
      MAIL_PROVIDER: "smtp"
    })).toThrow();
  });

  it("Given production env with example refresh jwt secret When env is parsed Then it rejects the placeholder secret", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...productionSmtpEnv,
      JWT_REFRESH_SECRET: "replace-refresh-secret"
    })).toThrow();
  });

  it("Given a short jwt secret When env is parsed Then it still rejects the secret length", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...productionSmtpEnv,
      JWT_REFRESH_SECRET: "short"
    })).toThrow();
  });

  it("Given RS256 access key env with escaped newlines When env is parsed Then access key metadata is normalized", async () => {
    const { parseEnv } = await import("./env.js");
    const accessKeyEnv = createAccessKeyEnv();

    const parsed = parseEnv({
      ...baseEnv,
      ...accessKeyEnv
    });

    expect(parsed.JWT_ACCESS_ALGORITHM).toBe("RS256");
    expect(parsed.JWT_ACCESS_PRIVATE_KEY).toContain("-----BEGIN PRIVATE KEY-----\n");
    expect(parsed.JWT_ACCESS_PUBLIC_JWK).toMatchObject({
      kty: "RSA",
      alg: "RS256",
      use: "sig",
      kid: "temis-access-key-1"
    });
    expect(parsed.JWT_ACCESS_KEY_ID).toBe("temis-access-key-1");
  });

  it.each([
    ["non-RS256 algorithm", { JWT_ACCESS_ALGORITHM: "HS256" }],
    ["malformed private key", { JWT_ACCESS_PRIVATE_KEY: "not-a-private-key" }],
    ["malformed public JWK JSON", { JWT_ACCESS_PUBLIC_JWK: "{" }],
    ["wrong public JWK alg", { JWT_ACCESS_PUBLIC_JWK: JSON.stringify({ kty: "RSA", n: "abc", e: "AQAB", alg: "HS256", use: "sig", kid: "temis-access-key-1" }) }],
    ["wrong public JWK kid", { JWT_ACCESS_KEY_ID: "different-key-id" }]
  ])("Given %s When env is parsed Then it rejects the access key configuration", async (_name, override) => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...baseEnv,
      ...createAccessKeyEnv(),
      ...override
    })).toThrow();
  });

  it("Given the TEMIS relying client env When env is parsed Then the first client policy keeps the user default role", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv(baseEnv);

    expect(parsed.AUTH_CLIENTS_JSON[0]).toEqual({
      ...temisClientPolicy
    });
  });

  it("Given the first TEMIS client explicitly defaults to user When env is parsed Then the override is accepted", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...baseEnv,
      AUTH_CLIENTS_JSON: temisClientJson({ defaultRole: { serviceKey: "temis", name: "user" } })
    });

    expect(parsed.AUTH_CLIENTS_JSON[0]?.defaultRole).toEqual({ serviceKey: "temis", name: "user" });
  });

  it.each([
    ["admin role", { serviceKey: "temis", name: "admin" }],
    ["non TEMIS service", { serviceKey: "other", name: "pending" }]
  ])("Given the first TEMIS client explicitly defaults to %s When env is parsed Then it rejects the default role", async (_name, defaultRole) => {
    await expectTemisClientOverrideRejected({ defaultRole }, /defaultRole/i);
  });

  it.each([
    ["admin role", { serviceKey: "temis", name: "admin" }],
    ["non-TEMIS user role", { serviceKey: "payroll", name: "user" }]
  ])("Given a non-first relying client explicitly defaults to %s When env is parsed Then it rejects the default role", async (_name, defaultRole) => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...baseEnv,
      AUTH_CLIENTS_JSON: authClientsJson([
        temisClientPolicy,
        {
          clientId: "payroll",
          audience: "payroll",
          allowedRedirectUris: ["https://payroll.example.com/auth/callback"],
          allowedOrigins: ["https://payroll.example.com"],
          defaultRole
        }
      ])
    })).toThrow(/defaultRole/i);
  });

  it("Given a non-first relying client explicitly defaults to its pending role When env is parsed Then it accepts the least-privilege default", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...baseEnv,
      AUTH_CLIENTS_JSON: authClientsJson([
        temisClientPolicy,
        {
          clientId: "payroll",
          audience: "payroll",
          allowedRedirectUris: ["https://payroll.example.com/auth/callback"],
          allowedOrigins: ["https://payroll.example.com"],
          defaultRole: { serviceKey: "payroll", name: "pending" }
        }
      ])
    });

    expect(parsed.AUTH_CLIENTS_JSON[1]?.defaultRole).toEqual({ serviceKey: "payroll", name: "pending" });
  });

  it("Given the first TEMIS client has an extra redirect URI When env is parsed Then it rejects the config", async () => {
    await expectTemisClientOverrideRejected({
      allowedRedirectUris: [
        "https://financenow.kr/auth/callback",
        "https://financenow.kr/extra/callback"
      ]
    });
  });

  it("Given the first TEMIS client has an extra allowed origin When env is parsed Then it rejects the config", async () => {
    await expectTemisClientOverrideRejected({
      allowedOrigins: [
        "https://financenow.kr",
        "https://admin.financenow.kr"
      ]
    });
  });

  it.each([
    ["top-level key", { notes: "extra" }],
    ["defaultRole key", { defaultRole: { serviceKey: "temis", name: "pending", extra: "extra" } }]
  ])("Given the first TEMIS client has an extra %s When env is parsed Then it rejects unknown keys", async (_name, override) => {
    await expectTemisClientOverrideRejected(override, /unrecognized key|required TEMIS/i);
  });

  it("Given duplicate relying client ids When env is parsed Then it rejects the config", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...baseEnv,
      AUTH_CLIENTS_JSON: authClientsJson([
        temisClientPolicy,
        {
          clientId: "temis",
          audience: "temis-admin",
          allowedRedirectUris: ["https://financenow.kr/admin/callback"],
          allowedOrigins: ["https://financenow.kr"],
          defaultRole: { serviceKey: "temis", name: "pending" }
        }
      ])
    })).toThrow(/duplicate clientId/i);
  });

  it("Given malformed relying client JSON When env is parsed Then it rejects the config", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...baseEnv,
      AUTH_CLIENTS_JSON: "{"
    })).toThrow(/valid JSON/i);
  });

  it("Given an invalid relying client redirect URL When env is parsed Then it rejects the config", async () => {
    await expectTemisClientOverrideRejected({ allowedRedirectUris: ["not a url"] }, /valid URL|required TEMIS/i);
  });

  it("Given an invalid relying client origin with a path When env is parsed Then it rejects the config", async () => {
    await expectTemisClientOverrideRejected({ allowedOrigins: ["https://financenow.kr/auth/callback"] }, /origin/i);
  });

  it("Given an empty relying client audience When env is parsed Then it rejects the config", async () => {
    await expectTemisClientOverrideRejected({ audience: "" }, /required|too small/i);
  });

  it("Given a production relying client localhost redirect When env is parsed Then it rejects localhost unless explicitly allowed", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...productionSmtpEnv,
      AUTH_CLIENTS_JSON: authClientsJson([temisClientPolicy, localClientPolicy])
    })).toThrow(/localhost/i);
  });

  it("Given a production relying client localhost redirect and explicit override When env is parsed Then it accepts the policy", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...productionSmtpEnv,
      AUTH_CLIENTS_JSON: authClientsJson([
        temisClientPolicy,
        { ...localClientPolicy, allowLocalhostInProduction: true }
      ])
    });

    expect(parsed.AUTH_CLIENTS_JSON[1]?.allowedRedirectUris).toEqual(["http://localhost:3000/auth/callback"]);
  });

  it("Given CORS allows an evil origin When validating TEMIS redirects Then CORS does not authorize redirect URIs", async () => {
    const { parseEnv } = await import("./env.js");
    const { createClientPolicyService } = await import("../services/client-policy.service.js");
    const parsed = parseEnv({
      ...baseEnv,
      CORS_ALLOWED_ORIGINS: "https://evil.example"
    });
    const clientPolicy = createClientPolicyService(parsed.AUTH_CLIENTS_JSON);

    expect(parsed.CORS_ALLOWED_ORIGINS).toContain("https://evil.example");
    expect(clientPolicy.isRedirectUriAllowed("temis", "https://evil.example/callback")).toBe(false);
  });
});
