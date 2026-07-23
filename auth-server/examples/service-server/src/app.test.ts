import { generateKeyPairSync } from "node:crypto";
import jwt from "jsonwebtoken";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";

const originalPublicJwks = process.env["AUTH_JWT_ACCESS_PUBLIC_JWKS"];
const originalPublicKey = process.env["AUTH_JWT_ACCESS_PUBLIC_KEY"];
const originalIssuer = process.env["AUTH_JWT_ISSUER"];
const originalAudience = process.env["AUTH_JWT_AUDIENCE"];
const issuer = "https://auth.temis.co.kr";
const audience = "temis";
const keyId = "temis-access-key-1";
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicExponent: 0x10001
});
const publicJwk = publicKey.export({ format: "jwk" });

if (publicJwk.kty !== "RSA" || typeof publicJwk.n !== "string" || typeof publicJwk.e !== "string") {
  throw new Error("Generated RSA key did not export public parameters");
}

const publicJwks = {
  keys: [
    {
      kty: "RSA",
      n: publicJwk.n,
      e: publicJwk.e,
      alg: "RS256",
      use: "sig",
      kid: keyId
    }
  ]
};

const restoreEnv = (
  key: "AUTH_JWT_ACCESS_PUBLIC_JWKS" | "AUTH_JWT_ACCESS_PUBLIC_KEY" | "AUTH_JWT_ISSUER" | "AUTH_JWT_AUDIENCE",
  value: string | undefined
): void => {
  if (value !== undefined) {
    process.env[key] = value;
    return;
  }
  delete process.env[key];
};

const signAccessToken = (): string =>
  jwt.sign({
    sub: "auth-user-1",
    email: "user@example.com",
    name: "User Name",
    email_verified: true,
    roles: [{ serviceKey: "temis", name: "user" }],
    type: "access"
  }, privateKey, {
    algorithm: "RS256",
    keyid: keyId,
    issuer,
    audience,
    expiresIn: "15m"
  });

describe("service app config", () => {
  afterEach(() => {
    restoreEnv("AUTH_JWT_ACCESS_PUBLIC_JWKS", originalPublicJwks);
    restoreEnv("AUTH_JWT_ACCESS_PUBLIC_KEY", originalPublicKey);
    restoreEnv("AUTH_JWT_ISSUER", originalIssuer);
    restoreEnv("AUTH_JWT_AUDIENCE", originalAudience);
  });

  it("Given missing JWT public verification config When service app is created Then startup fails closed", async () => {
    delete process.env["AUTH_JWT_ACCESS_PUBLIC_JWKS"];
    delete process.env["AUTH_JWT_ACCESS_PUBLIC_KEY"];
    const { createServiceApp } = await import("./app.js");

    expect(() => createServiceApp()).toThrow(/AUTH_JWT_ACCESS_PUBLIC_JWKS|AUTH_JWT_ACCESS_PUBLIC_KEY/);
  });

  it("Given placeholder JWT public verification config When service app is created Then startup fails closed", async () => {
    process.env["AUTH_JWT_ACCESS_PUBLIC_JWKS"] = "replace-public-jwks";
    delete process.env["AUTH_JWT_ACCESS_PUBLIC_KEY"];
    const { createServiceApp } = await import("./app.js");

    expect(() => createServiceApp()).toThrow(/AUTH_JWT_ACCESS_PUBLIC_JWKS|AUTH_JWT_ACCESS_PUBLIC_KEY/);
  });

  it("Given JWKS public verification config and RS256 token When /me is called Then it returns current user", async () => {
    process.env["AUTH_JWT_ACCESS_PUBLIC_JWKS"] = JSON.stringify(publicJwks);
    delete process.env["AUTH_JWT_ACCESS_PUBLIC_KEY"];
    process.env["AUTH_JWT_ISSUER"] = issuer;
    process.env["AUTH_JWT_AUDIENCE"] = audience;
    const { createServiceApp } = await import("./app.js");

    const response = await request(createServiceApp()).get("/me").set("Authorization", `Bearer ${signAccessToken()}`);

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      id: "auth-user-1",
      email: "user@example.com",
      name: "User Name",
      roles: [{ serviceKey: "temis", name: "user" }]
    });
  });
});
