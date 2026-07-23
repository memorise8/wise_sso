import { generateKeyPairSync } from "node:crypto";
import express from "express";
import jwt from "jsonwebtoken";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { verifyAccessToken } from "./verifyAccessToken.js";

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

const trustedPublicJwk = {
  kty: "RSA",
  n: publicJwk.n,
  e: publicJwk.e,
  alg: "RS256",
  use: "sig",
  kid: keyId
} as const;

const publicJwks = {
  keys: [trustedPublicJwk]
};

const forbiddenJwkFields = [
  ["d", "private-exponent-must-not-be-accepted"],
  ["p", "private-prime-must-not-be-accepted"],
  ["q", "private-prime-must-not-be-accepted"],
  ["dp", "private-exponent-must-not-be-accepted"],
  ["dq", "private-exponent-must-not-be-accepted"],
  ["qi", "private-coefficient-must-not-be-accepted"],
  ["oth", "other-primes-must-not-be-accepted"],
  ["k", "symmetric-key-must-not-be-accepted"],
  ["privateKey", "private-key-must-not-be-accepted"],
  ["pem", "pem-material-must-not-be-accepted"],
  ["x5c", ["certificate-chain-must-not-be-accepted"]]
] as const;

const app = express();
app.get("/me", verifyAccessToken({
  issuer,
  audience,
  publicJwks
}), (req, res) => {
  res.json(req.authUser);
});

const signAccessToken = (claims: {
  readonly sub: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly email_verified: boolean;
  readonly roles: readonly { readonly serviceKey: string; readonly name: string }[];
  readonly type: "access";
}): string =>
  jwt.sign(claims, privateKey, {
    algorithm: "RS256",
    keyid: keyId,
    issuer,
    audience,
    expiresIn: "15m"
  });

describe("verifyAccessToken", () => {
  it("Given valid RS256 access token When /me is called Then it returns the AuthUser contract", async () => {
    const token = signAccessToken({
      sub: "auth-user-1",
      email: "user@example.com",
      name: "User Name",
      email_verified: true,
      roles: [{ serviceKey: "temis", name: "user" }],
      type: "access"
    });

    const response = await request(app).get("/me").set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      sub: "auth-user-1",
      email: "user@example.com",
      name: "User Name",
      email_verified: true,
      roles: [{ serviceKey: "temis", name: "user" }]
    });
  });

  it("Given malformed Authorization header When /me is called Then it returns 401", async () => {
    const response = await request(app).get("/me").set("Authorization", "Bearer malformed-token");

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: { code: "UNAUTHORIZED", message: "Invalid access token" } });
  });

  it.each(forbiddenJwkFields)(
    "Given public JWKS with %s field When verifier is configured Then it rejects the JWKS",
    (field, value) => {
      expect(() => verifyAccessToken({
        issuer,
        audience,
        publicJwks: {
          keys: [
            {
              ...trustedPublicJwk,
              [field]: value
            }
          ]
        }
      })).toThrow(/unrecognized key/i);
    }
  );

  it("Given private PEM material in public-key config When verifier is configured Then startup rejects the key", () => {
    const privatePem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();

    expect(() => verifyAccessToken({
      issuer,
      audience,
      publicKey: privatePem
    })).toThrow(/private key/i);
  });

  it("Given token with wrong audience When /me is called Then it returns 401", async () => {
    const token = jwt.sign({
      sub: "auth-user-1",
      email_verified: true,
      roles: [],
      type: "access"
    }, privateKey, {
      algorithm: "RS256",
      keyid: keyId,
      issuer,
      audience: "other-service",
      expiresIn: "15m"
    });

    const response = await request(app).get("/me").set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: { code: "UNAUTHORIZED", message: "Invalid access token" } });
  });

  it("Given refresh token When /me is called Then it returns 401", async () => {
    const token = jwt.sign({
      sub: "auth-user-1",
      email_verified: true,
      roles: [{ serviceKey: "temis", name: "user" }],
      type: "refresh"
    }, privateKey, {
      algorithm: "RS256",
      keyid: keyId,
      issuer,
      audience,
      expiresIn: "15m"
    });

    const response = await request(app).get("/me").set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: { code: "UNAUTHORIZED", message: "Invalid access token" } });
  });

  it("Given token without roles When /me is called Then it returns 401", async () => {
    const token = jwt.sign({
      sub: "auth-user-1",
      email_verified: true,
      type: "access"
    }, privateKey, {
      algorithm: "RS256",
      keyid: keyId,
      issuer,
      audience,
      expiresIn: "15m"
    });

    const response = await request(app).get("/me").set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: { code: "UNAUTHORIZED", message: "Invalid access token" } });
  });
});
