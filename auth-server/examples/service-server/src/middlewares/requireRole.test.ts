import { generateKeyPairSync } from "node:crypto";
import express from "express";
import jwt from "jsonwebtoken";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { requireRole } from "./requireRole.js";
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

const app = express();
app.get("/me", verifyAccessToken({
  issuer,
  audience,
  publicJwks
}), requireRole("temis", "user"), (req, res) => {
  res.json({ id: req.authUser.sub, roles: req.authUser.roles });
});

const signToken = (roles: readonly { readonly serviceKey: string; readonly name: string }[]): string =>
  jwt.sign({ sub: "auth-user-1", email: "user@example.com", name: "홍길동", email_verified: true, roles, type: "access" }, privateKey, {
    algorithm: "RS256",
    keyid: keyId,
    issuer,
    audience,
    expiresIn: "15m"
  });

describe("requireRole", () => {
  it("Given token with required role When /me is called Then it returns current auth user", async () => {
    const response = await request(app).get("/me").set("Authorization", `Bearer ${signToken([{ serviceKey: "temis", name: "user" }])}`);

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      id: "auth-user-1",
      roles: [{ serviceKey: "temis", name: "user" }]
    });
  });

  it("Given token without required role When /me is called Then it returns 403", async () => {
    const response = await request(app).get("/me").set("Authorization", `Bearer ${signToken([{ serviceKey: "review", name: "reviewer" }])}`);

    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: { code: "FORBIDDEN", message: "Required role is missing" } });
  });
});
