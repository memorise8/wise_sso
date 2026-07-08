import express from "express";
import jwt from "jsonwebtoken";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { requireRole } from "./requireRole.js";
import { verifyAccessToken } from "./verifyAccessToken.js";

const app = express();
app.get("/me", verifyAccessToken({
  issuer: "https://auth.temis.co.kr",
  audience: "temis",
  accessSecret: "test-access-secret-long"
}), requireRole("temis", "user"), (req, res) => {
  res.json({ id: req.authUser.sub, roles: req.authUser.roles });
});

const signToken = (roles: readonly { readonly serviceKey: string; readonly name: string }[]): string =>
  jwt.sign({ sub: "auth-user-1", email: "user@example.com", name: "홍길동", roles }, "test-access-secret-long", {
    issuer: "https://auth.temis.co.kr",
    audience: "temis",
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
