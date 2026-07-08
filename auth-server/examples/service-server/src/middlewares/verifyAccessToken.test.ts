import express from "express";
import jwt from "jsonwebtoken";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { verifyAccessToken } from "./verifyAccessToken.js";

const app = express();
app.get("/me", verifyAccessToken({
  issuer: "https://auth.temis.co.kr",
  audience: "temis",
  accessSecret: "test-access-secret-long"
}), (req, res) => {
  res.json(req.authUser);
});

describe("verifyAccessToken", () => {
  it("Given malformed Authorization header When /me is called Then it returns 401", async () => {
    const response = await request(app).get("/me").set("Authorization", "Bearer malformed-token");

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: { code: "UNAUTHORIZED", message: "Invalid access token" } });
  });

  it("Given token with wrong audience When /me is called Then it returns 401", async () => {
    const token = jwt.sign({ sub: "auth-user-1", roles: [] }, "test-access-secret-long", {
      issuer: "https://auth.temis.co.kr",
      audience: "other-service",
      expiresIn: "15m"
    });

    const response = await request(app).get("/me").set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: { code: "UNAUTHORIZED", message: "Invalid access token" } });
  });
});
