import express from "express";
import { createMeRouter } from "./routes/me.routes.js";

const placeholderAccessSecrets = new Set(["replace-access-secret"]);

const requireAccessSecret = (): string => {
  const secret = process.env["AUTH_JWT_ACCESS_SECRET"];
  if (!secret || placeholderAccessSecrets.has(secret)) {
    throw new Error("AUTH_JWT_ACCESS_SECRET must be configured with a non-placeholder value");
  }
  return secret;
};

export const createServiceApp = () => {
  const app = express();

  app.use(createMeRouter({
    issuer: process.env["AUTH_JWT_ISSUER"] ?? "https://auth.temis.co.kr",
    audience: process.env["AUTH_JWT_AUDIENCE"] ?? "temis",
    accessSecret: requireAccessSecret()
  }));

  return app;
};
