import express from "express";
import type { VerifyAccessTokenOptions } from "./middlewares/verifyAccessToken.js";
import { createMeRouter } from "./routes/me.routes.js";

const placeholderPublicVerificationConfig = new Set(["replace-public-jwks", "replace-public-key"]);
type AccessVerificationConfig = Pick<VerifyAccessTokenOptions, "publicJwks"> | Pick<VerifyAccessTokenOptions, "publicKey">;

const readPublicVerificationEnv = (key: "AUTH_JWT_ACCESS_PUBLIC_JWKS" | "AUTH_JWT_ACCESS_PUBLIC_KEY"): string | null => {
  const value = process.env[key];
  if (!value || placeholderPublicVerificationConfig.has(value)) {
    return null;
  }
  return value;
};

const requireAccessVerificationConfig = (): AccessVerificationConfig => {
  const publicJwks = readPublicVerificationEnv("AUTH_JWT_ACCESS_PUBLIC_JWKS");
  if (publicJwks) {
    const parsedPublicJwks: unknown = JSON.parse(publicJwks);
    return {
      publicJwks: parsedPublicJwks
    };
  }

  const publicKey = readPublicVerificationEnv("AUTH_JWT_ACCESS_PUBLIC_KEY");
  if (publicKey) {
    return {
      publicKey: publicKey.replace(/\\n/g, "\n")
    };
  }

  throw new Error("AUTH_JWT_ACCESS_PUBLIC_JWKS or AUTH_JWT_ACCESS_PUBLIC_KEY must be configured");
};

export const createServiceApp = () => {
  const app = express();
  const accessVerificationConfig = requireAccessVerificationConfig();

  app.use(createMeRouter({
    issuer: process.env["AUTH_JWT_ISSUER"] ?? "https://auth.temis.co.kr",
    audience: process.env["AUTH_JWT_AUDIENCE"] ?? "temis",
    ...accessVerificationConfig
  }));

  return app;
};
