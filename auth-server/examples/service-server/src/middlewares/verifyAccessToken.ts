import type { RequestHandler } from "express";
import jwt from "jsonwebtoken";
import type { JwtPayload } from "jsonwebtoken";
import { z } from "zod";

export type AuthRole = {
  readonly serviceKey: string;
  readonly name: string;
};

export type AuthUser = {
  readonly sub: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly roles: readonly AuthRole[];
};

export type VerifyAccessTokenOptions = {
  readonly issuer: string;
  readonly audience: string;
  readonly accessSecret: string;
};

declare global {
  namespace Express {
    interface Request {
      authUser: AuthUser;
    }
  }
}

const authUserSchema = z.object({
  sub: z.string().min(1),
  email: z.string().email().nullable().optional().default(null),
  name: z.string().nullable().optional().default(null),
  roles: z.array(z.object({
    serviceKey: z.string().min(1),
    name: z.string().min(1)
  })).default([])
});

const readPayload = (payload: string | JwtPayload): JwtPayload => {
  if (typeof payload === "string") {
    throw new Error("JWT payload must be an object");
  }
  return payload;
};

export const verifyAccessToken = (options: VerifyAccessTokenOptions): RequestHandler => (req, res, next) => {
  const authorization = req.header("authorization");
  const [scheme, token] = authorization?.split(" ") ?? [];

  if (scheme !== "Bearer" || !token) {
    res.status(401).json({ error: { code: "UNAUTHORIZED", message: "Bearer access token is required" } });
    return;
  }

  try {
    const payload = readPayload(jwt.verify(token, options.accessSecret, {
      issuer: options.issuer,
      audience: options.audience
    }));
    req.authUser = authUserSchema.parse(payload);
    next();
  } catch (error) {
    if (error instanceof Error) {
      res.status(401).json({ error: { code: "UNAUTHORIZED", message: "Invalid access token" } });
      return;
    }
    next(error);
  }
};
