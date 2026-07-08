import { createHash, randomBytes } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import { env } from "../config/env.js";
import { getCurrentUser } from "./user.service.js";
import type { CurrentUser } from "./user.service.js";
import { HttpError } from "../utils/httpError.js";

const prisma = new PrismaClient();

type TokenPair = {
  readonly accessToken: string;
  readonly refreshToken: string;
};

type RefreshTokenRotation = {
  readonly tokens: TokenPair;
  readonly userId: string;
};

type AccessTokenPayload = {
  readonly sub: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly roles: CurrentUser["roles"];
};

type RefreshTokenPayload = {
  readonly sub: string;
  readonly type: "refresh";
  readonly tokenId: string;
};

const hashToken = (token: string): string => createHash("sha256").update(token).digest("hex");

const refreshExpiresAt = (): Date => {
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + env.REFRESH_TOKEN_EXPIRES_IN_DAYS);
  return expiresAt;
};

const readJwtPayload = (value: string | JwtPayload): JwtPayload => {
  if (typeof value === "string") {
    throw new HttpError(401, "INVALID_TOKEN", "Invalid token");
  }
  return value;
};

const accessOptions = (): SignOptions => ({
  expiresIn: env.ACCESS_TOKEN_EXPIRES_IN,
  issuer: env.JWT_ISSUER,
  audience: env.JWT_AUDIENCE
});

const refreshOptions = (): SignOptions => ({
  expiresIn: `${env.REFRESH_TOKEN_EXPIRES_IN_DAYS}d`
});

export const createAccessToken = (user: CurrentUser): string => {
  const payload: AccessTokenPayload = {
    sub: user.id,
    email: user.email,
    name: user.name,
    roles: user.roles
  };
  return jwt.sign(payload, env.JWT_ACCESS_SECRET, accessOptions());
};

export const issueTokenPair = async (userId: string): Promise<TokenPair> => {
  const user = await getCurrentUser(userId);
  if (!user) {
    throw new HttpError(404, "USER_NOT_FOUND", "User not found");
  }

  const tokenId = randomBytes(32).toString("hex");
  const payload: RefreshTokenPayload = { sub: userId, type: "refresh", tokenId };
  const refreshToken = jwt.sign(payload, env.JWT_REFRESH_SECRET, refreshOptions());

  await prisma.refreshToken.create({
    data: {
      tokenHash: hashToken(refreshToken),
      userId,
      expiresAt: refreshExpiresAt()
    }
  });

  return {
    accessToken: createAccessToken(user),
    refreshToken
  };
};

export const verifyAccessToken = (accessToken: string): string => {
  const payload = readJwtPayload(jwt.verify(accessToken, env.JWT_ACCESS_SECRET, {
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE
  }));
  if (typeof payload.sub !== "string") {
    throw new HttpError(401, "INVALID_TOKEN", "Invalid token");
  }
  return payload.sub;
};

export const rotateRefreshToken = async (refreshToken: string): Promise<RefreshTokenRotation> => {
  const payload = readJwtPayload(jwt.verify(refreshToken, env.JWT_REFRESH_SECRET));
  if (payload["type"] !== "refresh" || typeof payload.sub !== "string") {
    throw new HttpError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token");
  }

  const tokenHash = hashToken(refreshToken);
  const now = new Date();
  const storedToken = await prisma.refreshToken.findFirst({
    where: { tokenHash },
    select: { userId: true }
  });
  if (!storedToken) {
    throw new HttpError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token");
  }

  const revokeResult = await prisma.refreshToken.updateMany({
    where: {
      tokenHash,
      revokedAt: null,
      expiresAt: { gt: now }
    },
    data: { revokedAt: now }
  });
  if (revokeResult.count !== 1) {
    throw new HttpError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token");
  }

  return {
    tokens: await issueTokenPair(storedToken.userId),
    userId: storedToken.userId
  };
};

export const refreshAccessToken = async (refreshToken: string): Promise<TokenPair> => {
  const rotation = await rotateRefreshToken(refreshToken);
  return rotation.tokens;
};

export const revokeRefreshToken = async (refreshToken: string): Promise<string | null> => {
  const tokenHash = hashToken(refreshToken);
  const storedToken = await prisma.refreshToken.findFirst({
    where: { tokenHash, revokedAt: null },
    select: { userId: true }
  });
  await prisma.refreshToken.updateMany({
    where: { tokenHash, revokedAt: null },
    data: { revokedAt: new Date() }
  });
  return storedToken?.userId ?? null;
};
