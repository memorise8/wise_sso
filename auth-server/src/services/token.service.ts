import { createHash, createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import type { Prisma } from "@prisma/client";
import jwt from "jsonwebtoken";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import { env } from "../config/env.js";
import { userStatuses } from "./user-status.service.js";
import type { CurrentUserWithStatus } from "./user-status.service.js";
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

type TokenAudience = {
  readonly audience: string;
};

type AccessTokenPayload = {
  readonly sub: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly email_verified: boolean;
  readonly type: "access";
  readonly roles: CurrentUserWithStatus["roles"];
};

type RefreshTokenPayload = {
  readonly sub: string;
  readonly type: "refresh";
  readonly tokenId: string;
  readonly audience: string;
};

type TokenIssueClient = Pick<Prisma.TransactionClient, "$queryRaw" | "refreshToken" | "user">;

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

const invalidRefreshTokenError = (): HttpError =>
  new HttpError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token");

const defaultTokenAudience = (): TokenAudience => ({ audience: env.JWT_AUDIENCE });
const accessPrivateKey = createPrivateKey(env.JWT_ACCESS_PRIVATE_KEY);
const accessPublicKey = createPublicKey({ key: env.JWT_ACCESS_PUBLIC_JWK, format: "jwk" });

const accessOptions = (tokenAudience: TokenAudience): SignOptions => ({
  algorithm: env.JWT_ACCESS_ALGORITHM,
  keyid: env.JWT_ACCESS_KEY_ID,
  expiresIn: env.ACCESS_TOKEN_EXPIRES_IN,
  issuer: env.JWT_ISSUER,
  audience: tokenAudience.audience
});

const refreshOptions = (): SignOptions => ({
  expiresIn: `${env.REFRESH_TOKEN_EXPIRES_IN_DAYS}d`
});

export const createAccessToken = (
  user: CurrentUserWithStatus,
  tokenAudience: TokenAudience = defaultTokenAudience()
): string => {
  if (user.status !== userStatuses.active) {
    throw new HttpError(401, "UNAUTHORIZED", "Authentication is required");
  }

  const payload: AccessTokenPayload = {
    sub: user.id,
    email: user.email,
    name: user.name,
    email_verified: user.emailVerified,
    type: "access",
    roles: user.roles
  };
  return jwt.sign(payload, accessPrivateKey, accessOptions(tokenAudience));
};

const activeUserTokenIssueError = (): HttpError =>
  new HttpError(401, "UNAUTHORIZED", "Authentication is required");

const toCurrentUserWithStatus = (user: {
  readonly id: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly emailVerified: boolean;
  readonly status: CurrentUserWithStatus["status"];
  readonly roles: readonly {
    readonly role: {
      readonly serviceKey: string;
      readonly name: string;
    };
  }[];
}): CurrentUserWithStatus => ({
  id: user.id,
  email: user.email,
  name: user.name,
  emailVerified: user.emailVerified,
  status: user.status,
  roles: user.roles.map((userRole) => ({
    serviceKey: userRole.role.serviceKey,
    name: userRole.role.name
  }))
});

const lockActiveUserForTokenIssue = async (
  client: TokenIssueClient,
  userId: string,
  error: HttpError
): Promise<CurrentUserWithStatus> => {
  const lockedUsers = await client.$queryRaw<readonly { readonly id: string }[]>`
    SELECT "id" FROM "User" WHERE "id" = ${userId} AND "status" = ${userStatuses.active}::"UserStatus" FOR UPDATE
  `;
  if (lockedUsers.length !== 1) {
    throw error;
  }

  const user = await client.user.findUnique({
    where: { id: userId },
    include: {
      roles: {
        include: {
          role: true
        }
      }
    }
  });
  if (!user || user.status !== userStatuses.active) {
    throw error;
  }

  return toCurrentUserWithStatus(user);
};

const persistRefreshTokenForUser = async (
  client: TokenIssueClient,
  userId: string,
  user: CurrentUserWithStatus,
  tokenAudience: TokenAudience
): Promise<TokenPair> => {
  const tokenId = randomBytes(32).toString("hex");
  const payload: RefreshTokenPayload = {
    sub: userId,
    type: "refresh",
    tokenId,
    audience: tokenAudience.audience
  };
  const refreshToken = jwt.sign(payload, env.JWT_REFRESH_SECRET, refreshOptions());

  await client.refreshToken.create({
    data: {
      tokenHash: hashToken(refreshToken),
      userId,
      audience: tokenAudience.audience,
      expiresAt: refreshExpiresAt()
    }
  });

  return {
    accessToken: createAccessToken(user, tokenAudience),
    refreshToken
  };
};

const createRefreshTokenForActiveUser = async (
  client: TokenIssueClient,
  userId: string,
  error: HttpError,
  tokenAudience: TokenAudience
): Promise<TokenPair> => {
  const user = await lockActiveUserForTokenIssue(client, userId, error);
  return persistRefreshTokenForUser(client, userId, user, tokenAudience);
};

export const issueTokenPair = async (
  userId: string,
  tokenAudience: TokenAudience = defaultTokenAudience()
): Promise<TokenPair> =>
  prisma.$transaction(async (transaction) =>
    createRefreshTokenForActiveUser(transaction, userId, activeUserTokenIssueError(), tokenAudience)
  );

export const verifyAccessToken = (accessToken: string): string => {
  const payload = readJwtPayload(jwt.verify(accessToken, accessPublicKey, {
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
    algorithms: ["RS256"]
  }));
  if (typeof payload.sub !== "string" || payload["type"] !== "access") {
    throw new HttpError(401, "INVALID_TOKEN", "Invalid token");
  }
  return payload.sub;
};

export const rotateRefreshToken = async (refreshToken: string): Promise<RefreshTokenRotation> => {
  const payload = readJwtPayload(jwt.verify(refreshToken, env.JWT_REFRESH_SECRET));
  if (payload["type"] !== "refresh" || typeof payload.sub !== "string") {
    throw new HttpError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token");
  }
  const payloadAudience = typeof payload["audience"] === "string" ? payload["audience"] : env.JWT_AUDIENCE;

  const tokenHash = hashToken(refreshToken);
  const now = new Date();

  return prisma.$transaction(async (transaction) => {
    const storedToken = await transaction.refreshToken.findFirst({
      where: { tokenHash },
      select: { userId: true, audience: true }
    });
    if (!storedToken || storedToken.audience !== payloadAudience) {
      throw invalidRefreshTokenError();
    }

    const user = await lockActiveUserForTokenIssue(transaction, storedToken.userId, invalidRefreshTokenError());

    const revokeResult = await transaction.refreshToken.updateMany({
      where: {
        tokenHash,
        revokedAt: null,
        expiresAt: { gt: now }
      },
      data: { revokedAt: now }
    });
    if (revokeResult.count !== 1) {
      throw invalidRefreshTokenError();
    }

    return {
      tokens: await persistRefreshTokenForUser(transaction, storedToken.userId, user, {
        audience: storedToken.audience
      }),
      userId: storedToken.userId
    };
  });
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
