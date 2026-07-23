import { createPublicKey } from "node:crypto";
import type { KeyObject } from "node:crypto";
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
  readonly email_verified: boolean;
  readonly roles: readonly AuthRole[];
};

export type VerifyAccessTokenOptions = {
  readonly issuer: string;
  readonly audience: string;
} & (
  | {
    readonly publicJwks: unknown;
    readonly publicKey?: never;
  }
  | {
    readonly publicJwks?: never;
    readonly publicKey: string;
  }
);

declare global {
  namespace Express {
    interface Request {
      authUser: AuthUser;
    }
  }
}

const rsaPublicJwkSchema = z.object({
  kty: z.literal("RSA"),
  n: z.string().min(1),
  e: z.string().min(1),
  alg: z.literal("RS256").optional(),
  use: z.literal("sig").optional(),
  kid: z.string().min(1)
}).strict();

const jwksSchema = z.object({
  keys: z.array(rsaPublicJwkSchema).min(1)
}).strict();

const protectedHeaderSchema = z.object({
  alg: z.literal("RS256"),
  kid: z.string().min(1).optional()
}).passthrough();

const privatePemMarkerPattern = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;

const authRoleSchema = z.object({
  serviceKey: z.string().min(1),
  name: z.string().min(1)
});

const authUserPayloadSchema = z.object({
  sub: z.string().min(1),
  email: z.string().email().nullable().optional().default(null),
  name: z.string().nullable().optional().default(null),
  email_verified: z.boolean(),
  roles: z.array(authRoleSchema),
  type: z.literal("access"),
  iss: z.string().min(1),
  aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  exp: z.number().int().positive()
});

type ProtectedHeader = z.infer<typeof protectedHeaderSchema>;

type VerificationKeyStore =
  | {
    readonly kind: "publicKey";
    readonly key: KeyObject;
  }
  | {
    readonly kind: "jwks";
    readonly keysByKid: ReadonlyMap<string, KeyObject>;
  };

const createJwksKeyStore = (publicJwks: unknown): VerificationKeyStore => {
  const parsedJwks = jwksSchema.parse(publicJwks);
  const keysByKid = new Map<string, KeyObject>();

  for (const jwk of parsedJwks.keys) {
    if (keysByKid.has(jwk.kid)) {
      throw new Error("JWT public JWKS contains duplicate kid values");
    }
    keysByKid.set(jwk.kid, createPublicKey({
      key: {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e
      },
      format: "jwk"
    }));
  }

  return {
    kind: "jwks",
    keysByKid
  };
};

const createVerificationKeyStore = (options: VerifyAccessTokenOptions): VerificationKeyStore => {
  if (options.publicJwks !== undefined) {
    return createJwksKeyStore(options.publicJwks);
  }

  if (options.publicKey?.trim()) {
    if (privatePemMarkerPattern.test(options.publicKey)) {
      throw new Error("AUTH_JWT_ACCESS_PUBLIC_KEY must not contain private key material");
    }
    return {
      kind: "publicKey",
      key: createPublicKey(options.publicKey)
    };
  }

  throw new Error("AUTH_JWT_ACCESS_PUBLIC_JWKS or AUTH_JWT_ACCESS_PUBLIC_KEY must be configured");
};

const readProtectedHeader = (token: string): ProtectedHeader => {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded === "string") {
    throw new Error("JWT must include a protected header");
  }

  return protectedHeaderSchema.parse(decoded.header);
};

const selectVerificationKey = (keyStore: VerificationKeyStore, header: ProtectedHeader): KeyObject => {
  switch (keyStore.kind) {
    case "publicKey":
      return keyStore.key;
    case "jwks": {
      if (!header.kid) {
        throw new Error("JWT kid is required for JWKS verification");
      }
      const key = keyStore.keysByKid.get(header.kid);
      if (!key) {
        throw new Error("JWT kid is not trusted");
      }
      return key;
    }
  }
};

const toAuthUser = (payload: JwtPayload): AuthUser => {
  const parsedPayload = authUserPayloadSchema.parse(payload);
  return {
    sub: parsedPayload.sub,
    email: parsedPayload.email,
    name: parsedPayload.name,
    email_verified: parsedPayload.email_verified,
    roles: parsedPayload.roles
  };
};

const verifyJwtPayload = (
  token: string,
  keyStore: VerificationKeyStore,
  options: VerifyAccessTokenOptions
): JwtPayload => {
  const header = readProtectedHeader(token);
  const key = selectVerificationKey(keyStore, header);
  return readPayload(jwt.verify(token, key, {
    issuer: options.issuer,
    audience: options.audience,
    algorithms: ["RS256"]
  }));
};

export const verifyAccessToken = (options: VerifyAccessTokenOptions): RequestHandler => {
  const keyStore = createVerificationKeyStore(options);

  return (req, res, next) => {
    const authorization = req.header("authorization");
    const [scheme, token] = authorization?.split(" ") ?? [];

    if (scheme !== "Bearer" || !token) {
      res.status(401).json({ error: { code: "UNAUTHORIZED", message: "Bearer access token is required" } });
      return;
    }

    try {
      req.authUser = toAuthUser(verifyJwtPayload(token, keyStore, options));
      next();
    } catch (error) {
      if (error instanceof Error) {
        res.status(401).json({ error: { code: "UNAUTHORIZED", message: "Invalid access token" } });
        return;
      }
      next(error);
    }
  };
};
const readPayload = (payload: string | JwtPayload): JwtPayload => {
  if (typeof payload === "string") {
    throw new Error("JWT payload must be an object");
  }
  return payload;
};
