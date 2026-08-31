import { env } from "../config/env.js";

export type JsonWebKeySet = {
  readonly keys: readonly [typeof env.JWT_ACCESS_PUBLIC_JWK];
};

export type OpenIdConfiguration = {
  readonly issuer: string;
  readonly jwks_uri: string;
  readonly subject_types_supported: readonly ["public"];
  readonly response_types_supported: readonly ["code"];
  readonly claims_supported: readonly string[];
};

const jwksPath = "/.well-known/jwks.json";

export const publicMetadataCacheControl = "public, max-age=300";

export const getJsonWebKeySet = (): JsonWebKeySet => ({
  keys: [env.JWT_ACCESS_PUBLIC_JWK]
});

export const getOpenIdConfiguration = (): OpenIdConfiguration => ({
  issuer: env.JWT_ISSUER,
  jwks_uri: new URL(jwksPath, env.JWT_ISSUER).toString(),
  subject_types_supported: ["public"],
  response_types_supported: ["code"],
  claims_supported: [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "roles",
    "email",
    "email_verified",
    "name",
    "type"
  ]
});
