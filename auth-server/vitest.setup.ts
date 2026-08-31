import { generateKeyPairSync } from "node:crypto";

const createAccessKeyEnv = (): Record<string, string> => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  if (publicJwk.kty !== "RSA" || typeof publicJwk.n !== "string" || typeof publicJwk.e !== "string") {
    throw new Error("Generated RSA key did not export a public JWK");
  }

  const keyId = "test-access-key-1";
  const publicJwkWithMetadata = {
    kty: "RSA",
    n: publicJwk.n,
    e: publicJwk.e,
    alg: "RS256",
    use: "sig",
    kid: keyId
  };

  return {
    JWT_ACCESS_ALGORITHM: "RS256",
    JWT_ACCESS_PRIVATE_KEY: privateKey.export({ format: "pem", type: "pkcs8" }).toString().replace(/\n/g, "\\n"),
    JWT_ACCESS_PUBLIC_JWK: JSON.stringify(publicJwkWithMetadata),
    JWT_ACCESS_KEY_ID: keyId
  };
};

Object.assign(process.env, createAccessKeyEnv());

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = "postgresql://user:password@localhost:5432/auth_db";
process.env.JWT_REFRESH_SECRET = "test-refresh-secret-long";
process.env.JWT_ISSUER = "https://auth.temis.co.kr";
process.env.JWT_AUDIENCE = "temis";
process.env.REDIS_URL = "redis://localhost:6379";
process.env.FRONTEND_REDIRECT_URL = "http://localhost:3000/auth/callback";
process.env.GOOGLE_CLIENT_ID = "google";
process.env.GOOGLE_CLIENT_SECRET = "google-secret";
process.env.GOOGLE_REDIRECT_URI = "http://localhost:4000/auth/google/callback";
process.env.NAVER_CLIENT_ID = "naver";
process.env.NAVER_CLIENT_SECRET = "naver-secret";
process.env.NAVER_REDIRECT_URI = "http://localhost:4000/auth/naver/callback";
process.env.KAKAO_CLIENT_ID = "kakao";
process.env.KAKAO_CLIENT_SECRET = "kakao-secret";
process.env.KAKAO_REDIRECT_URI = "http://localhost:4000/auth/kakao/callback";
process.env.AUTH_CLIENTS_JSON = JSON.stringify([
  {
    clientId: "temis",
    audience: "temis",
    allowedRedirectUris: ["https://financenow.kr/auth/callback"],
    allowedOrigins: ["https://financenow.kr"],
    defaultRole: { serviceKey: "temis", name: "pending" }
  }
]);
process.env.MAIL_PROVIDER = "dev";
delete process.env.SMTP_HOST;
delete process.env.SMTP_USERNAME;
delete process.env.SMTP_PASSWORD;
