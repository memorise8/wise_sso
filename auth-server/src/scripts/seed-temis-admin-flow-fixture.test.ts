import { generateKeyPairSync } from "node:crypto";
import jwt from "jsonwebtoken";
import type { JwtPayload } from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import { createAccessToken } from "./seed-temis-admin-flow-fixture.js";

const issuer = "https://auth.temis.co.kr";
const audience = "temis";
const keyId = "temis-access-key-1";

const configureAccessKeyEnv = (): string => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001
  });
  process.env["JWT_ACCESS_ALGORITHM"] = "RS256";
  process.env["JWT_ACCESS_PRIVATE_KEY"] = privateKey.export({ format: "pem", type: "pkcs8" }).toString().replace(/\n/g, "\\n");
  process.env["JWT_ACCESS_KEY_ID"] = keyId;
  process.env["JWT_ISSUER"] = issuer;
  process.env["JWT_AUDIENCE"] = audience;
  return publicKey.export({ format: "pem", type: "spki" }).toString();
};

const readPayload = (payload: string | JwtPayload): JwtPayload => {
  if (typeof payload === "string") {
    throw new Error("JWT payload must be an object");
  }
  return payload;
};

describe("seed TEMIS admin flow fixture access token", () => {
  it("Given configured RS256 access key When fixture token is signed Then it includes kid and access claims", () => {
    const publicKeyPem = configureAccessKeyEnv();

    const token = createAccessToken({
      id: "auth-user-1",
      email: "qa-admin@temis.example.test",
      emailVerified: true,
      name: "QA Admin",
      roles: [{ serviceKey: "temis", name: "admin" }]
    });
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === "string") {
      throw new Error("JWT must include a protected header");
    }

    const payload = readPayload(jwt.verify(token, publicKeyPem, {
      algorithms: ["RS256"],
      issuer,
      audience
    }));

    expect(decoded.header.alg).toBe("RS256");
    expect(decoded.header.kid).toBe(keyId);
    expect(payload["type"]).toBe("access");
    expect(payload["email_verified"]).toBe(true);
    expect(payload["roles"]).toEqual([{ serviceKey: "temis", name: "admin" }]);
  });
});
