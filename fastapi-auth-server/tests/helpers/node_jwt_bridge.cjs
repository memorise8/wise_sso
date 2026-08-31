"use strict";

const { createPrivateKey, createPublicKey } = require("node:crypto");
const jwt = require("../../../auth-server/node_modules/jsonwebtoken");

const chunks = [];
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => chunks.push(chunk));
process.stdin.on("end", () => {
  try {
    const input = JSON.parse(chunks.join(""));
    const result = run(input);
    process.stdout.write(JSON.stringify({ ok: true, result }));
  } catch (error) {
    const name = error instanceof Error ? error.name : "Error";
    process.stdout.write(JSON.stringify({ ok: false, error: name }));
  }
});

function run(input) {
  switch (input.operation) {
    case "sign-access":
      return jwt.sign(input.payload, createPrivateKey(input.privateKey), {
        algorithm: "RS256",
        keyid: input.keyId,
        allowInsecureKeySizes: true,
      });
    case "sign-access-hs256":
      return jwt.sign(input.payload, input.secret, {
        algorithm: "HS256",
      });
    case "verify-access": {
      const payload = jwt.verify(input.token, publicKey(input.publicJwk), {
        algorithms: ["RS256"],
        issuer: input.issuer,
        audience: input.audience,
      });
      if (typeof payload !== "object" || payload.type !== "access") {
        throw new Error("Invalid access token shape");
      }
      return { sub: payload.sub, type: payload.type };
    }
    case "sign-refresh":
      return jwt.sign(input.payload, input.secret, {
        algorithm: input.algorithm ?? "HS256",
      });
    case "verify-refresh": {
      const payload = jwt.verify(input.token, input.secret, { algorithms: ["HS256"] });
      if (
        typeof payload !== "object" ||
        payload.type !== "refresh" ||
        payload.audience !== input.audience ||
        typeof payload.tokenId !== "string" ||
        !/^[a-f0-9]{64}$/.test(payload.tokenId)
      ) {
        throw new Error("Invalid refresh token shape");
      }
      return { sub: payload.sub, type: payload.type, audience: payload.audience };
    }
    case "verify-jwks": {
      const payload = jwt.verify(input.token, publicKey(input.publicJwk), {
        algorithms: ["RS256"],
        issuer: input.issuer,
        audience: input.audience,
      });
      return { sub: payload.sub };
    }
    default:
      throw new Error("Unsupported bridge operation");
  }
}

function publicKey(publicJwk) {
  return createPublicKey({ key: publicJwk, format: "jwk" });
}
