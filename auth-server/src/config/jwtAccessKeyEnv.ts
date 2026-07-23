import { createPrivateKey, createPublicKey } from "node:crypto";
import { z } from "zod";

const accessPublicJwkSchema = z.object({
  kty: z.literal("RSA"),
  n: z.string().min(1),
  e: z.string().min(1),
  alg: z.literal("RS256"),
  use: z.literal("sig"),
  kid: z.string().min(1)
}).strict();

const accessPrivateKeySchema = z.string().min(1).transform((value, context) => {
  const normalizedPem = value.replace(/\\n/g, "\n");
  if (!normalizedPem.includes("-----BEGIN PRIVATE KEY-----")) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "JWT_ACCESS_PRIVATE_KEY must be a PKCS8 PEM private key"
    });
    return z.NEVER;
  }

  try {
    const privateKey = createPrivateKey(normalizedPem);
    if (privateKey.asymmetricKeyType !== "rsa") {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "JWT_ACCESS_PRIVATE_KEY must be an RSA private key"
      });
      return z.NEVER;
    }
  } catch (error) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "JWT_ACCESS_PRIVATE_KEY must be a valid PKCS8 PEM private key"
    });
    return z.NEVER;
  }

  return normalizedPem;
});

const accessPublicJwkJsonSchema = z.string().min(1).transform((value, context) => {
  let rawJwk: unknown;
  try {
    rawJwk = JSON.parse(value);
  } catch (error) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "JWT_ACCESS_PUBLIC_JWK must be valid JSON"
    });
    return z.NEVER;
  }

  const parsedJwk = accessPublicJwkSchema.safeParse(rawJwk);
  if (!parsedJwk.success) {
    for (const issue of parsedJwk.error.issues) {
      context.addIssue(issue);
    }
    return z.NEVER;
  }

  try {
    const publicKey = createPublicKey({ key: parsedJwk.data, format: "jwk" });
    if (publicKey.asymmetricKeyType !== "rsa") {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "JWT_ACCESS_PUBLIC_JWK must be an RSA public JWK"
      });
      return z.NEVER;
    }
  } catch (error) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "JWT_ACCESS_PUBLIC_JWK must be a valid RSA public JWK"
    });
    return z.NEVER;
  }

  return parsedJwk.data;
});

export const jwtAccessKeyEnvSchema = {
  JWT_ACCESS_ALGORITHM: z.literal("RS256"),
  JWT_ACCESS_PRIVATE_KEY: accessPrivateKeySchema,
  JWT_ACCESS_PUBLIC_JWK: accessPublicJwkJsonSchema,
  JWT_ACCESS_KEY_ID: z.string().min(1)
} as const;

const jwtAccessKeyObjectSchema = z.object(jwtAccessKeyEnvSchema);

type JwtAccessKeyEnv = z.infer<typeof jwtAccessKeyObjectSchema>;

export const validateJwtAccessKeyEnv = (
  value: JwtAccessKeyEnv,
  context: z.RefinementCtx
): void => {
  if (value.JWT_ACCESS_PUBLIC_JWK.kid !== value.JWT_ACCESS_KEY_ID) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "JWT_ACCESS_KEY_ID must match JWT_ACCESS_PUBLIC_JWK kid",
      path: ["JWT_ACCESS_KEY_ID"]
    });
  }

  const privatePublicJwk = createPublicKey(createPrivateKey(value.JWT_ACCESS_PRIVATE_KEY)).export({ format: "jwk" });
  if (
    privatePublicJwk.kty !== "RSA"
    || privatePublicJwk.n !== value.JWT_ACCESS_PUBLIC_JWK.n
    || privatePublicJwk.e !== value.JWT_ACCESS_PUBLIC_JWK.e
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "JWT_ACCESS_PRIVATE_KEY must match JWT_ACCESS_PUBLIC_JWK",
      path: ["JWT_ACCESS_PRIVATE_KEY"]
    });
  }
};
