import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

const durationInSecondsSchema = z.string().min(1).transform((value, context) => {
  const match = /^(\d+)([smhd])?$/.exec(value);
  if (!match) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Duration must use a number with optional s, m, h, or d suffix"
    });
    return z.NEVER;
  }

  const amountText = match[1];
  const unit = match[2] ?? "s";
  if (!amountText) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Duration amount is required"
    });
    return z.NEVER;
  }

  const amount = Number.parseInt(amountText, 10);
  switch (unit) {
    case "s":
      return amount;
    case "m":
      return amount * 60;
    case "h":
      return amount * 60 * 60;
    case "d":
      return amount * 60 * 60 * 24;
    default:
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Unsupported duration unit"
      });
      return z.NEVER;
  }
});

const mailProviderSchema = z.enum(["dev", "smtp"]).default("dev");
const optionalNonEmptyStringSchema = z.preprocess(
  (value) => value === "" ? undefined : value,
  z.string().min(1).optional()
);

const localCorsOrigins = ["http://localhost:3000", "http://127.0.0.1:3000"] as const;

const placeholderJwtSecrets = new Set([
  "replace-access-secret",
  "replace-refresh-secret"
]);

const corsOriginsSchema = z.string().default("").transform((value, context) => {
  const origins: string[] = [];
  for (const candidate of value.split(",").map((entry) => entry.trim()).filter(Boolean)) {
    try {
      const origin = new URL(candidate).origin;
      if (origin !== candidate) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "CORS origins must include scheme, host, and optional port only"
        });
        return z.NEVER;
      }
      origins.push(origin);
    } catch (error) {
      if (error instanceof TypeError) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "CORS origins must be valid URLs"
        });
        return z.NEVER;
      }
      throw error;
    }
  }

  return [...new Set(origins)];
});

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  DATABASE_URL: z.string().min(1),
  PORT: z.coerce.number().int().positive().default(4000),
  JWT_ACCESS_SECRET: z.string().min(16),
  JWT_REFRESH_SECRET: z.string().min(16),
  JWT_ISSUER: z.string().url(),
  JWT_AUDIENCE: z.string().min(1),
  ACCESS_TOKEN_EXPIRES_IN: durationInSecondsSchema.default("15m"),
  REFRESH_TOKEN_EXPIRES_IN_DAYS: z.coerce.number().int().positive().default(30),
  PASSWORD_MIN_LENGTH: z.coerce.number().int().min(8).default(12),
  COMPANY_ALLOWED_EMAIL_DOMAIN: z.string().optional().default(""),
  CORS_ALLOWED_ORIGINS: corsOriginsSchema,
  AUTH_RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().positive().default(60),
  AUTH_RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(20),
  FRONTEND_REDIRECT_URL: z.string().url(),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  GOOGLE_REDIRECT_URI: z.string().url(),
  NAVER_CLIENT_ID: z.string().min(1),
  NAVER_CLIENT_SECRET: z.string().min(1),
  NAVER_REDIRECT_URI: z.string().url(),
  KAKAO_CLIENT_ID: z.string().min(1),
  KAKAO_CLIENT_SECRET: z.string().min(1),
  KAKAO_REDIRECT_URI: z.string().url(),
  MAIL_PROVIDER: mailProviderSchema,
  MAIL_FROM: z.string().min(1).default("Auth <no-reply@example.com>"),
  SMTP_HOST: optionalNonEmptyStringSchema,
  SMTP_PORT: z.coerce.number().int().positive().default(587),
  SMTP_USERNAME: optionalNonEmptyStringSchema,
  SMTP_PASSWORD: optionalNonEmptyStringSchema
}).superRefine((value, context) => {
  if (value.NODE_ENV !== "production") {
    return;
  }

  if (value.MAIL_PROVIDER !== "smtp") {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "MAIL_PROVIDER must be smtp in production",
      path: ["MAIL_PROVIDER"]
    });
  }

  if (placeholderJwtSecrets.has(value.JWT_ACCESS_SECRET)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "JWT_ACCESS_SECRET must not use the example placeholder value in production",
      path: ["JWT_ACCESS_SECRET"]
    });
  }

  if (placeholderJwtSecrets.has(value.JWT_REFRESH_SECRET)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "JWT_REFRESH_SECRET must not use the example placeholder value in production",
      path: ["JWT_REFRESH_SECRET"]
    });
  }

  if (!value.SMTP_HOST) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "SMTP_HOST is required when MAIL_PROVIDER=smtp in production",
      path: ["SMTP_HOST"]
    });
  }

  if ((value.SMTP_USERNAME && !value.SMTP_PASSWORD) || (!value.SMTP_USERNAME && value.SMTP_PASSWORD)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "SMTP_USERNAME and SMTP_PASSWORD must be provided together",
      path: ["SMTP_USERNAME"]
    });
  }
});

export type Env = z.infer<typeof envSchema>;

export const parseEnv = (input: NodeJS.ProcessEnv): Env => {
  const parsedEnv = envSchema.parse(input);
  const environmentLocalOrigins = parsedEnv.NODE_ENV === "production" ? [] : localCorsOrigins;
  return {
    ...parsedEnv,
    CORS_ALLOWED_ORIGINS: [
      ...new Set([
        ...parsedEnv.CORS_ALLOWED_ORIGINS,
        new URL(parsedEnv.FRONTEND_REDIRECT_URL).origin,
        ...environmentLocalOrigins
      ])
    ]
  };
};

export const env = parseEnv(process.env);
