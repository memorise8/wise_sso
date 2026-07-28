import type { RequestHandler } from "express";
import { z } from "zod";
import { env } from "../config/env.js";
import {
  auditContextFromRequest,
  auditEventTypes,
  recordAuthAuditEvent,
  recordLoginFailureAuditEvent
} from "../services/audit.service.js";
import { auditLogStore } from "../services/audit.store.js";
import { confirmEmailVerification, requestEmailVerification } from "../services/email-verification.service.js";
import { emailVerificationStore } from "../services/email-verification.store.js";
import { authHandoffStore } from "../services/auth-handoff.store.js";
import { createMailService } from "../services/mail.service.js";
import { isPasswordAuthFailure, loginWithPassword, registerWithPassword } from "../services/password-auth.service.js";
import { passwordAuthStore } from "../services/password-auth.store.js";
import { confirmPasswordReset, requestPasswordReset } from "../services/password-reset.service.js";
import { passwordResetStore } from "../services/password-reset.store.js";
import { revokeRefreshToken, rotateRefreshToken } from "../services/token.service.js";
import { issueTokenPair } from "../services/token.service.js";
import { createClientPolicyService } from "../services/client-policy.service.js";
import { HttpError } from "../utils/httpError.js";

const credentialsBodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

const handoffBodySchema = z.object({
  clientId: z.string().min(1).optional(),
  redirectUri: z.string().url().optional(),
  state: z.string().min(1).max(512).optional(),
  codeChallenge: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/).optional(),
  codeChallengeMethod: z.literal("S256").optional()
}).strict();

const registerBodySchema = credentialsBodySchema.extend({
  name: z.string().min(1).nullable().optional().default(null)
});

const loginBodySchema = credentialsBodySchema.merge(handoffBodySchema).superRefine((body, context) => {
  const handoffFields = [
    body.clientId,
    body.redirectUri,
    body.codeChallenge,
    body.codeChallengeMethod
  ];
  const hasAnyHandoffField = handoffFields.some((value) => value !== undefined) || body.state !== undefined;
  const hasRequiredHandoffFields = body.clientId !== undefined &&
    body.redirectUri !== undefined &&
    body.codeChallenge !== undefined &&
    body.codeChallengeMethod !== undefined;

  if (hasAnyHandoffField && !hasRequiredHandoffFields) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "clientId, redirectUri, codeChallenge, and codeChallengeMethod are required together for SSO handoff"
    });
  }
});

const refreshTokenBodySchema = z.object({
  refreshToken: z.string().min(1)
});

const passwordResetRequestBodySchema = z.object({
  email: z.string().email()
});

const passwordResetConfirmBodySchema = z.object({
  token: z.string().min(1),
  password: z.string().min(1)
});

const emailVerificationRequestBodySchema = z.object({
  email: z.string().email(),
  clientId: z.string().min(1).optional(),
  redirectUri: z.string().url().optional(),
  state: z.string().min(1).max(512).optional(),
  codeChallenge: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/).optional(),
  codeChallengeMethod: z.literal("S256").optional()
}).strict().superRefine((body, context) => {
  const handoffFields = [
    body.clientId,
    body.redirectUri,
    body.codeChallenge,
    body.codeChallengeMethod
  ];
  const hasAnyHandoffField = handoffFields.some((value) => value !== undefined) || body.state !== undefined;
  const hasRequiredHandoffFields = body.clientId !== undefined &&
    body.redirectUri !== undefined &&
    body.codeChallenge !== undefined &&
    body.codeChallengeMethod !== undefined;

  if (hasAnyHandoffField && !hasRequiredHandoffFields) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "clientId, redirectUri, codeChallenge, and codeChallengeMethod are required together for SSO handoff"
    });
  }
});

const emailVerificationConfirmBodySchema = z.object({
  token: z.string().min(1)
});

const mailService = createMailService();
const clientPolicyService = createClientPolicyService(env.AUTH_CLIENTS_JSON);

const passwordResetUrlBase = (): string => {
  const frontendUrl = new URL(env.FRONTEND_REDIRECT_URL);
  return `${frontendUrl.origin}/password-reset`;
};

const emailVerificationUrlBase = (): string => {
  const frontendUrl = new URL(env.FRONTEND_REDIRECT_URL);
  return `${frontendUrl.origin}/verify-email`;
};

const clientForHandoff = (clientId: string, redirectUri: string) => {
  const client = clientPolicyService.findClient(clientId);
  if (!client || !clientPolicyService.isRedirectUriAllowed(clientId, redirectUri)) {
    throw new HttpError(400, "INVALID_CLIENT_REDIRECT_URI", "Invalid request");
  }
  return client;
};

const redirectUrlForHandoff = async (input: {
  readonly clientId: string;
  readonly audience: string;
  readonly redirectUri: string;
  readonly userId: string;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
  readonly state?: string;
}): Promise<string> => {
  const redirectUrl = new URL(input.redirectUri);
  redirectUrl.searchParams.set("code", await authHandoffStore.create({
    clientId: input.clientId,
    audience: input.audience,
    redirectUri: input.redirectUri,
    userId: input.userId,
    loginMethod: "password",
    codeChallenge: input.codeChallenge,
    codeChallengeMethod: input.codeChallengeMethod,
    state: input.state ?? null
  }));
  if (input.state) {
    redirectUrl.searchParams.set("state", input.state);
  }
  return redirectUrl.toString();
};

export const refreshTokens: RequestHandler = (request, response, next) => {
  void (async () => {
    const body = refreshTokenBodySchema.parse(request.body);
    try {
      const rotation = await rotateRefreshToken(body.refreshToken);
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.refresh,
        outcome: "success",
        userId: rotation.userId,
        ...auditContextFromRequest(request)
      });
      response.json(rotation.tokens);
    } catch (error) {
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.refresh,
        outcome: "failure",
        userId: null,
        ...auditContextFromRequest(request),
        reasonCode: "REFRESH_FAILED"
      });
      throw error;
    }
  })().catch(next);
};

export const registerWithCredentials: RequestHandler = (request, response, next) => {
  void (async () => {
    const body = registerBodySchema.parse(request.body);
    await registerWithPassword(passwordAuthStore, body, {
      minLength: env.PASSWORD_MIN_LENGTH,
      allowedEmailDomain: env.COMPANY_ALLOWED_EMAIL_DOMAIN || null
    });
    await recordAuthAuditEvent(auditLogStore, {
      eventType: auditEventTypes.registerRequest,
      outcome: "request",
      userId: await auditLogStore.findUserIdByPasswordEmail(body.email),
      ...auditContextFromRequest(request)
    });
    response.status(202).json({ status: "accepted" });
  })().catch(next);
};

export const loginWithCredentials: RequestHandler = (request, response, next) => {
  void (async () => {
    const body = loginBodySchema.parse(request.body);
    const client = body.clientId && body.redirectUri ? clientForHandoff(body.clientId, body.redirectUri) : null;
    try {
      const result = await loginWithPassword(passwordAuthStore, {
        email: body.email,
        password: body.password
      });
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.loginSuccess,
        outcome: "success",
        userId: result.user.id,
        ...auditContextFromRequest(request)
      });
      if (client && body.redirectUri && body.codeChallenge && body.codeChallengeMethod) {
        response.json({
          redirectUrl: await redirectUrlForHandoff({
            clientId: client.clientId,
            audience: client.audience,
            redirectUri: body.redirectUri,
            userId: result.user.id,
            codeChallenge: body.codeChallenge,
            codeChallengeMethod: body.codeChallengeMethod,
            ...(body.state ? { state: body.state } : {})
          })
        });
        return;
      }

      const tokens = await issueTokenPair(result.user.id);
      response.json(tokens);
    } catch (error) {
      if (isPasswordAuthFailure(error)) {
        await recordLoginFailureAuditEvent(auditLogStore, {
          email: body.email,
          userId: error.audit.userId,
          reasonCode: error.audit.reasonCode,
          ...auditContextFromRequest(request)
        });
      }
      throw error;
    }
  })().catch(next);
};

export const logout: RequestHandler = (request, response, next) => {
  void (async () => {
    const body = refreshTokenBodySchema.parse(request.body);
    const userId = await revokeRefreshToken(body.refreshToken);
    await recordAuthAuditEvent(auditLogStore, {
      eventType: auditEventTypes.logout,
      outcome: "success",
      userId: userId ?? null,
      ...auditContextFromRequest(request)
    });
    response.status(204).send();
  })().catch(next);
};

export const requestPasswordResetEmail: RequestHandler = (request, response, next) => {
  void (async () => {
    const body = passwordResetRequestBodySchema.parse(request.body);
    const result = await requestPasswordReset(passwordResetStore, mailService, {
      email: body.email,
      resetUrlBase: passwordResetUrlBase()
    });
    await recordAuthAuditEvent(auditLogStore, {
      eventType: auditEventTypes.passwordResetRequest,
      outcome: "request",
      userId: await auditLogStore.findUserIdByPasswordEmail(body.email),
      ...auditContextFromRequest(request)
    });
    response.status(202).json(result);
  })().catch(next);
};

export const confirmPasswordResetWithToken: RequestHandler = (request, response, next) => {
  void (async () => {
    const body = passwordResetConfirmBodySchema.parse(request.body);
    try {
      const result = await confirmPasswordReset(passwordResetStore, body, {
        minLength: env.PASSWORD_MIN_LENGTH,
        allowedEmailDomain: env.COMPANY_ALLOWED_EMAIL_DOMAIN || null
      });
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.passwordResetConfirm,
        outcome: "success",
        userId: result.userId,
        ...auditContextFromRequest(request)
      });
      response.status(204).send();
    } catch (error) {
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.passwordResetConfirm,
        outcome: "failure",
        userId: null,
        ...auditContextFromRequest(request),
        reasonCode: "INVALID_RESET_TOKEN"
      });
      throw error;
    }
  })().catch(next);
};

export const requestEmailVerificationEmail: RequestHandler = (request, response, next) => {
  void (async () => {
    const body = emailVerificationRequestBodySchema.parse(request.body);
    const client = body.clientId ? clientPolicyService.findClient(body.clientId) : null;
    if (body.clientId && (!client || !clientPolicyService.isRedirectUriAllowed(body.clientId, body.redirectUri ?? ""))) {
      throw new HttpError(400, "INVALID_CLIENT_REDIRECT_URI", "Invalid request");
    }
    const result = await requestEmailVerification({
      store: emailVerificationStore,
      mailer: mailService,
      input: {
        email: body.email,
        ...(client && body.redirectUri && body.codeChallenge && body.codeChallengeMethod ? {
          handoff: {
            clientId: client.clientId,
            audience: client.audience,
            redirectUri: body.redirectUri,
            state: body.state ?? null,
            codeChallenge: body.codeChallenge,
            codeChallengeMethod: body.codeChallengeMethod
          }
        } : {})
      },
      verificationUrlBase: emailVerificationUrlBase()
    });
    await recordAuthAuditEvent(auditLogStore, {
      eventType: auditEventTypes.emailVerificationRequest,
      outcome: "request",
      userId: await auditLogStore.findUserIdByEmail(body.email),
      ...auditContextFromRequest(request)
    });
    response.status(202).json(result);
  })().catch(next);
};

export const confirmEmailVerificationWithToken: RequestHandler = (request, response, next) => {
  void (async () => {
    const body = emailVerificationConfirmBodySchema.parse(request.body);
    let result: Awaited<ReturnType<typeof confirmEmailVerification>>;
    try {
      result = await confirmEmailVerification({
        store: emailVerificationStore,
        input: body
      });
    } catch (error) {
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.emailVerificationConfirm,
        outcome: "failure",
        userId: null,
        ...auditContextFromRequest(request),
        reasonCode: "INVALID_VERIFICATION_TOKEN"
      });
      throw error;
    }

    await recordAuthAuditEvent(auditLogStore, {
      eventType: auditEventTypes.emailVerificationConfirm,
      outcome: "success",
      userId: result.userId,
      ...auditContextFromRequest(request)
    });
    if (!result.handoff) {
      response.json({ status: result.status });
      return;
    }

    try {
      const redirectUrl = new URL(result.handoff.redirectUri);
      redirectUrl.searchParams.set("code", await authHandoffStore.create({
        clientId: result.handoff.clientId,
        audience: result.handoff.audience,
        redirectUri: result.handoff.redirectUri,
        userId: result.userId,
        loginMethod: "password",
        codeChallenge: result.handoff.codeChallenge,
        codeChallengeMethod: result.handoff.codeChallengeMethod,
        state: result.handoff.state
      }));
      if (result.handoff.state) {
        redirectUrl.searchParams.set("state", result.handoff.state);
      }

      response.json({ status: result.status, redirectUrl: redirectUrl.toString() });
    } catch (error) {
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.emailVerificationConfirm,
        outcome: "failure",
        userId: result.userId,
        ...auditContextFromRequest(request),
        reasonCode: "AUTH_HANDOFF_CREATE_FAILED"
      });
      throw error;
    }
  })().catch(next);
};
