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
import { createMailService } from "../services/mail.service.js";
import { isPasswordAuthFailure, loginWithPassword, registerWithPassword } from "../services/password-auth.service.js";
import { passwordAuthStore } from "../services/password-auth.store.js";
import { confirmPasswordReset, requestPasswordReset } from "../services/password-reset.service.js";
import { passwordResetStore } from "../services/password-reset.store.js";
import { revokeRefreshToken, rotateRefreshToken } from "../services/token.service.js";
import { issueTokenPair } from "../services/token.service.js";

const credentialsBodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

const registerBodySchema = credentialsBodySchema.extend({
  name: z.string().min(1).nullable().optional().default(null)
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
  email: z.string().email()
});

const emailVerificationConfirmBodySchema = z.object({
  token: z.string().min(1)
});

const mailService = createMailService();

const passwordResetUrlBase = (): string => {
  const frontendUrl = new URL(env.FRONTEND_REDIRECT_URL);
  return `${frontendUrl.origin}/password-reset`;
};

const emailVerificationUrlBase = (): string => {
  const frontendUrl = new URL(env.FRONTEND_REDIRECT_URL);
  return `${frontendUrl.origin}/verify-email`;
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
    const body = credentialsBodySchema.parse(request.body);
    try {
      const result = await loginWithPassword(passwordAuthStore, body);
      const tokens = await issueTokenPair(result.user.id);
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.loginSuccess,
        outcome: "success",
        userId: result.user.id,
        ...auditContextFromRequest(request)
      });
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
    const result = await requestEmailVerification({
      store: emailVerificationStore,
      mailer: mailService,
      input: body,
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
    try {
      const result = await confirmEmailVerification({
        store: emailVerificationStore,
        input: body
      });
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.emailVerificationConfirm,
        outcome: "success",
        userId: result.userId,
        ...auditContextFromRequest(request)
      });
      response.json({ status: result.status });
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
  })().catch(next);
};
