import type { RequestHandler } from "express";
import { z } from "zod";
import { env } from "../config/env.js";
import {
  auditContextFromRequest,
  auditEventTypes,
  recordAuthAuditEvent
} from "../services/audit.service.js";
import { auditLogStore } from "../services/audit.store.js";
import { authHandoffStore } from "../services/auth-handoff.store.js";
import { getAuthorizationUrl, handleOAuthCallback } from "../services/oauth.service.js";
import type { Provider } from "../services/user.service.js";
import { HttpError } from "../utils/httpError.js";

const oauthStateSchema = z.string().min(1);
const authExchangeBodySchema = z.object({ code: z.string().min(1) });

export const startOAuthLogin = (provider: Provider): RequestHandler => (_request, response) => {
  response.redirect(getAuthorizationUrl(provider));
};

export const completeOAuthLogin = (provider: Provider): RequestHandler => (request, response, next) => {
  void (async () => {
    if (request.query["error"]) {
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.loginFailure,
        outcome: "failure",
        userId: null,
        provider,
        ...auditContextFromRequest(request),
        reasonCode: "OAUTH_PROVIDER_ERROR"
      });
      throw new HttpError(400, "OAUTH_PROVIDER_ERROR", "OAuth provider returned an error");
    }

    const code = z.string().min(1).parse(request.query["code"]);
    const parsedState = oauthStateSchema.safeParse(request.query["state"]);
    if (!parsedState.success) {
      throw new HttpError(400, "INVALID_OAUTH_STATE", "Invalid OAuth state");
    }

    const tokens = await handleOAuthCallback(provider, code, parsedState.data);
    await recordAuthAuditEvent(auditLogStore, {
      eventType: auditEventTypes.loginSuccess,
      outcome: "success",
      userId: tokens.userId,
      provider,
      ...auditContextFromRequest(request)
    });
    const redirectUrl = new URL(env.FRONTEND_REDIRECT_URL);
    redirectUrl.searchParams.set("code", authHandoffStore.create({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    }));
    response.redirect(redirectUrl.toString());
  })().catch(next);
};

export const exchangeAuthHandoffCode: RequestHandler = (request, response, next) => {
  void (async () => {
    const body = authExchangeBodySchema.parse(request.body);
    const tokens = authHandoffStore.consume(body.code);
    if (!tokens) {
      throw new HttpError(400, "INVALID_AUTH_HANDOFF_CODE", "Invalid authorization code");
    }
    response.json(tokens);
  })().catch(next);
};
