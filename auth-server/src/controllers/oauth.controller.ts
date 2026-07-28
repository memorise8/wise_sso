import type { Request, RequestHandler } from "express";
import { z } from "zod";
import {
  auditContextFromRequest,
  auditEventTypes,
  recordAuthAuditEvent
} from "../services/audit.service.js";
import { auditLogStore } from "../services/audit.store.js";
import { authHandoffStore } from "../services/auth-handoff.store.js";
import { getAuthorizationUrl, handleOAuthCallback } from "../services/oauth.service.js";
import type { OAuthLoginStartInput } from "../services/oauth.service.js";
import { issueTokenPair } from "../services/token.service.js";
import type { Provider } from "../services/user.service.js";
import { HttpError } from "../utils/httpError.js";

const oauthStateSchema = z.string().min(1);
const codeChallengeSchema = z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/);
const oauthStartQuerySchema = z.object({
  client_id: z.string().min(1).optional(),
  redirect_uri: z.string().url().optional(),
  state: z.string().min(1).max(512).optional(),
  code_challenge: codeChallengeSchema.optional(),
  code_challenge_method: z.literal("S256").optional()
}).strict().superRefine((query, context) => {
  if (!query.code_challenge) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "code_challenge is required",
      path: ["code_challenge"]
    });
  }
});

const authExchangeCamelBodySchema = z.object({
  clientId: z.string().min(1),
  redirectUri: z.string().url(),
  code: z.string().min(1),
  codeVerifier: z.string().min(1)
}).strict();
const authExchangeBodySchema = authExchangeCamelBodySchema;
const invalidAuthHandoffCodeError = (): HttpError =>
  new HttpError(400, "INVALID_AUTH_HANDOFF_CODE", "Invalid authorization code");
type AuthHandoffExchangeAuditEventType =
  | typeof auditEventTypes.authHandoffExchangeSuccess
  | typeof auditEventTypes.authHandoffExchangeFailure;
type AuthHandoffExchangeAuditInput = {
  readonly eventType: AuthHandoffExchangeAuditEventType;
  readonly outcome: "success" | "failure";
  readonly userId: string | null;
  readonly request: Request;
  readonly reasonCode?: string;
  readonly clientId?: string;
  readonly provider?: Provider;
};

const recordAuthHandoffExchangeAudit = async (input: AuthHandoffExchangeAuditInput): Promise<void> => {
  await recordAuthAuditEvent(auditLogStore, {
    eventType: input.eventType,
    outcome: input.outcome,
    userId: input.userId,
    ...(input.provider ? { provider: input.provider } : {}),
    ...auditContextFromRequest(input.request),
    ...(input.reasonCode ? { reasonCode: input.reasonCode } : {}),
    detailsJson: {
      route: "/auth/exchange",
      ...(input.clientId ? { clientId: input.clientId } : {})
    }
  });
};

const oauthLoginStartInputFromQuery = (query: unknown): OAuthLoginStartInput => {
  const parsedQuery = oauthStartQuerySchema.parse(query);
  return {
    clientId: parsedQuery.client_id ?? "temis",
    ...(parsedQuery.redirect_uri ? { redirectUri: parsedQuery.redirect_uri } : {}),
    ...(parsedQuery.state ? { callerState: parsedQuery.state } : {}),
    ...(parsedQuery.code_challenge ? { codeChallenge: parsedQuery.code_challenge } : {}),
    codeChallengeMethod: parsedQuery.code_challenge_method ?? "S256"
  };
};

export const startOAuthLogin = (provider: Provider): RequestHandler => (request, response, next) => {
  void (async () => {
    const authorizationUrl = await getAuthorizationUrl(provider, oauthLoginStartInputFromQuery(request.query));
    response.redirect(authorizationUrl);
  })().catch(next);
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

    const callbackResult = await handleOAuthCallback(provider, code, parsedState.data);
    await recordAuthAuditEvent(auditLogStore, {
      eventType: auditEventTypes.loginSuccess,
      outcome: "success",
      userId: callbackResult.userId,
      provider,
      ...auditContextFromRequest(request)
    });
    const redirectUrl = new URL(callbackResult.redirectUri);
    redirectUrl.searchParams.set("code", await authHandoffStore.create({
      clientId: callbackResult.clientId,
      audience: callbackResult.audience,
      redirectUri: callbackResult.redirectUri,
      userId: callbackResult.userId,
      provider,
      loginMethod: "oauth",
      codeChallenge: callbackResult.codeChallenge,
      codeChallengeMethod: callbackResult.codeChallengeMethod,
      state: callbackResult.callerState
    }));
    if (callbackResult.callerState) {
      redirectUrl.searchParams.set("state", callbackResult.callerState);
    }
    response.redirect(redirectUrl.toString());
  })().catch(next);
};

export const exchangeAuthHandoffCode: RequestHandler = (request, response, next) => {
  void (async () => {
    const parsedBody = authExchangeBodySchema.safeParse(request.body);
    if (!parsedBody.success) {
      await recordAuthHandoffExchangeAudit({
        eventType: auditEventTypes.authHandoffExchangeFailure,
        outcome: "failure",
        userId: null,
        request,
        reasonCode: "INVALID_AUTH_HANDOFF_CODE"
      });
      throw invalidAuthHandoffCodeError();
    }

    const body = parsedBody.data;
    const handoff = await authHandoffStore.consume({
      clientId: body.clientId,
      redirectUri: body.redirectUri,
      code: body.code,
      codeVerifier: body.codeVerifier
    });
    if (!handoff) {
      await recordAuthHandoffExchangeAudit({
        eventType: auditEventTypes.authHandoffExchangeFailure,
        outcome: "failure",
        userId: null,
        request,
        reasonCode: "INVALID_AUTH_HANDOFF_CODE",
        clientId: body.clientId
      });
      throw invalidAuthHandoffCodeError();
    }
    try {
      const tokenPair = await issueTokenPair(handoff.userId, { audience: handoff.audience });
      await recordAuthHandoffExchangeAudit({
        eventType: auditEventTypes.authHandoffExchangeSuccess,
        outcome: "success",
        userId: handoff.userId,
        request,
        clientId: handoff.clientId,
        ...(handoff.provider ? { provider: handoff.provider } : {})
      });
      response.json(tokenPair);
    } catch (error: unknown) {
      await recordAuthHandoffExchangeAudit({
        eventType: auditEventTypes.authHandoffExchangeFailure,
        outcome: "failure",
        userId: handoff.userId,
        request,
        reasonCode: error instanceof HttpError ? error.code : "AUTH_HANDOFF_EXCHANGE_FAILED",
        clientId: handoff.clientId,
        ...(handoff.provider ? { provider: handoff.provider } : {})
      });
      throw error;
    }
  })().catch(next);
};
