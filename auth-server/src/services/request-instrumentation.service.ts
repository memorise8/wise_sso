import type { RequestHandler } from "express";
import { performance } from "node:perf_hooks";

const knownAuthRoutes = new Set([
  "/auth/google",
  "/auth/naver",
  "/auth/kakao",
  "/auth/google/callback",
  "/auth/naver/callback",
  "/auth/kakao/callback",
  "/auth/register",
  "/auth/login",
  "/auth/exchange",
  "/auth/refresh",
  "/auth/logout",
  "/auth/password-reset/request",
  "/auth/password-reset/confirm",
  "/auth/email-verification/request",
  "/auth/email-verification/confirm"
]);

const knownPublicRoutes = new Set([
  "/",
  "/healthz",
  "/readyz",
  "/.well-known/jwks.json",
  "/.well-known/openid-configuration",
  "/login",
  "/signup",
  "/auth/callback",
  "/password-reset",
  "/verify-email",
  "/admin/dashboard",
  "/manage/dashboard",
  "/users/me",
  "/admin/users",
  "/admin/audit-logs",
  "/manage-api/users",
  "/manage-api/audit-logs"
]);

const normalizedMethods = new Set(["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]);

export type RequestOutcome = "1xx" | "2xx" | "3xx" | "4xx" | "5xx" | "aborted";

export type RequestObservation = {
  readonly backend: "express";
  readonly version: "1.0.0";
  readonly method: string;
  readonly route: string;
  readonly outcome: RequestOutcome;
  readonly latencyMs: number;
};

export type RequestInstrumentation = {
  observeRequest(observation: RequestObservation): void | Promise<void>;
};

const noopRequestInstrumentation: RequestInstrumentation = {
  observeRequest: () => undefined
};

export const structuredRequestInstrumentation: RequestInstrumentation = {
  observeRequest: (observation) => {
    console.info(JSON.stringify({ metric: "sso_http_request", ...observation }));
  }
};

const normalizedMethod = (method: string): string => {
  const upperMethod = method.toUpperCase();
  return normalizedMethods.has(upperMethod) ? upperMethod : "OTHER";
};

const normalizedRoute = (originalUrl: string): string => {
  const queryStart = originalUrl.indexOf("?");
  const pathname = queryStart === -1 ? originalUrl : originalUrl.slice(0, queryStart);

  if (knownPublicRoutes.has(pathname) || knownAuthRoutes.has(pathname)) {
    return pathname;
  }
  if (pathname.startsWith("/assets/")) {
    return "/assets/*";
  }

  const adminRoute = pathname.match(/^\/(admin|manage-api)\/users\/[^/]+\/(status|roles|revoke-sessions)$/);
  if (adminRoute) {
    return `/${adminRoute[1]}/users/:id/${adminRoute[2]}`;
  }

  const adminRoleRoute = pathname.match(/^\/(admin|manage-api)\/users\/[^/]+\/roles\/[^/]+$/);
  if (adminRoleRoute) {
    return `/${adminRoleRoute[1]}/users/:id/roles/:roleId`;
  }

  if (pathname === "/auth" || pathname.startsWith("/auth/")) {
    return "/auth/*";
  }
  if (pathname === "/users" || pathname.startsWith("/users/")) {
    return "/users/*";
  }
  if (pathname === "/admin" || pathname.startsWith("/admin/")) {
    return "/admin/*";
  }
  if (pathname === "/manage-api" || pathname.startsWith("/manage-api/")) {
    return "/manage-api/*";
  }

  return "unmatched";
};

const statusOutcome = (statusCode: number): Exclude<RequestOutcome, "aborted"> => {
  if (statusCode < 200) return "1xx";
  if (statusCode < 300) return "2xx";
  if (statusCode < 400) return "3xx";
  if (statusCode < 500) return "4xx";
  return "5xx";
};

export const createRequestInstrumentationMiddleware = (
  instrumentation: RequestInstrumentation = noopRequestInstrumentation
): RequestHandler => (request, response, next) => {
  const startedAt = performance.now();
  let observed = false;

  const observe = (outcome: RequestOutcome): void => {
    if (observed) return;
    observed = true;

    try {
      const observationResult = instrumentation.observeRequest({
        backend: "express",
        version: "1.0.0",
        method: normalizedMethod(request.method),
        route: normalizedRoute(request.originalUrl),
        outcome,
        latencyMs: Math.max(0, performance.now() - startedAt)
      });
      void Promise.resolve(observationResult).catch(() => undefined);
    } catch {
      // Instrumentation must never change request handling.
    }
  };

  response.once("finish", () => observe(statusOutcome(response.statusCode)));
  response.once("close", () => observe(response.writableFinished ? statusOutcome(response.statusCode) : "aborted"));
  next();
};
