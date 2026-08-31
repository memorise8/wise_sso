import type { Request, RequestHandler } from "express";
import {
  auditContextFromRequest,
  auditEventTypes,
  recordAuthAuditEvent
} from "../services/audit.service.js";
import { auditLogStore } from "../services/audit.store.js";
import { redisTtlStoreClient } from "../services/redis.client.js";

type RateLimitOptions = {
  readonly windowMs: number;
  readonly maxRequests: number;
  readonly message: string;
};

const getClientKey = (request: Request): string => {
  const address = request.ip || request.socket.remoteAddress || "unknown";
  return address;
};

export const createRateLimitMiddleware = (options: RateLimitOptions): RequestHandler => {
  return (request, response, next) => {
    void (async () => {
      const clientKey = getClientKey(request);
      const windowSeconds = Math.ceil(options.windowMs / 1000);
      const count = await redisTtlStoreClient.incrementWithTtl(
        `wiseacct:rate-limit:${clientKey}:${request.baseUrl}${request.path}`,
        windowSeconds
      );

      if (count <= options.maxRequests) {
        next();
        return;
      }

      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.rateLimitExceeded,
        outcome: "failure",
        userId: null,
        ...auditContextFromRequest(request),
        reasonCode: "RATE_LIMITED",
        detailsJson: {
          route: `${request.baseUrl}${request.path}`,
          method: request.method,
          maxRequests: options.maxRequests,
          windowSeconds,
          retryAfterSeconds: windowSeconds
        }
      });
      response.setHeader("Retry-After", String(windowSeconds));
      response.status(429).json({
        error: {
          code: "RATE_LIMITED",
          message: options.message
        }
      });
    })().catch(next);
  };
};
