import type { Request, RequestHandler } from "express";

type RateLimitOptions = {
  readonly windowMs: number;
  readonly maxRequests: number;
  readonly message: string;
};

type RateLimitBucket = {
  count: number;
  resetAtMs: number;
};

const getClientKey = (request: Request): string => {
  const address = request.ip || request.socket.remoteAddress || "unknown";
  return address;
};

export const createRateLimitMiddleware = (options: RateLimitOptions): RequestHandler => {
  const buckets = new Map<string, RateLimitBucket>();

  return (request, response, next) => {
    const nowMs = Date.now();
    const clientKey = getClientKey(request);
    const existingBucket = buckets.get(clientKey);
    const bucket =
      existingBucket && existingBucket.resetAtMs > nowMs
        ? existingBucket
        : { count: 0, resetAtMs: nowMs + options.windowMs };

    bucket.count += 1;
    buckets.set(clientKey, bucket);

    if (bucket.count <= options.maxRequests) {
      next();
      return;
    }

    const retryAfterSeconds = Math.max(1, Math.ceil((bucket.resetAtMs - nowMs) / 1000));
    response.setHeader("Retry-After", String(retryAfterSeconds));
    response.status(429).json({
      error: {
        code: "RATE_LIMITED",
        message: options.message
      }
    });
  };
};
