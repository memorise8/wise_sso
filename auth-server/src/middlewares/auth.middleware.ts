import type { RequestHandler } from "express";
import { verifyAccessToken } from "../services/token.service.js";
import { HttpError } from "../utils/httpError.js";

declare global {
  namespace Express {
    interface Request {
      userId?: string;
    }
  }
}

export const authMiddleware: RequestHandler = (request, _response, next) => {
  const authorization = request.header("authorization");
  const [scheme, token] = authorization?.split(" ") ?? [];

  if (scheme !== "Bearer" || !token) {
    next(new HttpError(401, "UNAUTHORIZED", "Bearer access token is required"));
    return;
  }

  try {
    request.userId = verifyAccessToken(token);
    next();
  } catch (error) {
    next(error);
  }
};
