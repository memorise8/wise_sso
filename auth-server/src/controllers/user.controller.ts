import type { RequestHandler } from "express";
import { getCurrentUser } from "../services/user.service.js";
import { HttpError } from "../utils/httpError.js";

export const getMe: RequestHandler = (request, response, next) => {
  void (async () => {
    const userId = request.userId;
    if (!userId) {
      throw new HttpError(401, "UNAUTHORIZED", "Authentication is required");
    }

    const user = await getCurrentUser(userId);
    if (!user) {
      throw new HttpError(404, "USER_NOT_FOUND", "User not found");
    }

    response.json(user);
  })().catch(next);
};
