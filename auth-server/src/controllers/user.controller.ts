import type { RequestHandler } from "express";
import { getCurrentUserWithStatus } from "../services/user.service.js";
import { assertActiveUserForTokenIssue } from "../services/user-status.service.js";
import { HttpError } from "../utils/httpError.js";

export const getMe: RequestHandler = (request, response, next) => {
  void (async () => {
    const userId = request.userId;
    if (!userId) {
      throw new HttpError(401, "UNAUTHORIZED", "Authentication is required");
    }

    const user = await assertActiveUserForTokenIssue({ getCurrentUserWithStatus }, userId);

    response.json({
      id: user.id,
      email: user.email,
      email_verified: user.emailVerified,
      name: user.name,
      roles: user.roles
    });
  })().catch(next);
};
