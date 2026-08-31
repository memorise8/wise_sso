import { Router } from "express";
import { requireRole } from "../middlewares/requireRole.js";
import { verifyAccessToken } from "../middlewares/verifyAccessToken.js";
import type { VerifyAccessTokenOptions } from "../middlewares/verifyAccessToken.js";

export type ServiceServerAuthConfig = VerifyAccessTokenOptions;

export const createMeRouter = (config: ServiceServerAuthConfig): Router => {
  const router = Router();

  router.get("/me", verifyAccessToken(config), requireRole("temis", "user"), (req, res) => {
    res.json({
      id: req.authUser.sub,
      email: req.authUser.email,
      name: req.authUser.name,
      roles: req.authUser.roles
    });
  });

  return router;
};
