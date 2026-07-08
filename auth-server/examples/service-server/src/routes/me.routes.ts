import { Router } from "express";
import { requireRole } from "../middlewares/requireRole.js";
import { verifyAccessToken } from "../middlewares/verifyAccessToken.js";

export type ServiceServerAuthConfig = {
  readonly issuer: string;
  readonly audience: string;
  readonly accessSecret: string;
};

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
