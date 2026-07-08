import type { RequestHandler } from "express";

export const requireRole = (serviceKey: string, roleName: string): RequestHandler => (req, res, next) => {
  const hasRole = req.authUser.roles.some((role) => role.serviceKey === serviceKey && role.name === roleName);

  if (!hasRole) {
    res.status(403).json({ error: { code: "FORBIDDEN", message: "Required role is missing" } });
    return;
  }

  next();
};
