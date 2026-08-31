import { Router } from "express";
import type { Request, RequestHandler } from "express";
import { z } from "zod";
import { authMiddleware } from "../middlewares/auth.middleware.js";
import { findAdminRoleById, listAdminUsers } from "../services/admin-directory.service.js";
import type { AdminUserListInput } from "../services/admin-directory.service.js";
import { createAdminUserService } from "../services/admin-user.service.js";
import { adminUserMutationStore } from "../services/admin-user.store.js";
import {
  auditEventTypes,
  listAdminAuditLogs,
  recordAuthAuditEvent
} from "../services/audit.service.js";
import type { AuditLogListInput } from "../services/audit.service.js";
import { auditLogStore } from "../services/audit.store.js";
import { getCurrentUserWithStatus } from "../services/user.service.js";
import { userStatuses } from "../services/user-status.service.js";
import { HttpError } from "../utils/httpError.js";

export const adminRouter = Router();

const adminUserService = createAdminUserService(adminUserMutationStore);

const userParamsSchema = z.object({
  id: z.string().min(1)
});

const roleParamsSchema = userParamsSchema.extend({
  roleId: z.string().min(1)
});

const listUsersQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  status: z.enum([
    userStatuses.pendingEmailVerification,
    userStatuses.active,
    userStatuses.suspended,
    userStatuses.deleted
  ]).optional(),
  email: z.string().trim().min(1).optional(),
  role: z.string().trim().min(1).optional()
});

const auditDateQueryParam = z.string().trim().min(1).refine((value) => !Number.isNaN(Date.parse(value))).transform((value) => new Date(value));

const auditLogsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  createdAtFrom: auditDateQueryParam.optional(),
  createdAtTo: auditDateQueryParam.optional(),
  eventType: z.string().trim().min(1).optional(),
  outcome: z.enum(["request", "success", "failure"]).optional(),
  userId: z.string().trim().min(1).optional(),
  actorUserId: z.string().trim().min(1).optional(),
  targetUserId: z.string().trim().min(1).optional(),
  reasonCode: z.string().trim().min(1).optional()
});

const statusBodySchema = z.object({
  status: z.enum([
    userStatuses.pendingEmailVerification,
    userStatuses.active,
    userStatuses.suspended,
    userStatuses.deleted
  ]),
  reasonCode: z.string().trim().min(1).default("ADMIN_STATUS_CHANGE")
});

const roleBodySchema = z.object({
  serviceKey: z.string().trim().min(1),
  name: z.string().trim().min(1),
  reasonCode: z.string().trim().min(1).default("ADMIN_ROLE_ASSIGN")
});

const reasonBodySchema = z.object({
  reasonCode: z.string().trim().min(1)
});

const isTemisAdmin = (user: Awaited<ReturnType<typeof getCurrentUserWithStatus>>): boolean =>
  user?.status === userStatuses.active &&
  user.roles.some((role) => role.serviceKey === "temis" && role.name === "admin");

const actorUserId = (request: Request): string => {
  if (!request.userId) {
    throw new HttpError(401, "UNAUTHORIZED", "Authentication is required");
  }
  return request.userId;
};

const requireDbBackedAdmin: RequestHandler = (request, _response, next) => {
  void (async () => {
    const userId = actorUserId(request);
    const user = await getCurrentUserWithStatus(userId);
    if (!isTemisAdmin(user)) {
      await recordAuthAuditEvent(auditLogStore, {
        eventType: auditEventTypes.adminAuthorizationFailure,
        outcome: "failure",
        userId,
        actorUserId: userId,
        targetUserId: null,
        reasonCode: "FORBIDDEN",
        detailsJson: {
          route: `${request.baseUrl}${request.path}`,
          method: request.method
        }
      });
      throw new HttpError(403, "FORBIDDEN", "Admin role is required");
    }
    next();
  })().catch(next);
};

const adminOnly = [authMiddleware, requireDbBackedAdmin] as const;

const assertSelfStatusChangeAllowed = (actorId: string, targetId: string, status: string): void => {
  if (
    actorId === targetId &&
    (status === userStatuses.suspended || status === userStatuses.deleted)
  ) {
    throw new HttpError(403, "FORBIDDEN", "Admins cannot suspend or delete their own account");
  }
};

const assertSelfAdminRoleRemovalAllowed = (
  actorId: string,
  targetId: string,
  role: { readonly serviceKey: string; readonly name: string }
): void => {
  if (actorId === targetId && role.serviceKey === "temis" && role.name === "admin") {
    throw new HttpError(403, "FORBIDDEN", "Admins cannot remove their own admin role");
  }
};

const assertSelfSessionRevokeAllowed = (actorId: string, targetId: string): void => {
  if (actorId === targetId) {
    throw new HttpError(403, "FORBIDDEN", "Admins cannot revoke their own sessions");
  }
};

const adminUserListInput = (query: z.infer<typeof listUsersQuerySchema>): AdminUserListInput => ({
  page: query.page,
  pageSize: query.pageSize,
  ...(query.status ? { status: query.status } : {}),
  ...(query.email ? { email: query.email } : {}),
  ...(query.role ? { role: query.role } : {})
});

const auditLogListInput = (query: z.infer<typeof auditLogsQuerySchema>): AuditLogListInput => ({
  page: query.page,
  pageSize: query.pageSize,
  ...(query.createdAtFrom ? { createdAtFrom: query.createdAtFrom } : {}),
  ...(query.createdAtTo ? { createdAtTo: query.createdAtTo } : {}),
  ...(query.eventType ? { eventType: query.eventType } : {}),
  ...(query.outcome ? { outcome: query.outcome } : {}),
  ...(query.userId ? { userId: query.userId } : {}),
  ...(query.actorUserId ? { actorUserId: query.actorUserId } : {}),
  ...(query.targetUserId ? { targetUserId: query.targetUserId } : {}),
  ...(query.reasonCode ? { reasonCode: query.reasonCode } : {})
});

adminRouter.get("/users", ...adminOnly, (request, response, next) => {
  void (async () => {
    const query = listUsersQuerySchema.parse(request.query);
    response.json(await listAdminUsers(adminUserListInput(query)));
  })().catch(next);
});

adminRouter.get("/audit-logs", ...adminOnly, (request, response, next) => {
  void (async () => {
    const query = auditLogsQuerySchema.parse(request.query);
    response.json(await listAdminAuditLogs(auditLogStore, auditLogListInput(query)));
  })().catch(next);
});

adminRouter.patch("/users/:id/status", ...adminOnly, (request, response, next) => {
  void (async () => {
    const actorId = actorUserId(request);
    const params = userParamsSchema.parse(request.params);
    const body = statusBodySchema.parse(request.body);
    assertSelfStatusChangeAllowed(actorId, params.id, body.status);

    response.json(await adminUserService.setUserStatus({
      actorUserId: actorId,
      targetUserId: params.id,
      status: body.status,
      reasonCode: body.reasonCode,
      details: { route: "PATCH /admin/users/:id/status" }
    }));
  })().catch(next);
});

adminRouter.post("/users/:id/roles", ...adminOnly, (request, response, next) => {
  void (async () => {
    const actorId = actorUserId(request);
    const params = userParamsSchema.parse(request.params);
    const body = roleBodySchema.parse(request.body);

    response.json(await adminUserService.assignRole({
      actorUserId: actorId,
      targetUserId: params.id,
      serviceKey: body.serviceKey,
      name: body.name,
      reasonCode: body.reasonCode,
      details: { route: "POST /admin/users/:id/roles" }
    }));
  })().catch(next);
});

adminRouter.delete("/users/:id/roles/:roleId", ...adminOnly, (request, response, next) => {
  void (async () => {
    const actorId = actorUserId(request);
    const params = roleParamsSchema.parse(request.params);
    const body = reasonBodySchema.parse(request.body);
    const role = await findAdminRoleById(params.roleId);
    if (!role) {
      throw new HttpError(404, "ROLE_NOT_FOUND", "Role not found");
    }
    assertSelfAdminRoleRemovalAllowed(actorId, params.id, role);

    response.json(await adminUserService.removeRole({
      actorUserId: actorId,
      targetUserId: params.id,
      serviceKey: role.serviceKey,
      name: role.name,
      reasonCode: body.reasonCode,
      details: { roleId: params.roleId, route: "DELETE /admin/users/:id/roles/:roleId" }
    }));
  })().catch(next);
});

adminRouter.post("/users/:id/revoke-sessions", ...adminOnly, (request, response, next) => {
  void (async () => {
    const actorId = actorUserId(request);
    const params = userParamsSchema.parse(request.params);
    const body = reasonBodySchema.parse(request.body);
    assertSelfSessionRevokeAllowed(actorId, params.id);

    response.json(await adminUserService.revokeSessions({
      actorUserId: actorId,
      targetUserId: params.id,
      reasonCode: body.reasonCode,
      details: { route: "POST /admin/users/:id/revoke-sessions" }
    }));
  })().catch(next);
});
