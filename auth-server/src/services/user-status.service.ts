import type { CurrentUser } from "./user.service.js";
import { HttpError } from "../utils/httpError.js";

export const userStatuses = {
  pendingEmailVerification: "PENDING_EMAIL_VERIFICATION",
  active: "ACTIVE",
  suspended: "SUSPENDED",
  deleted: "DELETED"
} as const;

export type UserStatusValue = typeof userStatuses[keyof typeof userStatuses];

export type CurrentUserWithStatus = CurrentUser & {
  readonly status: UserStatusValue;
};

export type ActiveUserTokenIssueStore = {
  readonly getCurrentUserWithStatus: (userId: string) => Promise<CurrentUserWithStatus | null>;
};

export const parseUserStatusValue = (status: string): UserStatusValue => {
  switch (status) {
    case userStatuses.pendingEmailVerification:
    case userStatuses.active:
    case userStatuses.suspended:
    case userStatuses.deleted:
      return status;
    default:
      throw new HttpError(400, "INVALID_USER_STATUS", "Unsupported user status");
  }
};

export const assertActiveUserForTokenIssue = async (
  store: ActiveUserTokenIssueStore,
  userId: string
): Promise<CurrentUserWithStatus> => {
  const user = await store.getCurrentUserWithStatus(userId);
  if (!user) {
    throw new HttpError(401, "UNAUTHORIZED", "Authentication is required");
  }

  if (user.status !== userStatuses.active) {
    throw new HttpError(401, "UNAUTHORIZED", "Authentication is required");
  }

  return user;
};
