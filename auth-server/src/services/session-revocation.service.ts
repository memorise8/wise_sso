import { HttpError } from "../utils/httpError.js";

export type RevokeAllRefreshTokensInput = {
  readonly userId: string;
  readonly revokedAt: Date;
};

export type RevokeAllRefreshTokensResult = {
  readonly revokedCount: number;
};

export type RefreshTokenRevocationStore = {
  readonly revokeAllRefreshTokensForUser: (input: RevokeAllRefreshTokensInput) => Promise<number>;
};

const assertUserId = (userId: string): void => {
  if (userId.trim() === "") {
    throw new HttpError(400, "INVALID_USER_ID", "User id is required");
  }
};

export const revokeAllRefreshTokensForUser = async (
  store: RefreshTokenRevocationStore,
  input: RevokeAllRefreshTokensInput
): Promise<RevokeAllRefreshTokensResult> => {
  assertUserId(input.userId);
  return {
    revokedCount: await store.revokeAllRefreshTokensForUser(input)
  };
};
