import { beforeEach, describe, expect, it, vi } from "vitest";

process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
process.env["JWT_REFRESH_SECRET"] = "test-refresh-secret-long";
process.env["JWT_ISSUER"] = "https://auth.temis.co.kr";
process.env["JWT_AUDIENCE"] = "temis";
process.env["REDIS_URL"] = "redis://localhost:6379";
process.env["FRONTEND_REDIRECT_URL"] = "http://localhost:3000/auth/callback";
process.env["OAUTH_ENABLED_PROVIDERS"] = "google";
process.env["GOOGLE_CLIENT_ID"] = "google";
process.env["GOOGLE_CLIENT_SECRET"] = "google-secret";
process.env["GOOGLE_REDIRECT_URI"] = "http://localhost:4000/auth/google/callback";
process.env["NAVER_CLIENT_ID"] = "";
process.env["NAVER_CLIENT_SECRET"] = "";
process.env["NAVER_REDIRECT_URI"] = "http://localhost:4000/auth/naver/callback";
process.env["KAKAO_CLIENT_ID"] = "";
process.env["KAKAO_CLIENT_SECRET"] = "";
process.env["KAKAO_REDIRECT_URI"] = "http://localhost:4000/auth/kakao/callback";

const createOAuthState = vi.fn();

vi.mock("./oauth-state.store.js", () => ({
  oauthStateStore: {
    create: createOAuthState,
    consume: vi.fn()
  }
}));

describe("disabled OAuth provider", () => {
  beforeEach(() => {
    vi.resetModules();
    createOAuthState.mockReset();
  });

  it("Given only Google OAuth is enabled When Naver authorization starts Then it is rejected before state creation", async () => {
    const { getAuthorizationUrl } = await import("./oauth.service.js");

    await expect(getAuthorizationUrl("naver")).rejects.toMatchObject({
      statusCode: 404,
      code: "OAUTH_PROVIDER_DISABLED"
    });
    expect(createOAuthState).not.toHaveBeenCalled();
  });
});
