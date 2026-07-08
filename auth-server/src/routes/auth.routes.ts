import { Router } from "express";
import {
  confirmEmailVerificationWithToken,
  confirmPasswordResetWithToken,
  loginWithCredentials,
  logout,
  refreshTokens,
  registerWithCredentials,
  requestEmailVerificationEmail,
  requestPasswordResetEmail
} from "../controllers/auth.controller.js";
import {
  completeOAuthLogin,
  exchangeAuthHandoffCode,
  startOAuthLogin
} from "../controllers/oauth.controller.js";
import { env } from "../config/env.js";
import { createRateLimitMiddleware } from "../middlewares/rateLimit.middleware.js";

export const authRouter = Router();
const authRateLimit = createRateLimitMiddleware({
  windowMs: env.AUTH_RATE_LIMIT_WINDOW_SECONDS * 1000,
  maxRequests: env.AUTH_RATE_LIMIT_MAX_REQUESTS,
  message: "Too many authentication requests"
});

authRouter.get("/google", startOAuthLogin("google"));
authRouter.get("/naver", startOAuthLogin("naver"));
authRouter.get("/kakao", startOAuthLogin("kakao"));

authRouter.get("/google/callback", completeOAuthLogin("google"));
authRouter.get("/naver/callback", completeOAuthLogin("naver"));
authRouter.get("/kakao/callback", completeOAuthLogin("kakao"));

authRouter.post("/register", authRateLimit, registerWithCredentials);
authRouter.post("/login", authRateLimit, loginWithCredentials);
authRouter.post("/exchange", authRateLimit, exchangeAuthHandoffCode);
authRouter.post("/refresh", authRateLimit, refreshTokens);
authRouter.post("/logout", authRateLimit, logout);
authRouter.post("/password-reset/request", authRateLimit, requestPasswordResetEmail);
authRouter.post("/password-reset/confirm", authRateLimit, confirmPasswordResetWithToken);
authRouter.post("/email-verification/request", authRateLimit, requestEmailVerificationEmail);
authRouter.post("/email-verification/confirm", authRateLimit, confirmEmailVerificationWithToken);
