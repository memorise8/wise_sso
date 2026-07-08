import ky from "ky";
import { z } from "zod";
import { env } from "../config/env.js";
import { HttpError } from "../utils/httpError.js";
import { oauthStateStore } from "./oauth-state.store.js";
import { issueTokenPair } from "./token.service.js";
import { findOrCreateUserBySocialProfile } from "./user.service.js";
import type { OAuthProfile, Provider } from "./user.service.js";

type ProviderConfig = {
  readonly authorizeEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly scope: string;
};

type LoginResult = {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly userId: string;
};

const providerConfigs: Record<Provider, ProviderConfig> = {
  google: {
    authorizeEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    userInfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
    clientId: env.GOOGLE_CLIENT_ID,
    clientSecret: env.GOOGLE_CLIENT_SECRET,
    redirectUri: env.GOOGLE_REDIRECT_URI,
    scope: "openid email profile"
  },
  naver: {
    authorizeEndpoint: "https://nid.naver.com/oauth2.0/authorize",
    tokenEndpoint: "https://nid.naver.com/oauth2.0/token",
    userInfoEndpoint: "https://openapi.naver.com/v1/nid/me",
    clientId: env.NAVER_CLIENT_ID,
    clientSecret: env.NAVER_CLIENT_SECRET,
    redirectUri: env.NAVER_REDIRECT_URI,
    scope: "email profile"
  },
  kakao: {
    authorizeEndpoint: "https://kauth.kakao.com/oauth/authorize",
    tokenEndpoint: "https://kauth.kakao.com/oauth/token",
    userInfoEndpoint: "https://kapi.kakao.com/v2/user/me",
    clientId: env.KAKAO_CLIENT_ID,
    clientSecret: env.KAKAO_CLIENT_SECRET,
    redirectUri: env.KAKAO_REDIRECT_URI,
    scope: "profile_nickname profile_image account_email"
  }
};

const tokenResponseSchema = z.object({
  access_token: z.string().min(1)
});

const googleUserSchema = z.object({
  sub: z.string().min(1),
  email: z.string().email().optional(),
  name: z.string().optional(),
  picture: z.string().url().optional()
});

const naverUserSchema = z.object({
  response: z.object({
    id: z.string().min(1),
    email: z.string().email().optional(),
    name: z.string().optional(),
    profile_image: z.string().url().optional()
  })
});

const kakaoUserSchema = z.object({
  id: z.union([z.string(), z.number()]),
  kakao_account: z.object({
    email: z.string().email().optional(),
    profile: z.object({
      nickname: z.string().optional(),
      profile_image_url: z.string().url().optional()
    }).optional()
  }).optional()
});

export const getAuthorizationUrl = (provider: Provider): string => {
  const config = providerConfigs[provider];
  const state = oauthStateStore.create(provider);
  const authorizationUrl = new URL(config.authorizeEndpoint);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("client_id", config.clientId);
  authorizationUrl.searchParams.set("redirect_uri", config.redirectUri);
  authorizationUrl.searchParams.set("scope", config.scope);
  authorizationUrl.searchParams.set("state", state);
  return authorizationUrl.toString();
};

const requestProviderAccessToken = async (provider: Provider, code: string): Promise<string> => {
  const config = providerConfigs[provider];
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: config.redirectUri,
    code
  });

  const tokenResponse = await ky.post(config.tokenEndpoint, {
    body,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    timeout: 10_000
  }).json<unknown>();

  return tokenResponseSchema.parse(tokenResponse).access_token;
};

const requestProviderUser = async (provider: Provider, accessToken: string): Promise<unknown> => {
  const config = providerConfigs[provider];
  return ky.get(config.userInfoEndpoint, {
    headers: { authorization: `Bearer ${accessToken}` },
    timeout: 10_000
  }).json<unknown>();
};

const normalizeProfile = (provider: Provider, rawUser: unknown): OAuthProfile => {
  switch (provider) {
    case "google": {
      const user = googleUserSchema.parse(rawUser);
      return {
        provider,
        providerUserId: user.sub,
        email: user.email ?? null,
        name: user.name ?? null,
        profileUrl: user.picture ?? null
      };
    }
    case "naver": {
      const user = naverUserSchema.parse(rawUser).response;
      return {
        provider,
        providerUserId: user.id,
        email: user.email ?? null,
        name: user.name ?? null,
        profileUrl: user.profile_image ?? null
      };
    }
    case "kakao": {
      const user = kakaoUserSchema.parse(rawUser);
      return {
        provider,
        providerUserId: String(user.id),
        email: user.kakao_account?.email ?? null,
        name: user.kakao_account?.profile?.nickname ?? null,
        profileUrl: user.kakao_account?.profile?.profile_image_url ?? null
      };
    }
  }
};

export const handleOAuthCallback = async (provider: Provider, code: string, state: string): Promise<LoginResult> => {
  if (!code) {
    throw new HttpError(400, "MISSING_AUTHORIZATION_CODE", "Authorization code is required");
  }

  if (!oauthStateStore.consume(provider, state)) {
    throw new HttpError(400, "INVALID_OAUTH_STATE", "Invalid OAuth state");
  }

  const providerAccessToken = await requestProviderAccessToken(provider, code);
  const providerUser = await requestProviderUser(provider, providerAccessToken);
  const profile = normalizeProfile(provider, providerUser);
  const user = await findOrCreateUserBySocialProfile(profile);
  return {
    ...await issueTokenPair(user.id),
    userId: user.id
  };
};
