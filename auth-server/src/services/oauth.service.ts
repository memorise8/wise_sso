import ky from "ky";
import { z } from "zod";
import { env } from "../config/env.js";
import { HttpError } from "../utils/httpError.js";
import { createClientPolicyService } from "./client-policy.service.js";
import { oauthStateStore } from "./oauth-state.store.js";
import type { OAuthStateMetadata } from "./oauth-state.store.js";
import { findOrCreateUserBySocialProfile } from "./user.service.js";
import type { OAuthProfile, Provider } from "./user.service.js";
import { userStatuses } from "./user-status.service.js";

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
  readonly userId: string;
  readonly clientId: string;
  readonly audience: string;
  readonly redirectUri: string;
  readonly callerState: string | null;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
};

export type OAuthLoginStartInput = {
  readonly clientId: string;
  readonly redirectUri?: string;
  readonly callerState?: string;
  readonly codeChallenge?: string;
  readonly codeChallengeMethod?: "S256";
};

const enabledProviders = new Set<Provider>(env.OAUTH_ENABLED_PROVIDERS);
const clientPolicyService = createClientPolicyService(env.AUTH_CLIENTS_JSON);

const requireOAuthSecret = (value: string | undefined, name: string): string => {
  if (!value) {
    throw new HttpError(500, "OAUTH_PROVIDER_MISCONFIGURED", `${name} is not configured`);
  }
  return value;
};

const providerConfigFor = (provider: Provider): ProviderConfig => {
  if (!enabledProviders.has(provider)) {
    throw new HttpError(404, "OAUTH_PROVIDER_DISABLED", "OAuth provider is disabled");
  }

  switch (provider) {
    case "google":
      return {
        authorizeEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenEndpoint: "https://oauth2.googleapis.com/token",
        userInfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
        clientId: requireOAuthSecret(env.GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID"),
        clientSecret: requireOAuthSecret(env.GOOGLE_CLIENT_SECRET, "GOOGLE_CLIENT_SECRET"),
        redirectUri: env.GOOGLE_REDIRECT_URI,
        scope: "openid email profile"
      };
    case "naver":
      return {
        authorizeEndpoint: "https://nid.naver.com/oauth2.0/authorize",
        tokenEndpoint: "https://nid.naver.com/oauth2.0/token",
        userInfoEndpoint: "https://openapi.naver.com/v1/nid/me",
        clientId: requireOAuthSecret(env.NAVER_CLIENT_ID, "NAVER_CLIENT_ID"),
        clientSecret: requireOAuthSecret(env.NAVER_CLIENT_SECRET, "NAVER_CLIENT_SECRET"),
        redirectUri: env.NAVER_REDIRECT_URI,
        scope: "email profile"
      };
    case "kakao":
      return {
        authorizeEndpoint: "https://kauth.kakao.com/oauth/authorize",
        tokenEndpoint: "https://kauth.kakao.com/oauth/token",
        userInfoEndpoint: "https://kapi.kakao.com/v2/user/me",
        clientId: requireOAuthSecret(env.KAKAO_CLIENT_ID, "KAKAO_CLIENT_ID"),
        clientSecret: requireOAuthSecret(env.KAKAO_CLIENT_SECRET, "KAKAO_CLIENT_SECRET"),
        redirectUri: env.KAKAO_REDIRECT_URI,
        scope: "profile_nickname profile_image account_email"
      };
  }
};

const resolveOAuthStateMetadata = (input: OAuthLoginStartInput): OAuthStateMetadata => {
  const client = clientPolicyService.findClient(input.clientId);
  if (!client) {
    throw new HttpError(400, "INVALID_OAUTH_CLIENT", "Invalid OAuth client");
  }

  const defaultRedirectUri = client.allowedRedirectUris[0];
  if (!defaultRedirectUri) {
    throw new HttpError(500, "OAUTH_CLIENT_MISCONFIGURED", "OAuth client is not configured");
  }

  const redirectUri = input.redirectUri ?? defaultRedirectUri;
  if (!clientPolicyService.isRedirectUriAllowed(client.clientId, redirectUri)) {
    throw new HttpError(400, "INVALID_REDIRECT_URI", "Invalid redirect URI");
  }

  return {
    clientId: client.clientId,
    redirectUri,
    callerState: input.callerState ?? null,
    codeChallenge: input.codeChallenge ?? null,
    codeChallengeMethod: input.codeChallengeMethod ?? null
  };
};

const tokenResponseSchema = z.object({
  access_token: z.string().min(1)
});

const googleUserSchema = z.object({
  sub: z.string().min(1),
  email: z.string().email().optional(),
  email_verified: z.boolean().optional(),
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

export const getAuthorizationUrl = async (
  provider: Provider,
  input: OAuthLoginStartInput = { clientId: "temis" }
): Promise<string> => {
  const config = providerConfigFor(provider);
  const metadata = resolveOAuthStateMetadata(input);
  const state = await oauthStateStore.create(provider, metadata);
  const authorizationUrl = new URL(config.authorizeEndpoint);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("client_id", config.clientId);
  authorizationUrl.searchParams.set("redirect_uri", config.redirectUri);
  authorizationUrl.searchParams.set("scope", config.scope);
  authorizationUrl.searchParams.set("state", state);
  return authorizationUrl.toString();
};

const requestProviderAccessToken = async (config: ProviderConfig, code: string): Promise<string> => {
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

const requestProviderUser = async (config: ProviderConfig, accessToken: string): Promise<unknown> => {
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
        emailVerified: user.email_verified === true,
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
        emailVerified: false,
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
        emailVerified: false,
        name: user.kakao_account?.profile?.nickname ?? null,
        profileUrl: user.kakao_account?.profile?.profile_image_url ?? null
      };
    }
  }
};

export const handleOAuthCallback = async (provider: Provider, code: string, state: string): Promise<LoginResult> => {
  const config = providerConfigFor(provider);

  if (!code) {
    throw new HttpError(400, "MISSING_AUTHORIZATION_CODE", "Authorization code is required");
  }

  const metadata = await oauthStateStore.consume(provider, state);
  if (!metadata || !metadata.codeChallenge || metadata.codeChallengeMethod !== "S256") {
    throw new HttpError(400, "INVALID_OAUTH_STATE", "Invalid OAuth state");
  }
  const client = clientPolicyService.findClient(metadata.clientId);
  if (!client) {
    throw new HttpError(400, "INVALID_OAUTH_STATE", "Invalid OAuth state");
  }

  const providerAccessToken = await requestProviderAccessToken(config, code);
  const providerUser = await requestProviderUser(config, providerAccessToken);
  const profile = normalizeProfile(provider, providerUser);
  const user = await findOrCreateUserBySocialProfile(profile, metadata.clientId);
  if (user.status !== userStatuses.active) {
    throw new HttpError(401, "UNAUTHORIZED", "Authentication is required");
  }

  return {
    userId: user.id,
    clientId: metadata.clientId,
    audience: client.audience,
    redirectUri: metadata.redirectUri,
    callerState: metadata.callerState,
    codeChallenge: metadata.codeChallenge,
    codeChallengeMethod: metadata.codeChallengeMethod
  };
};
