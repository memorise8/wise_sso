export type ProviderName = "google" | "naver" | "kakao";
export type ProviderOutcome =
  | "success"
  | "timeout"
  | "malformed-json"
  | "redirect"
  | "invalid-payload";

export type ProviderScenario = {
  provider: ProviderName;
  issuer: string;
  code: string;
  accessToken: string;
  profile: unknown;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  tokenOutcome: ProviderOutcome;
  userOutcome: ProviderOutcome;
};

export type ProviderTransportConfig = {
  scenarios: ProviderScenario[];
};

export type ProviderRequestRecord = Readonly<{
  provider: ProviderName;
  operation: "token" | "user-info";
  method: string;
  url: string;
}>;

export type PrivateProviderRecordWriter = Readonly<{
  emit(provider: ProviderName, operation: "token" | "user-info"): void;
  close(): void;
}>;

export const endpoints: Readonly<Record<ProviderName, Readonly<{
  issuer: string;
  token: string;
  userInfo: string;
}>>>;

export function validateConfig(value: unknown): ProviderTransportConfig;
export function readConfig(file: string): ProviderTransportConfig;
export function readBoundedConfigBytes(descriptor: number): Buffer;
export function createProviderRecordWriterFromEnvironment(): PrivateProviderRecordWriter | null;
export function installProviderTransport(
  config: ProviderTransportConfig,
  recorder?: PrivateProviderRecordWriter | null
): ProviderRequestRecord[];
