import { z } from "zod";

const temisClientPolicy = {
  clientId: "temis",
  audience: "temis",
  allowedRedirectUris: ["https://financenow.kr/auth/callback", "https://temis.me/auth/callback", "https://ti.temis.me/auth/callback"],
  allowedOrigins: ["https://financenow.kr"],
  defaultRole: { serviceKey: "temis", name: "user" }
} as const;

const allowedTemisDefaultRoleNames = new Set(["pending", "user"]);

const originSchema = z.string().min(1).transform((value, context) => {
  try {
    const origin = new URL(value).origin;
    if (origin !== value) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "allowedOrigins entries must include scheme, host, and optional port only"
      });
      return z.NEVER;
    }
    return origin;
  } catch (error) {
    if (error instanceof TypeError) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "allowedOrigins entries must be valid URLs"
      });
      return z.NEVER;
    }
    throw error;
  }
});

const redirectUriSchema = z.string().min(1).transform((value, context) => {
  try {
    return new URL(value).toString();
  } catch (error) {
    if (error instanceof TypeError) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "allowedRedirectUris entries must be valid URLs"
      });
      return z.NEVER;
    }
    throw error;
  }
});

const relyingClientPolicySchema = z.object({
  clientId: z.string().min(1),
  audience: z.string().min(1),
  allowedRedirectUris: z.array(redirectUriSchema).min(1),
  allowedOrigins: z.array(originSchema).min(1),
  allowLocalhostInProduction: z.boolean().optional(),
  defaultRole: z.object({
    serviceKey: z.string().min(1),
    name: z.string().min(1)
  }).strict()
}).strict();

const relyingClientPoliciesSchema = z.array(relyingClientPolicySchema).min(1).superRefine((clients, context) => {
  const firstClient = clients[0];
  if (
    !firstClient ||
    firstClient.clientId !== temisClientPolicy.clientId ||
    firstClient.audience !== temisClientPolicy.audience ||
    firstClient.allowedRedirectUris.length !== temisClientPolicy.allowedRedirectUris.length ||
    firstClient.allowedRedirectUris.some((redirectUri, index) => redirectUri !== temisClientPolicy.allowedRedirectUris[index]) ||
    firstClient.allowedOrigins.length !== temisClientPolicy.allowedOrigins.length ||
    firstClient.allowedOrigins.some((origin, index) => origin !== temisClientPolicy.allowedOrigins[index]) ||
    firstClient.allowLocalhostInProduction !== undefined
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "AUTH_CLIENTS_JSON first client must be the required TEMIS relying client policy",
      path: [0]
    });
  }

  if (
    firstClient &&
    (
      firstClient.defaultRole.serviceKey !== temisClientPolicy.defaultRole.serviceKey ||
      !allowedTemisDefaultRoleNames.has(firstClient.defaultRole.name)
    )
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "AUTH_CLIENTS_JSON first TEMIS client defaultRole must be temis:pending or temis:user",
      path: [0, "defaultRole"]
    });
  }

  const clientIds = new Set<string>();
  for (const [index, client] of clients.entries()) {
    const role = client.defaultRole;
    const temisUserAllowed = client.clientId === "temis" && role.serviceKey === "temis" && role.name === "user";
    if (role.name !== "pending" && !temisUserAllowed) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AUTH_CLIENTS_JSON defaultRole must be least-privilege pending unless explicitly allowed as temis:user",
        path: [index, "defaultRole"]
      });
    }

    if (clientIds.has(client.clientId)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: `AUTH_CLIENTS_JSON contains duplicate clientId: ${client.clientId}`,
        path: [index, "clientId"]
      });
    }
    clientIds.add(client.clientId);
  }
});

export const authClientsJsonSchema = z.string().min(1).transform((value, context) => {
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(value);
  } catch (error) {
    if (error instanceof SyntaxError) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AUTH_CLIENTS_JSON must be valid JSON"
      });
      return z.NEVER;
    }
    throw error;
  }

  const parsedClients = relyingClientPoliciesSchema.safeParse(parsedJson);
  if (!parsedClients.success) {
    for (const issue of parsedClients.error.issues) {
      context.addIssue(issue);
    }
    return z.NEVER;
  }

  return parsedClients.data;
});

export type RelyingClientPolicy = z.infer<typeof relyingClientPolicySchema>;

export type ClientPolicyService = {
  readonly findClient: (clientId: string) => RelyingClientPolicy | null;
  readonly isRedirectUriAllowed: (clientId: string, redirectUri: string) => boolean;
  readonly isOriginAllowed: (clientId: string, origin: string) => boolean;
};

const hasLocalhostUrl = (values: readonly string[]): boolean => {
  return values.some((value) => {
    const hostname = new URL(value).hostname;
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  });
};

export const rejectProductionLocalhostClients = (
  clients: readonly RelyingClientPolicy[],
  nodeEnv: "development" | "test" | "production",
  context: z.RefinementCtx
): void => {
  if (nodeEnv !== "production") {
    return;
  }

  for (let index = 0; index < clients.length; index += 1) {
    const client = clients[index];
    if (!client) {
      continue;
    }
    if (
      client.allowLocalhostInProduction !== true &&
      (hasLocalhostUrl(client.allowedRedirectUris) || hasLocalhostUrl(client.allowedOrigins))
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "AUTH_CLIENTS_JSON localhost clients are forbidden in production unless allowLocalhostInProduction is true",
        path: ["AUTH_CLIENTS_JSON", index]
      });
    }
  }
};

export const createClientPolicyService = (clients: readonly RelyingClientPolicy[]): ClientPolicyService => {
  const clientsById = new Map(clients.map((client) => [client.clientId, client]));

  return {
    findClient(clientId) {
      return clientsById.get(clientId) ?? null;
    },
    isRedirectUriAllowed(clientId, redirectUri) {
      const client = clientsById.get(clientId);
      return client?.allowedRedirectUris.includes(redirectUri) ?? false;
    },
    isOriginAllowed(clientId, origin) {
      const client = clientsById.get(clientId);
      return client?.allowedOrigins.includes(origin) ?? false;
    }
  };
};
