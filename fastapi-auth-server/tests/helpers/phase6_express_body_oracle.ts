import { request } from "node:http";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";

import { createApp } from "../../../auth-server/src/app.js";

type Probe = {
  readonly bodyBase64: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly method?: string;
  readonly path?: string;
};

type Result = {
  readonly body: string;
  readonly status: number;
};

const main = async (): Promise<void> => {
  const probes = JSON.parse(readFileSync(0, "utf8")) as readonly Probe[];
  const server = createApp().listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;

  const run = async (probe: Probe): Promise<Result> => {
    const body = Buffer.from(probe.bodyBase64, "base64");
    const headers = { ...probe.headers };
    if (!("content-length" in headers)) {
      headers["content-length"] = String(body.length);
    }
    return await new Promise<Result>((resolve, reject) => {
      const outgoing = request(
        {
          host: "127.0.0.1",
          port: address.port,
          method: probe.method ?? "PATCH",
          path: probe.path ?? "/admin/users/target/status",
          headers,
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => chunks.push(chunk));
          response.on("end", () => {
            resolve({
              body: Buffer.concat(chunks).toString("utf8"),
              status: response.statusCode ?? 0,
            });
          });
        },
      );
      outgoing.once("error", reject);
      outgoing.end(body);
    });
  };

  try {
    const results: Result[] = [];
    for (const probe of probes) {
      results.push(await run(probe));
    }
    process.stdout.write(JSON.stringify(results));
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
};

void main();
