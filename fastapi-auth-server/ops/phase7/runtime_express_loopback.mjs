#!/usr/bin/env node
import { stat } from "node:fs/promises";
import net from "node:net";
import { pathToFileURL } from "node:url";

if (process.env.WISEACCT_PHASE7_EXPRESS_LOOPBACK !== "1") {
  throw new Error("explicit Phase 7 loopback acknowledgement is required");
}

const serverPath = process.argv[2];
if (!serverPath || !serverPath.startsWith("/") || !(await stat(serverPath)).isFile()) {
  throw new Error("an absolute built Express server module is required");
}

const originalListen = net.Server.prototype.listen;
net.Server.prototype.listen = function phase7LoopbackListen(...arguments_) {
  const [first, second, ...remaining] = arguments_;
  if (typeof first === "number") {
    if (typeof second === "string") {
      if (second !== "127.0.0.1" && second !== "::1") {
        throw new Error("Phase 7 Express runtime refused a non-loopback listen host");
      }
      return originalListen.call(this, first, second, ...remaining);
    }
    return originalListen.call(this, first, "127.0.0.1", second, ...remaining);
  }
  if (first && typeof first === "object") {
    if (first.host && first.host !== "127.0.0.1" && first.host !== "::1") {
      throw new Error("Phase 7 Express runtime refused a non-loopback listen host");
    }
    return originalListen.call(this, { ...first, host: first.host ?? "127.0.0.1" }, second, ...remaining);
  }
  throw new Error("Phase 7 Express runtime requires an explicit TCP port");
};

await import(pathToFileURL(serverPath).href);
