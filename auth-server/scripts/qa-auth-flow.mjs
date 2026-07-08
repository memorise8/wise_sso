#!/usr/bin/env node
import { spawn } from "node:child_process";

const command = process.platform === "win32" ? "npm.cmd" : "npm";
const args = ["test", "--", "src/routes/auth.flow.routes.test.ts"];

const child = spawn(command, args, {
  cwd: new URL("..", import.meta.url),
  stdio: "inherit",
  env: {
    ...process.env,
    NODE_ENV: "test"
  }
});

child.on("exit", (code, signal) => {
  if (signal) {
    console.error(`auth flow QA stopped by ${signal}`);
    process.exit(1);
  }

  process.exit(code ?? 1);
});
