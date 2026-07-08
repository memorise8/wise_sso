import { afterEach, describe, expect, it } from "vitest";

const originalSecret = process.env["AUTH_JWT_ACCESS_SECRET"];

describe("service app config", () => {
  afterEach(() => {
    if (originalSecret) {
      process.env["AUTH_JWT_ACCESS_SECRET"] = originalSecret;
      return;
    }
    delete process.env["AUTH_JWT_ACCESS_SECRET"];
  });

  it("Given missing JWT access secret When service app is created Then startup fails closed", async () => {
    delete process.env["AUTH_JWT_ACCESS_SECRET"];
    const { createServiceApp } = await import("./app.js");

    expect(() => createServiceApp()).toThrow(/AUTH_JWT_ACCESS_SECRET/);
  });

  it("Given placeholder JWT access secret When service app is created Then startup fails closed", async () => {
    process.env["AUTH_JWT_ACCESS_SECRET"] = "replace-access-secret";
    const { createServiceApp } = await import("./app.js");

    expect(() => createServiceApp()).toThrow(/AUTH_JWT_ACCESS_SECRET/);
  });
});
