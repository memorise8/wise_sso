import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
  createRequestInstrumentationMiddleware,
  structuredRequestInstrumentation,
  type RequestObservation
} from "./request-instrumentation.service.js";

describe("request instrumentation", () => {
  it("records bounded comparison dimensions and excludes query values and route identifiers", async () => {
    const observations: RequestObservation[] = [];
    const app = express();
    app.use(createRequestInstrumentationMiddleware({
      observeRequest: (observation) => observations.push(observation)
    }));
    app.patch("/admin/users/:id/status", (_request, response) => response.status(204).end());

    await request(app)
      .patch("/admin/users/private-user-id/status?token=private-oauth-token")
      .send({ password: "private-password" })
      .expect(204);

    expect(observations).toHaveLength(1);
    expect(observations[0]).toMatchObject({
      backend: "express",
      version: "1.0.0",
      method: "PATCH",
      route: "/admin/users/:id/status",
      outcome: "2xx"
    });
    expect(observations[0]?.latencyMs).toBeGreaterThanOrEqual(0);
    expect(JSON.stringify(observations)).not.toContain("private-user-id");
    expect(JSON.stringify(observations)).not.toContain("private-oauth-token");
    expect(JSON.stringify(observations)).not.toContain("private-password");
  });

  it("uses finite fallback labels for unknown routes and methods", async () => {
    const observations: RequestObservation[] = [];
    const app = express();
    app.use(createRequestInstrumentationMiddleware({
      observeRequest: (observation) => observations.push(observation)
    }));
    app.use((_request, response) => response.status(404).end());

    await request(app).get("/random/private-value").expect(404);

    expect(observations[0]).toMatchObject({ method: "GET", route: "unmatched", outcome: "4xx" });
  });

  it("does not affect the response when the observer throws synchronously", async () => {
    const app = express();
    app.use(createRequestInstrumentationMiddleware({
      observeRequest: () => {
        throw new Error("collector unavailable");
      }
    }));
    app.get("/healthz", (_request, response) => response.status(200).json({ status: "ok" }));

    const response = await request(app).get("/healthz");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("consumes an asynchronous observer rejection without affecting the response", async () => {
    const app = express();
    const observeRequest = vi.fn(async () => {
      throw new Error("async collector unavailable");
    });
    app.use(createRequestInstrumentationMiddleware({ observeRequest }));
    app.get("/healthz", (_request, response) => response.status(200).json({ status: "ok" }));

    const response = await request(app).get("/healthz");
    await new Promise<void>((resolve) => setImmediate(resolve));

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
    expect(observeRequest).toHaveBeenCalledTimes(1);
  });

  it("emits a machine-readable metric containing only bounded request dimensions", () => {
    const consoleInfo = vi.spyOn(console, "info").mockImplementation(() => undefined);
    const observation: RequestObservation = {
      backend: "express",
      version: "1.0.0",
      method: "GET",
      route: "/healthz",
      outcome: "2xx",
      latencyMs: 1.25
    };

    structuredRequestInstrumentation.observeRequest(observation);

    expect(consoleInfo).toHaveBeenCalledOnce();
    expect(JSON.parse(String(consoleInfo.mock.calls[0]?.[0]))).toEqual({
      metric: "sso_http_request",
      ...observation
    });
    consoleInfo.mockRestore();
  });

  it("records a completed response only once", async () => {
    const observeRequest = vi.fn();
    const app = express();
    app.use(createRequestInstrumentationMiddleware({ observeRequest }));
    app.get("/healthz", (_request, response) => response.status(200).end());

    await request(app).get("/healthz").expect(200);

    expect(observeRequest).toHaveBeenCalledTimes(1);
  });
});
