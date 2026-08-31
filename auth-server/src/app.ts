import cors from "cors";
import express from "express";
import type { Express, Response } from "express";
import helmet from "helmet";
import path from "node:path";
import { ZodError } from "zod";
import { corsOptions } from "./middlewares/cors.middleware.js";
import { adminRouter } from "./routes/admin.routes.js";
import { authRouter } from "./routes/auth.routes.js";
import { userRouter } from "./routes/user.routes.js";
import {
  getJsonWebKeySet,
  getOpenIdConfiguration,
  publicMetadataCacheControl
} from "./services/jwks-discovery.service.js";
import { checkPostgresReadiness } from "./services/readiness.service.js";
import type { ReadinessCheck } from "./services/readiness.service.js";
import { isHttpError } from "./utils/httpError.js";

const publicDir = path.resolve(process.cwd(), "public");
const authPortalFile = path.join(publicDir, "auth-portal.html");
const adminDashboardFile = path.join(publicDir, "admin-dashboard.html");
const authPortalRoutes = ["/", "/login", "/signup", "/auth/callback", "/password-reset", "/verify-email"] as const;

type AppDependencies = {
  readonly readinessCheck?: ReadinessCheck;
};

const sendReadinessUnavailable = (response: Response): void => {
  response.status(503).json({ status: "unavailable" });
};

export const createApp = (dependencies: AppDependencies = {}): Express => {
  const app = express();
  const readinessCheck = dependencies.readinessCheck ?? checkPostgresReadiness;

  app.set("trust proxy", 1);
  app.use(helmet());
  app.use(cors(corsOptions));
  app.use(express.json());
  app.use("/assets", express.static(path.join(publicDir, "assets"), {
    etag: true,
    immutable: true,
    maxAge: "1h"
  }));

  app.get("/healthz", (_request, response) => {
    response.status(200).json({ status: "ok" });
  });

  app.get("/readyz", async (_request, response) => {
    const isReady = await readinessCheck().catch(() => false);
    if (!isReady) {
      sendReadinessUnavailable(response);
      return;
    }

    response.status(200).json({ status: "ok" });
  });

  app.get("/.well-known/jwks.json", (_request, response) => {
    response.set("cache-control", publicMetadataCacheControl).status(200).json(getJsonWebKeySet());
  });

  app.get("/.well-known/openid-configuration", (_request, response) => {
    response.set("cache-control", publicMetadataCacheControl).status(200).json(getOpenIdConfiguration());
  });

  app.get(["/admin/dashboard", "/manage/dashboard"], (_request, response) => {
    response.sendFile(adminDashboardFile);
  });

  app.use("/auth", authRouter);
  app.use("/users", userRouter);
  app.use("/admin", adminRouter);
  app.use("/manage-api", adminRouter);

  for (const route of authPortalRoutes) {
    app.get(route, (_request, response) => {
      response.sendFile(authPortalFile);
    });
  }

  app.use((_request, response) => {
    response.status(404).json({
      error: {
        code: "NOT_FOUND",
        message: "Route not found"
      }
    });
  });

  app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
    if (isHttpError(error)) {
      response.status(error.statusCode).json({
        error: {
          code: error.code,
          message: error.message
        }
      });
      return;
    }

    if (error instanceof ZodError) {
      response.status(400).json({
        error: {
          code: "INVALID_REQUEST",
          message: "Invalid request"
        }
      });
      return;
    }

    response.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Internal server error"
      }
    });
  });

  return app;
};

export const app = createApp();
