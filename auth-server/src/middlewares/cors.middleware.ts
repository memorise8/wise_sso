import type { CorsOptions } from "cors";
import { env } from "../config/env.js";

const allowedOrigins = new Set(env.CORS_ALLOWED_ORIGINS);

export const corsOptions: CorsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      callback(null, origin);
      return;
    }

    callback(null, false);
  }
};
