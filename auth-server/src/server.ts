import { env } from "./config/env.js";
import { app } from "./app.js";
import { connectRedis } from "./services/redis.client.js";

const start = async (): Promise<void> => {
  await connectRedis();
  app.listen(env.PORT, () => {
    console.log(`Auth server listening on port ${env.PORT}`);
  });
};

void start();
