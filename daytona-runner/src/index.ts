import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { Daytona } from "@daytonaio/sdk";
import { createApp } from "./routes.js";
import { serviceTokenAuth } from "./middleware.js";

function requiredEnv(key: string): string {
  const val = process.env[key];
  if (!val) {
    console.error(`fatal: ${key} environment variable is required`);
    process.exit(1);
  }
  return val;
}

const serviceToken = requiredEnv("HAL_CLOUD_RUNNER_SERVICE_TOKEN");
const port = parseInt(process.env.PORT || "8090", 10);

const daytonaApiKey = process.env.DAYTONA_API_KEY;
const daytonaApiUrl = process.env.DAYTONA_SERVER_URL || process.env.DAYTONA_API_URL;

const daytona = new Daytona({
  apiKey: daytonaApiKey,
  apiUrl: daytonaApiUrl,
});

const routes = createApp(daytona);

// Wire auth middleware on all routes except health
const app = new Hono();
app.get("/health", async (c) => {
  return c.json({ ok: true, version: "0.1.0" });
});
app.use("/*", serviceTokenAuth(serviceToken));
app.route("/", routes);

console.log(`daytona-runner listening on :${port}`);
serve({ fetch: app.fetch, port });
