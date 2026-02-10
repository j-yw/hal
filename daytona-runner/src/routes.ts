import { Hono } from "hono";
import type { Daytona } from "@daytonaio/sdk";

/** Request body for POST /sandboxes — matches Go runner.CreateSandboxRequest. */
interface CreateSandboxBody {
  image: string;
  repo?: string;
  branch?: string;
  env_vars?: Record<string, string>;
}

/** Response body for POST /sandboxes — matches Go runner.Sandbox. */
interface SandboxResponse {
  id: string;
  status: string;
  created_at: string;
}

const VERSION = "0.1.0";

/**
 * Creates the Hono app with all runner endpoints.
 * Accepts a Daytona client instance for sandbox lifecycle calls.
 */
export function createApp(daytona: Daytona) {
  const app = new Hono();

  // POST /sandboxes — create a new Daytona sandbox
  app.post("/sandboxes", async (c) => {
    const body = await c.req.json<CreateSandboxBody>();

    if (!body.image) {
      return c.json({ error: "image is required", error_code: "validation_error" }, 400);
    }

    try {
      const sandbox = await daytona.create({
        image: body.image,
        envVars: body.env_vars,
      });

      const info = await sandbox.info();

      const resp: SandboxResponse = {
        id: sandbox.id,
        status: String(info.state ?? "unknown"),
        created_at: new Date().toISOString(),
      };

      return c.json(resp, 201);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return c.json({ error: message, error_code: "create_failed" }, 500);
    }
  });

  // DELETE /sandboxes/:id — destroy an existing sandbox
  app.delete("/sandboxes/:id", async (c) => {
    const sandboxId = c.req.param("id");

    try {
      const sandbox = await daytona.get(sandboxId);
      await sandbox.delete();
      return c.body(null, 204);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("not found") || message.includes("404")) {
        return c.json({ error: `sandbox ${sandboxId} not found`, error_code: "not_found" }, 404);
      }
      return c.json({ error: message, error_code: "destroy_failed" }, 500);
    }
  });

  // GET /health — health check
  app.get("/health", async (c) => {
    return c.json({ ok: true, version: VERSION });
  });

  return app;
}
