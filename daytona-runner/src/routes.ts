import { Hono } from "hono";
import { stream } from "hono/streaming";
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

/** Request body for POST /sandboxes/:id/exec — matches Go runner.ExecRequest. */
interface ExecBody {
  command: string;
  work_dir?: string;
  timeout?: number;
}

/** Response body for POST /sandboxes/:id/exec — matches Go runner.ExecResult. */
interface ExecResponse {
  exit_code: number;
  stdout: string;
  stderr: string;
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

  // POST /sandboxes/:id/exec — execute a command in a sandbox
  app.post("/sandboxes/:id/exec", async (c) => {
    const sandboxId = c.req.param("id");
    const body = await c.req.json<ExecBody>();

    if (!body.command) {
      return c.json({ error: "command is required", error_code: "validation_error" }, 400);
    }

    try {
      const sandbox = await daytona.get(sandboxId);
      const response = await sandbox.process.executeCommand(
        body.command,
        body.work_dir,
        body.timeout,
      );

      const resp: ExecResponse = {
        exit_code: response.exitCode,
        stdout: response.result ?? "",
        stderr: "",
      };

      return c.json(resp, 200);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("not found") || message.includes("404")) {
        return c.json({ error: `sandbox ${sandboxId} not found`, error_code: "not_found" }, 404);
      }
      return c.json({ error: message, error_code: "exec_failed" }, 500);
    }
  });

  // GET /sandboxes/:id/logs — stream logs from a sandbox
  app.get("/sandboxes/:id/logs", async (c) => {
    const sandboxId = c.req.param("id");
    const sessionId = c.req.query("session_id") ?? "default";
    const commandId = c.req.query("command_id") ?? "default";

    try {
      const sandbox = await daytona.get(sandboxId);

      return stream(c, async (s) => {
        try {
          await sandbox.process.getSessionCommandLogs(
            sessionId,
            commandId,
            (chunk: string) => {
              s.write(chunk);
            },
          );
        } catch (streamErr) {
          // If streaming callback fails, try fetching logs as a single string
          const logs = await sandbox.process.getSessionCommandLogs(sessionId, commandId);
          if (logs) {
            await s.write(logs);
          }
        }
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("not found") || message.includes("404")) {
        return c.json({ error: `sandbox ${sandboxId} not found`, error_code: "not_found" }, 404);
      }
      return c.json({ error: message, error_code: "logs_failed" }, 500);
    }
  });

  // GET /health — health check
  app.get("/health", async (c) => {
    return c.json({ ok: true, version: VERSION });
  });

  return app;
}
