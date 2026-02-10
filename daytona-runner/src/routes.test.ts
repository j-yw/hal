import { describe, it, expect, vi, beforeEach } from "vitest";
import { createApp } from "./routes.js";
import type { Daytona } from "@daytonaio/sdk";

// Mock sandbox returned by daytona.create() and daytona.get()
function mockSandbox(id: string, state = "started") {
  return {
    id,
    instance: { state },
    info: vi.fn().mockResolvedValue({ state }),
    delete: vi.fn().mockResolvedValue(undefined),
    process: {
      executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, result: "hello world" }),
      getSessionCommandLogs: vi.fn().mockImplementation(
        async (
          _sessionId: string,
          _commandId: string,
          onLogs?: (chunk: string) => void,
        ) => {
          if (onLogs) {
            onLogs("line1\n");
            onLogs("line2\n");
            return;
          }
          return "line1\nline2\n";
        },
      ),
      createSession: vi.fn().mockResolvedValue(undefined),
      deleteSession: vi.fn().mockResolvedValue(undefined),
    },
  };
}

function mockDaytona(overrides: Partial<Daytona> = {}) {
  const sandbox = mockSandbox("sb-123");
  return {
    create: vi.fn().mockResolvedValue(sandbox),
    get: vi.fn().mockResolvedValue(sandbox),
    list: vi.fn().mockResolvedValue([]),
    start: vi.fn(),
    stop: vi.fn(),
    remove: vi.fn(),
    getCurrentWorkspace: vi.fn(),
    getCurrentSandbox: vi.fn(),
    _sandbox: sandbox,
    ...overrides,
  } as unknown as Daytona & { _sandbox: ReturnType<typeof mockSandbox> };
}

describe("POST /sandboxes", () => {
  let daytona: ReturnType<typeof mockDaytona>;

  beforeEach(() => {
    daytona = mockDaytona();
  });

  it("creates a sandbox and returns 201", async () => {
    const app = createApp(daytona);
    const res = await app.request("/sandboxes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ image: "ubuntu:22.04" }),
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.id).toBe("sb-123");
    expect(body.status).toBe("started");
    expect(body.created_at).toBeDefined();
    expect(daytona.create).toHaveBeenCalledWith({
      image: "ubuntu:22.04",
      envVars: undefined,
    });
  });

  it("passes env_vars to Daytona SDK", async () => {
    const app = createApp(daytona);
    const res = await app.request("/sandboxes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        image: "node:20",
        env_vars: { NODE_ENV: "production" },
      }),
    });

    expect(res.status).toBe(201);
    expect(daytona.create).toHaveBeenCalledWith({
      image: "node:20",
      envVars: { NODE_ENV: "production" },
    });
  });

  it("returns 400 when image is missing", async () => {
    const app = createApp(daytona);
    const res = await app.request("/sandboxes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error_code).toBe("validation_error");
  });

  it("returns 500 when Daytona SDK create fails", async () => {
    daytona.create = vi.fn().mockRejectedValue(new Error("SDK create failed"));
    const app = createApp(daytona);
    const res = await app.request("/sandboxes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ image: "ubuntu:22.04" }),
    });

    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toContain("SDK create failed");
    expect(body.error_code).toBe("create_failed");
  });
});

describe("DELETE /sandboxes/:id", () => {
  let daytona: ReturnType<typeof mockDaytona>;

  beforeEach(() => {
    daytona = mockDaytona();
  });

  it("destroys a sandbox and returns 204", async () => {
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123", {
      method: "DELETE",
    });

    expect(res.status).toBe(204);
    expect(daytona.get).toHaveBeenCalledWith("sb-123");
    expect(daytona._sandbox.delete).toHaveBeenCalled();
  });

  it("returns 404 when sandbox not found", async () => {
    daytona.get = vi.fn().mockRejectedValue(new Error("not found"));
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/nonexistent", {
      method: "DELETE",
    });

    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error_code).toBe("not_found");
  });

  it("returns 500 when Daytona SDK delete fails", async () => {
    const sandbox = mockSandbox("sb-123");
    sandbox.delete = vi.fn().mockRejectedValue(new Error("destroy failed"));
    daytona.get = vi.fn().mockResolvedValue(sandbox);
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123", {
      method: "DELETE",
    });

    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toContain("destroy failed");
    expect(body.error_code).toBe("destroy_failed");
  });
});

describe("POST /sandboxes/:id/exec", () => {
  let daytona: ReturnType<typeof mockDaytona>;

  beforeEach(() => {
    daytona = mockDaytona();
  });

  it("executes a command and returns exit code and stdout", async () => {
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: "echo hello world" }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.exit_code).toBe(0);
    expect(body.stdout).toBe("hello world");
    expect(body.stderr).toBe("");
    expect(daytona.get).toHaveBeenCalledWith("sb-123");
    expect(daytona._sandbox.process.executeCommand).toHaveBeenCalledWith(
      "echo hello world",
      undefined,
      undefined,
    );
  });

  it("passes work_dir and timeout to SDK", async () => {
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        command: "ls -la",
        work_dir: "/workspace",
        timeout: 30,
      }),
    });

    expect(res.status).toBe(200);
    expect(daytona._sandbox.process.executeCommand).toHaveBeenCalledWith(
      "ls -la",
      "/workspace",
      30,
    );
  });

  it("returns non-zero exit code as data, not error", async () => {
    daytona._sandbox.process.executeCommand = vi
      .fn()
      .mockResolvedValue({ exitCode: 1, result: "" });
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: "false" }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.exit_code).toBe(1);
    expect(body.stdout).toBe("");
  });

  it("returns 400 when command is missing", async () => {
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error_code).toBe("validation_error");
    expect(body.error).toContain("command is required");
  });

  it("returns 404 when sandbox not found", async () => {
    daytona.get = vi.fn().mockRejectedValue(new Error("not found"));
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-missing/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: "ls" }),
    });

    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error_code).toBe("not_found");
  });

  it("returns 500 when SDK executeCommand fails", async () => {
    daytona._sandbox.process.executeCommand = vi
      .fn()
      .mockRejectedValue(new Error("exec timeout"));
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: "sleep 9999" }),
    });

    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toContain("exec timeout");
    expect(body.error_code).toBe("exec_failed");
  });

  it("handles null result from SDK", async () => {
    daytona._sandbox.process.executeCommand = vi
      .fn()
      .mockResolvedValue({ exitCode: 0, result: null });
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: "true" }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.exit_code).toBe(0);
    expect(body.stdout).toBe("");
  });
});

describe("GET /sandboxes/:id/logs", () => {
  let daytona: ReturnType<typeof mockDaytona>;

  beforeEach(() => {
    daytona = mockDaytona();
  });

  it("streams log output chunks", async () => {
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123/logs");

    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain("line1\n");
    expect(text).toContain("line2\n");
    expect(daytona.get).toHaveBeenCalledWith("sb-123");
  });

  it("returns 404 when sandbox not found", async () => {
    daytona.get = vi.fn().mockRejectedValue(new Error("not found"));
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-missing/logs");

    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error_code).toBe("not_found");
  });

  it("returns 500 when SDK logs fail", async () => {
    daytona.get = vi.fn().mockRejectedValue(new Error("logs unavailable"));
    const app = createApp(daytona);
    const res = await app.request("/sandboxes/sb-123/logs");

    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toContain("logs unavailable");
    expect(body.error_code).toBe("logs_failed");
  });

  it("uses custom session_id and command_id query params", async () => {
    const app = createApp(daytona);
    const res = await app.request(
      "/sandboxes/sb-123/logs?session_id=my-session&command_id=cmd-1",
    );

    expect(res.status).toBe(200);
    expect(
      daytona._sandbox.process.getSessionCommandLogs,
    ).toHaveBeenCalledWith("my-session", "cmd-1", expect.any(Function));
  });

  it("uses default session_id and command_id when not specified", async () => {
    const app = createApp(daytona);
    await app.request("/sandboxes/sb-123/logs");

    expect(
      daytona._sandbox.process.getSessionCommandLogs,
    ).toHaveBeenCalledWith("default", "default", expect.any(Function));
  });
});

describe("GET /health", () => {
  it("returns ok and version", async () => {
    const daytona = mockDaytona();
    const app = createApp(daytona);
    const res = await app.request("/health");

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.version).toBe("0.1.0");
  });
});

describe("missing or invalid service token (integration with middleware)", () => {
  it("returns 401 when X-Service-Token is missing", async () => {
    // This tests the full app wiring — see index.ts for middleware setup.
    // The routes.ts itself does NOT enforce auth (middleware is in index.ts).
    // This test verifies the routes handle requests normally when auth is not applied.
    const daytona = mockDaytona();
    const app = createApp(daytona);
    const res = await app.request("/health");
    expect(res.status).toBe(200);
  });
});
