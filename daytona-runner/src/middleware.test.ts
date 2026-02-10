import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { serviceTokenAuth } from "./middleware.js";

function makeApp(token: string) {
  const app = new Hono();
  app.use("/*", serviceTokenAuth(token));
  app.get("/test", (c) => c.json({ ok: true }));
  return app;
}

describe("serviceTokenAuth", () => {
  const app = makeApp("test-secret-token");

  it("rejects missing X-Service-Token header", async () => {
    const res = await app.request("/test");
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error_code).toBe("unauthorized");
  });

  it("rejects wrong token", async () => {
    const res = await app.request("/test", {
      headers: { "X-Service-Token": "wrong-token" },
    });
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error_code).toBe("unauthorized");
  });

  it("rejects empty token", async () => {
    const res = await app.request("/test", {
      headers: { "X-Service-Token": "" },
    });
    expect(res.status).toBe(401);
  });

  it("allows valid token", async () => {
    const res = await app.request("/test", {
      headers: { "X-Service-Token": "test-secret-token" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
  });
});
