import type { Context, Next } from "hono";

/**
 * Service token authentication middleware.
 * Validates X-Service-Token header against the configured service token.
 * Returns HTTP 401 with error_code "unauthorized" on failure.
 */
export function serviceTokenAuth(serviceToken: string) {
  return async (c: Context, next: Next) => {
    const token = c.req.header("X-Service-Token");
    if (!token || token !== serviceToken) {
      return c.json(
        { error: "missing or invalid service token", error_code: "unauthorized" },
        401,
      );
    }
    await next();
  };
}
