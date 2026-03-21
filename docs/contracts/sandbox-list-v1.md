# Sandbox List Contract v1

**Command:** `hal sandbox list --json`  
**Contract Version:** `sandbox-list-v1`  
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"sandbox-list-v1"` for this contract |
| `sandboxes` | array | List of sandbox entries (see below) |
| `totals` | object | Aggregate counts and cost estimate |

## Sandbox Entry — Required Fields

These fields are always present on every entry in the `sandboxes` array.

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUIDv7 identifier for the sandbox instance |
| `name` | string | Validated sandbox name (1–59 chars, lowercase alphanumeric + hyphens) |
| `provider` | string | Provider that manages this sandbox (e.g. `"daytona"`, `"hetzner"`, `"digitalocean"`, `"lightsail"`) |
| `status` | string | Lifecycle status: `"running"`, `"stopped"`, or `"unknown"` |
| `createdAt` | string | RFC 3339 timestamp of when the sandbox was created |

## Sandbox Entry — Optional Fields

These fields use `omitempty` and are only present when the value is non-zero.

| Field | Type | Description |
|-------|------|-------------|
| `workspaceId` | string | Provider-specific workspace or instance identifier |
| `ip` | string | Public IP address |
| `tailscaleIp` | string | Tailscale IP address (when Tailscale is configured) |
| `tailscaleHostname` | string | Tailscale hostname (format: `"hal-<name>"`) |
| `stoppedAt` | string | RFC 3339 timestamp of when the sandbox was stopped |
| `autoShutdown` | boolean | Whether auto-shutdown is enabled |
| `idleHours` | integer | Hours of idle time before auto-shutdown triggers |
| `size` | string | Provider-specific instance size (e.g. `"cpx21"`, `"s-2vcpu-4gb"`) |
| `repo` | string | Informational repository label |
| `snapshotId` | string | Provider-specific snapshot identifier |
| `estimatedCost` | number | Estimated cost in USD since creation (omitted when rate data is unavailable) |

## Totals

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Total number of sandboxes |
| `running` | integer | Number of sandboxes with status `"running"` |
| `stopped` | integer | Number of sandboxes with status `"stopped"` |
| `estimatedCost` | number | Aggregate estimated cost in USD across all sandboxes with known rates (omitted when no rate data is available) |

## Example: Multiple Sandboxes

```json
{
  "contractVersion": "sandbox-list-v1",
  "sandboxes": [
    {
      "id": "0192d4e5-6f78-7abc-def0-123456789abc",
      "name": "api-backend",
      "provider": "hetzner",
      "status": "running",
      "createdAt": "2026-03-20T10:30:00Z",
      "workspaceId": "srv-12345",
      "ip": "203.0.113.10",
      "tailscaleIp": "100.64.0.1",
      "tailscaleHostname": "hal-api-backend",
      "autoShutdown": true,
      "idleHours": 48,
      "size": "cpx21",
      "repo": "github.com/myorg/api",
      "estimatedCost": 3.84
    },
    {
      "id": "0192d4e5-6f78-7abc-def0-123456789abd",
      "name": "frontend",
      "provider": "digitalocean",
      "status": "stopped",
      "createdAt": "2026-03-19T08:00:00Z",
      "workspaceId": "456789",
      "ip": "198.51.100.5",
      "stoppedAt": "2026-03-20T18:00:00Z",
      "size": "s-2vcpu-4gb",
      "estimatedCost": 1.56
    },
    {
      "id": "0192d4e5-6f78-7abc-def0-123456789abe",
      "name": "worker-01",
      "provider": "daytona",
      "status": "running",
      "createdAt": "2026-03-21T12:00:00Z"
    }
  ],
  "totals": {
    "total": 3,
    "running": 2,
    "stopped": 1,
    "estimatedCost": 5.40
  }
}
```

## Example: Empty Registry

```json
{
  "contractVersion": "sandbox-list-v1",
  "sandboxes": [],
  "totals": {
    "total": 0,
    "running": 0,
    "stopped": 0
  }
}
```

## Example: Single Running Sandbox (Minimal Fields)

```json
{
  "contractVersion": "sandbox-list-v1",
  "sandboxes": [
    {
      "id": "0192d4e5-6f78-7abc-def0-123456789abc",
      "name": "dev-sandbox",
      "provider": "lightsail",
      "status": "running",
      "createdAt": "2026-03-21T09:00:00Z",
      "size": "micro_3_0",
      "estimatedCost": 0.12
    }
  ],
  "totals": {
    "total": 1,
    "running": 1,
    "stopped": 0,
    "estimatedCost": 0.12
  }
}
```

## Notes

- The `estimatedCost` field on individual sandboxes is omitted (not `null` or `0`) when hourly rate data is unavailable for the provider/size combination (e.g. Daytona).
- The `totals.estimatedCost` field aggregates only sandboxes with known rates and is omitted when no sandbox has rate data.
- Cost accrues from `createdAt` regardless of status, since cloud providers charge for allocated instances even when stopped.
- The `--live` flag queries providers for fresh status before rendering but does not change the JSON structure.
- New optional fields may be added in future versions with `omitempty`. Consumers should ignore unknown fields for forward compatibility.
