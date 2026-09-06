# Sandbox Host Status Contract v1

**Command:** `hal sandbox host status <id> --json`
**Contract Version:** `sandbox-host-status-v1`
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

**Privacy boundary:** This contract summarizes host endpoints without exposing
raw socket paths, hostnames, credentials, or URL query strings. Consumers that
need the exact endpoint should read the durable host registry directly in a
trusted local context.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"sandbox-host-status-v1"` for this contract |
| `source` | object | Indicates whether the response came from cached durable state or a live refresh |
| `refresh` | object | Request and cache-update metadata for this status call |
| `host` | object | Safe durable host status payload |

## Source

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | `"cached"` for durable registry reads or `"live-refreshed"` after a successful `--live` worker refresh |
| `summary` | string | Human-readable source summary |

## Refresh

| Field | Type | Description |
|-------|------|-------------|
| `requestedLive` | boolean | Whether the command requested `--live` |
| `cacheUpdated` | boolean | Whether the durable host cache was updated during this call |
| `refreshedAt` | string | RFC 3339 timestamp for the live refresh, omitted when the response is cached or the time is unknown |

## Host

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable durable host identifier |
| `name` | string | Display name for the host |
| `kind` | string | Host kind, such as `"worker"`, `"ssh"`, `"local"`, or `"k8s"` |
| `endpoint` | object | Safe endpoint summary; raw endpoint values are not emitted |
| `health` | object | Cached or live-refreshed health metadata |
| `supportedRuntimes` | array | Sorted runtime driver IDs reported for the host, or an empty array |
| `capacity` | object | Cached or live-refreshed capacity metadata with a human summary |

## Endpoint

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Summary type: `"unix_socket"`, `"endpoint"`, `"configured"`, or `"none"` |
| `summary` | string | Human-readable safe summary, such as `"local Unix socket"` or `"ssh endpoint"` |
| `scheme` | string | Optional endpoint scheme, such as `"unix"` or `"ssh"` |

Raw Unix socket paths, URL hosts, credentials, and query strings are omitted.

## Health

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Health status, such as `"healthy"`, `"degraded"`, or `"unknown"` |
| `checkedAt` | string | RFC 3339 timestamp for the health check, omitted when unknown |
| `lastHeartbeatAt` | string | RFC 3339 timestamp for the last heartbeat, omitted when unknown |
| `message` | string | Optional health message |

## Capacity

| Field | Type | Description |
|-------|------|-------------|
| `summary` | string | Human-readable capacity summary, or `"unknown"` |
| `cpuCores` | integer | CPU cores, omitted when unknown |
| `memoryMb` | integer | Memory in MiB, omitted when unknown |
| `diskGb` | integer | Disk in GiB, omitted when unknown |
| `maxConcurrentSandboxes` | integer | Worker concurrency, omitted when unknown |

## Example: Cached Status

```json
{
  "contractVersion": "sandbox-host-status-v1",
  "source": {
    "mode": "cached",
    "summary": "cached durable registry (not live)"
  },
  "refresh": {
    "requestedLive": false,
    "cacheUpdated": false
  },
  "host": {
    "id": "worker-a",
    "name": "builder",
    "kind": "worker",
    "endpoint": {
      "type": "unix_socket",
      "summary": "local Unix socket",
      "scheme": "unix"
    },
    "health": {
      "status": "healthy",
      "checkedAt": "2026-07-01T12:30:00Z",
      "message": "ready"
    },
    "supportedRuntimes": [
      "rootless_podman",
      "ssh_machine"
    ],
    "capacity": {
      "summary": "max 2 sandboxes",
      "maxConcurrentSandboxes": 2
    }
  }
}
```

## Example: Live-Refreshed Status

```json
{
  "contractVersion": "sandbox-host-status-v1",
  "source": {
    "mode": "live-refreshed",
    "summary": "live worker refresh (durable cache updated)"
  },
  "refresh": {
    "requestedLive": true,
    "cacheUpdated": true,
    "refreshedAt": "2026-07-01T14:00:00Z"
  },
  "host": {
    "id": "worker-a",
    "name": "builder",
    "kind": "worker",
    "endpoint": {
      "type": "unix_socket",
      "summary": "local Unix socket",
      "scheme": "unix"
    },
    "health": {
      "status": "healthy",
      "checkedAt": "2026-07-01T14:00:00Z",
      "message": "ready now"
    },
    "supportedRuntimes": [
      "rootless_podman"
    ],
    "capacity": {
      "summary": "max 4 sandboxes",
      "maxConcurrentSandboxes": 4
    }
  }
}
```

## Notes

- Without `--live`, the command reads the durable registry only and does not contact worker daemons or runtime providers.
- With `--live`, only worker hosts with local Unix socket endpoints are refreshed. A successful refresh updates the durable host cache before emitting JSON.
- Endpoint output is intentionally summary-only. Raw socket paths, hostnames, credentials, and query strings are not part of this contract.
