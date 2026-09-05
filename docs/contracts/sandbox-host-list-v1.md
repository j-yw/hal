# Sandbox Host List Contract v1

**Command:** `hal sandbox host list --json`
**Contract Version:** `sandbox-host-list-v1`
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

**Privacy boundary:** This contract summarizes host endpoints without exposing
raw socket paths, hostnames, credentials, or URL query strings. Consumers that
need the exact endpoint should read the durable host registry directly in a
trusted local context.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"sandbox-host-list-v1"` for this contract |
| `hosts` | array | List of host entries sorted by host `name`, then `id` |
| `totals` | object | Aggregate host counts |

## Host Entry

These fields are always present on every entry in the `hosts` array.

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable durable host identifier |
| `name` | string | Display name for the host |
| `kind` | string | Host kind, such as `"worker"`, `"ssh"`, `"local"`, or `"k8s"` |
| `endpoint` | object | Safe endpoint summary; raw endpoint values are not emitted |
| `health` | object | Cached durable health metadata |
| `supportedRuntimes` | array | Sorted runtime driver IDs reported for the host, or an empty array |
| `capacity` | object | Cached durable capacity metadata with a human summary |

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
| `status` | string | Cached health status, such as `"healthy"`, `"degraded"`, or `"unknown"` |
| `checkedAt` | string | RFC 3339 timestamp for the cached health check, omitted when unknown |
| `lastHeartbeatAt` | string | RFC 3339 timestamp for the last heartbeat, omitted when unknown |
| `message` | string | Optional cached health message |

## Capacity

| Field | Type | Description |
|-------|------|-------------|
| `summary` | string | Human-readable cached capacity summary, or `"unknown"` |
| `cpuCores` | integer | Cached CPU cores, omitted when unknown |
| `memoryMb` | integer | Cached memory in MiB, omitted when unknown |
| `diskGb` | integer | Cached disk in GiB, omitted when unknown |
| `maxConcurrentSandboxes` | integer | Cached worker concurrency, omitted when unknown |

## Totals

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Total number of host entries emitted |

## Example: Multiple Hosts

```json
{
  "contractVersion": "sandbox-host-list-v1",
  "hosts": [
    {
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
        "checkedAt": "2026-07-01T12:30:00Z"
      },
      "supportedRuntimes": [
        "rootless_podman",
        "ssh_machine"
      ],
      "capacity": {
        "summary": "max 2 sandboxes",
        "maxConcurrentSandboxes": 2
      }
    },
    {
      "id": "ssh-1",
      "name": "zeta",
      "kind": "ssh",
      "endpoint": {
        "type": "endpoint",
        "summary": "ssh endpoint",
        "scheme": "ssh"
      },
      "health": {
        "status": "degraded",
        "checkedAt": "2026-07-01T12:30:00Z",
        "message": "slow"
      },
      "supportedRuntimes": [
        "ssh_machine"
      ],
      "capacity": {
        "summary": "4 CPU, 8192 MiB, 80 GiB disk",
        "cpuCores": 4,
        "memoryMb": 8192,
        "diskGb": 80
      }
    }
  ],
  "totals": {
    "total": 2
  }
}
```

## Example: Empty Registry

```json
{
  "contractVersion": "sandbox-host-list-v1",
  "hosts": [],
  "totals": {
    "total": 0
  }
}
```

## Notes

- The command reads durable registry records only; it does not contact worker daemons or runtime providers.
- Host ordering follows the durable registry order: `name`, then `id`.
- `supportedRuntimes` is always present and uses an empty array when no runtime metadata is cached.
- Endpoint output is intentionally summary-only. Raw socket paths are not part of this contract.
