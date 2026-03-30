# CI Status Contract v1

**Command:** `hal ci status --json` (and `hal ci status --wait --json`)  
**Contract Version:** `ci-status-v1`  
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

## Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"ci-status-v1"` |
| `branch` | string | Current git branch |
| `sha` | string | Commit SHA used for aggregation |
| `status` | string | Aggregated status (`pending`, `failing`, `passing`) |
| `checksDiscovered` | boolean | `true` when at least one CI context was found |
| `wait` | boolean | `true` when command executed wait mode |
| `waitTerminalReason` | string | Wait terminal reason (`completed`, `timeout`, `no_checks_detected`) |
| `checks` | array | Aggregated check contexts |
| `totals` | object | Counts by outcome |
| `summary` | string | Human-readable status summary |

## `checks[]` Fields

| Field | Type | Description |
|-------|------|-------------|
| `key` | string | Stable dedupe key (`check:<name>` or `status:<context>`) |
| `source` | string | Source type: `check` or `status` |
| `name` | string | Check-run name or status context |
| `status` | string | Normalized status (`pending`, `failing`, `passing`) |
| `url` | string | CI details URL (optional) |

## `totals` Fields

| Field | Type | Description |
|-------|------|-------------|
| `pending` | integer | Number of pending contexts |
| `failing` | integer | Number of failing contexts |
| `passing` | integer | Number of passing contexts |

## Enumerated Values

### `status`
- `pending`
- `failing`
- `passing`

### `waitTerminalReason`
- `completed`
- `timeout`
- `no_checks_detected`

### `checks[].source`
- `check`
- `status`

## Example: Wait Timeout

```json
{
  "contractVersion": "ci-status-v1",
  "branch": "hal/ci-gap-free-safety-v3",
  "sha": "a1b2c3d4",
  "status": "pending",
  "checksDiscovered": true,
  "wait": true,
  "waitTerminalReason": "timeout",
  "checks": [
    {
      "key": "check:test",
      "source": "check",
      "name": "test",
      "status": "pending",
      "url": "https://github.com/acme/repo/actions/runs/123"
    },
    {
      "key": "status:lint",
      "source": "status",
      "name": "lint",
      "status": "passing"
    }
  ],
  "totals": {
    "pending": 1,
    "failing": 0,
    "passing": 1
  },
  "summary": "status=pending (passing=1, failing=0, pending=1)"
}
```

## Example: No Checks Detected

```json
{
  "contractVersion": "ci-status-v1",
  "branch": "hal/ci-gap-free-safety-v3",
  "sha": "a1b2c3d4",
  "status": "pending",
  "checksDiscovered": false,
  "wait": true,
  "waitTerminalReason": "no_checks_detected",
  "checks": [],
  "totals": {
    "pending": 0,
    "failing": 0,
    "passing": 0
  },
  "summary": "no CI contexts discovered; status pending"
}
```