# Factory Queue Entry Contract v1

**Embedded by:** `hal factory queue add --json`, `hal factory queue list --json`, `hal factory queue work --json`
**Contract Version:** `factory-queue-entry-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

Factory queue entries represent file-backed local factory work stored under Hal's global config directory. Queue command responses embed this entry shape so automation can inspect scheduling state without reading queue files directly.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

Succeeded and failed entries are retained in queue state as inspectable history. Workers should only select entries with `status` set to `queued` as active work.

## Queue Entry

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `queueId` | string | yes | Stable queue entry identifier |
| `runId` | string | yes | Existing factory run identifier to execute |
| `executorMode` | string | yes | Factory executor mode for the run |
| `status` | string | yes | Queue lifecycle status; see status values below |
| `createdAt` | string | yes | RFC 3339 timestamp when the entry was created |
| `claimedAt` | string | no | RFC 3339 timestamp when a worker claimed the entry |
| `completedAt` | string | no | RFC 3339 timestamp when the worker recorded success or failure |
| `claim` | object | no | Metadata for the local worker that claimed the entry |
| `attemptCount` | integer | yes | Number of times this entry has been claimed for execution |
| `lastError` | string | no | Sanitized last worker or executor error message recorded for the entry |

## Claim Metadata

When `claim` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `workerId` | string | no | Stable worker identifier for the claiming process |
| `pid` | integer | no | Local process ID for the claiming worker |
| `hostname` | string | no | Hostname for the claiming machine |

## Status Values

| Status | Meaning |
|--------|---------|
| `queued` | Entry is waiting for a worker |
| `claimed` | Entry has been claimed by one worker and is in progress or recoverable after interruption |
| `succeeded` | Entry completed successfully and remains retained in queue history |
| `failed` | Entry failed and remains inspectable through queue JSON output |

## Executor Mode Values

| Mode | Meaning |
|------|---------|
| `local` | Run through the local factory executor wrapping the local auto pipeline |

## Error Behavior

Queue command contracts document command-level error behavior. Consumers should treat queue entry fields as durable state only after a command exits successfully.
