# Factory Queue Work Contract v1

**Command:** `hal factory queue work --json`
**Contract Version:** `factory-queue-work-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory queue work --json` claims at most one queued entry for local execution and reports whether work was claimed.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-queue-work-v1"` for this contract |
| `claimed` | boolean | Whether this invocation claimed one queue entry |
| `entry` | object or null | Claimed queue entry using `factory-queue-entry-v1`, or `null` when no work is available |
| `summary` | string | Short human-readable summary of the work result |

`entry` is always present. It is an object when `claimed` is `true` and `null` when `claimed` is `false`.

## Claimed Work

When work is claimed, the entry status is `claimed`, `claimedAt` is set, and `claim` identifies the local worker process. The claimed entry uses the reusable queue entry contract documented in `docs/contracts/factory-queue-entry-v1.md`.

## No Work

When no queued entries exist, the command exits successfully and emits:

```json
{
  "contractVersion": "factory-queue-work-v1",
  "claimed": false,
  "entry": null,
  "summary": "no queued factory work"
}
```

## Error Behavior

Queue read, parse, lock, claim, persistence, and executor setup failures return non-zero command errors. If a command error occurs before a valid JSON response is produced, consumers should treat stdout as undefined and rely on the command exit status.

## Example Artifacts

- `docs/contracts/examples/factory-queue-work-claimed-v1.json`
- `docs/contracts/examples/factory-queue-work-noop-v1.json`
