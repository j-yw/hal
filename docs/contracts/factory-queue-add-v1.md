# Factory Queue Add Contract v1

**Command:** `hal factory queue add <run-id> <executor-mode> --json`
**Contract Version:** `factory-queue-add-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory queue add --json` enqueues an existing factory run for later local execution and emits the created queue entry.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-queue-add-v1"` for this contract |
| `entry` | object | Created queue entry using `factory-queue-entry-v1` |
| `summary` | string | Short human-readable summary of the enqueue result |

`entry` is always present on successful JSON output.

## Queue Entry

The `entry` object uses the reusable queue entry contract documented in `docs/contracts/factory-queue-entry-v1.md`.

Newly added entries have `status` set to `queued`, `attemptCount` set to `0`, and omit `claimedAt`, `completedAt`, `claim`, and `lastError`.

## Error Behavior

Missing run IDs, missing executor modes, unsupported executor modes, queue load errors, and queue persistence errors return non-zero command errors. On failures, consumers should treat stdout as undefined and rely on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-queue-add-v1.json`
