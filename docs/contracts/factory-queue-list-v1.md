# Factory Queue List Contract v1

**Command:** `hal factory queue list --json`
**Contract Version:** `factory-queue-list-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory queue list --json` reads the global factory queue and emits queue entries in FIFO order.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-queue-list-v1"` for this contract |
| `entries` | array | Queue entries using `factory-queue-entry-v1`, ordered FIFO by `createdAt` |
| `summary` | string | Short human-readable summary of the queue state |

`entries` is always present. Empty state is represented as an empty array.

## Included Entries

By default, list output includes active and inspectable queue entries: `queued`, `claimed`, and `failed`. Successful work may be removed from the active queue or retained as `succeeded` history by later lifecycle behavior, but consumers must not require succeeded entries to appear in list output.

## Queue Entry

Each `entries` item uses the reusable queue entry contract documented in `docs/contracts/factory-queue-entry-v1.md`.

## Ordering Rules

Entries are returned in FIFO order by `createdAt`. When two entries have the same creation timestamp, `queueId` ascending is the stable tie-breaker.

## Error Behavior

Missing queue files are treated as empty state and return:

```json
{
  "contractVersion": "factory-queue-list-v1",
  "entries": [],
  "summary": "0 queue entries"
}
```

Queue read or parse failures return a non-zero command error and do not overwrite or delete queue files. On failures, consumers should treat stdout as undefined and rely on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-queue-list-v1.json`
