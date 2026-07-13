# Run Contract v1

**Command:** `hal run --json`

**Contract Version:** 1

**Stability:** Stable for v1 fields listed below. New optional fields may be added; existing fields will not be renamed or removed.

## Required Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | int | Always `1` |
| `ok` | bool | `true` when loop execution itself succeeded |
| `iterations` | int | Number of loop iterations completed |
| `complete` | bool | Whether every selected PRD story passes |
| `summary` | string | Human-readable result summary |

`ok=true` and `complete=false` is a successful bounded run: the requested
iterations completed and stories remain. Consumers must not treat it as a
process failure.

## Optional Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `engine` | string | Selected engine |
| `storyId` | string | Explicit story selection |
| `lastStoryId` | string | Last story attempted |
| `dryRun` | bool | Whether execution was only previewed |
| `duration` | string | Wall-clock duration when available |
| `prd` | object | PRD path and completed/total story counts |
| `credentialDelivery` | object | Redaction-safe sandbox credential-delivery status |
| `syncOut` | object | Redaction-safe sandbox sync-out summary |
| `syncOutApply` | object | Redaction-safe sandbox apply or handoff result |
| `securityReadinessGate` | object | Sandbox security readiness decision |
| `nextAction` | object | Recommended next command |
| `error` | string | Failure summary when `ok=false` |

## Exit Status

`hal run --json` writes exactly one `run-v1` JSON document to stdout. Process
status and `ok` must be evaluated together:

| Status | Meaning |
|--------|---------|
| `0` | The run has `ok=true`, whether `complete` is true or false |
| `2` | Validation or preflight failed; stdout contains `ok=false` JSON |
| `4` | Loop execution finished with `ok=false` |

Sandbox execution preserves the inner `hal run --json` nonzero status. A
rendered JSON failure does not also print the same error to stderr.

## Example Artifacts

- `docs/contracts/examples/run-v1-success.json`
- `docs/contracts/examples/run-v1-failure.json`
