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
| `sandboxExecutionId` | string | Durable execution ID emitted with sandbox sync-out metadata for later `hal sandbox apply EXECUTION_ID`, or with a worker-backed sandbox failure/detach result for recovery |
| `securityReadinessGate` | object | Sandbox security readiness decision |
| `sandboxPreview` | object | Pure sandbox dry-run intent preview; present only for `hal run --sandbox --dry-run` |
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

For explicitly selected daemon-owned rootless sandbox jobs, `ok=true` also
requires completed, consistent host-side finalization. A failure collecting
artifacts, releasing the lease, or publishing durable terminal state produces
one `ok=false` document with a sanitized error and `sandboxExecutionId`, even
if the inner loop succeeded. Validated inner `complete`, iteration, and story
facts remain intact: `complete` describes PRD stories, not host finalization.
Successful bounded runs (`ok=true`, `complete=false`) remain valid.

Worker stdout must contain exactly one non-null, correctly typed `run-v1`
object. Missing, malformed, multiple-document, oversized (more than 1 MiB),
or explicitly truncated output fails closed with a normal `ok=false`,
`complete=false` envelope; invalid bytes are not passed through. A detached
worker job likewise reports unconfirmed completion with `complete=false` and
its recovery identity, without canceling the daemon-owned job or finalizing it.
Existing command errors retain their exit status; a JSON-only validation or
inner failure without a command error exits `4`. Successful output retains
its existing schema and optional augmentations. Legacy SSH output is unchanged.

For `hal run --sandbox --dry-run --json`, `iterations` is `0`, `complete` is
`false`, and `sandboxPreview` describes requested target, runtime, workspace,
security, and post-execution intent. Target/workspace resolution and security
enforcement remain `unresolved`, `resourcesCreated` is `false`, and security
`active` is `false`. The preview contains no durable execution ID and is
returned before opening the execution store or contacting a sandbox boundary.

## Example Artifacts

- `docs/contracts/examples/run-v1-success.json`
- `docs/contracts/examples/run-v1-failure.json`
