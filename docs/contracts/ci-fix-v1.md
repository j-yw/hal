# CI Fix Contract v1

**Command:** `hal ci fix --json`  
**Contract Version:** `ci-fix-v1`  
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

## Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"ci-fix-v1"` |
| `attempt` | integer | Attempt number applied in this result (`0` means no attempt was needed) |
| `applied` | boolean | `true` when a fix attempt was applied |
| `branch` | string | Branch targeted by the fix flow |
| `pushed` | boolean | `true` when a fix commit was pushed |
| `summary` | string | Human-readable summary |

## Optional Fields (`omitempty`)

| Field | Type | Description |
|-------|------|-------------|
| `maxAttempts` | integer | Configured retry cap |
| `commitSha` | string | Commit SHA for the applied fix |
| `filesChanged` | array | Changed file paths included in the fix commit |

## Example: Applied Fix

```json
{
  "contractVersion": "ci-fix-v1",
  "attempt": 1,
  "maxAttempts": 3,
  "applied": true,
  "branch": "hal/ci-gap-free-safety-v3",
  "commitSha": "9f8e7d6",
  "pushed": true,
  "filesChanged": [
    "cmd/ci.go",
    "internal/ci/fix.go"
  ],
  "summary": "applied ci fix attempt 1 on branch hal/ci-gap-free-safety-v3 and pushed 2 files"
}
```

## Example: No Attempt Needed

```json
{
  "contractVersion": "ci-fix-v1",
  "attempt": 0,
  "maxAttempts": 3,
  "applied": false,
  "branch": "hal/ci-gap-free-safety-v3",
  "pushed": false,
  "summary": "ci status is passing; no fix attempt needed"
}
```