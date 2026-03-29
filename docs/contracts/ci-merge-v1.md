# CI Merge Contract v1

**Command:** `hal ci merge --json`  
**Contract Version:** `ci-merge-v1`  
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

## Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"ci-merge-v1"` |
| `prNumber` | integer | Pull request number targeted for merge |
| `strategy` | string | Merge strategy (`squash`, `merge`, `rebase`) |
| `dryRun` | boolean | `true` when run with `--dry-run` |
| `merged` | boolean | `true` when merge succeeded |
| `branchDeleted` | boolean | `true` when remote branch deletion succeeded |
| `summary` | string | Human-readable summary |

## Optional Fields (`omitempty`)

| Field | Type | Description |
|-------|------|-------------|
| `mergeCommitSha` | string | Merge commit SHA |
| `deleteWarning` | string | Warning text when branch deletion failed non-fatally |

## Example: Successful Merge With Delete Warning

```json
{
  "contractVersion": "ci-merge-v1",
  "prNumber": 124,
  "strategy": "squash",
  "dryRun": false,
  "merged": true,
  "mergeCommitSha": "abcd1234",
  "branchDeleted": false,
  "deleteWarning": "delete remote branch \"hal/ci-gap-free-safety-v3\": permission denied",
  "summary": "merged pull request #124 using squash strategy; warning: delete remote branch \"hal/ci-gap-free-safety-v3\": permission denied"
}
```

## Example: Dry Run

```json
{
  "contractVersion": "ci-merge-v1",
  "prNumber": 0,
  "strategy": "rebase",
  "dryRun": true,
  "merged": false,
  "branchDeleted": false,
  "summary": "dry-run: would merge pull request for branch hal/ci-gap-free-safety-v3 using rebase strategy"
}
```