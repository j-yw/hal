# CI Push Contract v1

**Command:** `hal ci push --json`  
**Contract Version:** `ci-push-v1`  
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

## Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"ci-push-v1"` |
| `branch` | string | Current git branch that was pushed (or would be pushed in dry-run) |
| `pushed` | boolean | `true` when branch push occurred |
| `dryRun` | boolean | `true` when command ran with `--dry-run` |
| `pullRequest` | object | Pull request metadata |
| `summary` | string | Human-readable summary |

## `pullRequest` Fields

| Field | Type | Description |
|-------|------|-------------|
| `number` | integer | Pull request number (`0` when unknown in dry-run preview) |
| `url` | string | Pull request URL (empty when unknown/not created) |
| `title` | string | Pull request title |
| `draft` | boolean | Draft state |
| `existing` | boolean | `true` when an existing open PR was reused |
| `headRef` | string | Source branch name (optional) |
| `headSha` | string | Source head SHA (optional) |
| `baseRef` | string | Target/base branch (optional) |

## Example: Created PR

```json
{
  "contractVersion": "ci-push-v1",
  "branch": "hal/ci-gap-free-safety-v3",
  "pushed": true,
  "dryRun": false,
  "pullRequest": {
    "number": 124,
    "url": "https://github.com/acme/repo/pull/124",
    "title": "hal ci: hal/ci-gap-free-safety-v3",
    "headRef": "hal/ci-gap-free-safety-v3",
    "headSha": "b6f6f7f",
    "baseRef": "main",
    "draft": true,
    "existing": false
  },
  "summary": "pushed branch hal/ci-gap-free-safety-v3 and created pull request"
}
```

## Example: Dry Run

```json
{
  "contractVersion": "ci-push-v1",
  "branch": "hal/ci-gap-free-safety-v3",
  "pushed": false,
  "dryRun": true,
  "pullRequest": {
    "number": 0,
    "url": "",
    "title": "",
    "headRef": "hal/ci-gap-free-safety-v3",
    "draft": true,
    "existing": false
  },
  "summary": "dry-run: would push branch hal/ci-gap-free-safety-v3 and create or reuse a pull request"
}
```