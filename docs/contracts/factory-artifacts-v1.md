# Factory Artifacts Contract v1

**Command:** `hal factory artifacts <run-id> --json`
**Contract Version:** `factory-artifacts-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory artifacts <run-id> --json` reads one run from the global factory store and emits a safe artifact listing for automation. It is narrower than `hal factory status <run-id> --json`: this surface includes artifact metadata, aggregate warning counts, and sanitized summary metadata, but omits the full run record and timeline.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-artifacts-v1"` for this contract |
| `runId` | string | Stable factory run identifier |
| `artifacts` | array | Safe artifact entries in stored run order |
| `warnings` | array | Unique warning strings collected from artifact entries |
| `summary` | object | Aggregate artifact counts |

`artifacts` and `warnings` are always present. Empty state is represented as empty arrays.

## Artifact Entry

Each entry in `artifacts` contains safe metadata for one collected artifact.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Stable artifact label |
| `type` | string | yes | Artifact category, such as `json`, `markdown`, or `text` |
| `id` | string | no | Stable artifact ID when recorded |
| `path` | string | no | Display path for the artifact |
| `storedPath` | string | no | Store-relative path under `artifacts/<run-id>/` |
| `sizeBytes` | integer | no | Artifact size when known |
| `createdAt` | string | no | RFC 3339 timestamp when known |
| `summary` | object | no | Sanitized artifact-specific summary metadata |
| `warnings` | array | no | Sanitized warning strings for this artifact |
| `partial` | boolean | no | Present and true when artifact collection was partial |

The JSON surface intentionally omits raw `sourcePath` and `url` fields from the stored run record. If an artifact only has a remote URL and no display or stored path, `path` is emitted as `"[redacted]"`.

## Summary

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Number of artifact entries |
| `partial` | integer | Number of partial artifact entries |
| `warnings` | integer | Total warning strings across artifact entries |

## Redaction Rules

Summary metadata and warnings redact values as `"[redacted]"` when they contain:

- Secret-like keys such as `token`, `secret`, `password`, `credential`, `api_key`, or `access_key`
- URL userinfo or secret-like URL query parameters
- Raw IP addresses or IP host/port values

Consumers should treat `summary` as an open object and ignore unknown keys. Redaction may become stricter in future patch releases.

## Error Behavior

If `<run-id>` does not exist, the command returns a non-zero error with the message:

```text
factory run "<run-id>" not found
```

No JSON payload is written for missing run IDs. Store resolution, run parse, or serialization failures also return non-zero command errors. On failures, consumers should treat stdout as undefined and rely on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-artifacts-v1.json`
