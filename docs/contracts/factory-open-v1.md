# Factory Open Contract v1

**Command:** `hal factory open <run-id> --json`
**Contract Version:** `factory-open-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory open <run-id> --json` reads one run from the global factory store and emits the redaction-safe handoff guidance that the text command would print. It never executes a handoff command. `--json` and `--exec` are mutually exclusive.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-open-v1"` for this contract |
| `runId` | string | Requested factory run identifier |
| `handoff` | object | Handoff guidance for the run; omitted when the run cannot be loaded |
| `error` | string | Error message for expected non-zero outcomes, such as a missing run |
| `summary` | string | Short machine-friendly summary of the selected action or error |

Successful responses include `handoff` and omit `error`. Expected non-zero JSON responses, such as a missing run ID, include `error` and omit `handoff`.

## Handoff Summary

When `handoff` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `runId` | string | yes | Run identifier the handoff summary describes |
| `status` | string | yes | Stored run lifecycle status |
| `executorMode` | string | yes | Stored executor mode |
| `handoffRequired` | boolean | yes | True when a failed run has actionable follow-up guidance |
| `nextAction` | object | no | Structured suggested next action for failed resumable or takeover runs |
| `inspectCommand` | string | no | Safe command for inspecting the durable run record |
| `resumeCommand` | string | no | Safe local resume command when saved auto state permits continuation |
| `sshCommand` | string | no | Safe sandbox SSH command when the recorded sandbox status is running |
| `repoPath` | string | no | Repository path recorded for local handoff |
| `branchName` | string | no | Branch recorded for the run |
| `sandboxName` | string | no | Sandbox name recorded for sandbox-backed runs |
| `pullRequestUrl` | string | no | Safe PR URL when already available from stored artifacts |
| `currentStep` | string | no | Current or failed pipeline step |
| `failureReason` | string | no | Stored failure message |
| `artifactLocations` | array | no | Non-log artifact display or store locations relevant to handoff |
| `logLocations` | array | no | Log artifact display or store locations relevant to handoff |

Handoff data is derived only from durable factory store records and stored artifact payloads. The command does not perform live sandbox, GitHub, shell, network, or engine lookups while rendering JSON.

## Next Action

When `nextAction` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Stable action identifier, such as `takeover_sandbox`, `resume_auto`, or `inspect_factory_run` |
| `type` | string | yes | Action type: `inspect`, `takeover`, `continue`, or `completed` |
| `command` | string | yes | Safe local Hal command to inspect, take over, or continue |
| `description` | string | yes | Human-readable action summary |
| `runId` | string | no | Run identifier for the action |
| `sandboxName` | string | no | Sandbox name for sandbox takeover actions |
| `repoPath` | string | no | Repository path for local continue actions |
| `branchName` | string | no | Branch associated with the run |
| `pullRequestUrl` | string | no | Safe PR URL when known |
| `currentStep` | string | no | Current or failed step |
| `failureReason` | string | no | Stored failure reason |
| `artifactLocations` | array | no | Non-log artifact locations |
| `logLocations` | array | no | Log locations |

`artifactLocations` and `logLocations` entries use:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | no | Artifact label |
| `path` | string | no | Display path |
| `storedPath` | string | no | Store-relative path for persisted payloads |

## Redaction Rules

The JSON surface must not expose raw IP addresses, SSH hosts, tokens, private keys, secret environment values, raw credentials, API keys, or unsafe environment values. Sandbox takeover commands use `hal sandbox ssh <sandboxName>` instead of provider hostnames.

## Error Behavior

If `<run-id>` does not exist, the command returns a non-zero exit code and emits:

```json
{
  "contractVersion": "factory-open-v1",
  "runId": "missing-run",
  "error": "factory run \"missing-run\" not found",
  "summary": "factory run \"missing-run\" not found"
}
```

Store resolution, run parse, or serialization failures may return non-contract command errors. On non-contract command errors, consumers should treat stdout as undefined and rely on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-open-v1.json`
