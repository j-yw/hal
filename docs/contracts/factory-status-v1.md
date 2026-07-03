# Factory Status Contract v1

**Command:** `hal factory status <run-id> --json`
**Contract Version:** `factory-status-v1`
**Stability:** Stable. New optional fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal factory status <run-id> --json` reads one run from the global factory store and emits the run record plus timeline events. This is the detail surface for artifacts, failures, and event history. Artifact output is a safe summary surface and omits raw local source paths and URLs.

This contract does not change the existing `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt` contracts.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | string | Always `"factory-status-v1"` for this contract |
| `run` | object | Full factory run record |
| `timeline` | array | Timeline event records in append order |

`timeline` is always present. A run with no stored events emits an empty array.

## Run Record Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `runId` | string | Stable factory run identifier |
| `status` | string | Run lifecycle status; see status values below |
| `executorMode` | string | Factory executor mode that produced the run record |
| `source` | object | Input source metadata for the run |
| `repoPath` | string | Repository path recorded for the run |
| `repoRemote` | string | Repository remote recorded for the run |
| `branchName` | string | Feature branch associated with the run |
| `baseBranch` | string | Base branch used for the run |
| `currentStep` | string | Current or terminal factory step |
| `createdAt` | string | RFC 3339 timestamp of run creation |
| `updatedAt` | string | RFC 3339 timestamp of the last run update |

## Run Record Optional Fields

These fields use `omitempty` and are only present when the value is non-zero.

| Field | Type | Description |
|-------|------|-------------|
| `engine` | string | Engine snapshot resolved at factory run creation time, such as `codex`, `claude`, or `pi` |
| `policy` | object | Factory policy snapshot applied to the run |
| `policyDecisions` | array | Policy decisions recorded from the run timeline |
| `sandboxName` | string | Sandbox name used for the run |
| `sandbox` | object | Redaction-safe sandbox execution metadata for sandbox-backed runs |
| `finishedAt` | string | RFC 3339 timestamp of terminal completion |
| `artifacts` | array | Safe artifact summaries associated with the run |
| `verification` | object | Verification summary and artifact references recorded from `hal verify --json` |
| `telemetry` | object | Derived observability summary including durations, engine, sandbox, outcomes, artifact count, cost estimate, and failure classification |
| `failure` | object | Terminal failure summary when the run failed or stopped on a recoverable error |
| `handoff` | object | Redaction-safe human handoff and next-action guidance for failed runs with actionable follow-up |
| `secrets` | array | Redaction-safe run-scoped secret metadata; raw values are never stored |

`sandboxName` is retained as a compatibility summary field. New consumers
should read `sandbox.name` when the `sandbox` object is present.

## Policy Metadata

When `policy` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sandboxRequired` | boolean | yes | Whether factory runs must use sandbox executor mode |
| `allowedEngines` | array | yes | Engine identifiers allowed for the run, such as `claude`, `codex`, or `pi` |
| `maxRunAttempts` | number | yes | Maximum run attempts; `0` means uncapped |
| `maxReviewFixAttempts` | number | yes | Maximum review autofix attempts; `0` means uncapped |
| `maxCiFixAttempts` | number | yes | Maximum CI autofix attempts; `0` means uncapped |
| `verificationRequired` | boolean | yes | Whether verification failures block successful completion |
| `prCreationAllowed` | boolean | yes | Whether pull request creation is allowed |
| `mergeAllowed` | boolean | yes | Whether merge automation is allowed |
| `cleanupBehavior` | string | yes | Sandbox cleanup policy: `preserve`, `on_success`, or `always` |

When `policyDecisions` is present, each entry contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policyField` | string | yes | Policy field that produced the decision |
| `decision` | string | yes | Decision value: `allowed_execution`, `rejected_execution`, `passed_gate`, or `blocked_gate` |
| `outcome` | string | yes | Outcome value: `allowed`, `rejected`, `passed`, or `blocked` |
| `reason` | string | yes | Safe human-readable reason for the decision |

## Run Secret Metadata

When `secrets` is present, each entry describes one run-scoped secret
requirement without storing its value:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Secret identifier; for env-backed secrets this is the environment variable name |
| `source` | string | yes | Secret source type, currently env for environment variables |
| `required` | boolean | yes | Whether setup must fail when the secret is missing or empty |
| `present` | boolean | yes | Whether a value was resolved during setup |

Raw secret values, tokens, API keys, and credential material must not appear in
run records, timeline events, artifact summaries, or factory JSON outputs.

## Sandbox Metadata

When `sandbox` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Sandbox registry name used for the run |
| `provider` | string | yes | Sandbox provider identifier |
| `size` | string | no | Provider-specific sandbox size when known |
| `status` | string | yes | Final known sandbox lifecycle status, such as `running`, `stopped`, or `unknown` |
| `connection` | object | no | Safe connection display fields |
| `sshCommand` | string | no | Suggested local command for interactive inspection |
| `cleanupCommand` | string | no | Suggested local command for sandbox cleanup |
| `handoff` | string | no | Human-readable diagnostic or continuation guidance |
| `host` | object | no | Redaction-safe Sandbox Runtime v2 host summary metadata |
| `runtime` | object | no | Redaction-safe Sandbox Runtime v2 runtime summary metadata |
| `workspace` | object | no | Redaction-safe Sandbox Runtime v2 workspace summary metadata |
| `security` | object | no | Redaction-safe Sandbox Runtime v2 security summary metadata |
| `networkProxySession` | object | no | Sanitized network proxy-session metadata for policy debugging; metadata only and not proof of live enforcement |
| `credentialProxyPlan` | object | no | Sanitized credential proxy plan metadata; safe identifiers and enum-like metadata only |
| `credentialProxySession` | object | no | Sanitized credential proxy session metadata; safe identifiers and enum-like metadata only |
| `credentialProxyBindings` | array | no | Sanitized credential proxy binding metadata; safe identifiers, safe secret references, and enum-like metadata only |
| `credentialDelivery` | object | no | Sanitized credential delivery status metadata; requested versus active mode labels only |
| `lease` | object | no | Redaction-safe Sandbox Runtime v2 lease summary metadata |
| `workerRouting` | object | no | Redaction-safe worker-backed execution route metadata |
| `templateLock` | object | no | Redaction-safe template acquisition lock metadata; digest and status labels only |

Sandbox metadata is safe for durable local records. It must not include tokens,
private keys, secret names, secret values, raw filesystem paths, raw workspace
paths, raw credentials, API keys, lease holders, provider credentials, or unsafe
environment details. Credential proxy metadata is metadata-only and must not
include raw hosts, URLs, ports, headers, bodies, environment values, socket
paths, local paths, credential values, or secret values. In Phase 26, credential
proxy persistence is limited to non-factory sandbox execution manifests and
factory sandbox metadata; factory timeline events do not mirror credential
proxy plan, session, or binding metadata. Template lock metadata must not
include local paths, raw registry endpoints, query strings, credentials, tokens,
or secret-like values.

When `sandbox.connection` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `address` | string | no | Preferred safe display address for the sandbox |
| `publicIp` | string | no | Public IP address when safe to display |
| `tailscaleIp` | string | no | Tailscale IP address when available |
| `tailscaleHostname` | string | no | Tailscale hostname when available |
| `tailscaleLockdown` | boolean | no | Whether provider access expects Tailscale-only connectivity |

When `sandbox.host` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Stable host identifier |
| `name` | string | yes | Redaction-safe host display name |
| `kind` | string | yes | Host kind, such as `local`, `ssh`, `worker`, or `k8s` |

When `sandbox.runtime` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `driver` | string | yes | Runtime driver, such as `ssh_machine`, `rootless_podman`, or `microvm` |
| `isolationLevel` | string | yes | Runtime isolation level, such as `host`, `container`, or `vm` |
| `runtimeId` | string | yes | Stable runtime identifier |
| `image` | string | yes | Runtime image or image reference when known |
| `workerId` | string | yes | Worker identifier associated with the runtime when known |

For factory sandbox runs, `rootless_podman` is an experimental lower-isolation
local container runtime. Its `sandbox.runtime.isolationLevel` is `container`;
consumers must not treat it as VM isolation or as the production default runtime.
When rootless Podman uses the current compatibility security posture,
`sandbox.security.network.policyEnforced` is `best_effort` and
`sandbox.security.network.enforcementMode` is `none`.

When `sandbox.workspace` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | string | yes | Workspace materialization mode, such as `clone`, `copy`, or `direct` |
| `inputSource` | string | yes | Workspace input source, such as `remote_ref`, `git_bundle`, or `copy` |
| `branch` | string | yes | Branch associated with the workspace |
| `syncRef` | string | yes | Redaction-safe synchronization reference |

When `sandbox.security` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `network` | object | no | Redaction-safe network policy summary |
| `secrets` | object | no | Redaction-safe secret delivery summary |
| `capabilityReadiness` | object | no | Additive security capability readiness output with redaction-safe result metadata |
| `capabilityReadinessDiagnostics` | object | no | Additive advisory diagnostics derived from redaction-safe capability readiness output |

When `sandbox.security.network` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policyRequested` | string | no | Requested network policy summary |
| `policyEnforced` | string | no | Enforced network policy summary |
| `enforcementMode` | string | no | Network enforcement mode, such as `none`, `best_effort`, `proxy`, `firewall`, `runtime`, or `proxy_firewall` |
| `policyResult` | object | no | Additive effective policy metadata with requested/effective intent, enforcement capability, selected enforcement mode, and redaction-safe warnings |

When `sandbox.networkProxySession` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Safe proxy-session identifier |
| `source` | string | yes | Decision source label, such as `factory` |
| `policySnapshot` | object | no | Safe policy snapshot identity |
| `enforcementMode` | string | no | Metadata-only enforcement mode, such as `none`, `best_effort`, `proxy`, `firewall`, `runtime`, or `proxy_firewall` |

When `sandbox.networkProxySession.policySnapshot` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Safe policy snapshot identifier |
| `version` | string | no | Safe policy snapshot version identifier |
| `preset` | string | no | Policy preset identifier, such as `deny_by_default`, `allow_listed`, `best_effort`, `disabled`, or `legacy_default` |
| `ruleSetId` | string | no | Safe rule-set identifier |

When `sandbox.security.secrets` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `requestedModes` | array | no | Requested secret delivery mode identifiers; mode names are safe summaries only |
| `activeModes` | array | no | Active secret delivery mode identifiers; mode names are safe summaries only |

When `sandbox.credentialDelivery` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Safe credential delivery status identifier |
| `requestId` | string | no | Safe request identifier |
| `planId` | string | no | Safe delivery plan identifier |
| `activationId` | string | no | Safe activation identifier |
| `requestedModes` | array | no | Requested delivery mode identifiers; mode names are safe summaries only |
| `activeModes` | array | no | Active delivery mode identifiers; omitted for plan-only metadata |
| `status` | string | no | Sanitized lifecycle status, such as `planned`, `ready`, `active`, `completed`, `skipped`, `failed`, or `disabled` |
| `reasonCode` | string | no | Sanitized reason code |
| `warningCount` | number | no | Count of sanitized warning records |
| `errorCount` | number | no | Count of sanitized error records |

When `sandbox.lease` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Stable lease identifier |
| `hostId` | string | yes | Stable selected host identifier associated with the lease |
| `hostName` | string | yes | Redaction-safe selected host display name |
| `runtimeDriver` | string | yes | Selected runtime driver associated with the lease, such as `ssh_machine`, `rootless_podman`, or `microvm` |
| `resourceKey` | string | yes | Redaction-safe leased resource key |
| `purpose` | string | yes | Lease purpose |
| `runId` | string | yes | Factory run identifier associated with the lease |
| `acquiredAt` | string | yes | RFC 3339 timestamp when the lease was acquired |
| `expiresAt` | string | yes | RFC 3339 timestamp when the lease expires |

When `sandbox.workerRouting` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `selectedWorkerHostId` | string | yes | Stable identifier of the selected worker host |
| `selectedWorkerHostName` | string | yes | Redaction-safe display name of the selected worker host |
| `runtimeDriverId` | string | yes | Selected runtime driver ID, such as `rootless_podman` |
| `isolationLevel` | string | yes | Selected isolation level, such as `host`, `container`, or `vm` |
| `endpointSummary` | string | yes | Safe endpoint summary, such as `local Unix socket`; raw socket paths, hostnames, credentials, query strings, and temp paths are omitted |

Factory sandbox workspace metadata intentionally omits repository paths, raw
workspace paths, and raw filesystem paths. Factory sandbox security metadata
intentionally omits secret names, secret values, tokens, credentials, private
keys, provider credentials, and raw environment values. Factory sandbox lease
metadata intentionally omits the lease holder. Worker routing metadata
intentionally omits raw endpoint values and filesystem paths.

## Source Metadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kind` | string | yes | Source kind, such as `auto_discovery`, `markdown`, `report`, or `prd` |
| `path` | string | no | Source file path when the run started from a local file |
| `reportPath` | string | no | Report path when the run started from an analysis report |
| `title` | string | no | Human-readable source title |

## Artifact Summary

When `artifacts` is present, each entry may contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | no | Stable artifact identifier |
| `name` | string | yes | Stable artifact label |
| `type` | string | yes | Artifact category, such as `json`, `markdown`, `text`, or `url` |
| `path` | string | no | Display path for file artifacts, or `"[redacted]"` when only a raw URL is available |
| `storedPath` | string | no | Store-relative path for persisted artifact payloads |
| `sizeBytes` | integer | no | Stored artifact payload size in bytes |
| `createdAt` | string | no | RFC 3339 timestamp of artifact creation |
| `summary` | object | no | Sanitized artifact-specific summary values |
| `warnings` | array | no | Sanitized artifact warnings |
| `partial` | boolean | no | True when the artifact record is incomplete or warning-only |

Raw `sourcePath` and `url` fields from stored run records are intentionally omitted from this JSON surface.

## Handoff Summary

When `handoff` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `runId` | string | yes | Run identifier the handoff summary describes |
| `status` | string | yes | Stored run lifecycle status |
| `executorMode` | string | yes | Stored executor mode |
| `handoffRequired` | boolean | yes | True when a failed run has actionable follow-up guidance |
| `nextAction` | object | no | Structured suggested next action for failed resumable/takeover runs |
| `inspectCommand` | string | no | Safe command for inspecting the durable run record |
| `resumeCommand` | string | no | Safe local resume command when saved auto state permits continuation |
| `sshCommand` | string | no | Safe sandbox SSH command when the recorded sandbox status is running |
| `repoPath` | string | no | Repository path recorded for local handoff |
| `branchName` | string | no | Branch recorded for the run |
| `sandboxName` | string | no | Sandbox name recorded for sandbox-backed runs |
| `pullRequestUrl` | string | no | Safe PR URL when already available from stored artifacts |
| `currentStep` | string | no | Current or failed pipeline step |
| `failureReason` | string | no | Stored failure message |
| `artifactLocations` | array | no | Non-log artifact display/store locations relevant to handoff |
| `logLocations` | array | no | Log artifact display/store locations relevant to handoff |

`handoff` is derived only from durable factory store records and stored artifact
payloads. It does not perform live sandbox, GitHub, shell, network, or engine
lookups. Default handoff fields must not include raw IP addresses, SSH hosts, or
credentials.

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

## Verification Record

When `verification` is present, it contains metadata copied from the `verify-v1` result:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `summary` | object | yes | Aggregate verification counts |
| `artifacts` | array | no | Verification artifact references emitted by `hal verify --json` |

The `summary` object uses the `verify-v1` summary field names:

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Total verification checks |
| `passed` | integer | Checks with `pass` status |
| `failed` | integer | Checks with `fail` status |
| `timedOut` | integer | Checks with `timeout` status |
| `missing` | integer | Checks with `missing` status |
| `skipped` | integer | Checks with `skipped` status |
| `warnings` | integer | Warning-producing optional checks |

Each verification artifact reference uses the `verify-v1` artifact shape:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `checkId` | string | yes | Verification check identifier |
| `kind` | string | yes | Artifact kind, such as `stdout` or `stderr` |
| `path` | string | yes | Local path emitted by `hal verify --json` |

## Telemetry

When `telemetry` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `totalDurationMs` | integer | no | Derived total run duration in milliseconds |
| `stepDurations` | array | no | Derived per-step duration records |
| `engine` | object | no | Engine name and model metadata when available |
| `sandbox` | object | no | Sandbox provider and size telemetry when available |
| `estimatedSandboxCost` | object | no | Estimated sandbox cost when provider, size, pricing, and duration are available |
| `ciOutcome` | string | no | CI outcome when available |
| `verificationOutcome` | string | no | Verification outcome when available |
| `artifactCount` | integer | no | Count of artifact metadata records stored on the run |
| `failureCategory` | string | no | Normalized failure category for failed runs, such as `validation`, `pipeline`, `engine`, `git`, `ci`, or `unknown` |

Each `stepDurations` entry contains `step`, `startedAt`, `finishedAt`, and
`durationMs`. `engine` contains `name` and `model`. `sandbox` contains
`provider` and `size`. `estimatedSandboxCost` contains `amountUsd` and
`estimated`.

## Failure Summary

When `failure` is present:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `step` | string | yes | Step that failed |
| `category` | string | no | Failure category, such as `validation`, `pipeline`, `engine`, `git`, `ci`, or `unknown` |
| `message` | string | yes | Human-readable failure summary |
| `recoverable` | boolean | yes | Whether an automated retry or fix can continue the run |
| `suggestedCommand` | string | no | Suggested inspection, retry, or resume command when safely available |
| `exitCode` | integer | no | Process exit code when available and non-zero |

## Status Values

| Status | Meaning |
|--------|---------|
| `pending` | Run record exists but execution has not started |
| `running` | Run is actively progressing |
| `succeeded` | Run completed successfully |
| `failed` | Run reached a terminal failure |
| `canceled` | Run was stopped before completion |

## Executor Mode Values

| Mode | Meaning |
|------|---------|
| `local` | Run was executed by the local factory executor wrapping the local auto pipeline |
| `sandbox` | Run was executed by a sandbox-backed factory executor wrapping the remote auto pipeline |

## Timeline

The `timeline` array uses the factory timeline event surface documented in `docs/contracts/factory-timeline-v1.md`.

Timeline events are returned in stored append order. Consumers must not assume the array is sorted by `sequence`, because records preserve durable append order for auditability.

## Error Behavior

If `<run-id>` does not exist, the command returns a non-zero error with the message:

```text
factory run "<run-id>" not found
```

No JSON payload is written for missing run IDs. Store resolution, run parse, or timeline load failures also return non-zero command errors. On failures, consumers should treat stdout as undefined and rely on the command exit status.

## Example Artifact

- `docs/contracts/examples/factory-status-v1.json`
