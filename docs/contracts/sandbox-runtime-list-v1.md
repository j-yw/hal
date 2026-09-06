# Sandbox Runtime List Contract v1

**Command:** `hal sandbox runtime list <host-id> --json`
**Contract Type:** `sandbox-runtime-list`
**Contract Version:** `sandbox-runtime-list-v1`
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

**Privacy boundary:** This contract summarizes host endpoints and runtime
metadata without exposing raw socket paths, hostnames, credentials, URL query
strings, temp paths, or sensitive endpoint details. Consumers that need exact
endpoint values should read the durable host registry directly in a trusted
local context.

## Top-Level Structure

These fields are always present.

| Field | Type | Description |
|-------|------|-------------|
| `contractType` | string | Always `"sandbox-runtime-list"` for this contract family |
| `contractVersion` | string | Always `"sandbox-runtime-list-v1"` for this contract |
| `host` | object | Safe host identity and endpoint summary |
| `source` | object | Indicates whether runtime metadata came from cached durable state, a live refresh, or an unsupported live request |
| `runtimes` | array | Runtime entries sorted by runtime `id` |
| `capacity` | object | Host capacity summary from durable or live metadata |
| `security` | object | Host security posture summary with requested controls separated from enforced controls |
| `diagnostics` | array | Non-fatal diagnostics, such as unsupported live inspection |
| `errors` | array | Fatal errors for callers that request JSON error output |

## Host

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Requested durable host identifier |
| `name` | string | Durable display name for the host, or the host id when no name is available |
| `kind` | string | Host kind, such as `"worker"`, `"ssh"`, `"local"`, or `"k8s"` |
| `endpoint` | object | Safe endpoint summary; raw endpoint values are not emitted |

## Endpoint

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Summary type: `"unix_socket"`, `"endpoint"`, `"configured"`, or `"none"` |
| `summary` | string | Human-readable safe summary, such as `"local Unix socket"` or `"ssh endpoint"` |
| `scheme` | string or null | Endpoint scheme such as `"unix"` or `"ssh"`, or `null` when no scheme is known |

Raw Unix socket paths, URL hosts, credentials, query strings, temp paths, and
sensitive endpoint details are omitted.

## Source

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | `"cached"`, `"live-refreshed"`, or `"unsupported-live"` |
| `requestedLive` | boolean | Whether the caller requested live runtime inspection |
| `cacheUpdated` | boolean | Whether this call updated durable host metadata. Phase 16 live runtime inspection does not update durable records, so this is `false`. |
| `refreshedAt` | string or null | RFC 3339 timestamp for a successful live refresh, or `null` for cached and unsupported-live output |
| `summary` | string | Human-readable source summary |

Source modes:

| Value | Meaning |
|-------|---------|
| `cached` | Runtime metadata was read from durable host records only |
| `live-refreshed` | Runtime metadata was queried from a supported live worker endpoint for this response |
| `unsupported-live` | Live inspection was requested, but the host kind or endpoint does not support live worker inspection; cached durable metadata is returned |

## Runtime Entry

These fields are always present on every entry in the `runtimes` array.

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Runtime driver id, such as `"rootless_podman"` or `"ssh_machine"` |
| `hostKind` | string or null | Runtime host kind from live capabilities, or `null` when cached durable metadata only includes the runtime id |
| `isolationLevel` | string or null | Runtime isolation level from live capabilities, or `null` when unknown |
| `supportedOperations` | array | Sorted supported operation ids, or an empty array when unknown |
| `selectedTemplate` | object | Sanitized selected-template status for this runtime |
| `security` | object | Runtime-level requested/enforced security summary, or empty requested/enforced objects when unknown |
| `diagnostics` | array | Runtime-specific diagnostics, or an empty array |

Runtime entries are sorted by `id` in ascending bytewise order.

## Selected Template

`selectedTemplate` is always present on runtime entries. It is a status
projection only: command code formats already-sanitized runtime metadata and
readiness diagnostics, while template reference parsing, acquisition, provenance
locking, and trust-policy decisions remain in internal template packages.
Runtime status commands do not acquire templates or contact live template
sources; default acquisition coverage remains fake/local.

| Field | Type | Description |
|-------|------|-------------|
| `state` | string | `"trusted"`, `"unresolved"`, `"rejected"`, `"advisory"`, `"unavailable"`, `"absent"`, or `"unknown"` |
| `present` | boolean | Whether selected-template metadata was present |
| `sourceKind` | string | Optional safe source kind such as `"local_file"` or `"template_reference"` |
| `referenceKind` | string | Optional safe reference kind such as `"local"`, `"git"`, or `"oci_artifact"` |
| `lockStatus` | string | Optional lock status, such as `"locked"` or `"unresolved"` |
| `trustMode` | string | Optional trust-policy mode, such as `"strict"` or `"advisory"` |
| `trustDecision` | string | Optional trust decision, such as `"trusted"` or `"rejected"` |
| `digest` | object | Optional locked digest with `algorithm`, `value`, and safe digest `source` |
| `provenanceStatus` | string | Optional provenance status derived from lock metadata |
| `provenanceLabels` | array | Optional safe provenance categories, not raw references |
| `readinessStatus` | string | Optional selected-template readiness state |
| `blockedReadinessReasonCodes` | array | Optional strict-readiness blocking reason codes such as `selected_template_trust_rejected` |
| `reasonCodes` | array | Optional sanitized lock/trust reason codes |

Selected-template JSON never includes raw references, local paths, credentials,
URL query strings, endpoints, or socket paths. A locked digest is safe identity
metadata and does not imply network enforcement, credential delivery, or live
runtime proof by itself.

## Capacity

These fields are always present. Unknown numeric values are represented as
`null` instead of being omitted.

| Field | Type | Description |
|-------|------|-------------|
| `summary` | string | Human-readable capacity summary, or `"unknown"` |
| `cpuCores` | integer or null | CPU cores, or `null` when unknown |
| `memoryMb` | integer or null | Memory in MiB, or `null` when unknown |
| `diskGb` | integer or null | Disk in GiB, or `null` when unknown |
| `maxConcurrentSandboxes` | integer or null | Worker concurrency, or `null` when unknown |
| `activeSandboxes` | integer or null | Live active sandbox count, or `null` when unknown |

## Security

Security summaries always separate requested policy from actually enforced
policy. The contract must not imply deny-by-default networking, firewall or
proxy enforcement, credential proxy support, or microVM isolation unless those
claims are present in durable metadata or live worker capabilities.

Secure-default readiness fields are redaction-safe status metadata. They report
strict secure-default readiness decisions, compatibility advisory diagnostics,
blocked reasons, allowed proof summaries, and aggregate reason-code counts when
those inputs are available.

| Field | Type | Description |
|-------|------|-------------|
| `requested` | object | Requested security controls, or an empty object when unknown |
| `enforced` | object | Actually enforced security controls, or an empty object when unknown |
| `networkEnforcementProof` | object | Optional sanitized proof summary for runtime network enforcement; omitted when no safe proof metadata is available |
| `capabilityReadiness` | object | Optional security capability readiness output when projected metadata is available |
| `capabilityReadinessDiagnostics` | object | Optional advisory diagnostic summary derived from sanitized readiness metadata |
| `securityReadinessGate` | object | Optional strict/advisory secure-default decision with safe outcome, reason, and aggregate counts |

Known control fields:

| Field | Type | Description |
|-------|------|-------------|
| `networkPolicy` | string | Network policy, such as `"deny_by_default"` or `"best_effort"` |
| `networkEnforcement` | string | Enforcement mode, such as `"none"` or `"runtime"` |
| `credentialModes` | array | Credential delivery modes, or an empty array |
| `credentialProxyMode` | boolean | Whether credential proxying is reported as active |
| `isolationLevel` | string | Isolation level, such as `"host"`, `"container"`, or `"vm"` |

## Secure-Default Readiness

`securityReadinessGate` is optional and additive. It contains only safe enum-like
metadata: `code`, `outcome`, `policyMode`, `reason`, and `counts`. Strict
secure-default readiness means strict mode reports blocked decisions when
required proof is missing, and compatibility mode reports advisory diagnostics
without claiming live protection. Proof-complete allowed decisions include
reason-code counts so callers can see which proof families were satisfied.

Requested deny-by-default metadata alone does not prove live deny-by-default enforcement.
Requested credential modes alone do not prove active credential delivery.
Template references without locked digest metadata do not prove digest-locked templates.
Requested VM isolation alone does not prove VM isolation.
`networkEnforcementProof` contains only safe IDs, lifecycle labels, result
outcome/mode/support flags, and warning counts. It never includes endpoints,
socket paths, host paths, firewall rules, provider details, credentials, or
environment values, and it reports `proxy_firewall` only when active proxy plus
firewall proof is present.

## Diagnostics And Errors

`diagnostics` contains non-fatal entries. `errors` contains fatal errors when a
JSON error document is emitted. Both arrays are present and use an empty array
when there are no entries.

| Field | Type | Description |
|-------|------|-------------|
| `code` | string | Stable diagnostic or error code |
| `severity` | string | Diagnostic severity such as `"info"` or `"warning"`; diagnostics only |
| `message` | string | Safe human-readable message without raw endpoint details |

## Sparse Metadata

Durable host records may contain only `supportedRuntimes` and no detailed live
capability metadata. Sparse values are represented with stable placeholders:

- Empty arrays for unknown lists, such as `supportedOperations`, `diagnostics`, and `errors`.
- Empty objects for unknown requested/enforced security controls.
- Explicit `null` for unknown scalar values, such as `hostKind`, `isolationLevel`, `refreshedAt`, and numeric capacity fields.

## Examples

The following examples are part of this contract and are decoded by static
contract tests:

- `docs/contracts/examples/sandbox-runtime-list-v1-cached.json`
- `docs/contracts/examples/sandbox-runtime-list-v1-live-refreshed.json`
- `docs/contracts/examples/sandbox-runtime-list-v1-unsupported-live.json`

## Notes

- Cached mode reads durable registry records only and does not contact worker daemons or runtime providers.
- Phase 16 live runtime inspection does not persist live capability results back to durable host records.
- `runtimes` is always present and uses an empty array when no runtime metadata is available.
- Endpoint output is intentionally summary-only. Raw socket paths, hostnames, credentials, URL query strings, temp paths, and sensitive endpoint details are not part of this contract.
- This contract is additive and does not change `sandbox-list-v1`, `sandbox-host-list-v1`, or `sandbox-host-status-v1`.
