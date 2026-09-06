# sandbox-list-v2

`hal sandbox list --live --json` emits one `sandbox-list-v2` JSON document.
The cached command `hal sandbox list --json` remains `sandbox-list-v1`.

## Top-level object

| Field | Type | Required | Meaning |
|---|---|---:|---|
| `contractVersion` | string | yes | Always `sandbox-list-v2`. |
| `source` | string | yes | `live` when every selected execution summary was validated from the worker; `cached` when any selected execution falls back to durable state. |
| `sandboxes` | array | yes | Safe sandbox entries in deterministic name/ID order. |
| `totals` | object | yes | Sandbox and active-execution counts. |
| `diagnostics` | array | no | Safe per-sandbox live-query diagnostics. |

Each sandbox entry preserves the v1 required identity fields `id`, `name`,
`provider`, `status`, and `createdAt`. It may add safe host/runtime identities
and one `execution` summary using the fields documented by
`sandbox-status-v1`.

`totals.activeExecutions` and every `execution.active` value use the same
definition: only queued or running durable jobs validated against the selected
sandbox/runtime are active. Terminal, interrupted, and unknown jobs are not
active. Worker `activeSandboxes` is independently derived from distinct
queued/running runtime IDs and must converge with these projections.

## Safety

Unlike optional legacy v1 address fields, v2 does not emit IP addresses,
hostnames, endpoints, sockets, URLs, ports, repository locations, host paths,
commands, environment, credentials, secret values, or raw errors. Live-query
failure retains cached safe state, changes the top-level source to `cached`,
and adds a diagnostic; it does not fabricate running or security-enforcement
claims. The conservative top-level `cached` value also covers a mixed list in
which only some execution summaries required durable fallback.

See [`examples/sandbox-list-v2-live.json`](examples/sandbox-list-v2-live.json).
