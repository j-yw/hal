# sandbox-status-v1

`hal sandbox status NAME --json` emits one `sandbox-status-v1` JSON document.
Add `--live` to query the selected worker job before rendering. Without
`--live`, the durable execution manifest is the source.

## Top-level object

| Field | Type | Required | Meaning |
|---|---|---:|---|
| `contractVersion` | string | yes | Always `sandbox-status-v1`. |
| `source` | string | yes | `live` or `cached`. |
| `sandbox` | object | yes | Safe sandbox identity and cached lifecycle metadata. |
| `execution` | object | no | Selected non-factory execution and job projection. |
| `recommendedAction` | string | no | Safe action identifier such as `follow_logs`, `recover`, or `none`. |
| `diagnostics` | array | no | Safe code/message diagnostics; never raw worker errors. |

The `sandbox` object contains `id`, `name`, `provider`, `status`, and
`createdAt`. It may contain safe host/runtime identity under `hostId`,
`runtimeDriver`, `runtimeId`, and `isolationLevel`.

The optional `execution` object contains:

- `runId`, `purpose`, `status`, `startedAt`, and optional `finishedAt`;
- `active`, derived only from queued/running durable or validated live job
  state;
- optional `job` with `id`, `state`, `submittedAt`, optional `startedAt`,
  `heartbeatAt`, `finishedAt`, and `logCursor`;
- optional `finalizationState`, `syncOutRequested`, and safe `reasonCode`.

Live job metadata is used only after its job, submission, worker, host,
runtime-driver, and runtime identities match the durable execution. A live
transport failure preserves the cached state and adds a sanitized diagnostic.
Unknown or interrupted work is inactive and is never presented as successful.

## Safety

The response omits worker/provider endpoints, sockets, IP addresses, URLs,
ports, project/work directories, commands, environment, repository
credentials, secret values, headers, bodies, artifact payload locations, and
raw errors. Runtime success does not upgrade isolation, network enforcement,
credential delivery, or template trust.

## Exit behavior

Selection, corrupt-manifest, identity-mismatch, and required-live failures use
the command's expected non-zero exit behavior. Machine stdout remains either
one complete JSON document or empty; diagnostics and command errors do not
append text to a successful document.

See
[`examples/sandbox-status-v1-live.json`](examples/sandbox-status-v1-live.json).
