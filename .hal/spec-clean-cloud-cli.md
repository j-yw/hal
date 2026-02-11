# Feature Spec: Unified Cloud UX for HAL (Clean, No Legacy Abstractions)

## Product Goal
Make cloud execution feel exactly like local execution, with one simple mental model:
- `hal run [--cloud]`
- `hal auto [--cloud]`
- `hal review [--cloud]`

Users should not need to understand backend resource abstractions to get work done.

## Hard Constraints
1. This feature is unreleased, so we can do breaking cleanup now.
2. Do not keep backward compatibility aliases/shims.
3. No secrets in project files.
4. Keep advanced workflows available, but minimal and obvious.

## Final Command Contract

### Primary workflow commands
- `hal run [--cloud]`
- `hal auto [--cloud]`
- `hal review [--cloud]`

### Cloud support commands
- `hal cloud setup`
- `hal cloud doctor`
- `hal cloud list`
- `hal cloud status <run-id>`
- `hal cloud logs <run-id> [--follow]`
- `hal cloud cancel <run-id>`
- `hal cloud pull <run-id> [--artifacts state|reports|all]`
- `hal cloud auth link|import|status|validate|revoke`

### Explicit removals
- remove `hal cloud run`
- remove `hal cloud runs ...` namespace
- remove `hal cloud submit/status/logs/cancel/pull` flat legacy variants
- remove `hal cloud smoke` and `hal cloud env` in favor of `hal cloud doctor`

## UX Principles
1. Intent-first: run work, not infrastructure.
2. Same command, different target via `--cloud`.
3. Sensible defaults with override controls.
4. Avoid extra nouns/abstractions in command names.
5. Clear diagnostics when setup is missing.

## Flags and Behavior

### Shared cloud flags on run/auto/review
- `--cloud`
- `--cloud-profile <name>`
- `--detach`
- `--wait`
- `--json`
- optional overrides: `--repo --base --engine --auth-profile --scope`

### Rules
- `--detach` and waiting are mutually exclusive
- machine output should be valid JSON when `--json` is used
- local behavior remains unchanged when `--cloud` is absent

## Config Model

### `.hal/cloud.yaml` (non-secret defaults only)
- default profile name
- per-profile mode/endpoints/default repo/base/engine/auth profile/scope
- behavior defaults like wait and pull policy

### Precedence
CLI flags > process env > `.env` (non-overriding) > `.hal/cloud.yaml` > inferred defaults > hard defaults

## Execution Model
Every cloud run should persist workflow type:
- run
- auto
- review

Worker must execute corresponding command:
- run kind -> `hal run ...`
- auto kind -> `hal auto ...`
- review kind -> `hal review ...`

Do not use invalid command constructions like `hal auto --mode ...` for workflow selection.

## Artifact and Pull Policy
- include state files required to continue local/cloud workflow
- include reports for auto/review flows
- pull supports `state`, `reports`, or `all`
- safe overwrite behavior unless force is specified

## Setup and Doctor
`hal cloud setup`:
- guided setup for profile defaults and mode
- writes `.hal/cloud.yaml`

`hal cloud doctor`:
- validates profile/config resolution
- checks connectivity and auth readiness
- provides actionable next-step hints

## Security
- no secrets in `.hal/cloud.yaml`
- strict redaction in logs/events/errors
- avoid leaking DSNs/tokens/secret refs
- replace placeholder auth import behavior with real secure handling

## Implementation Plan (high-level)
1. Command cleanup first (remove legacy/duplicate commands)
2. Add `hal cloud list` + store support
3. Add profile runtime, setup, doctor
4. Add `--cloud` paths to run/auto/review
5. Persist workflow kind and execute correctly in worker
6. Finish pull/artifact UX
7. Complete auth/security hardening
8. Update tests and docs

## Acceptance Criteria
A new user should be able to do:
1. `hal cloud setup`
2. `hal run --cloud`

And get:
- successful cloud run submission
- visible progress/logs
- terminal summary
- stable follow-up controls via list/status/logs/cancel/pull

Also:
- command help is clean and minimal
- removed commands are truly unavailable
- all command and cloud tests pass
