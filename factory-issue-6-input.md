# Issue #6: factory sandbox executor

Implement GitHub issue #6 for the Hal factory rollout.

## Goal

Add `hal factory run ... --sandbox` as the first sandbox-backed factory executor entrypoint. A factory run should be able to execute the existing `hal auto` pipeline inside a managed sandbox while preserving local factory run records and timeline events.

## Scope

- Extend `hal factory run` with a `--sandbox` option that selects sandbox-backed execution while keeping existing local execution behavior unchanged when the flag is absent.
- Provision or resolve a sandbox through existing `internal/sandbox` provider abstractions and registry state.
- Execute the remote pipeline through the provider `Exec`/SSH flow, streaming useful remote log lines into the factory event timeline.
- Record redaction-safe sandbox metadata in the durable factory run record: sandbox name, provider, status, connection metadata safe for display, and cleanup or handoff instructions.
- On failure, leave enough metadata for a human or agent to run `hal sandbox ssh <name>` and continue diagnosis.
- Cover the executor path with fake sandbox and fake pipeline dependencies. Avoid real sandbox providers, network calls, GitHub side effects, or long-running `hal auto` in tests.

## Acceptance Criteria

- `hal factory run <source> --sandbox` can run existing `hal auto` remotely through the sandbox provider execution path.
- Local factory run records track the remote sandbox used by the run.
- Timeline events include remote pipeline progress/log output.
- Failure output and saved state include sandbox handoff instructions.
- Existing `hal auto` and existing `hal factory run` local behavior remain unchanged without `--sandbox`.
- Tests cover sandbox resolve/provision behavior, remote exec invocation, metadata persistence, failure handoff metadata, and the no-flag local regression path.

## Constraints

- Follow existing factory patterns in `cmd/factory.go` and `internal/factory`.
- Keep command side effects injectable in tests.
- Reuse existing sandbox types and provider abstractions instead of creating a new provider layer.
- Keep machine-readable JSON contracts and generated CLI docs in sync if durable or command output fields change.
- Do not hand-edit `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt`.
