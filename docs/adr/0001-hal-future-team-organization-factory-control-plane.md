# ADR 0001: Hal Future Team and Organization Factory Control Plane

## Status

Proposed

## Related Issue

- [ReScienceLab/hal#16](https://github.com/ReScienceLab/hal/issues/16)

## Scope

This ADR is documentation-only. It records the intended architectural direction
for Hal's future team and organization factory control plane and does not
change runtime behavior, command behavior, storage formats, or machine-readable
CLI contracts.

## Context

Hal currently operates as a local CLI-driven factory workflow. Future work may
introduce shared coordination for teams and organizations, but that work needs a
stable architectural reference before implementation PRDs define concrete
runtime changes.

## Current Local Execution Boundary

Hal's current source of workflow state is the local `.hal/` directory in the
active worktree. Runtime files such as `.hal/config.yaml`, `.hal/prd.json`,
`.hal/progress.txt`, `.hal/auto-state.json`, and generated prompt or skill
assets are read and written by the CLI on the local filesystem. These files are
authoritative for the current workflow unless a future implementation PRD
explicitly introduces a shared control-plane state source.

Execution is scoped to the worktree where the command runs. A separate Git
worktree has its own `.hal/` runtime directory, branch checkout, working tree
changes, generated artifacts, and engine process context. Current commands do
not coordinate state across sibling worktrees, other clones, other users, or
organization-level project views.

The local artifact boundary includes markdown and JSON PRDs, progress logs,
auto-state snapshots, generated reports under `.hal/reports/`, archived feature
state under `.hal/archive/`, review-loop outputs, engine logs, and run output
captured by the active workflow. These artifacts are local records first; any
future shared artifact store must preserve the local workflow semantics until a
new contract says otherwise.

Queue coordination is also local today. The current pipeline chooses and resumes
work from local PRD and auto-state files rather than from a shared organization
queue. There is no cross-user leasing, shared run ownership, hosted scheduler,
or organization-wide queue arbitration in the current runtime behavior.

## CLI Machine Contract Boundary

The future control plane must preserve the existing machine-readable CLI
contract boundary for agent integrations. Commands that publish formal JSON
contracts under `docs/contracts/` are the compatibility surface; local storage
choices, hosted service topology, queue implementation details, authorization
internals, and run orchestration internals remain hidden from CLI consumers
unless they are explicitly added to a documented contract.

The stable contract areas are:

- `hal status --json` follows `docs/contracts/status-v1.md`. It exposes the
  workflow track, state, artifact presence, recommended next action, summary,
  and optional details such as the configured engine, manual progress,
  auto-pipeline step detail, review-loop report path, and canonical paths.
- `hal doctor --json` follows `docs/contracts/doctor-v1.md`. It exposes
  readiness checks, ordered check identifiers, check status and applicability,
  remediation identifiers, safe remediation commands, aggregate counts, and
  summary fields.
- `hal continue --json` follows `docs/contracts/continue-v1.md`. It combines
  status and doctor output into a single readiness decision and next command,
  with doctor failures blocking readiness and doctor warnings remaining
  advisory.
- `hal auto --json` follows `docs/contracts/auto-v2.md`. It exposes the
  auto-pipeline result, entry mode, resume flag, fixed step map, step statuses,
  summary, optional error and duration fields, and optional next action.
- Review-loop artifacts written under `.hal/reports/` preserve their persisted
  JSON result shape for review automation, including requested and completed
  iterations, stop reason, aggregate issue/fix totals, affected files, and
  per-iteration issue summaries. Summary reports under `.hal/reports/` remain
  workflow artifacts, not an authorization or backend implementation contract.

Additive extensions are allowed when they follow the existing contract posture:
new optional fields may be added, new optional health checks may be added, and
new step telemetry may be added without renaming or removing documented fields,
state values, action identifiers, check identifiers, or required step keys. A
future hosted control plane may expose organization, project, queue, run,
policy, or audit identifiers through these JSON surfaces only through explicit
contract updates and corresponding tests.

## Decision

Use this ADR as the canonical architectural reference for the future shared
factory control plane. The ADR will describe the current local boundary, CLI
contract compatibility expectations, control-plane domain model, authorization
boundaries, shared queue and run lifecycle, artifact and audit model, policy
precedence, migration strategy, and explicit non-goals.

## Consequences

- Future implementation PRDs can refer to this ADR for terminology and
  compatibility constraints.
- Current Hal runtime behavior remains unchanged by this document.
- Any future hosted or networked control-plane behavior must be introduced by
  separate implementation work with its own tests and contract updates.

## Topics To Define

The following sections track this ADR's major subjects and may be expanded by
subsequent stories:

- Current local execution boundary
- CLI machine contract boundary
- Control-plane domain model
- RBAC and authorization boundary
- Shared queue and run lifecycle
- Shared artifacts and audit logging
- Policy inheritance and overrides
- Migration strategy
- Non-goal guardrails
