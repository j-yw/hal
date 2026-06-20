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

The following sections will be expanded by subsequent stories:

- Current local execution boundary
- CLI machine contract boundary
- Control-plane domain model
- RBAC and authorization boundary
- Shared queue and run lifecycle
- Shared artifacts and audit logging
- Policy inheritance and overrides
- Migration strategy
- Non-goal guardrails
