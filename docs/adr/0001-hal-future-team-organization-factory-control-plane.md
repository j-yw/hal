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

## Control-Plane Domain Model

The future shared control plane should use a small set of stable domain terms so
implementation PRDs can extend the architecture without redefining core
ownership concepts.

A user is an authenticated actor that can initiate Hal workflows, inspect
authorized artifacts, receive assignments, and perform control-plane operations
according to role and project membership. A user may act as an individual
contributor, project maintainer, organization owner, or automation identity, but
the control plane should still model the actor consistently as a user.

An owner is a user or owner group with organization-level administrative
authority. Owners manage organization membership, organization policy,
project creation defaults, and other control-plane settings that apply above a
single project. Owner status is not the same as membership in every project:
owners may have broad administrative authority while still needing explicit or
policy-derived access for project-scoped workflow operations.

An organization is the top-level shared administrative boundary. It groups
users, owners, projects, policy defaults, audit records, and shared factory
resources under one governance context. Organization-scoped settings establish
the default posture for projects, but they should not expose implementation
details through CLI JSON contracts unless a future contract revision documents
those fields.

A project is the unit that maps Hal factory work to a repository, workspace, or
other implementation-defined codebase boundary. Projects own queues, runs,
project-scoped policy overrides, project artifacts, and project membership.
Future implementations may map one organization to many projects, and a single
project should belong to exactly one organization for authorization and audit
purposes.

Project membership is the project-level relationship between a user and a
project. Membership grants project-scoped abilities such as viewing project
queues, starting or reviewing runs, reading artifacts, or administering project
settings according to the assigned role. This is distinct from
organization-level ownership: organization owners govern the organization and
its defaults, while project members participate in or administer a specific
project's workflows.

## RBAC and Authorization Boundary

The future shared control plane is responsible for authorization. It should
evaluate who may inspect or mutate organization, project, queue, run, artifact,
and policy resources before any shared operation is accepted. Local CLI callers
may request actions, but the shared control plane must make the final
authorization decision for hosted or networked resources.

Queue operations should require project-scoped permissions. Users who can view a
project may inspect authorized queue state, while creating, prioritizing,
assigning, retrying, cancelling, or removing queue items should require roles
that explicitly allow coordination of factory work for that project. Queue
authorization should also account for organization policy, project membership,
and ownership of the queue item when future implementations define those
details.

Run operations should be authorized separately from queue visibility. Starting a
run, claiming a run lease, extending a lease, cancelling a run, approving a
retry, or attaching run results should require project membership or an
automation identity with run privileges. Read-only access to run status may be
broader than mutation access, but mutation rights should be limited to actors
trusted to affect repository state, engine execution, CI, or review output.

Artifact access should be governed by the project and organization that own the
artifact. PRDs, reports, logs, review results, archived state, and run output may
contain source context, issue details, credentials-adjacent diagnostics, or
decision history. The control plane should enforce read, write, retention, and
export permissions consistently across artifact types rather than relying on
artifact path conventions or client-side filtering.

Policy operations should be restricted to the administrative boundary that owns
the policy. Organization owners manage organization-wide defaults and guardrails;
project administrators manage project-scoped overrides only when organization
policy allows them; run-level overrides should be limited to actors authorized
to start or administer that run. Local developer overrides may remain useful for
ergonomics, but shared policy decisions must be validated by the control plane
before they influence hosted queue, run, or artifact behavior.

Authorization internals are not CLI JSON contract details. Role names,
permission graphs, membership expansion, owner-group resolution, and policy
evaluation traces should remain hidden backend implementation details unless a
future `docs/contracts/` revision explicitly adds a field, state value, action
identifier, or diagnostic surface for them.

## Shared Queue and Run Lifecycle

The future shared control plane should model factory coordination as explicit
queue items and runs. A queue item is created when authorized work is submitted
for a project, validated against policy, and recorded with enough immutable
intent to reproduce why the work exists. It may then move through pending,
ready, claimed, running, blocked, completed, failed, cancelled, or expired
states as future implementation PRDs define the exact state names. Completion
should attach durable results and artifact references; failure should attach
diagnostics, retry eligibility, and the actor or automation identity that made
the terminal transition.

A run is the execution attempt that works a queue item. Runs should be claimed
through leases rather than by trusting a local process or worktree. A lease
identifies the actor, project, queue item, run attempt, lease owner, expiration
time, and any implementation-defined execution environment. Only the current
lease holder should be allowed to append mutable run output, extend the lease,
mark the run complete, mark the run failed, or release the claim, subject to the
authorization boundary above.

Heartbeat updates should be required for active leases. The control plane
should record heartbeat time separately from terminal state transitions so it
can distinguish a healthy long-running attempt from an abandoned one. Heartbeat
cadence, grace periods, and maximum lease duration are policy decisions, but
future implementations should make them explicit enough for operators to reason
about stuck work without inspecting local `.hal/` files.

Cancellation should be a first-class transition. An authorized user or policy
may cancel a pending queue item before a run starts, request cancellation of an
active run, or force a terminal cancelled state after the control plane has
recorded that the lease holder did not complete cleanup in time. Cancellation
should preserve audit records and partial artifacts rather than deleting the
history that explains why work stopped.

Stale lease detection should be handled by the control plane using lease
expiration and missing heartbeat signals. Recovery may requeue the item, create
a new run attempt, mark the run failed, or require manual operator action,
depending on project policy and retry limits. Recovery should never require two
agents to coordinate by editing the same local runtime files; the shared
control plane owns the authoritative transition.

Queue and run transitions should be concurrency-safe. Claiming work, extending
leases, cancelling work, retrying failed attempts, and writing terminal results
should use compare-and-set semantics, version checks, database transactions, or
another future implementation mechanism that prevents two actors from
successfully making conflicting transitions. Concurrent read operations may be
broadly available to authorized users, but mutating operations should have a
single accepted winner and a clear conflict response for losing callers.

Transition requests should also be idempotent. Retried create, claim,
heartbeat, cancel, complete, fail, and retry requests should either return the
same accepted result for the same idempotency key or report the existing
terminal state without duplicating queue items, run attempts, artifacts, audit
entries, or repository side effects. Idempotency keys, attempt identifiers, and
artifact references should be treated as backend implementation details unless
a future CLI contract deliberately exposes them.

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
