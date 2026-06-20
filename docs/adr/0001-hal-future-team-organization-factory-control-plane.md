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

Factory workflow and run execution are scoped to the worktree where the command
runs. A separate Git worktree has its own `.hal/` runtime directory, branch
checkout, working tree changes, generated artifacts, and engine process
context. Current factory workflow commands do not coordinate run state across
sibling worktrees, other clones, other users, or organization-level project
views.

Sandbox management is an existing local-machine global exception to the
worktree-local boundary: sandbox configuration and registry entries live under
`$HAL_CONFIG_HOME`, `$XDG_CONFIG_HOME/hal`, or `$HOME/.config/hal`. That
sandbox state may be shared by sibling worktrees on the same machine, but it is
not the future organization control plane and does not provide shared project
membership, queue, artifact, or run authority.

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

Examples of current stable contract areas include:

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

This list is non-exhaustive. Every current and future formal JSON contract
document under `docs/contracts/` remains part of the compatibility surface,
including plan, CI, sandbox, status, doctor, continue, and auto contracts.

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

## Shared Artifact and Audit Model

The future shared control plane should treat artifacts as project-owned records
stored in a durable shared artifact store. The artifact store is the shared
source for organization and project collaboration, while local `.hal/` files
remain the current CLI runtime boundary until a future implementation PRD and
contract update deliberately changes that behavior.

PRD artifacts should include the submitted requirements source, canonical PRD
representation, generated planning context where retained, branch or project
association, author or automation identity, timestamps, and provenance needed to
explain why the work entered the factory. A shared PRD artifact may have many
local projections, but the control plane should keep the shared record stable
enough for review, retry, audit, and migration workflows.

Report artifacts should cover generated auto-pipeline reports, summary reports,
review reports, CI or handoff summaries, and any future project-level status
reports. Reports should be associated with the organization, project, queue
item, run, commit range, and producing actor where applicable. Once finalized,
reports should be immutable or versioned so later retries do not silently
replace the evidence used for previous decisions.

Log artifacts should capture engine logs, command transcripts, execution
diagnostics, and operator-visible warnings that are needed to debug a shared
run. Log storage should support retention, redaction, and segmented upload so
large or sensitive logs can be handled without relying on local filesystem path
conventions. Logs may be streamed while a run is active, but finalized log
records should remain tied to the run and lease context that produced them.

Review-result artifacts should preserve review-loop JSON and markdown outputs,
including issue findings, validation results, fixed issue counts, affected
files, recommendations, and iteration summaries. These artifacts are part of
the shared decision record for whether work can proceed, but their persisted
shape should remain aligned with documented artifact contracts rather than
leaking backend reviewer, queue, or lease internals into CLI JSON surfaces.

Run-output artifacts should include stdout and stderr summaries, command exit
metadata, generated file references, patch or diff summaries, and any other
durable output needed to reconstruct what a run did. Only the authorized lease
holder or control-plane recovery process should append mutable run output for
an active run. Terminal run output should be retained with the queue item and
run attempt so later operators can distinguish completed, failed, cancelled,
and recovered work.

Audit logging should be append-only for control-plane decisions. Decisions that
should produce audit records include authorization allow or deny outcomes,
policy resolution, queue creation and prioritization, assignment, lease claims,
heartbeat acceptance or rejection, cancellation, retries, artifact retention or
export, and administrative overrides. Each audit record should identify the
actor or automation identity, organization, project, resource class, decision
class, timestamp, outcome, and enough rationale or policy reference for an
operator to understand the decision without exposing hidden role graphs or
permission evaluation internals.

State transitions should also be audited. Queue item and run transitions should
record the previous state, requested next state, accepted next state, actor,
policy or version precondition, terminal reason when applicable, and links to
the artifacts produced by the transition. Failed or rejected transition attempts
should leave an audit trail when they affect operator understanding, such as
conflicting lease claims, stale heartbeat rejection, unauthorized cancellation,
or retry denial.

Data ownership follows the organization and project model. The organization
owns the top-level governance context, while projects own their queues, runs,
and artifacts within that organization. Access to PRDs, reports, logs, review
results, run output, audit records, exports, and retention controls should be
authorized through the control plane rather than through storage keys, URLs, or
local path conventions. Future implementations should define retention,
deletion, export, and redaction behavior explicitly so project members can
collaborate without weakening organization-level data governance.

## Policy Inheritance and Overrides

The future shared control plane should resolve policy through explicit
inheritance and bounded overrides. Policies define operational requirements such
as queue admission rules, allowed engines or execution environments, lease and
heartbeat limits, retry posture, artifact retention, review or CI gates,
network access, and administrative guardrails. Policy resolution is an
architecture concern for the control plane and should not become a CLI JSON
contract detail unless a future `docs/contracts/` revision deliberately exposes
it.

Organization-level policy is the root of inheritance. Organization owners define
defaults and non-overridable guardrails for all projects in the organization.
Defaults provide the starting posture for new projects, while guardrails define
requirements that project, run, or local settings cannot weaken. Examples
include minimum artifact retention, required audit logging, maximum lease
duration, required review gates, and restrictions on execution environments or
network access.

Project-level policy inherits organization policy and may refine it for a
specific repository, workspace, or codebase boundary. Project administrators may
set project defaults, tighten organization defaults, choose project-specific
engine or CI expectations, define queue concurrency, and configure artifact
visibility when organization policy allows those choices. Project overrides
should be validated by the control plane before they affect shared queues,
runs, artifacts, or audit behavior.

Run-level overrides are request-scoped choices made when an authorized actor
starts, retries, or administers a specific run. They may select an allowed
engine profile, iteration limit, branch target, execution environment, retry
limit, or other operational option within the bounds established by
organization and project policy. Run-level overrides should be recorded with
the run and included in audit context so later operators can explain why a run
used settings that differ from project defaults.

Local overrides remain useful for developer ergonomics, but they should not
change shared governance decisions. Local CLI flags, environment variables, and
worktree configuration may control local presentation, editor preferences,
diagnostic verbosity, local binary paths, local worktree or sandbox paths, and
other machine-specific execution details. They should not override shared
authorization, artifact visibility, retention, queue priority, lease ownership,
or required review and CI gates for hosted or networked control-plane
operations.

Policy precedence should be deterministic:

1. Built-in defaults apply only when no higher policy source sets a value.
2. Organization defaults replace built-in defaults.
3. Project defaults replace organization defaults where organization policy
   allows project choice.
4. Run-level overrides replace project defaults only for the specific run and
   only when both organization and project policy allow the override.
5. Local overrides apply last for local developer ergonomics, but they cannot
   weaken organization guardrails, project restrictions, run authorization, or
   shared artifact and audit requirements.

If a higher policy marks a setting as non-overridable, lower policy sources
must either comply or receive an explicit conflict response. Future
implementations should make conflict handling predictable, auditable, and
recoverable without requiring users or agents to inspect hidden backend policy
graphs or manually edit local `.hal/` runtime files.

## Migration Strategy

Migration from local Hal workflows to a shared control plane should be phased,
opt-in, and compatibility-gated. The existing local `.hal/` runtime files remain
authoritative for current CLI behavior until a future implementation PRD,
contract update, and migration plan deliberately move a specific responsibility
to shared state. Early migration phases should add projections, mirrors, and
diagnostics around local workflows rather than replacing the local source of
truth.

Local file state should migrate by introducing shared records as durable copies
of existing artifacts before any hosted service becomes authoritative. PRDs,
progress logs, reports, review outputs, run output, archive metadata, and
auto-state summaries can be uploaded, mirrored, or referenced by future
commands, but local commands should continue to read and write the existing
files in local mode. Shared records should carry provenance that ties them back
to the worktree, branch, commit range, actor, and CLI version that produced the
local artifact.

Local queue coordination should migrate separately from artifact sharing. The
first shared queue phase should allow authorized users to submit or inspect
queue items without requiring `hal auto`, `hal status`, `hal doctor`,
`hal continue`, or review loops to depend on networked coordination. A later
opt-in phase can let a project claim shared queue items and project them into a
local worktree. Only after lease, heartbeat, cancellation, stale recovery,
idempotency, RBAC, and audit behavior are implemented and tested should the
shared queue become authoritative for hosted runs.

Existing CLI behavior must be preserved during early migration phases. Local
mode should remain available, existing command meanings should stay stable, and
machine-readable fields documented under `docs/contracts/` should not be
renamed or repurposed to expose hosted implementation details. New hosted or
networked behavior should appear as explicit opt-in configuration, new commands,
or additive optional contract fields with documentation and tests.

Future implementation PRDs should use a phased plan:

1. Establish the local baseline by keeping current CLI contracts, local `.hal/`
   state, and documentation-only architecture references unchanged.
2. Add read-only control-plane discovery and diagnostics so projects can verify
   organization, project, auth, and policy readiness without changing local
   execution.
3. Add artifact mirroring for PRDs, reports, logs, review results, run output,
   and audit records while preserving local files as the runtime source of
   truth.
4. Add opt-in shared queue submission and inspection for projects that have
   passed authorization, policy, retention, and audit readiness checks.
5. Add opt-in shared run coordination with leases, heartbeats, cancellation,
   stale recovery, and idempotent terminal transitions while treating local
   auto-state as a projection of the shared run.
6. Consider hosted or networked behavior as a default only after migration,
   rollback, offline fallback, and contract compatibility gates have passed.

Compatibility gates should be explicit before hosted or networked behavior is
introduced. At minimum, future PRDs should require updated contract
documentation and field-locking tests for any JSON surface changes; migration
dry runs and rollback paths for local state; local/offline fallback behavior;
authorization, retention, and audit tests; clear handling for local/shared state
divergence; and operator documentation that explains how a project opts in,
opts out, or recovers from a failed migration.

Open questions for future implementation PRDs include which identity provider
and organization model should back user membership, how projects map to
repositories and worktrees, which artifacts need retention or redaction
controls first, how much historical `.hal/archive/` state should be backfilled,
what conflict response is best when local and shared run state diverge, which
CLI commands should own shared queue submission, and when control-plane
identifiers should become documented CLI contract fields rather than hidden
backend details.

## Non-Goal Guardrails

This ADR does not implement a hosted Hal service or turn local workflows into
networked workflows. It defines architecture terminology and migration
expectations only.

This ADR does not add server processes, API handlers, database schemas,
authentication integrations, hosted schedulers, or networked queues. Those
implementation details require future PRDs, tests, rollout plans, and contract
updates where applicable.

This ADR does not change runtime behavior for `hal auto`, `hal status`,
`hal doctor`, `hal continue`, review loops, report generation, CI commands, or
archive commands. Existing local command semantics remain the compatibility
baseline.

This ADR does not change any existing machine-readable JSON contract. Stable
fields documented under `docs/contracts/` remain unchanged, and future
control-plane identifiers, authorization diagnostics, policy details, queue
state, or backend run internals must not appear in CLI JSON output unless a
future contract revision explicitly adds them.

This ADR does not add local authentication, configuration, or state files for
the future control plane. The current `.hal/` files remain local runtime
artifacts managed by Hal commands.

Hal-owned runtime state files must not be manually modified to simulate future
control-plane behavior. Future implementations should introduce explicit
commands, migrations, dry runs, and repair paths instead of relying on direct
edits to `.hal/prd.json`, `.hal/progress.txt`, `.hal/auto-state.json`, or other
Hal-owned runtime files.

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
