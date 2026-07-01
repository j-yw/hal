# ADR 0002: Parallel Run Core

## Status

Proposed

## Context

`hal run` and the run step of `hal auto` currently execute PRD stories
sequentially. That preserves correctness because one fresh agent owns the
current working tree, commits one story, updates `.hal/prd.json`, appends
`.hal/progress.txt`, and then the next iteration observes the resulting state.

Parallel execution should improve throughput without letting multiple agents
write the same checkout, branch, git index, or canonical Hal state at the same
time.

The sandbox runtime v2 work is still active on separate branches. Parallel run
core should start from `develop` and avoid depending on unstable sandbox
internals. Sandbox-backed parallel workers can be added later through a
workspace-provider adapter once the sandbox workspace/runtime APIs stabilize.

## Decision

Implement local worktree-backed parallel execution first.

The core architecture is:

```text
hal run/auto
  -> ParallelCoordinator
      -> PRD scheduling contract
      -> dependency audit
      -> task graph scheduler
      -> workspace provider
          -> local git worktree provider
          -> sandbox workspace provider later
      -> worker runner
      -> worker manifest store
      -> serial integrator
      -> final review/CI gates
```

The core invariants are:

- `--parallel N` is a maximum concurrency limit, not a guarantee that N workers
  will launch.
- Each worker gets exactly one assigned task and one unique writable workspace.
- Workers do not edit canonical `.hal/prd.json` or `.hal/progress.txt`.
- Hal alone updates canonical PRD/progress state during serial integration.
- Integration is serial even when implementation is parallel.
- Unknown or low-confidence dependency/conflict metadata falls back to serial
  execution.
- Shared writable direct mounts are forbidden for automatic parallel workers.
- Sandbox-backed parallel execution is a later adapter, not a prerequisite for
  the local worktree core.

## Scheduling Contract

The runtime PRD remains `.hal/prd.json`, but stories/tasks gain scheduling
metadata:

```json
{
  "id": "T-003",
  "dependsOn": ["T-001"],
  "conflictDomains": ["internal/factory", "cmd/factory"],
  "parallelSafe": true,
  "barrier": false,
  "parallelReason": "Uses the queue store API introduced by T-001",
  "passes": false
}
```

`dependsOn` controls readiness. `conflictDomains` controls which otherwise-ready
tasks cannot share a batch. `barrier` forces a task to run alone. `parallelSafe`
allows conversion/audit to mark tasks as serial without inventing fake
dependencies.

## Worker Lifecycle

For local mode, Hal creates worker branches and worktrees under a configured
root such as:

```text
.worktrees/hal-runs/<run-id>/<task-id>
```

Worker branch names include the canonical feature branch, task ID, and run ID to
avoid collisions:

```text
hal/<feature>/task-T-003/run-<id>
```

Workers receive assigned-task prompts. They commit implementation changes and
write a worker manifest containing task ID, branch, commit, checks, changed
files, and a proposed progress entry.

## Integration Lifecycle

The serial integrator checks out the canonical feature branch, integrates one
worker commit at a time, runs checks, marks the task passing in `.hal/prd.json`,
appends `.hal/progress.txt`, and records success. On conflict or check failure,
the integrator aborts, preserves the worker workspace, and records a handoff
without marking the task complete.

## Concurrency Policy

The actual worker count is:

```text
min(requested_parallel, configured_max_workers, safe_ready_tasks, resource_budget)
```

Default policy should be conservative:

```yaml
parallel:
  workers: 3
  maxWorkers: 6
  allowHighConcurrency: false
  worktreeRoot: .worktrees/hal-runs
  cleanup: success
  preserveFailed: true
```

When a user requests `--parallel 10`, Hal may launch fewer than 10 workers and
must explain why in human and JSON output.

## Implementation Sequence

1. Add PRD scheduling fields, conversion guidance, and validation.
2. Add dependency audit/repair around converted PRDs.
3. Add command-agnostic task graph scheduler and dry-run planning output.
4. Add local worktree manager.
5. Add worker prompt and manifest primitives.
6. Add serial integrator.
7. Wire `hal run --parallel` to local worktrees.
8. Wire `hal auto --parallel` to the run step only.
9. Add sandbox workspace provider after sandbox runtime APIs stabilize.

## Consequences

Parallel implementation can deliver speedups for independent tasks while
preserving Hal's existing correctness model. The main cost is more orchestration
state, more git lifecycle management, and conservative fallback behavior when
the graph is uncertain.

The design intentionally avoids shared writable workspaces. It also avoids
coupling the first implementation to the active sandbox branch, reducing merge
churn while sandbox runtime v2 is still in progress.
