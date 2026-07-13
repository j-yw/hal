## hal run

Run the Hal loop

### Synopsis

Run the Hal loop to execute tasks from .hal/prd.json.

The loop spawns fresh AI instances that:
1. Read prd.json and pick the highest priority pending story
2. Implement the story
3. Run quality checks
4. Commit changes
5. Update prd.json to mark story complete
6. Repeat until all stories pass or max iterations reached

With --json, outputs machine-readable result JSON suitable for agent
orchestration and tooling integration.

Exit status with --json:
- 0 when ok=true, including successful runs with stories remaining
- 2 when validation or preflight fails after emitting ok=false JSON
- 4 when loop execution finishes with ok=false
- Sandbox execution preserves the inner hal command's nonzero status

Examples:
  hal run                          # Run with defaults (10 iterations)
  hal run 5                        # Run 5 iterations (positional)
  hal run -i 5                     # Run 5 iterations (flag)
  hal run 1 -s US-001              # Run single specific story
  hal run -e codex                 # Use Codex engine
  hal run --timeout 30m            # Override per-session engine timeout
  hal run --dry-run                # Show what would execute
  hal run --base develop           # Branch from develop when needed
  hal run --json                   # Machine-readable result output
  hal run --sandbox                # Run inside a sandbox
  hal run --sandbox 3              # Run 3 iterations inside a sandbox
  hal run --sandbox my-box         # Run inside a named sandbox
  hal run --sandbox --sandbox-sync-out # Collect sync-out handoff metadata without host apply
  hal run --sandbox --sandbox-apply    # Explicit opt-in to automatic eligible host apply
  hal run --sandbox --sandbox-host worker-1 --sandbox-runtime rootless_podman # Explicit worker/rootless target selection


```
hal run [iterations] [flags]
```

### Examples

```
  hal run
  hal run 5
  hal run --story US-001
  hal run --timeout 30m
  hal run --json
  hal run --sandbox
  hal run --sandbox 3
  hal run --sandbox my-box
  hal run --sandbox --sandbox-sync-out
  hal run --sandbox --sandbox-apply
  hal run --sandbox --sandbox-host worker-1 --sandbox-runtime rootless_podman
  hal run --engine codex --base develop
```

### Options

```
  -b, --base string              Base branch for creating the PRD branch (default: current branch, or HEAD when detached)
      --dry-run                  Show what would execute without running
  -e, --engine string            Engine to use (claude, codex, pi) (default "codex")
  -h, --help                     help for run
  -i, --iterations int           Maximum iterations to run (default 10)
      --json                     Output machine-readable JSON result
      --retries int              Max retries per iteration on failure (default 3)
      --retry-delay duration     Base retry delay (default 5s)
      --sandbox                  Run inside a sandbox
      --sandbox-apply            explicit opt-in: dry-run and apply eligible sandbox sync-out artifacts to the host worktree
      --sandbox-host string      Cached sandbox host ID for target selection
      --sandbox-name string      Sandbox name for --sandbox execution
      --sandbox-runtime string   Cached runtime constraint for target selection (ssh_machine, rootless_podman, microvm)
      --sandbox-sync-out         Collect sandbox sync-out metadata without applying to the host worktree
  -s, --story string             Run specific story by ID (e.g., US-001)
      --timeout duration         Per-engine session timeout override (e.g., 30m, 1h)
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
