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

Examples:
  hal run                          # Run with defaults (10 iterations)
  hal run 5                        # Run 5 iterations (positional)
  hal run -i 5                     # Run 5 iterations (flag)
  hal run 1 -s US-001              # Run single specific story
  hal run -e codex                 # Use Codex engine
  hal run --dry-run                # Show what would execute
  hal run --base develop           # Branch from develop when needed


```
hal run [iterations] [flags]
```

### Examples

```
  hal run
  hal run 5
  hal run --story US-001
  hal run --engine codex --base develop
```

### Options

```
  -b, --base string            Base branch for creating the PRD branch (default: current branch, or HEAD when detached)
      --dry-run                Show what would execute without running
  -e, --engine string          Engine to use (claude, codex, pi) (default "codex")
  -h, --help                   help for run
  -i, --iterations int         Maximum iterations to run (default 10)
      --retries int            Max retries per iteration on failure (default 3)
      --retry-delay duration   Base retry delay (default 5s)
  -s, --story string           Run specific story by ID (e.g., US-001)
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

