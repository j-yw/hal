## hal status

Show current workflow state

### Synopsis

Show the current Hal workflow state.

Inspects .hal/ artifacts to determine:
  - Which workflow track is active (manual, compound, unknown)
  - What state the workflow is in
  - What artifacts exist
  - What the next recommended action is

With --json, outputs a stable machine-readable contract (v1) suitable
for agent orchestration and tooling integration.

Workflow states:
  not_initialized         No .hal/ directory found
  hal_initialized_no_prd  .hal/ exists but no prd.json
  manual_in_progress      PRD has pending stories
  manual_complete         All PRD stories passed
  compound_active         Auto pipeline in progress
  compound_complete       Auto pipeline step is 'done'
  review_loop_complete    Review-loop reports exist (no active PRD)

Examples:
  hal status            # Human-readable summary
  hal status --json     # Machine-readable JSON contract

```
hal status [flags]
```

### Examples

```
  hal status
  hal status --json
```

### Options

```
  -h, --help   help for status
      --json   Output machine-readable JSON (v1 contract)
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

