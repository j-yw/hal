## hal doctor

Check Hal readiness and environment health

### Synopsis

Check that Hal is properly set up and ready to use.

Inspects:
  - Git repository presence
  - .hal/ directory and config
  - Default engine CLI availability
  - Installed skills and commands
  - Codex global links (only when engine is codex)

With --json, outputs a stable machine-readable contract (v1) suitable
for agent orchestration and tooling integration.

The doctor is engine-aware: Codex-specific checks are skipped when
the configured engine is not codex.

Examples:
  hal doctor            # Human-readable check results
  hal doctor --json     # Machine-readable JSON contract

```
hal doctor [flags]
```

### Examples

```
  hal doctor
  hal doctor --json
```

### Options

```
  -h, --help   help for doctor
      --json   Output machine-readable JSON (v1 contract)
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

