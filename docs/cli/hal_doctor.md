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

Use --fix to auto-apply safe remediations (equivalent to 'hal repair').

Examples:
  hal doctor            # Human-readable check results
  hal doctor --json     # Machine-readable JSON contract
  hal doctor --fix      # Check and auto-fix safe issues

```
hal doctor [flags]
```

### Examples

```
  hal doctor
  hal doctor --json
  hal doctor --fix
```

### Options

```
      --fix    Auto-fix safe issues (equivalent to hal repair)
  -h, --help   help for doctor
      --json   Output machine-readable JSON (v1 contract)
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

