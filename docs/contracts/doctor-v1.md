# Doctor Contract v1

**Command:** `hal doctor --json`  
**Contract Version:** 1  
**Stability:** Stable. New checks may be added; existing check IDs will not be removed or renamed.

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | int | Always `1` |
| `overallStatus` | string | `pass`, `fail`, or `warn` |
| `engine` | string | Configured default engine |
| `checks` | array | Health check results |
| `totalChecks` | int | Total number of checks run |
| `passedChecks` | int | Number of passing checks |
| `failures` | array | IDs of failed checks |
| `warnings` | array | IDs of warned checks |
| `summary` | string | Human-readable summary |

## Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `primaryRemediation` | object | First actionable fix `{command, safe}` |

## Check Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable check identifier |
| `status` | string | `pass`, `fail`, `warn`, or `skip` |
| `severity` | string | `info`, `warn`, or `error` |
| `scope` | string | `repo`, `engine_local`, `engine_global`, or `migration` |
| `applicability` | string | `required`, `optional`, or `not_applicable` |
| `remediationId` | string | Stable remediation identifier |
| `message` | string | Human-readable description |
| `remediation` | object | `{command, safe}` when actionable |

## Check IDs (ordered)

| ID | Scope | Description |
|----|-------|-------------|
| `git_repo` | repo | Git repository detected |
| `hal_dir` | repo | `.hal/` directory exists |
| `config_yaml` | repo | Config file readable and valid YAML |
| `default_engine_cli` | repo | Engine CLI in PATH |
| `prompt_md` | repo | Agent prompt template exists and non-empty |
| `progress_file` | repo | Progress file exists |
| `prd_json` | repo | PRD JSON valid (skipped when absent) |
| `hal_skills` | repo | Managed skills installed |
| `hal_commands` | repo | Managed commands installed |
| `local_skill_links` | engine_local | `.claude/skills/`, `.pi/skills/` links correct |
| `codex_global_links` | engine_global | `~/.codex/skills/` links correct (codex only) |
| `legacy_debris` | migration | No `.goralph/`, `ralph` links, or `rules/` |
| `broken_skill_links` | migration | No broken symlinks in engine dirs |

## Example: Healthy Pi Repo

```json
{
  "contractVersion": 1,
  "overallStatus": "pass",
  "engine": "pi",
  "checks": [
    {"id": "git_repo", "status": "pass", "severity": "info", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "Git repository detected."},
    {"id": "hal_dir", "status": "pass", "severity": "info", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "Found .hal/ directory."},
    {"id": "config_yaml", "status": "pass", "severity": "info", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "Loaded .hal/config.yaml."},
    {"id": "default_engine_cli", "status": "pass", "severity": "info", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "The configured default engine CLI is available in PATH."},
    {"id": "prompt_md", "status": "pass", "severity": "info", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "Loaded .hal/prompt.md."},
    {"id": "progress_file", "status": "pass", "severity": "info", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "Found .hal/progress.txt."},
    {"id": "prd_json", "status": "skip", "severity": "info", "scope": "repo", "applicability": "optional", "remediationId": "none", "message": "No prd.json found (normal before first plan/convert)."},
    {"id": "hal_skills", "status": "pass", "severity": "info", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "Installed Hal skills are present."},
    {"id": "hal_commands", "status": "pass", "severity": "info", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "Installed Hal commands are present."},
    {"id": "local_skill_links", "status": "pass", "severity": "info", "scope": "engine_local", "applicability": "optional", "remediationId": "none", "message": "Engine-local skill links are correct."},
    {"id": "codex_global_links", "status": "skip", "severity": "info", "scope": "engine_global", "applicability": "not_applicable", "remediationId": "none", "message": "Codex global links are not required because the configured engine is pi."},
    {"id": "legacy_debris", "status": "pass", "severity": "info", "scope": "migration", "applicability": "optional", "remediationId": "none", "message": "No legacy migration debris found."},
    {"id": "broken_skill_links", "status": "pass", "severity": "info", "scope": "migration", "applicability": "optional", "remediationId": "none", "message": "No broken skill symlinks found."}
  ],
  "totalChecks": 13,
  "passedChecks": 11,
  "failures": [],
  "warnings": [],
  "summary": "Hal is ready to use."
}
```

## Example: Not Initialized

```json
{
  "contractVersion": 1,
  "overallStatus": "fail",
  "engine": "codex",
  "checks": [
    {"id": "git_repo", "status": "warn", "severity": "warn", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "No .git directory found. Hal works best inside a git repository."},
    {"id": "hal_dir", "status": "fail", "severity": "error", "scope": "repo", "applicability": "required", "remediationId": "run_hal_init", "message": "Missing .hal/ directory.", "remediation": {"command": "hal init", "safe": true}},
    {"id": "config_yaml", "status": "skip", "severity": "info", "scope": "repo", "applicability": "required", "remediationId": "none", "message": "Skipped: .hal/ directory not found."}
  ],
  "totalChecks": 3,
  "passedChecks": 0,
  "failures": ["hal_dir"],
  "warnings": [],
  "primaryRemediation": {"command": "hal init", "safe": true},
  "summary": "Hal is not initialized. Run hal init."
}
```
