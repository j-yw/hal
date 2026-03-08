## hal

Hal - Autonomous task executor using AI coding agents

### Synopsis

Hal is a CLI tool that autonomously executes PRD-driven tasks
using AI coding agents like Codex (default), Claude Code, and pi.

"I am putting myself to the fullest possible use, which is all I think
that any conscious entity can ever hope to do."

Workflow:
  hal init                             Initialize project with skills
  hal plan "feature desc"              Generate PRD interactively
  hal convert                          Convert markdown PRD to JSON
  hal run --base develop [iterations]  Execute stories autonomously
  hal archive create                   Archive feature state when done

Review / Reporting:
  hal report                           Legacy session report generation
  hal review --base <branch> [iters]  Iterative review/fix loop
  hal review against <branch> [iters] Deprecated alias

Analyze:
  hal analyze --format text|json
  hal analyze --output json           Deprecated alias for --format

Quick Start:
  1. hal init
  2. hal plan "add user authentication" --format json
  3. hal run

### Examples

```
  hal init
  hal plan "add user authentication" --format json
  hal validate
  hal run
```

### Options

```
  -h, --help   help for hal
```

### SEE ALSO

* [hal analyze](hal_analyze.md)	 - Analyze a report to identify the highest priority item
* [hal archive](hal_archive.md)	 - Archive current feature state
* [hal auto](hal_auto.md)	 - Run the full compound engineering pipeline
* [hal cleanup](hal_cleanup.md)	 - Remove orphaned files from .hal/
* [hal config](hal_config.md)	 - Show current configuration
* [hal convert](hal_convert.md)	 - Convert markdown PRD to JSON
* [hal explode](hal_explode.md)	 - Break a PRD into granular tasks for autonomous execution
* [hal init](hal_init.md)	 - Initialize .hal/ directory
* [hal plan](hal_plan.md)	 - Generate a PRD interactively
* [hal report](hal_report.md)	 - Run legacy session reporting for completed work
* [hal review](hal_review.md)	 - Run an iterative review loop against a base branch
* [hal run](hal_run.md)	 - Run the Hal loop
* [hal sandbox](hal_sandbox.md)	 - Manage Daytona sandboxes
* [hal standards](hal_standards.md)	 - Manage project standards
* [hal validate](hal_validate.md)	 - Validate a PRD using AI
* [hal version](hal_version.md)	 - Show version info

