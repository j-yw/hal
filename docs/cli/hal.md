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
  hal prd audit [--json]               Audit PRD health and drift
  hal run --base develop [iterations]  Execute stories autonomously
  hal archive create                   Archive feature state when done

Review / Reporting:
  hal report                           Generate summary report for completed work
  hal review --base <branch> [iters]  Iterative review/fix loop
  hal review against <branch> [iters] Deprecated alias

Status / Health:
  hal status [--json]                  Show workflow state
  hal doctor [--json]                  Check environment health
  hal continue [--json]                Show what to do next
  hal repair [--dry-run] [--json]      Auto-fix safe issues

Links:
  hal links status [--json]            Inspect engine skill links
  hal links refresh [engine]           Recreate skill links
  hal links clean                      Remove deprecated/broken links

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
* [hal cleanup](hal_cleanup.md)	 - Remove orphaned and deprecated files
* [hal config](hal_config.md)	 - Show current configuration
* [hal continue](hal_continue.md)	 - Show what to do next
* [hal convert](hal_convert.md)	 - Convert markdown PRD to JSON
* [hal doctor](hal_doctor.md)	 - Check Hal readiness and environment health
* [hal explode](hal_explode.md)	 - Break a PRD into granular tasks for autonomous execution
* [hal init](hal_init.md)	 - Initialize .hal/ directory
* [hal links](hal_links.md)	 - Manage engine skill links
* [hal plan](hal_plan.md)	 - Generate a PRD interactively
* [hal prd](hal_prd.md)	 - Manage PRD files
* [hal repair](hal_repair.md)	 - Auto-fix environment issues detected by doctor
* [hal report](hal_report.md)	 - Generate a summary report for completed work
* [hal review](hal_review.md)	 - Run an iterative review loop against a base branch
* [hal run](hal_run.md)	 - Run the Hal loop
* [hal sandbox](hal_sandbox.md)	 - Manage Daytona sandboxes
* [hal standards](hal_standards.md)	 - Manage project standards
* [hal status](hal_status.md)	 - Show current workflow state
* [hal validate](hal_validate.md)	 - Validate a PRD using AI
* [hal version](hal_version.md)	 - Show version info

