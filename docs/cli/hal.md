## hal

Hal - Autonomous task executor using AI coding agents

### Synopsis

Hal is a CLI tool that autonomously executes PRD-driven tasks
using AI coding agents like Codex (default), Claude Code, and pi.

"I am putting myself to the fullest possible use, which is all I think
that any conscious entity can ever hope to do."

Core flow:
  hal init
  hal plan "feature desc"
  hal convert
  hal run --base develop [iterations]
  hal archive create

Auto flow:
  hal auto [prd-path]
  source selection uses auto.sourcePriority (default report_first: latest report -> newest .hal/prd-*.md)

Review / reporting:
  hal report
  hal review --base <branch> [iters]

Status / health:
  hal status [--json]
  hal doctor [--json]
  hal continue [--json]
  hal repair [--dry-run] [--json]

Agent-safe examples:
  hal plan --input .hal/input/feature.md --no-questions --format json --json
  hal plan --input - --no-questions --format json --json < .hal/input/feature.md
  hal auto .hal/prd-feature.md --dry-run --json
  hal archive create --name checkout-flow

Links:
  hal links status [--json]
  hal links refresh [engine]
  hal links clean

Analyze:
  hal analyze --format text|json
  hal analyze --output json  # deprecated alias

Quick start:
  1. hal init
  2. hal plan "add user authentication" --format json
  3. hal run
  4. hal auto

### Examples

```
  hal init
  hal plan "add user authentication" --format json
  hal validate
  hal run
  hal auto
```

### Options

```
  -h, --help   help for hal
```

### SEE ALSO

* [hal analyze](hal_analyze.md)	 - Analyze a report to identify the highest priority item
* [hal archive](hal_archive.md)	 - Archive current feature state
* [hal auto](hal_auto.md)	 - Run the single deterministic auto pipeline
* [hal ci](hal_ci.md)	 - Run CI workflow commands
* [hal cleanup](hal_cleanup.md)	 - Remove orphaned and deprecated files
* [hal config](hal_config.md)	 - Show current configuration
* [hal continue](hal_continue.md)	 - Show what to do next
* [hal convert](hal_convert.md)	 - Convert markdown PRD to JSON
* [hal doctor](hal_doctor.md)	 - Check Hal readiness and environment health
* [hal explode](hal_explode.md)	 - Deprecated shim for 'hal convert --granular'
* [hal factory](hal_factory.md)	 - Inspect factory run history
* [hal init](hal_init.md)	 - Initialize .hal/ directory
* [hal links](hal_links.md)	 - Manage engine skill links
* [hal plan](hal_plan.md)	 - Generate a PRD interactively
* [hal prd](hal_prd.md)	 - Manage PRD files
* [hal repair](hal_repair.md)	 - Auto-fix environment issues detected by doctor
* [hal report](hal_report.md)	 - Generate a summary report for completed work
* [hal review](hal_review.md)	 - Run an iterative review loop against a base branch
* [hal run](hal_run.md)	 - Run the Hal loop
* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
* [hal standards](hal_standards.md)	 - Manage project standards
* [hal status](hal_status.md)	 - Show current workflow state
* [hal validate](hal_validate.md)	 - Validate a PRD using AI
* [hal version](hal_version.md)	 - Show version info

