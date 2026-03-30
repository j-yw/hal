# Spec: CI Command Human Output Styling

## Problem

All `hal ci` subcommands (`push`, `status`, `fix`, `merge`) use raw `fmt.Fprintf` for human output. Other hal commands (`status`, `doctor`, `continue`) already use the shared lipgloss style system from `internal/engine/styles.go`.

## Goal

Align CI human output with existing hal styling while keeping JSON (`--json`) output byte-identical.

## Alignment Decisions (Locked)

1. Dry-run human output uses deterministic command-owned copy and the title format `CI <Command> (dry run)`.
2. In `cmd/ci.go`, keep the existing `engine` import and use `engine.Style*` (do not introduce a second alias for the same package).
3. `ci fix` no-op (`Applied=false`) status color is inferred from summary text:
   - `status is passing` -> success (`✓`)
   - `status is pending` -> warning (`⚠`)
   - otherwise -> muted (no icon)
4. `ci merge` dry-run human output does not render `result.Summary`; it renders fixed copy based on `opts.DeleteBranch`.

## Style System Reference

`cmd/ci.go` already imports:

```go
import "github.com/jywlabs/hal/internal/engine"
```

Use these existing styles:

| Style | Use for |
|---|---|
| `engine.StyleTitle` | Command header |
| `engine.StyleBold` | Field labels |
| `engine.StyleSuccess` | Pass states, `✓` |
| `engine.StyleError` | Fail states, `✗` |
| `engine.StyleWarning` | Pending states, `⚠` |
| `engine.StyleInfo` | Branch names, URLs, commands |
| `engine.StyleMuted` | Secondary detail, SHAs, timestamps |

## Formatting Pattern

- First line is always styled title.
- Label/value lines align values at column 10.
- Secondary detail lines are indented to align under the value column (`"          "`).

---

## Per-Command Output Spec

### `hal ci push`

**Target:**

```
CI Push
Branch:   test/smoke
Status:   ✓ Pushed

PR #26:   https://github.com/j-yw/hal/pull/26
          Draft · New
```

Existing PR:

```
CI Push
Branch:   test/smoke
Status:   ✓ Pushed

PR #26:   https://github.com/j-yw/hal/pull/26
          Draft · Existing
```

Dry-run:

```
CI Push (dry run)
Branch:   test/smoke

Would push branch and create or reuse a pull request.
```

**Fields from `PushResult`:**

- `Branch`
- `DryRun`
- `PullRequest.Number`
- `PullRequest.URL`
- `PullRequest.Draft`
- `PullRequest.Existing`

**Implementation note (`runCIPushWithDeps` human block):**

```go
if result.DryRun {
	fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Push (dry run)"))
	fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Branch:"), engine.StyleInfo.Render(result.Branch))
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s\n", engine.StyleMuted.Render("Would push branch and create or reuse a pull request."))
	return nil
}

fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Push"))
fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Branch:"), engine.StyleInfo.Render(result.Branch))
fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Status:"), engine.StyleSuccess.Render("✓ Pushed"))

if result.PullRequest.URL != "" {
	fmt.Fprintln(out)
	prLabel := "PR:"
	if result.PullRequest.Number > 0 {
		prLabel = fmt.Sprintf("PR #%d:", result.PullRequest.Number)
	}
	padding := ""
	if len(prLabel) < 9 {
		padding = strings.Repeat(" ", 9-len(prLabel))
	}
	fmt.Fprintf(out, "%s%s %s\n", engine.StyleBold.Render(prLabel), padding, engine.StyleInfo.Render(result.PullRequest.URL))

	prDetail := "Draft"
	if !result.PullRequest.Draft {
		prDetail = "Ready for review"
	}
	if result.PullRequest.Existing {
		prDetail += " · Existing"
	} else {
		prDetail += " · New"
	}
	fmt.Fprintf(out, "          %s\n", engine.StyleMuted.Render(prDetail))
}
```

---

### `hal ci status`

**Target (failing):**

```
CI Status
Branch:   test/ci-fix-smoke-2
SHA:      abc1234
Status:   ✗ failing

Checks:
  ✓  checks
  ✓  goreleaser-check
  ✗  integration-test
  ✓  sandbox-test

Totals:   3 passing · 1 failing
```

**Target (passing):**

```
CI Status
Branch:   test/ci-fix-smoke-2
SHA:      abc1234
Status:   ✓ passing

Checks:
  ✓  checks
  ✓  goreleaser-check
  ✓  integration-test
  ✓  sandbox-test

Totals:   4 passing
```

**Target (pending):**

```
CI Status
Branch:   test/ci-fix-smoke-2
SHA:      abc1234
Status:   ⚠ pending

Checks:
  ✓  checks
  ⚠  goreleaser-check
  ✗  integration-test
  ⚠  sandbox-test

Totals:   1 passing · 1 failing · 2 pending
```

With `--wait` terminal reason:

```
CI Status
Branch:   test/ci-fix-smoke-2
SHA:      abc1234
Status:   ✓ passing
Wait:     completed
```

No checks discovered:

```
CI Status
Branch:   test/ci-fix-smoke-2
SHA:      abc1234
Status:   ⚠ pending

No CI checks discovered.
```

**Fields from `StatusResult`:**

- `Branch`
- `SHA` (display first 7 chars)
- `Status`
- `ChecksDiscovered`
- `WaitTerminalReason` (only when `--wait`)
- `Checks[]`
- `Totals`

Implementation remains the same shape as drafted, switching style calls to `engine.Style*`.

---

### `hal ci fix`

**Target (no fix needed, pending):**

```
CI Fix
Status:   ⚠ ci status is pending; no fix attempt needed
```

**Target (no fix needed, passing):**

```
CI Fix
Status:   ✓ ci status is passing; no fix attempt needed
```

**Target (fix applied):**

```
CI Fix
Branch:   test/ci-fix-smoke-2
Attempt:  1/2
Status:   ✓ Fix applied

Commit:   abc1234
Pushed:   ✓
Files:    internal/ci/parse_test.go
```

**Fields from `FixResult`:**

- `Applied`
- `Summary`
- `Branch`
- `Attempt`
- `MaxAttempts`
- `CommitSHA` (display first 7 chars)
- `Pushed`
- `FilesChanged`

**Implementation note (`writeCIFixResult` human block):**

```go
fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Fix"))

if !result.Applied {
	summary := strings.TrimSpace(result.Summary)
	if summary == "" {
		summary = "no fix attempt needed"
	}
	lower := strings.ToLower(summary)
	render := engine.StyleMuted.Render
	if strings.Contains(lower, "status is passing") {
		render = engine.StyleSuccess.Render
		summary = "✓ " + summary
	} else if strings.Contains(lower, "status is pending") {
		render = engine.StyleWarning.Render
		summary = "⚠ " + summary
	}
	fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Status:"), render(summary))
	return nil
}

if result.Branch != "" {
	fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Branch:"), engine.StyleInfo.Render(result.Branch))
}
if result.MaxAttempts > 0 {
	fmt.Fprintf(out, "%s  %s\n", engine.StyleBold.Render("Attempt:"), fmt.Sprintf("%d/%d", result.Attempt, result.MaxAttempts))
}
fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Status:"), engine.StyleSuccess.Render("✓ Fix applied"))

sha := result.CommitSHA
if len(sha) > 7 {
	sha = sha[:7]
}
if sha != "" {
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Commit:"), engine.StyleMuted.Render(sha))
}
if result.Pushed {
	fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Pushed:"), engine.StyleSuccess.Render("✓"))
}
if len(result.FilesChanged) > 0 {
	fmt.Fprintf(out, "%s    %s\n", engine.StyleBold.Render("Files:"), engine.StyleMuted.Render(strings.Join(result.FilesChanged, ", ")))
}
```

---

### `hal ci merge`

**Target:**

```
CI Merge
PR:       #26
Strategy: squash
Status:   ✓ Merged

Commit:   abc1234
Branch:   ✓ Deleted
```

Dry-run with `--delete-branch`:

```
CI Merge (dry run)
Strategy: squash

Would merge pull request and delete the remote branch.
```

Dry-run without `--delete-branch`:

```
CI Merge (dry run)
Strategy: squash

Would merge pull request.
```

With delete warning:

```
CI Merge
PR:       #26
Strategy: squash
Status:   ✓ Merged

Commit:   abc1234
Branch:   ⚠ remote branch not found (already deleted?)
```

Without branch deletion requested:

```
CI Merge
PR:       #26
Strategy: squash
Status:   ✓ Merged

Commit:   abc1234
```

**Fields from `MergeResult`:**

- `DryRun`
- `PRNumber`
- `Strategy`
- `Merged`
- `MergeCommitSHA` (display first 7 chars)
- `BranchDeleted`
- `DeleteWarning`

**Implementation note (`runCIMergeWithDeps` human block):**

```go
if result.DryRun {
	fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Merge (dry run)"))
	fmt.Fprintf(out, "%s %s\n", engine.StyleBold.Render("Strategy:"), result.Strategy)
	fmt.Fprintln(out)
	if opts.DeleteBranch {
		fmt.Fprintf(out, "%s\n", engine.StyleMuted.Render("Would merge pull request and delete the remote branch."))
	} else {
		fmt.Fprintf(out, "%s\n", engine.StyleMuted.Render("Would merge pull request."))
	}
	return nil
}

fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Merge"))
if result.PRNumber > 0 {
	fmt.Fprintf(out, "%s       %s\n", engine.StyleBold.Render("PR:"), engine.StyleInfo.Render(fmt.Sprintf("#%d", result.PRNumber)))
}
fmt.Fprintf(out, "%s %s\n", engine.StyleBold.Render("Strategy:"), result.Strategy)
fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Status:"), engine.StyleSuccess.Render("✓ Merged"))

sha := result.MergeCommitSHA
if len(sha) > 7 {
	sha = sha[:7]
}
if sha != "" {
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Commit:"), engine.StyleMuted.Render(sha))
}
if result.BranchDeleted {
	fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Branch:"), engine.StyleSuccess.Render("✓ Deleted"))
} else if result.DeleteWarning != "" {
	fmt.Fprintf(out, "%s   %s\n", engine.StyleBold.Render("Branch:"), engine.StyleWarning.Render("⚠ "+result.DeleteWarning))
}
```

---

## Alignment Reference

All CI labels align values to column 10.

| Label | Length | Padding | Total |
|---|---|---|---|
| `Branch:` | 7 | 3 | 10 |
| `Status:` | 7 | 3 | 10 |
| `SHA:` | 4 | 6 | 10 |
| `Wait:` | 5 | 5 | 10 |
| `Totals:` | 7 | 3 | 10 |
| `PR:` | 3 | 7 | 10 |
| `Attempt:` | 8 | 2 | 10 |
| `Commit:` | 7 | 3 | 10 |
| `Pushed:` | 7 | 3 | 10 |
| `Files:` | 6 | 4 | 10 |
| `Strategy:` | 9 | 1 | 10 |
| `PR #N:` | dynamic | dynamic | 10 |

For `PR #N:`, when label width exceeds 9 chars (for example `PR #1000:`), skip extra padding.

## Scope

- Primary implementation file: `cmd/ci.go`.
- Modify only human-output paths in:
  - `runCIPushWithDeps`
  - `runCIStatusWithDeps`
  - `writeCIFixResult`
  - `runCIMergeWithDeps`
- Do not change JSON output, flag wiring, dependency injection, or `internal/ci/*` core logic.
- Keep SHA truncation to 7 chars in human output only.

## Tests

- JSON contract tests in `cmd/ci_test.go` stay unchanged.
- If branch-local human-output assertions exist (for example dry-run text checks), update only those expectations.
- If exact plain-text matching is used on styled output, normalize ANSI in tests before asserting.

## Acceptance

- `hal ci push|status|fix|merge` human output uses shared style system consistently.
- `hal ci * --json` output remains byte-identical to current behavior.
- `make test` passes.
