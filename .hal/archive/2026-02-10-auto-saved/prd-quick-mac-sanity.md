# Product Requirements Document: Quick macOS Sanity Check

## 1. Introduction/Overview

First-time developers can hit setup failures when required local tools are missing or outdated on macOS. This feature adds a fast, read-only `hal` CLI sanity check that verifies required prerequisites and minimum versions before development starts. The command should provide clear pass/fail diagnostics so developers can fix issues immediately.

## 2. Goals

- Provide a single, quick command for first-time macOS setup validation.
- Verify required tool presence and minimum supported versions.
- Produce clear per-tool and overall pass/fail output.
- Keep checks read-only and complete in under 5 seconds for the default prerequisite set.

## 3. User Stories

### US-001: Schema — Define prerequisite catalog
**Description:** As a hal maintainer, I want a single structured catalog of required macOS prerequisites so checks are consistent and easy to update.

**Acceptance Criteria:**
- [ ] A single source of truth defines each prerequisite with: tool label, executable name, minimum required version, and version probe command/args.
- [ ] Running the mac sanity check produces one result row per catalog entry.
- [ ] Updating a minimum version in the catalog is reflected in check output without additional code-path edits.
- [ ] Typecheck passes

### US-002: Backend — Detect tool presence and installed versions
**Description:** As a first-time developer, I want the check to detect installed tools and their versions so I can identify missing prerequisites quickly.

**Acceptance Criteria:**
- [ ] On macOS, each required executable is checked for presence in `PATH`.
- [ ] For found executables, the check captures a detected version string using the configured probe command.
- [ ] Missing executables are marked `FAIL` with reason `not found in PATH`.
- [ ] Probe-command failures are marked `FAIL` with a concise diagnostic reason.
- [ ] Typecheck passes

### US-003: Backend — Evaluate version rules and enforce fast, read-only behavior
**Description:** As a first-time developer, I want trustworthy pass/fail evaluation against minimum versions so I can act on results immediately.

**Acceptance Criteria:**
- [ ] A tool is marked `PASS` only when detected version satisfies the configured minimum version.
- [ ] The command exits with code `0` when all checks pass and non-zero when any check fails.
- [ ] Default checks complete in 5 seconds or less on a standard developer Mac (captured in benchmark/test notes).
- [ ] The check is read-only and does not modify files, system settings, or installed tools.
- [ ] Typecheck passes

### US-004: Frontend — Expose command and concise CLI output
**Description:** As a first-time developer, I want concise, human-readable CLI output so I can quickly see what passed, what failed, and what to fix.

**Acceptance Criteria:**
- [ ] The command is discoverable in CLI help (working name: `hal sanity mac`).
- [ ] Output includes per-tool fields: Tool, Required, Detected, Status, and Details.
- [ ] Output ends with a summary line formatted as `X/Y checks passed` plus overall `PASS` or `FAIL`.
- [ ] Output is readable in plain text without requiring ANSI color support.
- [ ] Typecheck passes

## 4. Functional Requirements

- FR-1: The system must provide a macOS prerequisite check command (working name: `hal sanity mac`).
- FR-2: The command must perform diagnostics only and must not install, update, or remove software.
- FR-3: The v1 scope must check required tools and minimum versions only.
- FR-4: Required tools and version constraints must be defined in one structured catalog.
- FR-5: The command must report installed/not installed status for every required tool.
- FR-6: The command must report detected version for installed tools and compare it against required minimum.
- FR-7: The command must emit explicit per-tool `PASS`/`FAIL` and an overall `PASS`/`FAIL` summary.
- FR-8: The command must return exit code `0` when all checks pass, otherwise non-zero.
- FR-9: The command must complete in under 5 seconds for the default check set on typical macOS developer hardware.
- FR-10: If run on non-macOS systems, the command must return a clear unsupported-platform response.

## 5. Non-Goals

- Automatically installing or upgrading missing prerequisites.
- Checking optional tools, IDE plugins, or shell customizations.
- Running network, authentication, or remote-service diagnostics.
- Supporting Linux/Windows prerequisite checks in this feature.
- Producing a full environment audit beyond required tools and versions.

## 6. Design Considerations

- Prefer compact tabular output for quick scanning.
- Use stable plain-text labels (`PASS`/`FAIL`) that remain clear in non-TTY output.
- Keep failure details concise and actionable.

## 7. Technical Considerations

- Use executable lookup and version probe execution with per-check timeouts to maintain speed.
- Normalize parsing for common version formats (e.g., `go version`, `git version`).
- Isolate probe execution behind testable interfaces for deterministic unit tests.
- Include tests for missing binary, probe failure, unparsable version, below-minimum version, and all-pass scenarios.

## 8. Success Metrics

- 95%+ of runs complete within 5 seconds on supported macOS developer machines.
- 100% of failed checks include a specific reason (missing tool, probe failure, or version below minimum).
- First-time macOS developers can identify all required-tool setup blockers in a single command run.
- Reduction in setup-related support/questions caused by missing or outdated required local tools.

## 9. Open Questions

- OQ-1: What is the exact v1 required tool list and minimum versions?
- OQ-2: Should the final command name be `hal sanity mac`, `hal doctor mac`, or another path?
- OQ-3: Should machine-readable output (e.g., JSON) be included in v1 or deferred?
- OQ-4: What reference machine profile should define the 5-second performance target?