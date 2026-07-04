package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase54OperatorReleaseHandoffSummarizesCompletedWave(t *testing.T) {
	doc := phase50ReadFile(t, phase54OperatorReleaseHandoffDocPath())

	for _, want := range []string{
		"# Sandbox Runtime v2 Phase 54 Operator Release Handoff",
		"US-001 locked the release scope",
		"US-002 documented and guarded the release package surface",
		"US-003 defined the default CI matrix as deterministic and fake-only",
		"US-004 separated optional live verification from default CI",
		"docs/design/sandbox-runtime-v2-phase54-release-package-verification.md",
		"docs/design/sandbox-runtime-v2-phase53-final-verification.md",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing handoff summary %q", phase50SafeDisplayPath(phase54OperatorReleaseHandoffDocPath()), want)
		}
	}
}

func TestPhase54OperatorReleaseHandoffDocumentsDefaultVerification(t *testing.T) {
	doc := phase50ReadFile(t, phase54OperatorReleaseHandoffDocPath())
	commands := map[string]bool{}
	for _, command := range phase54DefaultDocumentedCommands(doc) {
		commands[command] = true
		if marker := phase54ForbiddenDefaultCommandMarker(command); marker != "" {
			t.Fatalf("Phase 54 handoff default command %q contains optional live marker %q", command, marker)
		}
	}

	for _, want := range phase54DefaultCICommands() {
		if !commands[want] {
			t.Fatalf("Phase 54 handoff default verification missing command %q", want)
		}
	}
	for _, want := range []string{
		"go test -count=1 ./cmd -run TestPhase54OperatorReleaseHandoff",
		"go test -count=1 ./cmd -run TestPhase54",
		"The default verification path is fake-only.",
		"tagged live suites",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("Phase 54 handoff default verification missing %q", want)
		}
	}
}

func TestPhase54OperatorReleaseHandoffDocumentsOptionalLiveVerification(t *testing.T) {
	doc := phase50ReadFile(t, phase54OperatorReleaseHandoffDocPath())
	releaseDoc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())
	handoffCommands := phase54OperatorOptionalDocumentedCommands(doc)
	releaseCommands := phase54OperatorOptionalDocumentedCommands(releaseDoc)

	if len(releaseCommands) == 0 {
		t.Fatal("Phase 54 release package doc has no optional verification commands")
	}
	for want := range releaseCommands {
		if !handoffCommands[want] {
			t.Fatalf("Phase 54 handoff optional verification missing command %q", want)
		}
		phase54AssertOptionalLiveCommandRedactionSafe(t, want)
	}
}

func TestPhase54OperatorReleaseHandoffExplainsSkipAndDefaultBoundaries(t *testing.T) {
	doc := phase50ReadFile(t, phase54OperatorReleaseHandoffDocPath())
	normalized := strings.Join(strings.Fields(doc), " ")

	for _, want := range []string{
		"When required build tags are absent, Go excludes tagged live test files from default package builds.",
		"When required environment markers are absent, live gate tests skip with sanitized missing-prerequisite messages before Firecracker launch, listener or firewall mutation, credential delivery, template trust live execution, provider probing, or any runtime state change.",
		"The standalone network enforcement and credential delivery live harnesses currently remain opt-in placeholders after their gates are satisfied.",
		"The composed microVM live E2E command is the only documented live execution path.",
		"## Not Enabled By Default",
		"default-on network proxy/firewall enforcement in routine CI or packaging",
		"credential broker delivery as default agent behavior",
		"template/kits provenance, acquisition, or trust-policy behavior as a production default",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("Phase 54 handoff missing default boundary or skip behavior %q", want)
		}
	}
}

func TestPhase54OperatorReleaseHandoffIncludesPreMergeChecklist(t *testing.T) {
	doc := phase50ReadFile(t, phase54OperatorReleaseHandoffDocPath())
	normalized := strings.Join(strings.Fields(doc), " ")

	for _, want := range []string{
		"## Pre-PR And Pre-Merge Checklist",
		"Confirm `.hal/prd.json` and `.hal/progress.txt` were not hand-edited by the worker task.",
		"Run the default verification commands and keep the output available for the PR description.",
		"Decide explicitly whether optional live checks are in scope for the PR.",
		"Smoke check the built CLI with `./hal version` after `make build`.",
		"Re-run `git diff --check` after any final documentation or manifest edit.",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("Phase 54 handoff checklist missing %q", want)
		}
	}
}

func phase54OperatorReleaseHandoffDocPath() string {
	return filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase54-operator-release-handoff.md")
}

func phase54OperatorOptionalDocumentedCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	inOptionalSection := false
	optionalHeadingDepth := 0
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			depth := phase54MarkdownHeadingDepth(line)
			lower := strings.ToLower(line)
			if inOptionalSection && depth <= optionalHeadingDepth {
				inOptionalSection = false
				optionalHeadingDepth = 0
			}
			if strings.Contains(lower, "optional") && strings.Contains(lower, "verification") {
				inOptionalSection = true
				optionalHeadingDepth = depth
			}
			continue
		}
		if !inOptionalSection || !phase54IsShellCommandLine(line) {
			continue
		}
		commands[line] = true
	}
	return commands
}
