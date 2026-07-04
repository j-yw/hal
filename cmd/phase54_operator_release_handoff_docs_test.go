package cmd

import (
	"path/filepath"
	"strconv"
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

func TestPhase54OperatorReleaseHandoffDoesNotOverclaimDefaultEnforcement(t *testing.T) {
	doc := phase50ReadFile(t, phase54OperatorReleaseHandoffDocPath())
	if claim := phase54HandoffDefaultEnforcementOverclaim(doc); claim != "" {
		t.Fatalf("Phase 54 handoff document overclaims default enforcement: %s", claim)
	}
}

func TestPhase54OperatorReleaseHandoffOverclaimGuardFixtures(t *testing.T) {
	unsafe := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "default network proxy firewall enforcement",
			doc:  "## Release Notes\n\nDefault CI enforces live network proxy and firewall behavior for all runs.\n",
			want: "default live network proxy/firewall enforcement",
		},
		{
			name: "credential broker default agent delivery",
			doc:  "## Release Notes\n\nCredential broker delivery is default agent behavior for Phase 54.\n",
			want: "credential broker delivery default",
		},
		{
			name: "template trust production default",
			doc:  "## Release Notes\n\nTemplate/kits provenance and trust policy are fully operationalized as production defaults.\n",
			want: "template/kits provenance or trust-policy production default",
		},
		{
			name: "requested metadata deny by default",
			doc:  "## Release Notes\n\nRequested metadata is enough to claim deny-by-default network security.\n",
			want: "deny-by-default network security from requested metadata",
		},
	}
	for _, tc := range unsafe {
		t.Run(tc.name, func(t *testing.T) {
			claim := phase54HandoffDefaultEnforcementOverclaim(tc.doc)
			if !strings.Contains(claim, tc.want) {
				t.Fatalf("fixture claim = %q, want marker %q", claim, tc.want)
			}
		})
	}

	futureWork := `## Future Work

- Future work must add explicit live network proxy/firewall enforcement before
  any default CI or packaging claim.
- Credential broker delivery as default agent behavior still needs production
  hardening beyond metadata/projection.
- Template/kits provenance and trust policy exist, but production default
  operationalization still needs rollout decisions.
- Release/CI must not claim deny-by-default network security merely because
  requested metadata exists.
`
	if claim := phase54HandoffDefaultEnforcementOverclaim(futureWork); claim != "" {
		t.Fatalf("future-work fixture should be allowed, got claim %q", claim)
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

func phase54HandoffDefaultEnforcementOverclaim(doc string) string {
	currentHeading := ""
	var recent []string
	for index, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			currentHeading = line
			recent = phase54HandoffAppendRecent(recent, line)
			continue
		}

		windowParts := []string{currentHeading}
		windowParts = append(windowParts, recent...)
		windowParts = append(windowParts, line)
		normalized := phase54HandoffNormalizeClaimText(strings.Join(windowParts, " "))
		if !phase54HandoffAllowedClaimContext(normalized) {
			if claim := phase54HandoffUnsafeDefaultClaim(normalized); claim != "" {
				return claim + " near line " + strconv.Itoa(index+1) + ": " + line
			}
		}
		recent = phase54HandoffAppendRecent(recent, line)
	}
	return ""
}

func phase54HandoffAppendRecent(recent []string, line string) []string {
	recent = append(recent, line)
	if len(recent) > 3 {
		return recent[len(recent)-3:]
	}
	return recent
}

func phase54HandoffNormalizeClaimText(text string) string {
	replacer := strings.NewReplacer(
		"`", "",
		"*", " ",
		"_", " ",
		"-", " ",
		"/", " ",
		",", " ",
		";", " ",
		":", " ",
		".", " ",
		"(", " ",
		")", " ",
	)
	return strings.Join(strings.Fields(strings.ToLower(replacer.Replace(text))), " ")
}

func phase54HandoffAllowedClaimContext(text string) bool {
	for _, marker := range []string{
		"not enabled by default",
		"does not enable",
		"do not enable",
		"must not",
		"not claim",
		"not part of default",
		"outside default",
		"outside this default",
		"outside the default",
		"opt in",
		"optional",
		"manual operator",
		"prepared live infrastructure",
		"skip",
		"future work",
		"future phase",
		"future phases",
		"still needs",
		"needs production hardening",
		"needs rollout",
		"remaining",
		"not fully operationalized",
		"not operationalized",
		"gap audit",
		"after phase 54",
		"new wave",
		"deliberately enabled",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func phase54HandoffUnsafeDefaultClaim(text string) string {
	if phase54HandoffContainsDefaultContext(text) &&
		phase54HandoffContainsAny(text, []string{
			"network proxy", "proxy firewall", "live proxy", "live firewall", "firewall", "network enforcement",
		}) &&
		phase54HandoffContainsAny(text, []string{
			"enforce", "enforced", "enforces", "enforcement", "enable", "enabled", "requires", "required", "default on", "runs live", "starts live", "activates live",
		}) {
		return "default live network proxy/firewall enforcement claim"
	}

	if strings.Contains(text, "credential broker") &&
		strings.Contains(text, "delivery") &&
		phase54HandoffContainsAny(text, []string{
			"default agent", "default for agents", "agent default", "agent behavior", "default behavior", "production default", "enabled by default", "by default",
		}) {
		return "credential broker delivery default claim"
	}

	if phase54HandoffContainsAny(text, []string{"template", "kits"}) &&
		phase54HandoffContainsAny(text, []string{"provenance", "trust policy", "trust"}) &&
		phase54HandoffContainsAny(text, []string{
			"fully operationalized", "operationalized", "production default", "production defaults", "enabled by default", "by default", "default behavior",
		}) {
		return "template/kits provenance or trust-policy production default claim"
	}

	if strings.Contains(text, "deny by default") &&
		phase54HandoffContainsAny(text, []string{
			"requested metadata", "requested policy metadata", "requested network policy", "requested intent",
		}) &&
		phase54HandoffContainsAny(text, []string{
			"claim", "proves", "proven", "based only", "sufficient", "enforced", "security",
		}) {
		return "deny-by-default network security from requested metadata claim"
	}

	return ""
}

func phase54HandoffContainsDefaultContext(text string) bool {
	return phase54HandoffContainsAny(text, []string{
		"default ci",
		"routine ci",
		"default verification",
		"default package",
		"package verification",
		"pre merge gate",
		"default path",
		"production default",
		"enabled by default",
		"by default",
		"default on",
	})
}

func phase54HandoffContainsAny(text string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
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
