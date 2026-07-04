package cmd

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/livegate"
)

const (
	phase60OperatorVerificationDocPath = "sandbox-runtime-v2-phase60-operator-verification.md"
	phase60DocsGuardFile               = "cmd/phase60_operator_verification_docs_test.go"
)

var (
	phase60BuildTagTokenRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	phase60BacktickTokenRE = regexp.MustCompile("`([^`]+)`")
	phase60EnvMarkerNameRE = regexp.MustCompile(`\bHAL_[A-Z0-9_]+\b`)
	phase60EnvAssignmentRE = regexp.MustCompile(`\bHAL_[A-Z0-9_]+\s*=`)
	phase60URLLikeValueRE  = regexp.MustCompile(`[a-z][a-z0-9+.-]*://`)
)

func TestPhase60OperatorVerificationDefaultCommandsMatchReleaseGate(t *testing.T) {
	doc := readPhase60OperatorVerificationDoc(t)
	commands := phase54DefaultDocumentedCommands(doc)
	phase60AssertStringSequence(t, "Phase 60 default fake-only commands", commands, phase60ExpectedFakeOnlyReleaseGateCommands())
}

func TestPhase60OperatorVerificationOptionalLiveCommandsStaySynchronized(t *testing.T) {
	doc := readPhase60OperatorVerificationDoc(t)
	commands := phase60OptionalLiveDocumentedCommands(doc)
	phase60AssertStringSequence(t, "Phase 60 optional live commands", commands, phase60ExpectedOptionalLiveCommands())

	for _, command := range commands {
		tags := phase60BuildTagsFromCommand(command)
		if len(tags) == 0 {
			t.Fatalf("Phase 60 optional live command %q has no -tags flag", command)
		}
		for _, pkg := range phase54CommandPackageSelectors(command) {
			phase54AssertPackageSelectorExists(t, pkg, command)
		}
		if runSelector, ok := phase54CommandRunSelector(command); ok {
			for _, pkg := range phase54CommandPackageSelectors(command) {
				phase54AssertRunSelectorMatchesPackageTests(t, runSelector, pkg, command)
			}
		}
	}
}

func TestPhase60OperatorVerificationLiveBuildTagsMatchOptionalLiveTests(t *testing.T) {
	doc := readPhase60OperatorVerificationDoc(t)
	actualTags := phase60ActualOptionalLiveBuildTags(t)
	phase60AssertSameStrings(t, "Phase 60 optional live test build tags", actualTags, phase60LiveGateBuildTags())
	phase60AssertSameStrings(t, "Phase 60 documented live build tags", phase60DocumentedLiveBuildTags(doc), actualTags)
	phase60AssertSameStrings(t, "Phase 60 optional live command build tags", phase60OptionalLiveCommandBuildTags(doc), actualTags)
}

func TestPhase60OperatorVerificationMarkerNamesMatchOptionalLiveChecks(t *testing.T) {
	doc := readPhase60OperatorVerificationDoc(t)
	phase60AssertSameStrings(t, "Phase 60 documented live marker names", phase60DocumentedLiveMarkerNames(doc), phase60ActualOptionalLiveMarkerNames(t))
}

func TestPhase60OperatorVerificationDocumentOmitsMarkerValuesAndSensitiveExamples(t *testing.T) {
	doc := readPhase60OperatorVerificationDoc(t)
	if issue := phase60OperatorVerificationDocUnsafeDetail(doc); issue != "" {
		t.Fatalf("Phase 60 operator verification document contains unsafe marker detail: %s", issue)
	}
}

func TestPhase60OperatorVerificationSafetyGuardRejectsFixtures(t *testing.T) {
	for _, tt := range []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "marker assignment value",
			doc:  "Set `HAL_FIRECRACKER_LIVE=1` before running the live command.",
			want: "marker assignment syntax",
		},
		{
			name: "marker placeholder assignment",
			doc:  "Use `HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set>` for the proxy marker.",
			want: "marker assignment syntax",
		},
		{
			name: "credential header example",
			doc:  "Example credential marker value: Authorization: Bearer ghp_secret.",
			want: "credential-bearing example",
		},
		{
			name: "socket path example",
			doc:  "Use a socket path such as /tmp/firecracker-api.sock for local testing.",
			want: "host path or socket example",
		},
		{
			name: "url example",
			doc:  "Proxy marker example: https://proxy.internal.example.com?token=secret.",
			want: "URL-like example",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			issue := phase60OperatorVerificationDocUnsafeDetail(tt.doc)
			if !strings.Contains(issue, tt.want) {
				t.Fatalf("unsafe fixture issue = %q, want %q", issue, tt.want)
			}
		})
	}
}

func TestPhase60OperatorVerificationGuardFileStaysInLiveMarkerAllowlists(t *testing.T) {
	if !phase50ApprovedLiveMarkerFiles()[phase60DocsGuardFile] {
		t.Fatalf("%s must stay in the Phase 50 live marker allowlist because it documents optional live marker names", phase60DocsGuardFile)
	}
	if !us010ApprovedLiveE2EGuardFiles()[phase60DocsGuardFile] {
		t.Fatalf("%s must stay in the Phase 53 live E2E marker allowlist because it documents optional live E2E marker names", phase60DocsGuardFile)
	}
}

func TestPhase60OperatorVerificationDocPathStable(t *testing.T) {
	if got, want := phase60OperatorVerificationDocPath, "sandbox-runtime-v2-phase60-operator-verification.md"; got != want {
		t.Fatalf("phase60 operator verification doc path = %q, want %q", got, want)
	}
}

func readPhase60OperatorVerificationDoc(t *testing.T) string {
	t.Helper()
	return phase50ReadFile(t, filepath.Join("..", "docs", "design", phase60OperatorVerificationDocPath))
}

func phase60ExpectedFakeOnlyReleaseGateCommands() []string {
	return []string{
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
}

func phase60ExpectedOptionalLiveCommands() []string {
	return []string{
		"go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'",
		"go test -tags=credential_delivery_live -count=1 -timeout=120s ./internal/credentialdelivery -run 'TestCredentialDeliveryLiveHarnessRequiresExplicitOptIn|TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized|TestCredentialDeliveryLivePrerequisitesAcceptAnyModeGate'",
		"go test -tags=microvm_e2e_live,firecracker_live,network_enforcement_live,credential_delivery_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm -run TestMicroVMLiveE2EComposedLiveExecutionPath",
	}
}

func phase60LiveGateBuildTags() []string {
	var tags []string
	for _, tag := range livegate.MicroVME2ERequiredBuildTags() {
		tags = append(tags, string(tag))
	}
	return phase60SortedUniqueStrings(tags)
}

func phase60DocumentedLiveBuildTags(doc string) []string {
	return phase60BacktickValuesMatching(phase60DocSection(doc, "## Live Marker Names", "## Skip Semantics"), func(value string) bool {
		return strings.HasSuffix(value, "_live")
	})
}

func phase60DocumentedLiveMarkerNames(doc string) []string {
	return phase60BacktickValuesMatching(phase60DocSection(doc, "## Live Marker Names", "## Skip Semantics"), func(value string) bool {
		return phase60EnvMarkerNameRE.MatchString(value)
	})
}

func phase60OptionalLiveCommandBuildTags(doc string) []string {
	var tags []string
	for _, command := range phase60OptionalLiveDocumentedCommands(doc) {
		tags = append(tags, phase60BuildTagsFromCommand(command)...)
	}
	return phase60SortedUniqueStrings(tags)
}

func phase60ActualOptionalLiveBuildTags(t *testing.T) []string {
	t.Helper()
	var tags []string
	for _, path := range phase60OptionalLiveTaggedTestFiles(t) {
		source := phase50ReadFile(t, path)
		tags = append(tags, phase60BuildTagsFromGoBuildHeader(source)...)
	}
	return phase60SortedUniqueStrings(tags)
}

func phase60ActualOptionalLiveMarkerNames(t *testing.T) []string {
	t.Helper()
	var markers []string
	for _, envVar := range livegate.MicroVME2ERequiredEnvVars() {
		markers = append(markers, string(envVar))
	}
	for _, envVar := range livegate.CredentialDeliveryLiveModeEnvVars() {
		markers = append(markers, string(envVar))
	}
	for _, path := range phase60OptionalLiveTaggedTestFiles(t) {
		source := phase50ReadFile(t, path)
		markers = append(markers, phase60EnvMarkerNameRE.FindAllString(source, -1)...)
	}
	return phase60SortedUniqueStrings(markers)
}

func phase60OptionalLiveTaggedTestFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, path := range phase50RepositoryGoFiles(t) {
		rel := phase50RepositoryRelativePath(t, path)
		if !strings.HasSuffix(rel, "_test.go") || !phase60OptionalLiveTestScope(rel) {
			continue
		}
		source := phase50ReadFile(t, path)
		if len(phase60BuildTagsFromGoBuildHeader(source)) == 0 {
			continue
		}
		files = append(files, path)
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Fatal("Phase 60 optional live guard matched no live-tagged test files")
	}
	return files
}

func phase60OptionalLiveTestScope(rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(rel))
	return strings.HasPrefix(rel, "internal/credentialdelivery/") ||
		strings.HasPrefix(rel, "internal/sandboxruntime/microvm/") ||
		strings.HasPrefix(rel, "internal/sandboxruntime/networkenforcement/")
}

func phase60OptionalLiveDocumentedCommands(doc string) []string {
	var commands []string
	inOptionalLiveSection := false
	optionalLiveHeadingDepth := 0
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			depth := phase54MarkdownHeadingDepth(line)
			lower := strings.ToLower(line)
			if inOptionalLiveSection && depth <= optionalLiveHeadingDepth {
				inOptionalLiveSection = false
				optionalLiveHeadingDepth = 0
			}
			if strings.Contains(lower, "optional") && strings.Contains(lower, "live") {
				inOptionalLiveSection = true
				optionalLiveHeadingDepth = depth
			}
			continue
		}
		if inOptionalLiveSection && phase54IsShellCommandLine(line) {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase60BuildTagsFromGoBuildHeader(source string) []string {
	var tags []string
	for _, token := range phase60BuildTagTokenRE.FindAllString(phase19SourceHeader(source), -1) {
		if strings.HasSuffix(token, "_live") {
			tags = append(tags, token)
		}
	}
	return phase60SortedUniqueStrings(tags)
}

func phase60BuildTagsFromCommand(command string) []string {
	fields := strings.Fields(command)
	var tags []string
	for i, field := range fields {
		field = strings.Trim(field, "'\"")
		switch {
		case strings.HasPrefix(field, "-tags="):
			tags = append(tags, strings.Split(strings.TrimPrefix(field, "-tags="), ",")...)
		case field == "-tags" && i+1 < len(fields):
			tags = append(tags, strings.Split(strings.Trim(fields[i+1], "'\""), ",")...)
		}
	}
	return phase60SortedUniqueStrings(tags)
}

func phase60BacktickValuesMatching(section string, match func(string) bool) []string {
	var values []string
	for _, parts := range phase60BacktickTokenRE.FindAllStringSubmatch(section, -1) {
		if len(parts) != 2 {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if match(value) {
			values = append(values, value)
		}
	}
	return phase60SortedUniqueStrings(values)
}

func phase60DocSection(doc, startHeading, endHeading string) string {
	start := strings.Index(doc, startHeading)
	if start < 0 {
		return ""
	}
	section := doc[start+len(startHeading):]
	if end := strings.Index(section, endHeading); end >= 0 {
		section = section[:end]
	}
	return section
}

func phase60OperatorVerificationDocUnsafeDetail(doc string) string {
	lower := strings.ToLower(doc)
	switch {
	case phase60EnvAssignmentRE.MatchString(doc):
		return "marker assignment syntax"
	case phase60URLLikeValueRE.MatchString(lower):
		return "URL-like example"
	case strings.Contains(lower, "authorization:") || strings.Contains(lower, "bearer ") || strings.Contains(lower, "ghp_") || strings.Contains(lower, "token=") || strings.Contains(lower, "secret="):
		return "credential-bearing example"
	case strings.Contains(lower, "/tmp/") || strings.Contains(lower, "/users/") || strings.Contains(lower, "/home/") || strings.Contains(lower, ".sock") || strings.Contains(lower, "--api-sock"):
		return "host path or socket example"
	case strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "localhost"):
		return "host endpoint example"
	default:
		return ""
	}
}

func phase60AssertStringSequence(t *testing.T, label string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\x00") == strings.Join(want, "\x00") {
		return
	}
	t.Fatalf("%s = %#v, want %#v", label, got, want)
}

func phase60AssertSameStrings(t *testing.T, label string, got, want []string) {
	t.Helper()
	got = phase60SortedUniqueStrings(got)
	want = phase60SortedUniqueStrings(want)
	if strings.Join(got, "\x00") == strings.Join(want, "\x00") {
		return
	}
	t.Fatalf("%s = %#v, want %#v", label, got, want)
}

func phase60SortedUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
