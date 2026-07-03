package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase45NetworkEnforcementLiveDocPath = "sandbox-runtime-v2-phase45-network-enforcement-live-guard-verification.md"

func TestPhase45NetworkEnforcementLiveGuardDocumentation(t *testing.T) {
	doc := readPhase45NetworkEnforcementLiveGuardDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 45 adds guardrails for optional live network enforcement tests and documentation only.",
		"Default verification is fake-only and does not require root privileges, network access, firewall state, KVM, Docker, Podman, Firecracker, or live environment variables.",
		"Optional live coverage is behind the `network_enforcement_live` build tag and is not part of default verification.",
		"`HAL_NETWORK_ENFORCEMENT_LIVE=1`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=1`",
		"Optional live harnesses must clean up any listener, firewall, runtime rule, or process state they create and report cleanup failures with sanitized warnings.",
		"Default docs and CLI examples must not imply default secure enforcement, default firewall mutation, default listener binding, or default microVM worker availability.",
		"`hal convert <generated-prd-md> --validate --json`",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase45|NetworkEnforcementLiveGuard'",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement",
		"go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 45 network enforcement live guard documentation missing %q", want)
		}
	}
	if strings.Contains(doc, "hal convert --granular") || strings.Contains(normalizedDoc, "hal convert --granular") {
		t.Fatal("phase 45 documentation must name the plain conversion command and must not recommend hal convert --granular for this PRD")
	}

	phase45AssertDocumentedCommands(t, doc)
	phase45AssertOptionalLiveCommand(t, doc)
	phase45AssertDefaultCommandsAvoidLiveOptIn(t, doc)
}

func TestPhase45NetworkEnforcementLiveTestsRequireExplicitOptIn(t *testing.T) {
	paths := phase45NetworkEnforcementLiveTestFiles(t)
	if len(paths) == 0 {
		t.Fatal("expected at least one optional network enforcement live test file guarded by network_enforcement_live")
	}

	for _, path := range paths {
		source := phase45ReadFile(t, path)
		display := phase34FirecrackerDisplayPath(t, path)
		for _, marker := range []string{
			"//go:build network_enforcement_live",
			"HAL_NETWORK_ENFORCEMENT_LIVE",
			"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY",
			"HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL",
			"t.Skip",
		} {
			if !strings.Contains(source, marker) {
				t.Fatalf("%s missing optional live guard marker %q", display, marker)
			}
		}
		for _, forbidden := range []string{
			"//go:build integration",
			"//go:build worker_integration",
			"//go:build podman_integration",
			"//go:build firecracker_live",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s uses unrelated live/integration build tag marker %q", display, forbidden)
			}
		}
	}
}

func TestPhase45NetworkEnforcementDocsAvoidDefaultLiveClaims(t *testing.T) {
	for _, path := range phase45MarkdownDocumentationFiles(t) {
		normalized := strings.ToLower(strings.Join(strings.Fields(phase45ReadFile(t, path)), " "))
		for _, claim := range []string{
			"secure enforcement by default",
			"default secure enforcement is enabled",
			"default firewall mutation is enabled",
			"firewall mutation by default",
			"default listener binding is enabled",
			"listener binding by default",
			"default microvm worker availability is guaranteed",
			"microvm worker availability by default",
			"default `hal sandboxd` starts microvm workers",
			"default `hal run` applies firewall",
			"default `hal auto` applies firewall",
			"default test runs execute network_enforcement_live",
		} {
			if strings.Contains(normalized, claim) {
				t.Fatalf("%s contains unsupported default live-enforcement claim %q", phase34FirecrackerDisplayPath(t, path), claim)
			}
		}
	}
}

func readPhase45NetworkEnforcementLiveGuardDoc(t *testing.T) string {
	t.Helper()
	return phase45ReadFile(t, filepath.Join("..", "docs", "design", phase45NetworkEnforcementLiveDocPath))
}

func phase45AssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	for _, want := range []string{
		"go test -count=1 -timeout=180s ./cmd -run 'Phase45|NetworkEnforcementLiveGuard'",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement",
		"go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	} {
		if !commands[want] {
			t.Fatalf("phase 45 verification documentation missing command line %q", want)
		}
	}
}

func phase45AssertOptionalLiveCommand(t *testing.T, doc string) {
	t.Helper()
	var liveCommands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "network_enforcement_live") {
			liveCommands = append(liveCommands, command)
		}
	}
	if len(liveCommands) != 1 {
		t.Fatalf("phase 45 optional live command count = %d, want 1: %#v", len(liveCommands), liveCommands)
	}
	command := liveCommands[0]
	want := "go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'"
	if command != want {
		t.Fatalf("phase 45 optional live command = %q, want %q", command, want)
	}
	for _, forbidden := range []string{
		"-tags=integration",
		"-tags=worker_integration",
		"-tags=podman_integration",
		"-tags=firecracker_live",
		"docker ",
		"podman ",
		"firecracker ",
		"/dev/kvm",
		"hal sandboxd",
		"--live",
	} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("phase 45 optional live command %q contains unrelated live dependency marker %q", command, forbidden)
		}
	}

	for _, req := range []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "network_enforcement_live_test.go"), testName: "TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "network_enforcement_live_test.go"), testName: "TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted"},
	} {
		covered := phase34FocusedCommandCoveringTest(t, []string{command}, req.pkg, req.testName)
		if covered == "" {
			t.Fatalf("phase 45 optional live command does not cover %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 45 optional live test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase45AssertDefaultCommandsAvoidLiveOptIn(t *testing.T, doc string) {
	t.Helper()
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "network_enforcement_live") {
			continue
		}
		for _, forbidden := range []string{
			"-tags=network_enforcement_live",
			"HAL_NETWORK_ENFORCEMENT_LIVE",
			"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY",
			"HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL",
		} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 45 default verification command %q requires optional live marker %q", command, forbidden)
			}
		}
	}
}

func phase45NetworkEnforcementLiveTestFiles(t *testing.T) []string {
	t.Helper()
	pattern := filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "*_live_test.go")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("Glob(%s) error: %v", pattern, err)
	}
	return paths
}

func phase45MarkdownDocumentationFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{filepath.Join("..", "README.md")}
	for _, root := range []string{filepath.Join("..", "docs"), filepath.Join("..", "sandbox")} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(path), ".md") {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("WalkDir(%s) error: %v", root, err)
		}
	}
	return paths
}

func phase45ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
