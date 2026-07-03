package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase46RuntimeWorkerDocPath = "sandbox-runtime-v2-phase46-runtime-worker-docs-redaction-guards-verification.md"

func TestPhase46RuntimeWorkerVerificationDocs(t *testing.T) {
	doc := readPhase46RuntimeWorkerDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 46 adds runtime and worker metadata redaction guards plus CLI documentation example safety checks for credential-delivery live-readiness work.",
		"Default Phase 46 verification is fake-only and default-safe.",
		"`internal/sandboxruntime.RuntimeMetadata`",
		"`internal/sandboxworker.SecurityControls`",
		"`internal/sandboxworker.RuntimeDriver`",
		"Runtime and worker metadata may carry only compact safe identifiers, enum-like modes, status labels, reason codes, counts, and proven activation labels.",
		"They must not carry secret values, raw endpoints, local paths, socket paths, environment values, headers, bearer tokens, command lines, or raw credential proxy metadata.",
		"CLI examples must not present secure credential delivery, network enforcement, or microVM worker enforcement as default availability.",
		"Optional live behavior remains outside default Phase 46 verification.",
		"Any optional live behavior mentioned by docs must stay behind explicit build tags, explicit environment opt-ins, and skip by default when those opt-ins are absent.",
		"`network_enforcement_live`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE=1`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=1`",
		"go test -count=1 ./internal/sandboxruntime",
		"go test -count=1 ./internal/sandboxworker",
		"go test -count=1 ./cmd -run 'TestPhase46'",
		"go test -count=1 -run '^$' ./...",
		"make docs-check",
		"git diff --check",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 46 runtime/worker verification documentation missing %q", want)
		}
	}

	commands := phase34DocumentedShellCommands(doc)
	for _, want := range []string{
		"go test -count=1 ./internal/sandboxruntime",
		"go test -count=1 ./internal/sandboxworker",
		"go test -count=1 ./cmd -run 'TestPhase46'",
		"go test -count=1 -run '^$' ./...",
		"make docs-check",
		"git diff --check",
	} {
		if !commands[want] {
			t.Fatalf("phase 46 verification documentation missing command line %q", want)
		}
	}
}

func TestPhase46CLIExamplesAvoidDefaultAvailabilityClaims(t *testing.T) {
	for _, path := range phase46CLIDocFiles(t) {
		doc := strings.ToLower(strings.Join(strings.Fields(phase46ReadFile(t, path)), " "))
		for _, claim := range phase46ForbiddenDefaultAvailabilityClaims() {
			if strings.Contains(doc, claim) {
				t.Fatalf("%s contains unsupported default availability claim %q", phase34FirecrackerDisplayPath(t, path), claim)
			}
		}
	}
}

func TestPhase46VerificationExamplesStayDefaultSafe(t *testing.T) {
	doc := readPhase46RuntimeWorkerDoc(t)
	for _, command := range phase34AllGoTestCommands(doc) {
		for _, forbidden := range []string{
			"-tags=integration",
			"-tags=worker_integration",
			"-tags=podman_integration",
			"-tags=firecracker_live",
			"-tags=network_enforcement_live",
			"HAL_FIRECRACKER_LIVE_",
			"HAL_NETWORK_ENFORCEMENT_LIVE",
			"SSH_AUTH_SOCK",
			"DOCKER_HOST",
			"HCLOUD_TOKEN",
			"DIGITALOCEAN_ACCESS_TOKEN",
			"AWS_ACCESS_KEY_ID",
			"OPENAI_API_KEY=",
			"Authorization:",
			"Bearer ",
			"token=",
			"secret=",
		} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 46 default verification command %q contains forbidden live/raw marker %q", command, forbidden)
			}
		}
	}
}

func TestPhase46OptionalLiveDocumentationIsExplicitlyGated(t *testing.T) {
	doc := readPhase46RuntimeWorkerDoc(t)
	normalizedDoc := strings.ToLower(strings.Join(strings.Fields(doc), " "))
	if !strings.Contains(normalizedDoc, "optional live") {
		t.Fatal("phase 46 documentation must state optional live behavior is outside default verification")
	}
	for _, marker := range []string{
		"explicit build tags",
		"explicit environment opt-ins",
		"skip by default",
		"`network_enforcement_live`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE=1`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=1`",
	} {
		if !strings.Contains(doc, marker) && !strings.Contains(normalizedDoc, strings.Trim(marker, "`")) {
			t.Fatalf("phase 46 optional live documentation missing gating marker %q", marker)
		}
	}
}

func readPhase46RuntimeWorkerDoc(t *testing.T) string {
	t.Helper()
	return phase46ReadFile(t, filepath.Join("..", "docs", "design", phase46RuntimeWorkerDocPath))
}

func phase46ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func phase46CLIDocFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	root := filepath.Join("..", "docs", "cli")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(%s) error = %v", root, err)
	}
	return files
}

func phase46ForbiddenDefaultAvailabilityClaims() []string {
	return []string{
		"secure credential delivery is enabled by default",
		"secure credential delivery is available by default",
		"secure credential delivery is generally available",
		"credential delivery is enabled by default",
		"credential delivery is production ready",
		"credential delivery is production-ready",
		"network enforcement is enabled by default",
		"network enforcement is available by default",
		"network enforcement is generally available",
		"microvm worker enforcement is enabled by default",
		"microvm worker enforcement is available by default",
		"microvm worker enforcement is generally available",
		"default secure credential delivery",
		"default network enforcement",
		"default microvm worker enforcement",
	}
}
