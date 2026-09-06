package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	l3PreparedLinuxVerificationDocPath = "sandbox-runtime-v2-l3-prepared-linux-verification.md"
	l3PreparedLinuxLiveTestPath        = "l3_prepared_linux_e2e_test.go"
	l3PreparedLinuxBuildTag            = "l3_recovery_e2e"
	l3PreparedLinuxLiveCommand         = "go test -count=1 -tags='podman_integration,l3_recovery_e2e' ./cmd -run '^TestL3PreparedLinuxRecoveryE2E$'"
)

func TestL3PreparedLinuxVerificationDocumentation(t *testing.T) {
	doc := readL3PreparedLinuxVerificationFile(t, filepath.Join("..", "docs", "design", l3PreparedLinuxVerificationDocPath))
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, required := range []string{
		"Sandbox Runtime v2 L3 Prepared-Linux Verification",
		"The default verification matrix is fake-only.",
		"distinct `l3_recovery_e2e` build tag",
		"Missing prerequisites fail the explicitly invoked test; they never skip.",
		"A skipped required live test is a blocker, not a pass.",
		"existing local rootless Podman image",
		"never pulls an image",
		"initiating client process",
		"production `runSandboxWorkerJob` adoption path",
		"exact execution ID",
		"before emitting the observer timing signal",
		"sandbox name and run ID",
		"bounded log follow and terminal drain",
		"repeated recovery and sync-out",
		"exactly one durable lease",
		"output artifacts",
		"active sandbox count",
		"daemon restart",
		"`succeeded`, `failed`, or `canceled`",
		"`unknown` or `interrupted`",
		"without rerunning the admitted command",
		"Cleanup",
		"No cloud or billed provider calls",
		"Non-goals",
		"Run `golangci-lint` only when `command -v golangci-lint` succeeds",
	} {
		if !strings.Contains(doc, required) && !strings.Contains(normalized, required) {
			t.Fatalf("L3 prepared-Linux verification documentation missing %q", required)
		}
	}

	commands := l3PreparedLinuxDocumentedShellCommands(doc)
	for _, required := range []string{
		"go test -count=1 ./cmd -run '^TestL3PreparedLinuxVerification'",
		l3PreparedLinuxLiveCommand,
		"go test ./...",
		"go test -race ./internal/sandboxworker ./internal/sandboxexecution ./cmd",
		"go test -count=1 -run '^$' ./...",
		"GOOS=linux GOARCH=amd64 go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		`test -z "$(gofmt -l cmd internal)"`,
		"git diff --check",
	} {
		if !commands[required] {
			t.Fatalf("L3 prepared-Linux verification documentation missing command %q", required)
		}
	}
}

func l3PreparedLinuxDocumentedShellCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	inShellBlock := false
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if line == "```sh" {
			inShellBlock = true
			continue
		}
		if line == "```" {
			inShellBlock = false
			continue
		}
		if inShellBlock && line != "" {
			commands[line] = true
		}
	}
	return commands
}

func TestL3PreparedLinuxVerificationLiveAcceptanceBoundary(t *testing.T) {
	source := readL3PreparedLinuxVerificationFile(t, l3PreparedLinuxLiveTestPath)
	header := phase19SourceHeader(source)
	if !strings.Contains(header, "//go:build linux && podman_integration && "+l3PreparedLinuxBuildTag) {
		t.Fatalf("%s must require Linux, podman_integration, and the distinct %s tag", l3PreparedLinuxLiveTestPath, l3PreparedLinuxBuildTag)
	}
	for _, required := range []string{
		"func TestL3PreparedLinuxRecoveryE2E(",
		"func TestL3PreparedLinuxSubmitterHelper(",
		"HAL_PODMAN_TEST_IMAGE",
		"rootlesspodman.DefaultPodmanExecutable",
		`"image", "exists"`,
		"runSandboxWorkerJob(",
		"persistSandboxWorkerJobUpdate(",
		"SubmissionID:    l3PreparedLinuxExecutionID",
		"accepted worker job reference was not durable before initiating process loss",
		"helper.Process.Kill()",
		"selectSandboxL3Execution(",
		"runSandboxL3StatusJSON(",
		"runSandboxL3Logs(",
		"runSandboxL3RecoveryObservation(",
		"sandboxworker.DefaultJobLogReadBytes",
		"sandbox.SandboxLeaseStatusReleased",
		"ActiveSandboxes",
		"restartL3PreparedLinuxWorker(",
		"assertL3PreparedLinuxRecoveredArtifacts(",
		"assertL3PreparedLinuxContainerAbsent(",
		`"container", "exists"`,
		"Stdout = io.Discard",
		"Stderr = io.Discard",
		"exitCode == 1",
		"sandboxworker.JobStateSucceeded",
		"sandboxworker.JobStateUnknown",
		"sandboxworker.JobStateInterrupted",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("%s missing acceptance marker %q", l3PreparedLinuxLiveTestPath, required)
		}
	}
	if strings.Count(source, "assertL3PreparedLinuxContainerAbsent(") < 3 {
		t.Fatalf("%s must independently prove absence after explicit and cleanup deletion", l3PreparedLinuxLiveTestPath)
	}
	for _, forbidden := range []string{
		"t.Skip(",
		"t.Skipf(",
		"%#v",
		".JobStart(",
		`"pull"`,
		"podman pull",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("%s contains forbidden live acceptance marker %q", l3PreparedLinuxLiveTestPath, forbidden)
		}
	}
}

func TestL3PreparedLinuxVerificationLiveCommandStaysExplicit(t *testing.T) {
	if !strings.Contains(l3PreparedLinuxLiveCommand, "-tags='podman_integration,"+l3PreparedLinuxBuildTag+"'") {
		t.Fatalf("L3 prepared-Linux command does not require explicit tag %q: %s", l3PreparedLinuxBuildTag, l3PreparedLinuxLiveCommand)
	}
	if strings.Contains(l3PreparedLinuxLiveCommand, "./...") {
		t.Fatalf("L3 prepared-Linux live command must stay focused: %s", l3PreparedLinuxLiveCommand)
	}
}

func readL3PreparedLinuxVerificationFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
