package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const l8D7PID1NoForkExecDoc = "sandbox-runtime-v2-l8-d7-pid1-no-forkexec.md"

func TestL8D7PID1NoForkExecVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7PID1NoForkExecDoc))), " ")
	for _, required := range []string{
		"HL8E remains unissued",
		"`l8_production_pid1`",
		"does not import `os/exec`",
		"does not call `os.StartProcess`",
		"`clone` and `clone3`",
		"`syscall.rawVforkSyscall`",
		"not value-sensitive",
		"`main.main`",
		"does not catalog `clone` or `clone3` as `runtimeEnvelope`",
		"errEvidenceInputsUnavailable",
		"After successful helper-then-client admit",
		"must not spawn via ForkExec",
		"child descriptors are already admitted",
		"Missing FD 15 L7 `os.StartProcess`",
		"untagged L7-compatible binary",
		"tools/microvm/l8/build-in-container.sh",
		"`-tags=l8_production_pid1`",
		"pinned_evidence_default.go",
		"never writes `verified-pinned-callsites.hl8e` from a fixture",
		"`requireCompleteHonestIssuanceInputs`",
		"unique/reachable D4/D6",
		"`ImportPinnedCallsiteEvidence`",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"go test ./cmd/hal-guest-init -count=1",
		"go test -tags=l8_production_pid1 ./cmd/hal-guest-init -count=1",
		"go test ./tools/microvm/l8/policy/generate -count=1",
		"go test ./tools/microvm/l8 -count=1",
		"go test ./cmd -run '^TestL8D7PID1NoForkExec|^TestL8D7HL8E' -count=1",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"generate `verified-pinned-callsites.hl8e` from a fixture",
		"add `clone` or `clone3` to the Go runtime envelope",
		"claim extras empty as pinned-direct HL8E evidence",
		"treat L5 images as L8 proof",
		"boot Firecracker or require KVM",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("PID1 no-ForkExec verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"HL8E is issued",
		"HL8E issuance is accepted",
		"D7 live is accepted",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("PID1 no-ForkExec verification document contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8D7PID1NoForkExecProductionSources(t *testing.T) {
	l8Path := filepath.Join("hal-guest-init", "main_linux_l8.go")
	l8Source := readL8CredentialDeliveryFile(t, l8Path)
	if !strings.HasPrefix(strings.TrimSpace(l8Source), "//go:build linux && l8_production_pid1") {
		t.Fatal("L8 production PID1 source is missing //go:build linux && l8_production_pid1")
	}
	for _, required := range []string{
		"pid1StartGateRelease()",
		"superviseAdmittedPID1()",
	} {
		if !strings.Contains(l8Source, required) {
			t.Fatalf("L8 production PID1 omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.StartProcess",
		"exec.Command",
		"exec.CommandContext",
		"syscall.ForkExec",
		`"os/exec"`,
	} {
		if strings.Contains(l8Source, forbidden) {
			t.Fatalf("L8 production PID1 contains ForkExec marker %q", forbidden)
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), l8Path, l8Source, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range file.Imports {
		if strings.Trim(spec.Path.Value, `"`) == "os/exec" {
			t.Fatal("L8 production PID1 imports os/exec")
		}
	}

	l7Path := filepath.Join("hal-guest-init", "main_linux_l7.go")
	l7Source := readL8CredentialDeliveryFile(t, l7Path)
	if !strings.HasPrefix(strings.TrimSpace(l7Source), "//go:build linux && !l8_production_pid1") {
		t.Fatal("untagged L7 PID1 source is missing //go:build linux && !l8_production_pid1")
	}
	for _, required := range []string{
		"os.StartProcess(",
		"releasePID1AgentStartGate()",
		`"os/exec"`,
	} {
		if !strings.Contains(l7Source, required) {
			t.Fatalf("untagged L7 PID1 omits %q", required)
		}
	}

	shared := readL8CredentialDeliveryFile(t, filepath.Join("hal-guest-init", "main_linux.go"))
	for _, forbidden := range []string{"os.StartProcess", `"os/exec"`, "exec.CommandContext"} {
		if strings.Contains(shared, forbidden) {
			t.Fatalf("shared PID1 linux source contains ForkExec marker %q", forbidden)
		}
	}
}

func TestL8D7PID1NoForkExecImagePipelineCompilesTaggedInit(t *testing.T) {
	container := readL8CredentialDeliveryFile(t, filepath.Join("..", "tools", "microvm", "l8", "build-in-container.sh"))
	if !strings.Contains(container, "-tags=l8_production_pid1") {
		t.Fatal("L8 image pipeline does not compile hal-init with l8_production_pid1")
	}
	initBuild := l8D7PID1NoForkExecGuestBuild(container, "./cmd/hal-guest-init")
	if !strings.Contains(initBuild, "-tags=l8_production_pid1") || !strings.Contains(initBuild, "-o /build/guest-bin/hal-init") {
		t.Fatalf("hal-init pipeline build is missing the ForkExec-omitting tag: %s", initBuild)
	}
	for _, pkg := range []string{
		"./cmd/hal-guest-agent",
		"./cmd/hal-guest-credential-helper",
		"./cmd/hal-guest-mount-monitor",
		"./cmd/hal-guest-workload-shim",
	} {
		if strings.Contains(l8D7PID1NoForkExecGuestBuild(container, pkg), "-tags=l8_production_pid1") {
			t.Fatalf("%s pipeline build must not use the PID1 ForkExec-omitting tag", pkg)
		}
	}
}

func TestL8D7PID1NoForkExecDoesNotIssueHL8E(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "tools", "microvm", "l8", "policy", "verified-pinned-callsites.hl8e")); err == nil {
		t.Fatal("HL8E must remain unissued; do not generate verified-pinned-callsites.hl8e from a fixture")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestL8D7PID1NoForkExecRemainsDefaultOff(t *testing.T) {
	targets := []string{
		"run_sandbox.go", "auto_sandbox.go", "factory.go", "factory_sandbox_executor.go",
	}
	sandboxdFiles, err := filepath.Glob("sandboxd*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range sandboxdFiles {
		if !strings.HasSuffix(path, "_test.go") {
			targets = append(targets, path)
		}
	}
	for _, path := range targets {
		source := readL8CredentialDeliveryFile(t, path)
		for _, marker := range []string{
			"l8_production_pid1",
			"superviseAdmittedPID1",
			"pid1StartGateRelease",
		} {
			if strings.Contains(source, marker) {
				t.Fatalf("default production path %s wires L8 PID1 no-ForkExec %s", filepath.ToSlash(path), marker)
			}
		}
	}
}

func l8D7PID1NoForkExecGuestBuild(container, pkg string) string {
	marker := "-o /build/guest-bin/"
	index := 0
	for {
		start := strings.Index(container[index:], marker)
		if start < 0 {
			return ""
		}
		start += index
		end := strings.Index(container[start:], "\n")
		if end < 0 {
			end = len(container) - start
		}
		line := container[start : start+end]
		if strings.Contains(line, pkg) {
			blockStart := strings.LastIndex(container[:start], "go -C ")
			if blockStart < 0 {
				return line
			}
			return strings.TrimSpace(container[blockStart : start+end])
		}
		index = start + len(marker)
	}
}
