package cmd

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

const l8D7PID1AdmitDescriptorsDoc = "sandbox-runtime-v2-l8-d7-pid1-admit-descriptors.md"

func TestL8D7PID1AdmitDescriptorsVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7PID1AdmitDescriptorsDoc))), " ")
	for _, required := range []string{
		"releasePID1AgentStartGate",
		"admitPID1StartGate",
		"inherited helper-then-client",
		"Fixed inherited FD **16**",
		"Fixed inherited FD **17**",
		"never constructs helper or client",
		"l8composition.NewHelper",
		"l8composition.NewClient",
		"mismatch",
		"missing slot",
		"returns 127",
		"close-on-exec",
		"F_DUPFD_CLOEXEC",
		"Missing unsigned FD 15 still returns 0",
		"L7 supervisor path",
		"default-off",
		"sandboxd",
		"`hal run`",
		"`hal auto`",
		"does not claim D7 live",
		"does not claim HL8E issuance",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"D7 prepared-Linux acceptance remains unaccepted",
		"HL8E remains unissued",
		"go test ./cmd/hal-guest-init -count=1",
		"go test ./internal/sandboxruntime/microvm/guestagent/l8composition -run 'PID1StartGate' -count=1",
		"go test ./cmd -run '^TestL8D7PID1AdmitDescriptors|^TestL8GuestInitDoesNotInvent|^TestL8PID1GuestInit' -count=1",
		"go vet ./cmd/hal-guest-init ./cmd",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"change D7 live stub fatals",
		"issue HL8E or enable `generateEvidence` success",
		"construct helper or client processes",
		"HL8L `controller_attestation`",
		"HL8A `client_attestation`",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("PID1 admit-descriptors verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"HL8E issuance is accepted",
		"D7 live is accepted",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("PID1 admit-descriptors verification document contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8D7PID1AdmitDescriptorsProductionSource(t *testing.T) {
	source := readL8CredentialDeliveryFile(t, filepath.Join("hal-guest-init", "pid1_start_gate_linux.go"))
	for _, required := range []string{
		"pid1StartGateExpectedFDNumber = 15",
		"pid1StartGateHelperFDNumber = 16",
		"pid1StartGateClientFDNumber = 17",
		"admitPID1StartGate(expected, helper, client)",
		"DecodeProcessDescriptor",
		"loadPID1StartGateProcessDescriptor",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("PID1 start-gate production file omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"l8composition.NewHelper",
		"l8composition.NewClient",
		"os.Getenv",
		"os.LookupEnv",
		"os.ReadFile",
		"os.Open(",
		"/proc/cmdline",
		"go:embed",
		"json.Unmarshal",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("PID1 start-gate production file contains forbidden marker %q", forbidden)
		}
	}
}

func TestL8D7PID1AdmitDescriptorsRemainsDefaultOff(t *testing.T) {
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
			"admitPID1StartGate",
			"pid1StartGateHelperFD",
			"pid1StartGateClientFD",
			"loadPID1StartGateProcessDescriptor",
			"releasePID1AgentStartGate",
		} {
			if strings.Contains(source, marker) {
				t.Fatalf("default production path %s wires PID1 admit %s", filepath.ToSlash(path), marker)
			}
		}
	}
}

func TestL8D7PID1AdmitDescriptorsDoesNotInventUnsignedInputs(t *testing.T) {
	path := filepath.Join("hal-guest-init", "pid1_start_gate_linux.go")
	source := readL8CredentialDeliveryFile(t, path)
	file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range file.Imports {
		importPath := strings.Trim(spec.Path.Value, `"`)
		switch importPath {
		case "os", "os/exec", "net", "net/http", "unsafe", "syscall":
			t.Errorf("PID1 start-gate production imports unsigned or live package %s", importPath)
		}
	}
}
