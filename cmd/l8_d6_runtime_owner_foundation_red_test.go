package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D6RuntimeOwnerFoundationFilesAreExactAndDefaultOff(t *testing.T) {
	files := map[string][]string{
		"../internal/sandboxruntime/job_credential_runtime_recovery.go": {
			"JobCredentialRuntimeAbsenceProof", "JobCredentialRuntimeRecoveryCommitReceipt",
			"JobCredentialRuntimeRecoveryProvider", "JobCredentialRuntimeRecoveryBinding",
		},
		"../internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery.go": {
			"firecrackerRuntimeOwnerRecordV1", "commitJobCredentialRuntimeRecovery",
		},
		"../internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery_linux.go": {
			"readL8RuntimeOwnerHostBootID", "inspectL8RuntimeOwnerProcess",
		},
		"../internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery_other.go": {
			"readL8RuntimeOwnerHostBootID", "inspectL8RuntimeOwnerProcess",
		},
	}
	for path, declarations := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read R1 production file: %v", err)
			}
			for _, declaration := range declarations {
				if !strings.Contains(string(payload), declaration) {
					t.Errorf("R1 production file omits %s", declaration)
				}
			}
		})
	}

	for _, path := range []string{
		"job_service.go", "service.go", "scheduler.go", "sandboxd.go",
		"../internal/sandboxworker/service.go", "../internal/sandboxworker/job_service_v2.go",
	} {
		payload, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "RuntimeOwnerRecovery") || strings.Contains(string(payload), "JobCredentialRuntimeRecoveryProvider") {
			t.Fatalf("default production path wires R1 recovery foundation: %s", path)
		}
	}
}

func TestL8D6RuntimeOwnerFoundationDependenciesRemainUnaccepted(t *testing.T) {
	ownerPath := "../internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery.go"
	payload, err := os.ReadFile(ownerPath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), ownerPath, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	var finalize *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "FinalizeJobCredentialRuntimeRecovery" {
			finalize = function
		}
	}
	if finalize == nil {
		t.Fatal("recovery binding must implement FinalizeJobCredentialRuntimeRecovery")
	}
	source := string(payload)
	for _, forbidden := range []string{
		"TerminatedVMBinding{", "newTerminatedVMBinding", "NewTerminatedVMBinding",
		"productionL7TerminatedVMBinding",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("Finalize forges recovered L7 termination authority with %q", forbidden)
		}
	}
	if !strings.Contains(source, "l7network.NewRecoveredVMTerminationBinding") {
		t.Fatal("Finalize must construct recovered L7 termination via l7network.NewRecoveredVMTerminationBinding")
	}
	if !strings.Contains(source, "CleanupAfterVMQuiesced") || !strings.Contains(source, "l7network.NewReconciler") {
		t.Fatal("Finalize must drive same-boot L7 CleanupAfterVMQuiesced through NewReconciler")
	}
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-d6-runtime-owner-contract-verification.md"))
	for _, marker := range []string{
		"R1 foundation dependency-unaccepted",
		"type `l8RuntimeOwnerRecoveryBinding`",
		"Old-boot journal retirement also remains unavailable and fail-closed",
		"Finalize constructs `l7network.NewRecoveredVMTerminationBinding`",
		"old-boot journal retirement remains fail-closed",
	} {
		if !strings.Contains(doc, marker) {
			t.Errorf("R1 verification omits dependency marker %q", marker)
		}
	}
}
