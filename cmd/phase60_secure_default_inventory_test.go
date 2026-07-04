package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	phase60AnchorFunc = "func"
	phase60AnchorType = "type"
)

type phase60SourceAnchor struct {
	path string
	kind string
	name string
}

type phase60EvidenceContract struct {
	id      string
	notes   string
	anchors []phase60SourceAnchor
}

type phase60ProjectionBoundary struct {
	id      string
	notes   string
	anchors []phase60SourceAnchor
}

// TestPhase60SecureDefaultEvidenceContractInventory is an inventory guard, not
// a behavior assertion. Later Phase 60 tests should reuse these existing
// contracts instead of creating a parallel secure-default evidence model.
func TestPhase60SecureDefaultEvidenceContractInventory(t *testing.T) {
	contracts := phase60SecureDefaultEvidenceContracts()
	phase60RequireInventoryIDs(t, "evidence contract", phase60EvidenceContractIDs(contracts), []string{
		"target_selection",
		"microvm_readiness",
		"proxy_firewall_enforcement",
		"credential_delivery",
		"template_trust",
	})
	for _, contract := range contracts {
		contract := contract
		t.Run(contract.id, func(t *testing.T) {
			phase60RequireInventoryNotes(t, contract.id, contract.notes)
			phase60RequireAnchors(t, contract.id, contract.anchors)
		})
	}
}

// TestPhase60SecureDefaultProjectionBoundaryInventory identifies the current
// command/status projection boundaries before later stories add surface-specific
// assertions.
func TestPhase60SecureDefaultProjectionBoundaryInventory(t *testing.T) {
	boundaries := phase60SecureDefaultProjectionBoundaries()
	phase60RequireInventoryIDs(t, "projection boundary", phase60ProjectionBoundaryIDs(boundaries), []string{
		"run",
		"auto",
		"factory",
		"status",
		"sandbox_runtime",
	})
	for _, boundary := range boundaries {
		boundary := boundary
		t.Run(boundary.id, func(t *testing.T) {
			phase60RequireInventoryNotes(t, boundary.id, boundary.notes)
			phase60RequireAnchors(t, boundary.id, boundary.anchors)
		})
	}
}

func phase60SecureDefaultEvidenceContracts() []phase60EvidenceContract {
	return []phase60EvidenceContract{
		{
			id:    "target_selection",
			notes: "Target selection gathers target, host, runtime, workspace, and requested secure-default metadata, then delegates strict decisions to internal/sandbox.",
			anchors: []phase60SourceAnchor{
				phase60Func("internal/sandboxtarget/select.go", "targetSelectionSecurityReadinessGateDecision"),
				phase60Func("internal/sandboxtarget/select.go", "targetSelectionProjectedSecurityReadiness"),
				phase60Func("internal/sandboxtarget/select.go", "targetSelectionRequestedSecureDefaultReadinessInput"),
				phase60Func("internal/sandbox/security_capability_secure_default_policy.go", "EvaluateSandboxSecureDefaultReadiness"),
				phase60Func("internal/sandbox/security_capability_secure_default_policy.go", "ProjectSandboxSecureDefaultReadinessDiagnostics"),
			},
		},
		{
			id:    "microvm_readiness",
			notes: "MicroVM readiness evidence is active VM isolation proof projected from runtime target metadata and guest readiness labels, not driver identity alone.",
			anchors: []phase60SourceAnchor{
				phase60Func("internal/sandboxruntime/microvm/isolation_proof.go", "ProjectMicroVMIsolationProofMetadata"),
				phase60Func("internal/sandboxruntime/guest_readiness.go", "SanitizeRuntimeGuestReadinessMetadata"),
				phase60Func("internal/sandbox/security_capability_projection.go", "sandboxSecurityCapabilityProjectionAppendMicroVMIsolationProof"),
				phase60Func("internal/sandbox/security_capability_projection.go", "sandboxSecurityCapabilityProjectionMicroVMIsolationProofReadiness"),
			},
		},
		{
			id:    "proxy_firewall_enforcement",
			notes: "Proxy plus firewall enforcement evidence is sanitized runtime network proof; command and worker projections preserve proxy-only metadata without upgrading it to proxy_firewall.",
			anchors: []phase60SourceAnchor{
				phase60Func("internal/sandboxruntime/network_enforcement_proof.go", "ProjectRuntimeNetworkEnforcementProofMetadata"),
				phase60Func("internal/sandboxruntime/network_enforcement_proof.go", "RuntimeNetworkEnforcementProofProvesActiveProxyFirewall"),
				phase60Func("cmd/sandbox_network_enforcement_projection.go", "commandSandboxNetworkEnforcementProofFromRuntimeMetadata"),
				phase60Func("internal/sandboxworker/service.go", "projectWorkerSecurityPolicy"),
				phase60Func("internal/sandboxworker/service.go", "projectRuntimeDriverSecurityPolicy"),
				phase60Func("internal/sandbox/security_capability_projection.go", "sandboxSecurityCapabilityProjectionAppendNetworkEnforcementProof"),
				phase60Func("internal/sandbox/security_capability_projection.go", "sandboxSecurityCapabilityProjectionNetworkProofReadiness"),
			},
		},
		{
			id:    "credential_delivery",
			notes: "Credential delivery evidence is active brokered proof summaries correlated with sanitized credential-proxy bindings; plan-only and compatibility metadata remain non-proof.",
			anchors: []phase60SourceAnchor{
				phase60Func("internal/credentialdelivery/projection.go", "StatusMetadataFromActivation"),
				phase60Func("internal/credentialdelivery/projection.go", "secureActiveStatusProofSummaries"),
				phase60Type("internal/sandbox/credential_delivery.go", "SandboxCredentialDeliveryProofSummary"),
				phase60Func("internal/sandbox/credential_delivery.go", "SanitizeSandboxCredentialDeliverySurfaceStatusMetadata"),
				phase60Func("internal/sandboxruntime/credential_delivery.go", "SanitizeRuntimeCredentialDeliveryMetadata"),
				phase60Func("internal/sandboxruntime/credential_delivery.go", "RuntimeCredentialDeliveryMetadataValid"),
				phase60Func("internal/sandbox/security_capability_projection.go", "sandboxSecurityCapabilityProjectionAppendCredentialDeliveryProof"),
			},
		},
		{
			id:    "template_trust",
			notes: "Template trust evidence is digest-locked selected-template metadata with strict trusted policy status; advisory, unavailable, unresolved, or warning-bearing locks stay non-ready.",
			anchors: []phase60SourceAnchor{
				phase60Type("internal/sandbox/template_lock.go", "SandboxTemplateLockMetadata"),
				phase60Type("internal/sandbox/template_lock.go", "SandboxTemplateTrustPolicyMetadata"),
				phase60Func("internal/sandbox/template_lock.go", "SanitizeSandboxTemplateLockMetadata"),
				phase60Func("internal/sandboxruntime/template_lock.go", "ProjectRuntimeTemplateStatusMetadata"),
				phase60Func("internal/sandboxruntime/template_lock.go", "SanitizeRuntimeTemplateLockMetadata"),
				phase60Func("internal/sandbox/security_capability_projection.go", "sandboxSecurityCapabilityProjectionAppendTemplateLockProof"),
				phase60Func("internal/sandbox/security_capability_projection.go", "sandboxSecurityCapabilityProjectionSelectedTemplateTrustReadiness"),
			},
		},
	}
}

func phase60SecureDefaultProjectionBoundaries() []phase60ProjectionBoundary {
	return []phase60ProjectionBoundary{
		{
			id:    "run",
			notes: "The run surface persists readiness, credential delivery, and gate decisions through the sandbox execution manifest plus command JSON augmentation.",
			anchors: []phase60SourceAnchor{
				phase60Func("cmd/run_sandbox.go", "saveRunSandboxManifest"),
				phase60Func("cmd/run_sandbox.go", "runSandboxManifestCapabilityReadiness"),
				phase60Func("cmd/run_sandbox.go", "runSandboxManifestSecurityReadinessGate"),
				phase60Func("cmd/run_sandbox.go", "enforceSandboxExecutionSecurityReadinessGate"),
				phase60Func("cmd/credential_proxy_plumbing.go", "applyRunSandboxCredentialProxyMetadata"),
				phase60Func("cmd/sandbox_sync_out_apply.go", "sandboxCommandJSONSecurityReadinessGate"),
			},
		},
		{
			id:    "auto",
			notes: "The auto surface shares the run manifest model, then applies auto-specific readiness diagnostics and gate projection before saving the manifest.",
			anchors: []phase60SourceAnchor{
				phase60Func("cmd/auto_sandbox.go", "saveAutoSandboxManifest"),
				phase60Func("cmd/auto_sandbox.go", "autoSandboxManifestSecurityReadinessGate"),
				phase60Func("cmd/auto_sandbox_readiness.go", "applyAutoSandboxCapabilityReadinessMetadata"),
				phase60Func("cmd/auto_sandbox_readiness.go", "autoSandboxManifestNetworkPolicyResult"),
				phase60Func("cmd/credential_proxy_plumbing.go", "applyAutoSandboxCredentialProxyMetadata"),
			},
		},
		{
			id:    "factory",
			notes: "The factory surface projects readiness into factory sandbox metadata, policy timeline metadata, credential delivery logs, and readiness-gate policy decisions.",
			anchors: []phase60SourceAnchor{
				phase60Func("cmd/factory_sandbox_executor.go", "factorySandboxPersistentMetadataFromState"),
				phase60Func("cmd/factory_sandbox_executor.go", "factorySandboxSecurityMetadata"),
				phase60Func("cmd/factory_sandbox_executor.go", "factorySandboxSecurityTimelineMetadata"),
				phase60Func("cmd/factory_sandbox_executor.go", "recordFactorySandboxSecurityPolicyEvent"),
				phase60Func("cmd/factory_sandbox_readiness.go", "applyFactorySandboxCapabilityReadinessMetadata"),
				phase60Func("cmd/factory_sandbox_readiness.go", "factorySandboxCapabilityReadiness"),
				phase60Func("cmd/factory_sandbox_readiness_gate.go", "enforceFactorySandboxReadinessGate"),
				phase60Func("cmd/credential_proxy_plumbing.go", "applyFactorySandboxCredentialProxyMetadata"),
			},
		},
		{
			id:    "status",
			notes: "The sandbox status surface renders cached sandbox state and selected-template readiness through the runtime selected-template summary without making live enforcement claims.",
			anchors: []phase60SourceAnchor{
				phase60Func("cmd/sandbox_status.go", "runSandboxStatusWithDeps"),
				phase60Func("cmd/sandbox_status.go", "renderSandboxDetail"),
				phase60Func("cmd/sandbox_runtime_contracts.go", "newSandboxRuntimeSelectedTemplateFromSandboxLock"),
				phase60Func("cmd/sandbox_host_mapping.go", "sandboxHostSecurityFromWorker"),
			},
		},
		{
			id:    "sandbox_runtime",
			notes: "The sandbox runtime inspection surface projects cached or live worker metadata into sandbox-runtime-list/status JSON summaries and compatibility readiness gates.",
			anchors: []phase60SourceAnchor{
				phase60Func("cmd/sandbox_runtime.go", "runSandboxRuntimeList"),
				phase60Func("cmd/sandbox_runtime.go", "runSandboxRuntimeStatus"),
				phase60Func("cmd/sandbox_runtime_contracts.go", "newSandboxRuntimeSecuritySummary"),
				phase60Func("cmd/sandbox_runtime_contracts.go", "newSandboxRuntimeSecuritySummaryFromWorkerDriver"),
				phase60Func("cmd/sandbox_runtime_contracts.go", "newSandboxRuntimeSelectedTemplate"),
				phase60Func("cmd/sandbox_runtime_contracts.go", "sandboxRuntimeCapabilityReadinessFromWorkerPolicy"),
				phase60Func("cmd/sandbox_runtime_contracts.go", "sandboxRuntimeSecurityReadinessGate"),
			},
		},
	}
}

func phase60Func(path, name string) phase60SourceAnchor {
	return phase60SourceAnchor{path: path, kind: phase60AnchorFunc, name: name}
}

func phase60Type(path, name string) phase60SourceAnchor {
	return phase60SourceAnchor{path: path, kind: phase60AnchorType, name: name}
}

func phase60EvidenceContractIDs(contracts []phase60EvidenceContract) []string {
	ids := make([]string, 0, len(contracts))
	for _, contract := range contracts {
		ids = append(ids, contract.id)
	}
	return ids
}

func phase60ProjectionBoundaryIDs(boundaries []phase60ProjectionBoundary) []string {
	ids := make([]string, 0, len(boundaries))
	for _, boundary := range boundaries {
		ids = append(ids, boundary.id)
	}
	return ids
}

func phase60RequireInventoryIDs(t *testing.T, label string, got, want []string) {
	t.Helper()
	got = append([]string(nil), got...)
	want = append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%s ids = %#v, want %#v", label, got, want)
	}
}

func phase60RequireInventoryNotes(t *testing.T, id, notes string) {
	t.Helper()
	if strings.TrimSpace(id) == "" {
		t.Fatal("inventory entry id is empty")
	}
	if strings.TrimSpace(notes) == "" {
		t.Fatalf("%s notes are empty", id)
	}
}

func phase60RequireAnchors(t *testing.T, id string, anchors []phase60SourceAnchor) {
	t.Helper()
	if len(anchors) == 0 {
		t.Fatalf("%s anchors are empty", id)
	}
	for _, anchor := range anchors {
		if err := phase60SourceAnchorExists(t, anchor); err != nil {
			t.Fatalf("%s anchor %s: %v", id, phase60AnchorDisplay(anchor), err)
		}
	}
}

func phase60SourceAnchorExists(t *testing.T, anchor phase60SourceAnchor) error {
	t.Helper()
	if strings.TrimSpace(anchor.path) == "" || strings.TrimSpace(anchor.name) == "" || strings.TrimSpace(anchor.kind) == "" {
		return fmt.Errorf("anchor is incomplete")
	}
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, phase60RepoPath(t, anchor.path), nil, parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	if phase60ParsedFileHasDecl(parsed, anchor.kind, anchor.name) {
		return nil
	}
	return fmt.Errorf("%s declaration %q was not found", anchor.kind, anchor.name)
}

func phase60ParsedFileHasDecl(file *ast.File, kind, name string) bool {
	if file == nil {
		return false
	}
	for _, decl := range file.Decls {
		switch typed := decl.(type) {
		case *ast.FuncDecl:
			if kind == phase60AnchorFunc && typed.Name != nil && typed.Name.Name == name {
				return true
			}
		case *ast.GenDecl:
			if kind != phase60AnchorType || typed.Tok != token.TYPE {
				continue
			}
			for _, spec := range typed.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if ok && typeSpec.Name != nil && typeSpec.Name.Name == name {
					return true
				}
			}
		}
	}
	return false
}

func phase60RepoPath(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			path := filepath.Join(dir, filepath.FromSlash(rel))
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("repo path %s: %v", rel, err)
			}
			return path
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repository root for %s", rel)
		}
		dir = parent
	}
}

func phase60AnchorDisplay(anchor phase60SourceAnchor) string {
	return anchor.path + ":" + anchor.kind + ":" + anchor.name
}
