package selection_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
)

func TestL9StrictSelectionCanonicalizesTagBeforeUnchangedPolicyEvaluator(t *testing.T) {
	templateBytes := []byte(`apiVersion: sandbox-template.hal.dev/v1
kind: SandboxTemplate
metadata:
  id: l9-template
  reference:
    kind: oci_artifact
    ref: registry.test/hal/template:latest
runtime:
  driver: microvm
  isolationLevel: vm
`)
	documentDigest := selectionTestDigest(templateBytes)
	manifestBytes := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	manifestDigest := selectionTestDigest(manifestBytes)
	resolver := acquisition.NewOCIResolver(acquisition.NewInMemoryOCIArtifactResolver(map[string]acquisition.OCIArtifactResolveResult{
		"registry.test/hal/template:latest": {
			TemplateBytes:          templateBytes,
			ArtifactManifestBytes:  manifestBytes,
			Format:                 sandboxtemplate.FormatYAML,
			DocumentDigest:         documentDigest,
			TemplateArtifactDigest: manifestDigest,
			ReferenceDigests: []acquisition.ReferenceDigestProof{{
				Field:         "metadata.reference",
				Kind:          sandboxtemplate.ReferenceKindOCIArtifact,
				Digest:        manifestDigest,
				VerifiedBytes: manifestBytes,
			}},
		},
	}))

	result, err := selection.NewWorkflow(resolver).Select(context.Background(), selection.Request{
		Source: acquisition.TemplateSource{
			Kind: acquisition.SourceKindOCIArtifact,
			Reference: &sandboxtemplate.ImmutableRef{
				Kind: sandboxtemplate.ReferenceKindOCIArtifact,
				Ref:  "registry.test/hal/template:latest",
			},
		},
		TrustMode: acquisition.TrustPolicyModeStrict,
	})
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if result.Trust.Decision != acquisition.TrustPolicyDecisionTrusted {
		t.Fatalf("trust decision = %q, want trusted", result.Trust.Decision)
	}
	if result.Template.Metadata.Reference == nil || result.Template.Metadata.Reference.Ref != "" {
		t.Fatalf("selected reference = %#v, want digest-canonical ref without mutable alias", result.Template.Metadata.Reference)
	}
	if got := result.Template.Metadata.Reference.Digest; got == nil || got.Value != manifestDigest.Value {
		t.Fatalf("selected digest = %#v, want manifest digest", got)
	}
	if result.RuntimeDriver != "microvm" || result.IsolationLevel != "vm" {
		t.Fatalf("runtime intent = %q/%q, want microvm/vm", result.RuntimeDriver, result.IsolationLevel)
	}
}

func TestL9SelectionBindingRejectsRuntimeIdentityMismatch(t *testing.T) {
	result := selection.Result{
		ManifestDigest: &sandboxtemplate.DigestMetadata{
			Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
			Value:     strings.Repeat("a", 64),
		},
		RuntimeDriver: "microvm",
	}
	_, err := selection.Bind(result, selection.BindingRequest{
		ExecutionID:   "run-l9",
		SandboxID:     "sandbox-l9",
		RuntimeID:     "runtime-l9",
		RuntimeDriver: "rootless_podman",
	})
	if err == nil {
		t.Fatal("Bind() error = nil, want runtime identity mismatch")
	}
	if !strings.Contains(err.Error(), string(selection.ErrorCodeSelectionRejected)) {
		t.Fatalf("Bind() error = %q, want safe selection_rejected code", err)
	}
}

func TestL9SelectionRejectsStrictPolicyBeforeReturningRuntimeIntent(t *testing.T) {
	resolver := &selectionResolverStub{
		result: acquisition.ResolveResult{
			Template: sandboxtemplate.Template{
				APIVersion: sandboxtemplate.TemplateAPIVersionV1,
				Kind:       sandboxtemplate.TemplateKindSandbox,
				Metadata: sandboxtemplate.TemplateMetadata{
					ID: "unverified-template",
					Reference: &sandboxtemplate.ImmutableRef{
						Kind: sandboxtemplate.ReferenceKindOCIArtifact,
						Ref:  "registry.example/hal/template:latest",
					},
				},
				Runtime: &sandboxtemplate.RuntimeRequirements{
					Driver:         "microvm",
					IsolationLevel: "vm",
				},
			},
			Lock: acquisition.TemplateLock{
				SourceKind: acquisition.SourceKindOCIArtifact,
				Status:     acquisition.LockStatusUnresolved,
			},
		},
	}
	result, err := selection.NewWorkflow(resolver).Select(context.Background(), selection.Request{
		Source:    acquisition.TemplateSource{Kind: acquisition.SourceKindOCIArtifact},
		TrustMode: acquisition.TrustPolicyModeStrict,
	})
	if err == nil {
		t.Fatal("Select() error = nil, want strict rejection")
	}
	if result.RuntimeDriver != "" || result.RuntimeMetadata != nil || result.ManifestDigest != nil {
		t.Fatalf("rejected selection exposed runtime intent/evidence: %#v", result)
	}
	if !strings.Contains(err.Error(), string(selection.ErrorCodeSelectionRejected)) {
		t.Fatalf("Select() error = %q, want selection_rejected", err)
	}
}

func TestL9AdvisorySelectionNeverClaimsStrictTrust(t *testing.T) {
	resolver := &selectionResolverStub{
		result: acquisition.ResolveResult{
			Template: sandboxtemplate.Template{
				APIVersion: sandboxtemplate.TemplateAPIVersionV1,
				Kind:       sandboxtemplate.TemplateKindSandbox,
				Metadata:   sandboxtemplate.TemplateMetadata{ID: "advisory-template"},
			},
			Lock: acquisition.TemplateLock{
				SourceKind: acquisition.SourceKindOCIArtifact,
				Status:     acquisition.LockStatusUnresolved,
			},
		},
	}
	result, err := selection.NewWorkflow(resolver).Select(context.Background(), selection.Request{
		Source:    acquisition.TemplateSource{Kind: acquisition.SourceKindOCIArtifact},
		TrustMode: acquisition.TrustPolicyModeAdvisory,
	})
	if err != nil {
		t.Fatalf("Select() advisory error = %v", err)
	}
	if result.Trust.Decision == acquisition.TrustPolicyDecisionTrusted {
		t.Fatal("advisory selection claimed strict trust")
	}
}

func TestL9SelectionDoesNotFallbackAfterResolverFailure(t *testing.T) {
	resolver := &selectionResolverStub{err: errors.New("fixture registry unavailable")}
	result, err := selection.NewWorkflow(resolver).Select(context.Background(), selection.Request{
		Source:    acquisition.TemplateSource{Kind: acquisition.SourceKindOCIArtifact},
		TrustMode: acquisition.TrustPolicyModeStrict,
	})
	if err == nil {
		t.Fatal("Select() error = nil")
	}
	if result.Template.Metadata.ID != "" || result.ManifestDigest != nil {
		t.Fatalf("resolver failure returned fallback selection: %#v", result)
	}
}

func TestL9SelectionBindingRequiresAllExactIdentitiesAndDigest(t *testing.T) {
	digest := &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     strings.Repeat("a", 64),
	}
	result := selection.Result{
		ManifestDigest: digest,
		RuntimeDriver:  "microvm",
	}
	valid := selection.BindingRequest{
		ExecutionID:    "run-l9",
		SandboxID:      "sandbox-l9",
		RuntimeID:      "runtime-l9",
		RuntimeDriver:  "microvm",
		ManifestDigest: digest,
	}
	tests := []struct {
		name   string
		mutate func(*selection.BindingRequest)
	}{
		{"execution", func(r *selection.BindingRequest) { r.ExecutionID = "" }},
		{"sandbox", func(r *selection.BindingRequest) { r.SandboxID = "" }},
		{"runtime", func(r *selection.BindingRequest) { r.RuntimeID = "" }},
		{"driver", func(r *selection.BindingRequest) { r.RuntimeDriver = "rootless_podman" }},
		{"missing digest", func(r *selection.BindingRequest) { r.ManifestDigest = nil }},
		{"different digest", func(r *selection.BindingRequest) { r.ManifestDigest = selectionTestDigest([]byte("different")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := valid
			tt.mutate(&request)
			_, err := selection.Bind(result, request)
			if err == nil || !strings.Contains(err.Error(), string(selection.ErrorCodeSelectionRejected)) {
				t.Fatalf("Bind() error = %v, want selection_rejected", err)
			}
		})
	}
}

type selectionResolverStub struct {
	result acquisition.ResolveResult
	err    error
	calls  int
}

func (s *selectionResolverStub) Resolve(context.Context, acquisition.ResolveRequest) (acquisition.ResolveResult, error) {
	s.calls++
	return s.result, s.err
}

func selectionTestDigest(data []byte) *sandboxtemplate.DigestMetadata {
	sum := sha256.Sum256(data)
	return &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     hex.EncodeToString(sum[:]),
	}
}
