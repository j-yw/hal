package selection_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
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
		ExecutionID:    "run-l9",
		SandboxID:      "sandbox-l9",
		RuntimeID:      "runtime-l9",
		RuntimeDriver:  "rootless_podman",
		IsolationLevel: "vm",
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
	manifestDigest := selectionTestDigest([]byte("advisory manifest"))
	resolver := &selectionResolverStub{
		result: acquisition.ResolveResult{
			Template: sandboxtemplate.Template{
				APIVersion: sandboxtemplate.TemplateAPIVersionV1,
				Kind:       sandboxtemplate.TemplateKindSandbox,
				Metadata:   sandboxtemplate.TemplateMetadata{ID: "advisory-template"},
			},
			Lock: acquisition.TemplateLock{
				SourceKind:    acquisition.SourceKindOCIArtifact,
				ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
				Status:        acquisition.LockStatusLocked,
				References: []acquisition.ReferenceLock{{
					Field:  "metadata.reference",
					Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
					Status: acquisition.LockStatusLocked,
					Digest: manifestDigest,
				}},
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

func TestL9SelectionRechecksCancellationBeforeReturningEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	resolver := &selectionResolverStub{cancel: cancel}
	result, err := selection.NewWorkflow(resolver).Select(ctx, selection.Request{
		Source:    acquisition.TemplateSource{Kind: acquisition.SourceKindOCIArtifact},
		TrustMode: acquisition.TrustPolicyModeStrict,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Select() error = %v, want context.Canceled", err)
	}
	if result.ManifestDigest != nil || result.RuntimeMetadata != nil || result.Template.Metadata.ID != "" {
		t.Fatalf("canceled selection returned evidence: %#v", result)
	}
}

func TestL9SelectionRequiresExactLockedOCISHA256ManifestEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*acquisition.TemplateLock)
	}{
		{"source kind", func(lock *acquisition.TemplateLock) { lock.SourceKind = acquisition.SourceKindGit }},
		{"root reference kind", func(lock *acquisition.TemplateLock) { lock.ReferenceKind = sandboxtemplate.ReferenceKindGit }},
		{"root status", func(lock *acquisition.TemplateLock) { lock.Status = acquisition.LockStatusUnresolved }},
		{"reference kind", func(lock *acquisition.TemplateLock) { lock.References[0].Kind = sandboxtemplate.ReferenceKindGit }},
		{"reference status", func(lock *acquisition.TemplateLock) { lock.References[0].Status = acquisition.LockStatusUnresolved }},
		{"digest algorithm", func(lock *acquisition.TemplateLock) { lock.References[0].Digest.Algorithm = "sha512" }},
		{"uppercase digest", func(lock *acquisition.TemplateLock) {
			lock.References[0].Digest.Value = strings.ToUpper(lock.References[0].Digest.Value)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := selectionTestDigest([]byte("locked manifest"))
			lock := acquisition.TemplateLock{
				SourceKind:    acquisition.SourceKindOCIArtifact,
				ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
				Status:        acquisition.LockStatusLocked,
				References: []acquisition.ReferenceLock{{
					Field:  "metadata.reference",
					Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
					Status: acquisition.LockStatusLocked,
					Digest: digest,
				}},
			}
			tt.mutate(&lock)
			resolver := &selectionResolverStub{result: acquisition.ResolveResult{Lock: lock}}
			_, err := selection.NewWorkflow(resolver).Select(context.Background(), selection.Request{
				Source:    acquisition.TemplateSource{Kind: acquisition.SourceKindOCIArtifact},
				TrustMode: acquisition.TrustPolicyModeAdvisory,
			})
			if err == nil || !strings.Contains(err.Error(), string(selection.ErrorCodeSelectionRejected)) {
				t.Fatalf("Select() error = %v, want selection_rejected", err)
			}
		})
	}
}

func TestL9SelectionBindingRequiresAllExactIdentitiesAndDigest(t *testing.T) {
	digest := &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     strings.Repeat("a", 64),
	}
	result := validBindingSelectionResult(digest)
	valid := selection.BindingRequest{
		ExecutionID:    "run-l9",
		SandboxID:      "sandbox-l9",
		RuntimeID:      "runtime-l9",
		RuntimeDriver:  "microvm",
		IsolationLevel: "vm",
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
		{"isolation", func(r *selection.BindingRequest) { r.IsolationLevel = "container" }},
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

func TestL9SelectionBindingRejectsMissingOrMismatchedLockAndTrustCorrelation(t *testing.T) {
	digest := selectionTestDigest([]byte("verified manifest"))
	base := validBindingSelectionResult(digest)
	request := selection.BindingRequest{
		ExecutionID:    "run-l9",
		SandboxID:      "sandbox-l9",
		RuntimeID:      "runtime-l9",
		RuntimeDriver:  "microvm",
		IsolationLevel: "vm",
		ManifestDigest: digest,
	}
	if _, err := selection.Bind(base, request); err != nil {
		t.Fatalf("valid Bind() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*selection.Result)
	}{
		{"missing lock", func(r *selection.Result) { r.Lock = acquisition.TemplateLock{} }},
		{"wrong source", func(r *selection.Result) { r.Lock.SourceKind = acquisition.SourceKindLocalFile }},
		{"wrong lock reference kind", func(r *selection.Result) { r.Lock.ReferenceKind = sandboxtemplate.ReferenceKindGit }},
		{"wrong locked reference kind", func(r *selection.Result) { r.Lock.References[0].Kind = sandboxtemplate.ReferenceKindGit }},
		{"uppercase digest", func(r *selection.Result) { r.ManifestDigest.Value = strings.ToUpper(r.ManifestDigest.Value) }},
		{"template reference digest", func(r *selection.Result) { r.Template.Metadata.Reference.Digest.Value = strings.Repeat("b", 64) }},
		{"template runtime driver", func(r *selection.Result) { r.Template.Runtime.Driver = "rootless_podman" }},
		{"template runtime isolation", func(r *selection.Result) { r.Template.Runtime.IsolationLevel = "container" }},
		{"missing template metadata", func(r *selection.Result) { r.RuntimeMetadata.TemplateReference = nil }},
		{"template metadata source", func(r *selection.Result) { r.RuntimeMetadata.TemplateReference.SourceKind = "template_kit" }},
		{"template digest", func(r *selection.Result) { r.RuntimeMetadata.TemplateReference.DigestValue = strings.Repeat("b", 64) }},
		{"missing trust metadata", func(r *selection.Result) { r.RuntimeMetadata.TrustPolicy = nil }},
		{"trust digest", func(r *selection.Result) { r.RuntimeMetadata.TrustPolicy.DigestValue = strings.Repeat("b", 64) }},
		{"trust decision", func(r *selection.Result) { r.RuntimeMetadata.TrustPolicy.Decision = "advisory" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cloneSelectionResultForBinding(base)
			tt.mutate(&result)
			if _, err := selection.Bind(result, request); err == nil {
				t.Fatal("Bind() error = nil, want selection_rejected")
			}
		})
	}
}

func validBindingSelectionResult(digest *sandboxtemplate.DigestMetadata) selection.Result {
	return selection.Result{
		ManifestDigest: digest,
		RuntimeDriver:  "microvm",
		IsolationLevel: "vm",
		Template: sandboxtemplate.Template{
			Metadata: sandboxtemplate.TemplateMetadata{
				Reference: &sandboxtemplate.ImmutableRef{
					Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
					Digest: digest,
				},
			},
			Runtime: &sandboxtemplate.RuntimeRequirements{
				Driver:         "microvm",
				IsolationLevel: "vm",
			},
		},
		Lock: acquisition.TemplateLock{
			SourceKind:    acquisition.SourceKindOCIArtifact,
			ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
			Status:        acquisition.LockStatusLocked,
			References: []acquisition.ReferenceLock{{
				Field:  "metadata.reference",
				Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
				Status: acquisition.LockStatusLocked,
				Digest: digest,
			}},
		},
		Trust: acquisition.TrustPolicyResult{
			Mode:     acquisition.TrustPolicyModeStrict,
			Decision: acquisition.TrustPolicyDecisionTrusted,
		},
		RuntimeMetadata: &sandboxruntime.RuntimeTemplateLockMetadata{
			TemplateReference: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
				SourceKind:      "template_reference",
				ReferenceKind:   "oci_artifact",
				Status:          "locked",
				DigestAlgorithm: "sha256",
				DigestValue:     digest.Value,
			},
			TrustPolicy: &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{
				Mode:            "strict",
				Decision:        "trusted",
				SourceKind:      "oci_artifact",
				ReferenceKind:   "oci_artifact",
				Status:          "locked",
				DigestAlgorithm: "sha256",
				DigestValue:     digest.Value,
			},
		},
	}
}

func cloneSelectionResultForBinding(input selection.Result) selection.Result {
	out := input
	out.Lock.References = append([]acquisition.ReferenceLock(nil), input.Lock.References...)
	if input.ManifestDigest != nil {
		digest := *input.ManifestDigest
		out.ManifestDigest = &digest
	}
	if input.Template.Metadata.Reference != nil {
		reference := *input.Template.Metadata.Reference
		if reference.Digest != nil {
			digest := *reference.Digest
			reference.Digest = &digest
		}
		out.Template.Metadata.Reference = &reference
	}
	if input.Template.Runtime != nil {
		runtime := *input.Template.Runtime
		out.Template.Runtime = &runtime
	}
	if input.RuntimeMetadata != nil {
		metadata := *input.RuntimeMetadata
		if input.RuntimeMetadata.TemplateReference != nil {
			entry := *input.RuntimeMetadata.TemplateReference
			metadata.TemplateReference = &entry
		}
		if input.RuntimeMetadata.TrustPolicy != nil {
			policy := *input.RuntimeMetadata.TrustPolicy
			metadata.TrustPolicy = &policy
		}
		out.RuntimeMetadata = &metadata
	}
	return out
}

type selectionResolverStub struct {
	result acquisition.ResolveResult
	err    error
	calls  int
	cancel context.CancelFunc
}

func (s *selectionResolverStub) Resolve(context.Context, acquisition.ResolveRequest) (acquisition.ResolveResult, error) {
	s.calls++
	if s.cancel != nil {
		s.cancel()
	}
	return s.result, s.err
}

func selectionTestDigest(data []byte) *sandboxtemplate.DigestMetadata {
	sum := sha256.Sum256(data)
	return &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     hex.EncodeToString(sum[:]),
	}
}
