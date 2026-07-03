package acquisition_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

func TestOCIResolverUsesInjectedFixtureAndLocksImmutableDigests(t *testing.T) {
	sourceRef := "fixture-user:super-secret-password@ghcr.io/acme/templates/codex-go:1.2.0?token=ghp_fixturetoken&api_key=sk-live-template"
	document := ociFixtureTemplateYAML()
	templateArtifactDigest := testDigest(strings.Repeat("a", 64))
	runtimeImageDigest := testDigest(strings.Repeat("b", 64))
	sourceArtifactDigest := testDigest(strings.Repeat("c", 64))
	documentDigest := testDigest(strings.Repeat("d", 64))
	fixture := acquisition.OCIArtifactResolveResult{
		TemplateBytes:          []byte(document),
		Format:                 sandboxtemplate.FormatYAML,
		DocumentDigest:         documentDigest,
		TemplateArtifactDigest: templateArtifactDigest,
		SizeBytes:              int64(len(document)),
		ReferenceDigests: []acquisition.ReferenceDigestProof{
			{
				Field:  "metadata.reference",
				Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
				Ref:    "ghcr.io/acme/templates/codex-go:1.2.0",
				Digest: templateArtifactDigest,
			},
			{
				Field:  "runtime.image",
				Kind:   sandboxtemplate.ReferenceKindOCIImage,
				Ref:    "ghcr.io/acme/go-agent:1.2.0",
				Digest: runtimeImageDigest,
			},
			{
				Field:  "workspace.ref",
				Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
				Ref:    "ghcr.io/acme/sources/repo:20260703",
				Digest: sourceArtifactDigest,
			},
		},
	}
	fake := &fakeOCIArtifactResolver{
		fixtures: map[string]acquisition.OCIArtifactResolveResult{
			sourceRef: fixture,
		},
	}
	resolver := acquisition.NewOCIResolver(fake)

	result, err := resolver.Resolve(context.Background(), acquisition.ResolveRequest{
		Source: acquisition.TemplateSource{
			Kind: acquisition.SourceKindOCIArtifact,
			Reference: &sandboxtemplate.ImmutableRef{
				Kind: sandboxtemplate.ReferenceKindOCIArtifact,
				Ref:  sourceRef,
			},
			Format: sandboxtemplate.FormatYAML,
		},
		LockedAtUnixMillis: acquisitionTestLockedAtUnixMillis,
	})
	if len(fake.calls) != 1 {
		t.Fatalf("injected OCI resolver calls = %d, want 1", len(fake.calls))
	}
	if got := fake.calls[0].Reference.Ref; got != sourceRef {
		t.Fatalf("injected OCI resolver ref = %q, want fixture source ref", got)
	}
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}

	if result.Template.Metadata.ID != "codex-go" {
		t.Fatalf("template id = %q, want codex-go", result.Template.Metadata.ID)
	}
	assertOCIDocumentLock(t, result.Lock, documentDigest, int64(len(document)))
	assertReferenceDigestLock(t, result.Lock, "metadata.reference", sandboxtemplate.ReferenceKindOCIArtifact, templateArtifactDigest)
	assertReferenceDigestLock(t, result.Lock, "runtime.image", sandboxtemplate.ReferenceKindOCIImage, runtimeImageDigest)
	assertReferenceDigestLock(t, result.Lock, "workspace.ref", sandboxtemplate.ReferenceKindOCIArtifact, sourceArtifactDigest)
	assertAcquisitionLockOmitsFragments(t, result.Lock, unsafeOCIFragments(sourceRef)...)
}

func TestUnsupportedSourceKindReturnsStableSanitizedError(t *testing.T) {
	sourceRef := "fixture-user:super-secret-password@registry.invalid/acme/template:latest?token=ghp_fixturetoken&password=hunter2&secret=sk-live-template"
	fake := &fakeOCIArtifactResolver{
		fixtures: map[string]acquisition.OCIArtifactResolveResult{
			sourceRef: {},
		},
	}
	resolver := acquisition.NewOCIResolver(fake)

	_, err := resolver.Resolve(context.Background(), acquisition.ResolveRequest{
		Source: acquisition.TemplateSource{
			Kind: acquisition.SourceKind("oci_index?token=ghp_fixturetoken&password=hunter2"),
			Reference: &sandboxtemplate.ImmutableRef{
				Kind: sandboxtemplate.ReferenceKindOCIArtifact,
				Ref:  sourceRef,
			},
			Format: sandboxtemplate.FormatYAML,
		},
		LockedAtUnixMillis: acquisitionTestLockedAtUnixMillis,
	})
	if len(fake.calls) != 0 {
		t.Fatalf("injected OCI resolver calls = %d, want 0 for unsupported source kind", len(fake.calls))
	}
	if err == nil {
		t.Fatal("Resolve() error = nil, want unsupported source error")
	}
	var resolveErr *acquisition.ResolveError
	if !errors.As(err, &resolveErr) {
		t.Fatalf("Resolve() error = %T %[1]v, want *acquisition.ResolveError", err)
	}
	if resolveErr.Code != acquisition.ResolveErrorCodeUnsupportedSource {
		t.Fatalf("Resolve() code = %q, want %q", resolveErr.Code, acquisition.ResolveErrorCodeUnsupportedSource)
	}
	if !errors.Is(err, acquisition.ErrUnsupportedSource) {
		t.Fatalf("Resolve() error = %v, want ErrUnsupportedSource wrapper", err)
	}
	if got, want := resolveErr.Message, "template source kind is unsupported"; got != want {
		t.Fatalf("Resolve() message = %q, want %q", got, want)
	}
	if !strings.Contains(err.Error(), string(acquisition.ResolveErrorCodeUnsupportedSource)) {
		t.Fatalf("Resolve() error string = %q, want stable code", err.Error())
	}
	assertAcquisitionErrorOmitsFragments(t, err, unsafeOCIFragments(sourceRef)...)
	assertAcquisitionErrorOmitsFragments(t, err, "oci_index?token", "ghp_fixturetoken", "password=hunter2")
}

func TestInMemoryOCIArtifactResolverLeavesUnprovenMutableRefsUnresolved(t *testing.T) {
	sourceRef := "ghcr.io/acme/templates/codex-go:1.2.0"
	document := ociFixtureTemplateYAML()
	templateArtifactDigest := testDigest(strings.Repeat("e", 64))
	documentDigest := testDigest(strings.Repeat("f", 64))
	fake := acquisition.NewInMemoryOCIArtifactResolver(map[string]acquisition.OCIArtifactResolveResult{
		sourceRef: {
			TemplateBytes:          []byte(document),
			Format:                 sandboxtemplate.FormatYAML,
			DocumentDigest:         documentDigest,
			TemplateArtifactDigest: templateArtifactDigest,
			SizeBytes:              int64(len(document)),
		},
	})
	resolver := acquisition.NewOCIResolver(fake)

	result, err := resolver.Resolve(context.Background(), acquisition.ResolveRequest{
		Source: acquisition.TemplateSource{
			Kind: acquisition.SourceKindOCIArtifact,
			Reference: &sandboxtemplate.ImmutableRef{
				Ref: sourceRef,
			},
			Format: sandboxtemplate.FormatYAML,
		},
		LockedAtUnixMillis: acquisitionTestLockedAtUnixMillis,
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}

	calls := fake.Calls()
	if len(calls) != 1 {
		t.Fatalf("in-memory OCI resolver calls = %d, want 1", len(calls))
	}
	if got := calls[0].Reference.Kind; got != sandboxtemplate.ReferenceKindOCIArtifact {
		t.Fatalf("in-memory OCI resolver ref kind = %q, want normalized oci_artifact", got)
	}
	assertOCIDocumentLock(t, result.Lock, documentDigest, int64(len(document)))
	assertReferenceDigestLock(t, result.Lock, "metadata.reference", sandboxtemplate.ReferenceKindOCIArtifact, templateArtifactDigest)
	assertMutableReferenceUnresolved(t, result.Lock, "runtime.image")
	assertMutableReferenceUnresolved(t, result.Lock, "workspace.ref")
}

type fakeOCIArtifactResolver struct {
	fixtures map[string]acquisition.OCIArtifactResolveResult
	calls    []acquisition.OCIArtifactResolveRequest
}

func (f *fakeOCIArtifactResolver) ResolveOCIArtifact(_ context.Context, request acquisition.OCIArtifactResolveRequest) (acquisition.OCIArtifactResolveResult, error) {
	f.calls = append(f.calls, request)
	result, ok := f.fixtures[request.Reference.Ref]
	if !ok {
		return acquisition.OCIArtifactResolveResult{}, errors.New("fixture artifact is missing")
	}
	return result, nil
}

func assertOCIDocumentLock(t *testing.T, lock acquisition.TemplateLock, digest *sandboxtemplate.DigestMetadata, sizeBytes int64) {
	t.Helper()

	if lock.SourceKind != acquisition.SourceKindOCIArtifact {
		t.Fatalf("lock source kind = %q, want %q", lock.SourceKind, acquisition.SourceKindOCIArtifact)
	}
	if lock.ReferenceKind != sandboxtemplate.ReferenceKindOCIArtifact {
		t.Fatalf("lock reference kind = %q, want %q", lock.ReferenceKind, sandboxtemplate.ReferenceKindOCIArtifact)
	}
	if lock.Status != acquisition.LockStatusLocked {
		t.Fatalf("lock status = %q, want locked", lock.Status)
	}
	if lock.Document.Status != acquisition.LockStatusLocked {
		t.Fatalf("document lock status = %q, want locked", lock.Document.Status)
	}
	if lock.Document.ReasonCode != acquisition.LockReasonImmutableDigest {
		t.Fatalf("document lock reason = %q, want %q", lock.Document.ReasonCode, acquisition.LockReasonImmutableDigest)
	}
	if !reflect.DeepEqual(lock.Document.Digest, digest) {
		t.Fatalf("document digest = %#v, want fixture digest %#v", lock.Document.Digest, digest)
	}
	if lock.Document.SizeBytes != sizeBytes {
		t.Fatalf("document size = %d, want %d", lock.Document.SizeBytes, sizeBytes)
	}
	if lock.Document.LockedAtUnixMillis != acquisitionTestLockedAtUnixMillis {
		t.Fatalf("lockedAt = %d, want %d", lock.Document.LockedAtUnixMillis, acquisitionTestLockedAtUnixMillis)
	}
}

func assertReferenceDigestLock(t *testing.T, lock acquisition.TemplateLock, field string, kind sandboxtemplate.ReferenceKind, digest *sandboxtemplate.DigestMetadata) {
	t.Helper()

	for _, ref := range lock.References {
		if ref.Field != field {
			continue
		}
		if ref.Kind != kind {
			t.Fatalf("%s kind = %q, want %q", field, ref.Kind, kind)
		}
		if ref.Status != acquisition.LockStatusLocked {
			t.Fatalf("%s status = %q, want locked", field, ref.Status)
		}
		if ref.ReasonCode != acquisition.LockReasonImmutableDigest {
			t.Fatalf("%s reason = %q, want %q", field, ref.ReasonCode, acquisition.LockReasonImmutableDigest)
		}
		if !reflect.DeepEqual(ref.Digest, digest) {
			t.Fatalf("%s digest = %#v, want fixture digest %#v", field, ref.Digest, digest)
		}
		return
	}
	t.Fatalf("lock references = %#v, want immutable %s digest lock", lock.References, field)
}

func assertAcquisitionLockOmitsFragments(t *testing.T, lock acquisition.TemplateLock, fragments ...string) {
	t.Helper()

	data, err := json.Marshal(lock)
	if err != nil {
		t.Fatalf("Marshal(lock) error = %v", err)
	}
	assertAcquisitionTextOmitsFragments(t, string(data), fragments...)
}

func assertAcquisitionErrorOmitsFragments(t *testing.T, err error, fragments ...string) {
	t.Helper()

	publicText := err.Error()
	var resolveErr *acquisition.ResolveError
	if errors.As(err, &resolveErr) {
		data, marshalErr := json.Marshal(resolveErr)
		if marshalErr == nil {
			publicText += " " + string(data)
		}
	}
	assertAcquisitionTextOmitsFragments(t, publicText, fragments...)
}

func assertAcquisitionTextOmitsFragments(t *testing.T, publicText string, fragments ...string) {
	t.Helper()

	for _, fragment := range fragments {
		if fragment != "" && strings.Contains(publicText, fragment) {
			t.Fatalf("public acquisition text leaked %q in %q", fragment, publicText)
		}
	}
}

func unsafeOCIFragments(sourceRef string) []string {
	return []string{
		sourceRef,
		"fixture-user",
		"super-secret-password",
		"token=",
		"ghp_fixturetoken",
		"api_key=",
		"sk-live-template",
		"password=",
		"secret=",
	}
}

func testDigest(value string) *sandboxtemplate.DigestMetadata {
	return &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     value,
	}
}

func ociFixtureTemplateYAML() string {
	return `apiVersion: sandbox-template.hal.dev/v1
kind: SandboxTemplate
metadata:
  id: codex-go
  name: Codex Go
  version: 1.2.0
  reference:
    kind: oci_artifact
    ref: ghcr.io/acme/templates/codex-go:1.2.0
runtime:
  driver: microvm
  isolationLevel: vm
  image:
    kind: oci_image
    ref: ghcr.io/acme/go-agent:1.2.0
workspace:
  mode: clone
  inputSource: remote_ref
  ref:
    kind: oci_artifact
    ref: ghcr.io/acme/sources/repo:20260703
  readOnly: true
network:
  profile: deny_by_default
`
}
