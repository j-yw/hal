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

func TestDispatchResolverUsesClassifiedLocalGitAndOCIAdapters(t *testing.T) {
	localDocument := localTemplateYAML("1.2.0")
	localPath := writeLocalTemplateFile(t, "codex-go.yaml", localDocument)
	gitRef := "https://github.com/acme/hal-sandbox-templates.git"
	gitDocument := gitFixtureTemplateYAML(gitRef)
	ociRef := "registry.example.io/acme/templates/codex-go:1.2.0"
	ociDocument := ociFixtureTemplateYAML()
	ociDocumentDigest := testDigest(strings.Repeat("d", 64))
	ociTemplateArtifactDigest := testDigest(strings.Repeat("e", 64))

	gitFake := acquisition.NewInMemoryGitTemplateResolver(map[string]acquisition.GitTemplateResolveResult{
		gitRef: {
			TemplateBytes: []byte(gitDocument),
			Format:        sandboxtemplate.FormatYAML,
			SizeBytes:     int64(len(gitDocument)),
		},
	})
	ociFake := acquisition.NewInMemoryOCIArtifactResolver(map[string]acquisition.OCIArtifactResolveResult{
		ociRef: {
			TemplateBytes:          []byte(ociDocument),
			Format:                 sandboxtemplate.FormatYAML,
			DocumentDigest:         ociDocumentDigest,
			TemplateArtifactDigest: ociTemplateArtifactDigest,
			SizeBytes:              int64(len(ociDocument)),
		},
	})
	resolver := acquisition.NewDispatchResolver(acquisition.DispatchResolverOptions{
		Git: gitFake,
		OCI: ociFake,
	})

	localResult := resolveClassifiedTemplate(t, resolver, localPath, sandboxtemplate.FormatYAML)
	if localResult.Template.Metadata.ID != "codex-go" {
		t.Fatalf("local template id = %q, want codex-go", localResult.Template.Metadata.ID)
	}
	assertDocumentLock(t, localResult.Lock, localDocument)

	gitResult := resolveClassifiedTemplate(t, resolver, gitRef, sandboxtemplate.FormatYAML)
	if gitResult.Template.Metadata.ID != "codex-git" {
		t.Fatalf("git template id = %q, want codex-git", gitResult.Template.Metadata.ID)
	}
	gitCalls := gitFake.Calls()
	if len(gitCalls) != 1 {
		t.Fatalf("fake Git resolver calls = %d, want 1", len(gitCalls))
	}
	if got := gitCalls[0].Reference.Ref; got != gitRef {
		t.Fatalf("fake Git resolver ref = %q, want classified source ref", got)
	}
	assertDocumentDigestLockForSource(t, gitResult.Lock, acquisition.SourceKindGit, sandboxtemplate.ReferenceKindGit, gitDocument, acquisition.LockReasonDocumentDigest)
	assertMutableReferenceUnresolved(t, gitResult.Lock, "metadata.reference")
	assertMutableReferenceUnresolved(t, gitResult.Lock, "runtime.image")
	assertResolvedLockDigestSemantics(t, gitResult.Lock)

	ociResult := resolveClassifiedTemplate(t, resolver, "oci://"+ociRef, sandboxtemplate.FormatYAML)
	if ociResult.Template.Metadata.ID != "codex-go" {
		t.Fatalf("oci template id = %q, want codex-go", ociResult.Template.Metadata.ID)
	}
	ociCalls := ociFake.Calls()
	if len(ociCalls) != 1 {
		t.Fatalf("fake OCI resolver calls = %d, want 1", len(ociCalls))
	}
	if got := ociCalls[0].Reference.Ref; got != ociRef {
		t.Fatalf("fake OCI resolver ref = %q, want classified source ref", got)
	}
	assertOCIDocumentLock(t, ociResult.Lock, ociDocumentDigest, int64(len(ociDocument)))
	assertReferenceDigestLock(t, ociResult.Lock, "metadata.reference", sandboxtemplate.ReferenceKindOCIArtifact, ociTemplateArtifactDigest)
	assertResolvedLockDigestSemantics(t, ociResult.Lock)
}

func TestDispatchResolverDefaultRemotePathsRequireInjectedAdapters(t *testing.T) {
	resolver := acquisition.NewDispatchResolver(acquisition.DispatchResolverOptions{})
	for _, tt := range []struct {
		name          string
		ref           string
		wantSource    acquisition.SourceKind
		wantReference sandboxtemplate.ReferenceKind
	}{
		{
			name:          "git",
			ref:           "https://github.com/acme/hal-sandbox-templates.git",
			wantSource:    acquisition.SourceKindGit,
			wantReference: sandboxtemplate.ReferenceKindGit,
		},
		{
			name:          "oci artifact",
			ref:           "oci://registry.example.io/acme/templates/codex-go:1.2.0",
			wantSource:    acquisition.SourceKindOCIArtifact,
			wantReference: sandboxtemplate.ReferenceKindOCIArtifact,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			classified := acquisition.ClassifyTemplateSourceReference(tt.ref, sandboxtemplate.FormatYAML)
			result, err := resolver.Resolve(context.Background(), acquisition.ResolveRequest{
				Source:             classified.Source,
				LockedAtUnixMillis: acquisitionTestLockedAtUnixMillis,
			})
			assertResolveErrorCode(t, err, acquisition.ResolveErrorCodeResolverUnavailable, acquisition.ErrResolverUnavailable)
			assertUnresolvedDispatchLock(t, result.Lock, tt.wantSource, tt.wantReference, acquisition.LockReasonResolverUnavailable)
			assertUnresolvedLockDigestSemantics(t, result.Lock)
			assertAcquisitionLockOmitsFragments(t, result.Lock, tt.ref, "github.com/acme", "registry.example.io/acme")
			assertAcquisitionErrorOmitsFragments(t, err, tt.ref, "github.com/acme", "registry.example.io/acme")
		})
	}
}

func TestDispatchResolverUnsupportedSourceReturnsSafeUnresolvedLock(t *testing.T) {
	unsafeRef := "https://user:ghp_secret@github.com/acme/private.git?token=sk-live-template"
	classified := acquisition.ClassifyTemplateSourceReference(unsafeRef, sandboxtemplate.FormatYAML)
	if classified.Source.Kind != acquisition.SourceKindUnsupported {
		t.Fatalf("classified source kind = %q, want unsupported", classified.Source.Kind)
	}
	resolver := acquisition.NewDispatchResolver(acquisition.DispatchResolverOptions{})

	result, err := resolver.Resolve(context.Background(), acquisition.ResolveRequest{
		Source:             classified.Source,
		LockedAtUnixMillis: acquisitionTestLockedAtUnixMillis,
	})
	assertResolveErrorCode(t, err, acquisition.ResolveErrorCodeUnsupportedSource, acquisition.ErrUnsupportedSource)
	assertUnresolvedDispatchLock(t, result.Lock, acquisition.SourceKindUnsupported, "", acquisition.LockReasonUnsupportedSource)
	assertUnresolvedLockDigestSemantics(t, result.Lock)
	assertAcquisitionLockOmitsFragments(t, result.Lock, unsafeRef, "ghp_secret", "sk-live-template", "user:")
	assertAcquisitionErrorOmitsFragments(t, err, unsafeRef, "ghp_secret", "sk-live-template", "user:")
}

func TestDispatchResolverMutableReferencesRemainUnresolvedWithoutDigest(t *testing.T) {
	gitRef := "https://github.com/acme/hal-sandbox-templates.git"
	document := gitFixtureTemplateYAML(gitRef)
	gitFake := acquisition.NewInMemoryGitTemplateResolver(map[string]acquisition.GitTemplateResolveResult{
		gitRef: {
			TemplateBytes: []byte(document),
			Format:        sandboxtemplate.FormatYAML,
		},
	})
	resolver := acquisition.NewDispatchResolver(acquisition.DispatchResolverOptions{
		Git: gitFake,
	})

	result := resolveClassifiedTemplate(t, resolver, gitRef, sandboxtemplate.FormatYAML)

	assertMutableReferenceUnresolved(t, result.Lock, "metadata.reference")
	assertMutableReferenceUnresolved(t, result.Lock, "runtime.image")
	assertMutableReferenceUnresolved(t, result.Lock, "workspace.ref")
	assertResolvedLockDigestSemantics(t, result.Lock)
	for _, ref := range result.Lock.References {
		if ref.Status == acquisition.LockStatusUnresolved && ref.Digest != nil {
			t.Fatalf("%s unresolved digest = %#v, want nil", ref.Field, ref.Digest)
		}
	}
}

func resolveClassifiedTemplate(t *testing.T, resolver acquisition.Resolver, ref string, format sandboxtemplate.Format) acquisition.ResolveResult {
	t.Helper()

	classified := acquisition.ClassifyTemplateSourceReference(ref, format)
	result, err := resolver.Resolve(context.Background(), acquisition.ResolveRequest{
		Source:             classified.Source,
		LockedAtUnixMillis: acquisitionTestLockedAtUnixMillis,
	})
	if err != nil {
		t.Fatalf("Resolve(%q) error = %v, want nil", ref, err)
	}
	return result
}

func assertResolveErrorCode(t *testing.T, err error, want acquisition.ResolveErrorCode, sentinel error) {
	t.Helper()

	if err == nil {
		t.Fatalf("Resolve() error = nil, want %q", want)
	}
	var resolveErr *acquisition.ResolveError
	if !errors.As(err, &resolveErr) {
		t.Fatalf("Resolve() error = %T %[1]v, want *acquisition.ResolveError", err)
	}
	if resolveErr.Code != want {
		t.Fatalf("Resolve() code = %q, want %q", resolveErr.Code, want)
	}
	if sentinel != nil && !errors.Is(err, sentinel) {
		t.Fatalf("Resolve() error = %v, want sentinel %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), string(want)) {
		t.Fatalf("Resolve() error string = %q, want stable code %q", err.Error(), want)
	}
}

func assertUnresolvedDispatchLock(t *testing.T, lock acquisition.TemplateLock, source acquisition.SourceKind, reference sandboxtemplate.ReferenceKind, reason acquisition.LockReasonCode) {
	t.Helper()

	if lock.SourceKind != source {
		t.Fatalf("lock source kind = %q, want %q", lock.SourceKind, source)
	}
	if lock.ReferenceKind != reference {
		t.Fatalf("lock reference kind = %q, want %q", lock.ReferenceKind, reference)
	}
	if lock.Status != acquisition.LockStatusUnresolved {
		t.Fatalf("lock status = %q, want unresolved", lock.Status)
	}
	if lock.Document.Status != acquisition.LockStatusUnresolved {
		t.Fatalf("document status = %q, want unresolved", lock.Document.Status)
	}
	if lock.Document.ReasonCode != reason {
		t.Fatalf("document reason = %q, want %q", lock.Document.ReasonCode, reason)
	}
	if lock.Document.Digest != nil {
		t.Fatalf("document digest = %#v, want nil for unresolved lock", lock.Document.Digest)
	}
}

func assertDocumentDigestLockForSource(t *testing.T, lock acquisition.TemplateLock, source acquisition.SourceKind, reference sandboxtemplate.ReferenceKind, document string, reason acquisition.LockReasonCode) {
	t.Helper()

	if lock.SourceKind != source {
		t.Fatalf("lock source kind = %q, want %q", lock.SourceKind, source)
	}
	if lock.ReferenceKind != reference {
		t.Fatalf("lock reference kind = %q, want %q", lock.ReferenceKind, reference)
	}
	if lock.Status != acquisition.LockStatusLocked {
		t.Fatalf("lock status = %q, want locked", lock.Status)
	}
	if lock.Document.Status != acquisition.LockStatusLocked {
		t.Fatalf("document status = %q, want locked", lock.Document.Status)
	}
	if lock.Document.ReasonCode != reason {
		t.Fatalf("document reason = %q, want %q", lock.Document.ReasonCode, reason)
	}
	if got, want := lock.Document.Digest, testDigest(sha256Hex(document)); !reflect.DeepEqual(got, want) {
		t.Fatalf("document digest = %#v, want %#v", got, want)
	}
}

func assertResolvedLockDigestSemantics(t *testing.T, lock acquisition.TemplateLock) {
	t.Helper()

	if lock.Status != acquisition.LockStatusLocked {
		t.Fatalf("lock status = %q, want locked", lock.Status)
	}
	assertDigestLockSemantics(t, lock.Document)
	for _, ref := range lock.References {
		assertReferenceLockDigestSemantics(t, ref)
	}
}

func assertUnresolvedLockDigestSemantics(t *testing.T, lock acquisition.TemplateLock) {
	t.Helper()

	if lock.Status != acquisition.LockStatusUnresolved {
		t.Fatalf("lock status = %q, want unresolved", lock.Status)
	}
	assertDigestLockSemantics(t, lock.Document)
	for _, ref := range lock.References {
		assertReferenceLockDigestSemantics(t, ref)
	}
}

func assertDigestLockSemantics(t *testing.T, lock acquisition.DigestLock) {
	t.Helper()

	switch lock.Status {
	case acquisition.LockStatusLocked:
		assertValidDigestMetadata(t, lock.Digest)
	case acquisition.LockStatusUnresolved:
		if lock.Digest != nil {
			t.Fatalf("unresolved document digest = %#v, want nil", lock.Digest)
		}
	default:
		t.Fatalf("document status = %q, want locked or unresolved", lock.Status)
	}
}

func assertReferenceLockDigestSemantics(t *testing.T, lock acquisition.ReferenceLock) {
	t.Helper()

	switch lock.Status {
	case acquisition.LockStatusLocked:
		assertValidDigestMetadata(t, lock.Digest)
	case acquisition.LockStatusUnresolved:
		if lock.Digest != nil {
			t.Fatalf("%s unresolved digest = %#v, want nil", lock.Field, lock.Digest)
		}
	default:
		t.Fatalf("%s status = %q, want locked or unresolved", lock.Field, lock.Status)
	}
}

func assertValidDigestMetadata(t *testing.T, digest *sandboxtemplate.DigestMetadata) {
	t.Helper()

	if digest == nil {
		t.Fatal("locked digest = nil, want valid digest metadata")
	}
	if !sandboxtemplate.ReferenceDigestPinned(&sandboxtemplate.ImmutableRef{Digest: digest}) {
		data, _ := json.Marshal(digest)
		t.Fatalf("locked digest = %s, want valid digest metadata", data)
	}
}

func gitFixtureTemplateYAML(gitRef string) string {
	return `apiVersion: sandbox-template.hal.dev/v1
kind: SandboxTemplate
metadata:
  id: codex-git
  name: Codex Git
  version: 1.2.0
  reference:
    kind: git
    ref: ` + gitRef + `
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
    kind: git
    ref: https://github.com/acme/workspace.git
  readOnly: true
network:
  profile: deny_by_default
`
}
