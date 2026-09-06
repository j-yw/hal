package acquisition_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

const acquisitionTestLockedAtUnixMillis int64 = 1783200000000

func TestLocalResolverResolvesYAMLAndLocksDocumentDigest(t *testing.T) {
	document := localTemplateYAML("1.2.0")
	path := writeLocalTemplateFile(t, "codex-go.yaml", document)

	result := resolveLocalTemplate(t, path, sandboxtemplate.FormatYAML)

	if result.Template.Metadata.ID != "codex-go" {
		t.Fatalf("template id = %q, want codex-go", result.Template.Metadata.ID)
	}
	assertDocumentLock(t, result.Lock, document)
	assertPinnedTemplateReferencePreserved(t, result.Template.Metadata.Reference)
	assertMutableReferenceUnresolved(t, result.Lock, "runtime.image")
	assertMutableReferenceUnresolved(t, result.Lock, "workspace.ref")
	assertLockMetadataDoesNotLeak(t, result.Lock, path)
}

func TestLocalResolverResolvesJSONAndLocksDocumentDigest(t *testing.T) {
	document := localTemplateJSON("1.2.0")
	path := writeLocalTemplateFile(t, "codex-go.json", document)

	result := resolveLocalTemplate(t, path, sandboxtemplate.FormatJSON)

	if result.Template.Runtime == nil || result.Template.Runtime.Driver != sandboxtemplate.RuntimeDriverMicroVM {
		t.Fatalf("runtime = %#v, want microvm runtime from JSON document", result.Template.Runtime)
	}
	assertDocumentLock(t, result.Lock, document)
	assertPinnedTemplateReferencePreserved(t, result.Template.Metadata.Reference)
	assertMutableReferenceUnresolved(t, result.Lock, "runtime.image")
	assertMutableReferenceUnresolved(t, result.Lock, "workspace.ref")
	assertLockMetadataDoesNotLeak(t, result.Lock, path)
}

func TestLocalResolverDocumentDigestIsDeterministicForIdenticalContents(t *testing.T) {
	document := localTemplateYAML("1.2.0")
	firstPath := writeLocalTemplateFile(t, "first.yaml", document)
	secondPath := writeLocalTemplateFile(t, "second.yaml", document)

	first := resolveLocalTemplate(t, firstPath, sandboxtemplate.FormatYAML)
	second := resolveLocalTemplate(t, secondPath, sandboxtemplate.FormatYAML)

	if got, want := first.Lock.Document.Digest.Value, sha256Hex(document); got != want {
		t.Fatalf("first document digest = %q, want %q", got, want)
	}
	if got, want := second.Lock.Document.Digest.Value, first.Lock.Document.Digest.Value; got != want {
		t.Fatalf("second document digest = %q, want deterministic digest %q", got, want)
	}
	if !reflect.DeepEqual(second.Lock.Document, first.Lock.Document) {
		t.Fatalf("document lock changed for identical contents:\nfirst=%#v\nsecond=%#v", first.Lock.Document, second.Lock.Document)
	}
	assertLockMetadataDoesNotLeak(t, first.Lock, firstPath)
	assertLockMetadataDoesNotLeak(t, second.Lock, secondPath)
}

func TestLocalResolverDocumentDigestChangesWhenContentsChange(t *testing.T) {
	firstDocument := localTemplateJSON("1.2.0")
	secondDocument := localTemplateJSON("1.2.1")
	firstPath := writeLocalTemplateFile(t, "codex-go-1.2.0.json", firstDocument)
	secondPath := writeLocalTemplateFile(t, "codex-go-1.2.1.json", secondDocument)

	first := resolveLocalTemplate(t, firstPath, sandboxtemplate.FormatJSON)
	second := resolveLocalTemplate(t, secondPath, sandboxtemplate.FormatJSON)

	if got, want := first.Lock.Document.Digest.Value, sha256Hex(firstDocument); got != want {
		t.Fatalf("first document digest = %q, want %q", got, want)
	}
	if got, want := second.Lock.Document.Digest.Value, sha256Hex(secondDocument); got != want {
		t.Fatalf("second document digest = %q, want %q", got, want)
	}
	if first.Lock.Document.Digest.Value == second.Lock.Document.Digest.Value {
		t.Fatalf("document digest did not change for changed contents: %q", first.Lock.Document.Digest.Value)
	}
}

func TestLocalResolverErrorsDoNotLeakAbsoluteLocalPaths(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "private-token-template.yaml")
	resolver := acquisition.NewLocalResolver()

	_, err := resolver.Resolve(context.Background(), acquisition.ResolveRequest{
		Source: acquisition.TemplateSource{
			Kind:      acquisition.SourceKindLocalFile,
			LocalPath: missingPath,
			Format:    sandboxtemplate.FormatYAML,
		},
		LockedAtUnixMillis: acquisitionTestLockedAtUnixMillis,
	})
	if err == nil {
		t.Fatal("Resolve() error = nil, want missing local template error")
	}
	assertErrorDoesNotLeak(t, err, missingPath)
}

func resolveLocalTemplate(t *testing.T, path string, format sandboxtemplate.Format) acquisition.ResolveResult {
	t.Helper()

	resolver := acquisition.NewLocalResolver()
	result, err := resolver.Resolve(context.Background(), acquisition.ResolveRequest{
		Source: acquisition.TemplateSource{
			Kind:      acquisition.SourceKindLocalFile,
			LocalPath: path,
			Format:    format,
		},
		LockedAtUnixMillis: acquisitionTestLockedAtUnixMillis,
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	return result
}

func assertDocumentLock(t *testing.T, lock acquisition.TemplateLock, document string) {
	t.Helper()

	if lock.SourceKind != acquisition.SourceKindLocalFile {
		t.Fatalf("lock source kind = %q, want %q", lock.SourceKind, acquisition.SourceKindLocalFile)
	}
	if lock.ReferenceKind != sandboxtemplate.ReferenceKindLocal {
		t.Fatalf("lock reference kind = %q, want local", lock.ReferenceKind)
	}
	if lock.Status != acquisition.LockStatusLocked {
		t.Fatalf("lock status = %q, want locked", lock.Status)
	}
	if lock.Document.Status != acquisition.LockStatusLocked {
		t.Fatalf("document lock status = %q, want locked", lock.Document.Status)
	}
	if lock.Document.ReasonCode != acquisition.LockReasonDocumentDigest {
		t.Fatalf("document lock reason = %q, want %q", lock.Document.ReasonCode, acquisition.LockReasonDocumentDigest)
	}
	if lock.Document.Digest == nil {
		t.Fatal("document digest = nil, want sha256 lock")
	}
	if lock.Document.Digest.Algorithm != sandboxtemplate.DigestAlgorithmSHA256 {
		t.Fatalf("document digest algorithm = %q, want sha256", lock.Document.Digest.Algorithm)
	}
	if got, want := lock.Document.Digest.Value, sha256Hex(document); got != want {
		t.Fatalf("document digest = %q, want %q", got, want)
	}
	if got, want := lock.Document.SizeBytes, int64(len(document)); got != want {
		t.Fatalf("document size = %d, want %d", got, want)
	}
	if lock.Document.LockedAtUnixMillis != acquisitionTestLockedAtUnixMillis {
		t.Fatalf("lockedAt = %d, want %d", lock.Document.LockedAtUnixMillis, acquisitionTestLockedAtUnixMillis)
	}
}

func assertPinnedTemplateReferencePreserved(t *testing.T, got *sandboxtemplate.ImmutableRef) {
	t.Helper()

	want := &sandboxtemplate.ImmutableRef{
		Kind: sandboxtemplate.ReferenceKindOCIArtifact,
		Ref:  "ghcr.io/acme/templates/codex-go:1.2.0",
		Digest: &sandboxtemplate.DigestMetadata{
			Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
			Value:     strings.Repeat("a", 64),
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata reference = %#v, want pinned Phase 44 reference %#v", got, want)
	}
	if !sandboxtemplate.ReferenceDigestPinned(got) {
		t.Fatalf("metadata reference = %#v, want digest-pinned", got)
	}
}

func assertMutableReferenceUnresolved(t *testing.T, lock acquisition.TemplateLock, field string) {
	t.Helper()

	for _, ref := range lock.References {
		if ref.Field != field {
			continue
		}
		if ref.Status != acquisition.LockStatusUnresolved {
			t.Fatalf("%s status = %q, want unresolved", field, ref.Status)
		}
		if ref.ReasonCode != acquisition.LockReasonMutableReference {
			t.Fatalf("%s reason = %q, want mutable_reference", field, ref.ReasonCode)
		}
		if ref.Digest != nil {
			t.Fatalf("%s digest = %#v, want nil for unresolved mutable reference", field, ref.Digest)
		}
		return
	}
	t.Fatalf("lock references = %#v, want unresolved %s entry", lock.References, field)
}

func assertLockMetadataDoesNotLeak(t *testing.T, lock acquisition.TemplateLock, unsafePath string) {
	t.Helper()

	data, err := json.Marshal(lock)
	if err != nil {
		t.Fatalf("Marshal(lock) error = %v", err)
	}
	assertPublicTextDoesNotLeak(t, string(data), unsafePath)
}

func assertErrorDoesNotLeak(t *testing.T, err error, unsafePath string) {
	t.Helper()

	publicText := err.Error()
	var coded interface{ Unwrap() error }
	if errors.As(err, &coded) && coded.Unwrap() != nil {
		publicText += " " + coded.Unwrap().Error()
	}
	data, marshalErr := json.Marshal(err)
	if marshalErr == nil {
		publicText += " " + string(data)
	}
	assertPublicTextDoesNotLeak(t, publicText, unsafePath)
}

func assertPublicTextDoesNotLeak(t *testing.T, publicText string, unsafePath string) {
	t.Helper()

	for _, fragment := range unsafePathFragments(unsafePath) {
		if fragment != "" && strings.Contains(publicText, fragment) {
			t.Fatalf("public acquisition metadata leaked local path fragment %q in %q", fragment, publicText)
		}
	}
}

func unsafePathFragments(path string) []string {
	return []string{
		path,
		filepath.Dir(path),
		filepath.Base(path),
		"private-token",
		"/Users/",
		"\\Users\\",
	}
}

func writeLocalTemplateFile(t *testing.T, name string, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", name, err)
	}
	return path
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func localTemplateYAML(version string) string {
	return `apiVersion: sandbox-template.hal.dev/v1
kind: SandboxTemplate
metadata:
  id: codex-go
  name: Codex Go
  version: ` + version + `
  reference:
    kind: oci_artifact
    ref: ghcr.io/acme/templates/codex-go:1.2.0
    digest:
      algorithm: sha256
      value: ` + strings.Repeat("a", 64) + `
runtime:
  driver: microvm
  isolationLevel: vm
  image:
    kind: oci_image
    ref: ghcr.io/acme/go-agent:` + version + `
workspace:
  mode: clone
  inputSource: remote_ref
  ref:
    kind: git
    ref: github.com/acme/repo
  readOnly: true
network:
  profile: deny_by_default
`
}

func localTemplateJSON(version string) string {
	data, err := json.MarshalIndent(map[string]any{
		"apiVersion": "sandbox-template.hal.dev/v1",
		"kind":       "SandboxTemplate",
		"metadata": map[string]any{
			"id":      "codex-go",
			"name":    "Codex Go",
			"version": version,
			"reference": map[string]any{
				"kind": "oci_artifact",
				"ref":  "ghcr.io/acme/templates/codex-go:1.2.0",
				"digest": map[string]any{
					"algorithm": "sha256",
					"value":     strings.Repeat("a", 64),
				},
			},
		},
		"runtime": map[string]any{
			"driver":         "microvm",
			"isolationLevel": "vm",
			"image": map[string]any{
				"kind": "oci_image",
				"ref":  "ghcr.io/acme/go-agent:" + version,
			},
		},
		"workspace": map[string]any{
			"mode":        "clone",
			"inputSource": "remote_ref",
			"ref": map[string]any{
				"kind": "git",
				"ref":  "github.com/acme/repo",
			},
			"readOnly": true,
		},
		"network": map[string]any{
			"profile": "deny_by_default",
		},
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(data) + "\n"
}
