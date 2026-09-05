package acquisition_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

func TestProjectTemplateProvenanceProjectsLocalLockJSONFields(t *testing.T) {
	lock := acquisition.TemplateLock{
		SourceKind:    acquisition.SourceKindLocalFile,
		ReferenceKind: sandboxtemplate.ReferenceKindLocal,
		Status:        acquisition.LockStatusLocked,
		Document: acquisition.DigestLock{
			Status:             acquisition.LockStatusLocked,
			Digest:             testDigest(strings.Repeat("a", 64)),
			SizeBytes:          1234,
			LockedAtUnixMillis: acquisitionTestLockedAtUnixMillis,
			ReasonCode:         acquisition.LockReasonDocumentDigest,
		},
		References: []acquisition.ReferenceLock{
			{
				Field:      "metadata.reference",
				Kind:       sandboxtemplate.ReferenceKindOCIArtifact,
				Status:     acquisition.LockStatusLocked,
				Digest:     testDigest(strings.Repeat("b", 64)),
				ReasonCode: acquisition.LockReasonImmutableDigest,
			},
			{
				Field:      "runtime.image",
				Kind:       sandboxtemplate.ReferenceKindOCIImage,
				Status:     acquisition.LockStatusUnresolved,
				ReasonCode: acquisition.LockReasonMutableReference,
			},
			{
				Field:      "workspace.ref",
				Kind:       sandboxtemplate.ReferenceKindGit,
				Status:     acquisition.LockStatusUnresolved,
				ReasonCode: acquisition.LockReasonMutableReference,
			},
		},
		Warnings: []acquisition.LockReasonCode{
			acquisition.LockReasonResolverUnavailable,
			acquisition.LockReasonUnsupportedSource,
		},
	}

	projection := acquisition.ProjectTemplateProvenance(lock)
	if projection == nil {
		t.Fatal("ProjectTemplateProvenance() = nil, want projected metadata")
	}
	data, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("Marshal(projection) error = %v", err)
	}
	publicText := string(data)
	for _, want := range []string{
		`"document":`,
		`"templateReference":`,
		`"runtimeImage":`,
		`"sourceArtifact":`,
		`"sourceKind":"local_file"`,
		`"referenceKind":"local"`,
		`"referenceKind":"oci_artifact"`,
		`"referenceKind":"oci_image"`,
		`"referenceKind":"git"`,
		`"status":"locked"`,
		`"status":"unresolved"`,
		`"digestAlgorithm":"sha256"`,
		`"digestValue":"` + strings.Repeat("a", 64) + `"`,
		`"digestValue":"` + strings.Repeat("b", 64) + `"`,
		`"lockedAt":"` + time.UnixMilli(acquisitionTestLockedAtUnixMillis).UTC().Format(time.RFC3339) + `"`,
		`"warningCodes":["resolver_unavailable","unsupported_source"]`,
		`"reasonCode":"document_digest"`,
		`"reasonCode":"template_reference_digest"`,
		`"reasonCode":"unresolved_mutable_reference"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("projection JSON %s missing %s", publicText, want)
		}
	}
}

func TestProjectTemplateProvenanceProjectsOCIResolverLocksWithoutUnsafeRefs(t *testing.T) {
	sourceRef := "fixture-user:super-secret-password@ghcr.io/acme/templates/codex-go:1.2.0?token=ghp_fixturetoken&api_key=sk-live-template"
	document := ociFixtureTemplateYAML()
	manifestBytes := []byte(`{"schemaVersion":2}`)
	runtimeProof := []byte("runtime proof")
	sourceProof := []byte("source proof")
	templateArtifactDigest := testDigestForBytes(manifestBytes)
	runtimeImageDigest := testDigestForBytes(runtimeProof)
	sourceArtifactDigest := testDigestForBytes(sourceProof)
	documentDigest := testDigestForBytes([]byte(document))
	fake := &fakeOCIArtifactResolver{
		fixtures: map[string]acquisition.OCIArtifactResolveResult{
			sourceRef: {
				TemplateBytes:          []byte(document),
				ArtifactManifestBytes:  manifestBytes,
				Format:                 sandboxtemplate.FormatYAML,
				DocumentDigest:         documentDigest,
				TemplateArtifactDigest: templateArtifactDigest,
				SizeBytes:              int64(len(document)),
				ReferenceDigests: []acquisition.ReferenceDigestProof{
					{
						Field:         "metadata.reference",
						Kind:          sandboxtemplate.ReferenceKindOCIArtifact,
						Ref:           "ghcr.io/acme/templates/codex-go:1.2.0",
						Digest:        templateArtifactDigest,
						VerifiedBytes: manifestBytes,
					},
					{
						Field:         "runtime.image",
						Kind:          sandboxtemplate.ReferenceKindOCIImage,
						Ref:           "ghcr.io/acme/go-agent:1.2.0",
						Digest:        runtimeImageDigest,
						VerifiedBytes: runtimeProof,
					},
					{
						Field:         "workspace.ref",
						Kind:          sandboxtemplate.ReferenceKindOCIArtifact,
						Ref:           "ghcr.io/acme/sources/repo:20260703",
						Digest:        sourceArtifactDigest,
						VerifiedBytes: sourceProof,
					},
				},
			},
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
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}

	projection := acquisition.ProjectTemplateProvenance(result.Lock)
	if projection == nil {
		t.Fatal("ProjectTemplateProvenance() = nil, want projected metadata")
	}
	if projection.Document == nil || projection.TemplateReference == nil || projection.RuntimeImage == nil || projection.SourceArtifact == nil {
		t.Fatalf("projection = %#v, want document/template/runtime/source artifact entries", projection)
	}
	if projection.Document.SourceKind != "oci_artifact" || projection.Document.ReferenceKind != "oci_artifact" {
		t.Fatalf("document source/reference = %q/%q, want oci_artifact/oci_artifact", projection.Document.SourceKind, projection.Document.ReferenceKind)
	}
	if got := projection.TemplateReference.DigestValue; got != templateArtifactDigest.Value {
		t.Fatalf("template reference digest = %q, want template artifact digest", got)
	}
	if got := projection.RuntimeImage.DigestValue; got != runtimeImageDigest.Value {
		t.Fatalf("runtime image digest = %q, want fixture digest", got)
	}
	if got := projection.SourceArtifact.DigestValue; got != sourceArtifactDigest.Value {
		t.Fatalf("source artifact digest = %q, want fixture digest", got)
	}

	data, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("Marshal(projection) error = %v", err)
	}
	assertAcquisitionTextOmitsFragments(t, string(data),
		append(unsafeOCIFragments(sourceRef),
			"ghcr.io/acme/templates/codex-go:1.2.0",
			"ghcr.io/acme/go-agent:1.2.0",
			"ghcr.io/acme/sources/repo:20260703",
			"registryAuth",
			"authorization",
		)...,
	)
}

func TestProjectTemplateProvenanceOmitsUnsafeValuesAndBoundsWarnings(t *testing.T) {
	lock := acquisition.TemplateLock{
		SourceKind:    acquisition.SourceKind("local_file?token=ghp_secret"),
		ReferenceKind: sandboxtemplate.ReferenceKind("/Users/alice/private-template.yaml"),
		Status:        acquisition.LockStatus("locked?token=ghp_secret"),
		Document: acquisition.DigestLock{
			Status:             acquisition.LockStatusLocked,
			Digest:             &sandboxtemplate.DigestMetadata{Algorithm: sandboxtemplate.DigestAlgorithmSHA256, Value: "not-a-digest?token=ghp_secret"},
			SizeBytes:          -1,
			LockedAtUnixMillis: -1,
			ReasonCode:         acquisition.LockReasonCode("sk-live-template"),
		},
		References: []acquisition.ReferenceLock{
			{
				Field:      "runtime.image?token=ghp_secret",
				Kind:       sandboxtemplate.ReferenceKind("oci_image?token=ghp_secret"),
				Status:     acquisition.LockStatusLocked,
				Digest:     testDigest(strings.Repeat("e", 64)),
				ReasonCode: acquisition.LockReasonImmutableDigest,
			},
			{
				Field:      "runtime.image",
				Kind:       sandboxtemplate.ReferenceKind("oci_image?token=ghp_secret"),
				Status:     acquisition.LockStatusLocked,
				Digest:     &sandboxtemplate.DigestMetadata{Algorithm: sandboxtemplate.DigestAlgorithmSHA256, Value: "not-a-digest?token=ghp_secret"},
				ReasonCode: acquisition.LockReasonImmutableDigest,
			},
			{
				Field:      "workspace.ref",
				Kind:       sandboxtemplate.ReferenceKindGit,
				Status:     acquisition.LockStatusUnresolved,
				ReasonCode: acquisition.LockReasonMutableReference,
			},
		},
		Warnings: []acquisition.LockReasonCode{
			acquisition.LockReasonResolverUnavailable,
			acquisition.LockReasonUnsupportedSource,
			acquisition.LockReasonMutableReference,
			acquisition.LockReasonImmutableDigest,
			acquisition.LockReasonDocumentDigest,
			acquisition.LockReasonCode("template_reference_digest"),
			acquisition.LockReasonCode("runtime_image_digest"),
			acquisition.LockReasonCode("source_artifact_digest"),
			acquisition.LockReasonCode("unresolved_mutable_reference"),
			acquisition.LockReasonCode("token=ghp_secret"),
			acquisition.LockReasonCode("/Users/alice/private"),
		},
	}

	projection := acquisition.ProjectTemplateProvenance(lock)
	if projection == nil {
		t.Fatal("ProjectTemplateProvenance() = nil, want safe unresolved projection metadata")
	}
	data, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("Marshal(projection) error = %v", err)
	}
	publicText := string(data)
	assertAcquisitionTextOmitsFragments(t, publicText,
		"token=",
		"ghp_secret",
		"sk-live-template",
		"/Users/",
		"private-template",
		"not-a-digest",
		"runtime.image?token",
		"oci_image?token",
		"annotations",
		"registryAuth",
	)
	if projection.RuntimeImage == nil {
		t.Fatalf("projection = %#v, want runtime image entry with unsafe digest omitted", projection)
	}
	if projection.RuntimeImage.DigestValue != "" || projection.RuntimeImage.DigestAlgorithm != "" {
		t.Fatalf("runtime image digest = %q/%q, want unsafe digest omitted", projection.RuntimeImage.DigestAlgorithm, projection.RuntimeImage.DigestValue)
	}
	if projection.SourceArtifact == nil || projection.SourceArtifact.ReasonCode != "unresolved_mutable_reference" {
		t.Fatalf("source artifact = %#v, want unresolved mutable reason", projection.SourceArtifact)
	}
	if len(projection.Document.WarningCodes) != 8 {
		t.Fatalf("document warning codes = %#v, want bounded to 8 safe codes", projection.Document.WarningCodes)
	}
}
