package acquisition_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

func TestClassifyTemplateSourceReferenceBuildsSourcesAndSafeStatus(t *testing.T) {
	digestValue := strings.Repeat("b", 64)
	tests := []struct {
		name              string
		input             string
		wantSourceKind    acquisition.SourceKind
		wantReferenceKind sandboxtemplate.ReferenceKind
		wantRef           string
		wantDigest        bool
		wantReason        acquisition.LockReasonCode
	}{
		{
			name:              "local path",
			input:             "/Users/v/private-token-template.yaml",
			wantSourceKind:    acquisition.SourceKindLocalFile,
			wantReferenceKind: sandboxtemplate.ReferenceKindLocal,
			wantReason:        acquisition.LockReasonUnresolvedMutableReference,
		},
		{
			name:              "git url",
			input:             "https://github.com/acme/hal-sandbox-templates.git",
			wantSourceKind:    acquisition.SourceKindGit,
			wantReferenceKind: sandboxtemplate.ReferenceKindGit,
			wantRef:           "https://github.com/acme/hal-sandbox-templates.git",
			wantReason:        acquisition.LockReasonUnresolvedMutableReference,
		},
		{
			name:              "oci artifact",
			input:             "oci://registry.example.io/acme/templates/codex-go:1.2.0",
			wantSourceKind:    acquisition.SourceKindOCIArtifact,
			wantReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
			wantRef:           "registry.example.io/acme/templates/codex-go:1.2.0",
			wantReason:        acquisition.LockReasonUnresolvedMutableReference,
		},
		{
			name:              "digest pinned oci artifact",
			input:             "registry.example.io/acme/templates/codex-go@sha256:" + digestValue,
			wantSourceKind:    acquisition.SourceKindOCIArtifact,
			wantReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
			wantRef:           "registry.example.io/acme/templates/codex-go",
			wantDigest:        true,
			wantReason:        acquisition.LockReasonImmutableDigest,
		},
		{
			name:              "unsupported implicit registry default",
			input:             "codex-go:latest",
			wantSourceKind:    acquisition.SourceKindUnsupported,
			wantReferenceKind: "",
			wantReason:        acquisition.LockReasonUnsupportedSource,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := acquisition.ClassifyTemplateSourceReference(tt.input, sandboxtemplate.FormatYAML)
			if got.Source.Kind != tt.wantSourceKind {
				t.Fatalf("source kind = %q, want %q", got.Source.Kind, tt.wantSourceKind)
			}
			if got.Status.SourceKind != tt.wantSourceKind {
				t.Fatalf("status source kind = %q, want %q", got.Status.SourceKind, tt.wantSourceKind)
			}
			if got.Status.ReferenceKind != tt.wantReferenceKind {
				t.Fatalf("status reference kind = %q, want %q", got.Status.ReferenceKind, tt.wantReferenceKind)
			}
			if got.Status.Status != acquisition.LockStatusUnresolved {
				t.Fatalf("status = %q, want unresolved classification", got.Status.Status)
			}
			if got.Status.ReasonCode != tt.wantReason {
				t.Fatalf("status reason = %q, want %q", got.Status.ReasonCode, tt.wantReason)
			}
			if got.Lock.Status != acquisition.LockStatusUnresolved {
				t.Fatalf("lock status = %q, want unresolved before acquisition", got.Lock.Status)
			}
			if got.Lock.SourceKind != tt.wantSourceKind {
				t.Fatalf("lock source kind = %q, want %q", got.Lock.SourceKind, tt.wantSourceKind)
			}
			if got.Lock.ReferenceKind != tt.wantReferenceKind {
				t.Fatalf("lock reference kind = %q, want %q", got.Lock.ReferenceKind, tt.wantReferenceKind)
			}
			if tt.wantSourceKind == acquisition.SourceKindLocalFile {
				if got.Source.LocalPath != tt.input {
					t.Fatalf("local path source = %q, want caller input preserved for resolver", got.Source.LocalPath)
				}
			} else if tt.wantRef != "" {
				if got.Source.Reference == nil {
					t.Fatal("source reference = nil, want classified reference for resolver")
				}
				if got.Source.Reference.Ref != tt.wantRef {
					t.Fatalf("source reference = %q, want %q", got.Source.Reference.Ref, tt.wantRef)
				}
			}
			if tt.wantDigest {
				if got.Status.Digest == nil || got.Status.Digest.Value != digestValue {
					t.Fatalf("status digest = %#v, want supplied digest %s", got.Status.Digest, digestValue)
				}
				assertReferenceDigestLock(t, got.Lock, "metadata.reference", tt.wantReferenceKind, got.Status.Digest)
			}
		})
	}
}

func TestTemplateSourceIntakePublicMetadataDoesNotLeakUnsafeInputs(t *testing.T) {
	inputs := []string{
		"/Users/v/private-token-template.yaml",
		"https://user:ghp_secret@github.com/acme/repo.git?token=sk-live-template",
		"oci://user:password@registry.example.io/acme/template:1.0?api_key=sk-live-template",
		"ftp://example.invalid/acme/template.yaml?secret=sk-live-template",
	}
	fragments := []string{
		"/Users/v/private-token-template.yaml",
		"/Users/",
		"private-token",
		"user:ghp_secret",
		"user:password",
		"token=",
		"api_key=",
		"secret=",
		"sk-live-template",
		"?token",
		"?api_key",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			got := acquisition.ClassifyTemplateSourceReference(input, sandboxtemplate.FormatYAML)
			statusJSON := mustMarshalIntakePublicMetadata(t, got.Status)
			lockJSON := mustMarshalIntakePublicMetadata(t, got.Lock)
			provenanceJSON := mustMarshalIntakePublicMetadata(t, acquisition.ProjectTemplateProvenance(got.Lock))
			publicText := statusJSON + " " + lockJSON + " " + provenanceJSON
			assertAcquisitionTextOmitsFragments(t, publicText, fragments...)
			if got.Status.Status != acquisition.LockStatusUnresolved || got.Lock.Status != acquisition.LockStatusUnresolved {
				t.Fatalf("classification status/lock = %q/%q, want unresolved public metadata", got.Status.Status, got.Lock.Status)
			}
		})
	}
}

func TestTemplateSourceStatusJSONShapeOmitsRawReferenceSurfaces(t *testing.T) {
	statusType := reflectAcquisitionType[acquisition.TemplateSourceStatus]()
	assertAcquisitionField(t, statusType, "SourceKind", reflectAcquisitionType[acquisition.SourceKind](), `json:"sourceKind,omitempty"`)
	assertAcquisitionField(t, statusType, "ReferenceKind", reflectAcquisitionType[sandboxtemplate.ReferenceKind](), `json:"referenceKind,omitempty"`)
	assertAcquisitionField(t, statusType, "Status", reflectAcquisitionType[acquisition.LockStatus](), `json:"status,omitempty"`)
	assertAcquisitionField(t, statusType, "Digest", reflectAcquisitionType[*sandboxtemplate.DigestMetadata](), `json:"digest,omitempty"`)
	assertAcquisitionField(t, statusType, "ReasonCode", reflectAcquisitionType[acquisition.LockReasonCode](), `json:"reasonCode,omitempty"`)
	assertAcquisitionField(t, statusType, "WarningCodes", reflectAcquisitionType[[]acquisition.LockReasonCode](), `json:"warningCodes,omitempty"`)

	intakeType := reflectAcquisitionType[acquisition.TemplateSourceClassification]()
	assertAcquisitionField(t, intakeType, "Source", reflectAcquisitionType[acquisition.TemplateSource](), `json:"-"`)
	assertAcquisitionField(t, intakeType, "Status", reflectAcquisitionType[acquisition.TemplateSourceStatus](), `json:"status,omitempty"`)
	assertAcquisitionField(t, intakeType, "Lock", reflectAcquisitionType[acquisition.TemplateLock](), `json:"lock,omitempty"`)
}

func mustMarshalIntakePublicMetadata(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error = %v", value, err)
	}
	return string(data)
}

func reflectAcquisitionType[T any]() reflect.Type {
	var zero T
	return reflect.TypeOf(zero)
}
