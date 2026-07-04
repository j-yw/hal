package sandboxtemplate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClassifyTemplateReferenceAcceptsLocalGitAndOCIInputs(t *testing.T) {
	digestValue := strings.Repeat("a", 64)
	tests := []struct {
		name       string
		input      string
		wantKind   ReferenceKind
		wantRef    string
		wantDigest bool
		wantReason TemplateReferenceReasonCode
	}{
		{
			name:       "local path",
			input:      "/Users/v/private-token-template.yaml",
			wantKind:   ReferenceKindLocal,
			wantReason: TemplateReferenceReasonLocalPath,
		},
		{
			name:       "git url",
			input:      "https://github.com/acme/hal-sandbox-templates.git",
			wantKind:   ReferenceKindGit,
			wantRef:    "https://github.com/acme/hal-sandbox-templates.git",
			wantReason: TemplateReferenceReasonMutableReference,
		},
		{
			name:       "oci artifact",
			input:      "oci://registry.example.io/acme/templates/codex-go:1.2.0",
			wantKind:   ReferenceKindOCIArtifact,
			wantRef:    "registry.example.io/acme/templates/codex-go:1.2.0",
			wantReason: TemplateReferenceReasonMutableReference,
		},
		{
			name:       "digest pinned oci artifact",
			input:      "registry.example.io/acme/templates/codex-go@sha256:" + digestValue,
			wantKind:   ReferenceKindOCIArtifact,
			wantRef:    "registry.example.io/acme/templates/codex-go",
			wantDigest: true,
			wantReason: TemplateReferenceReasonDigestPinned,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyTemplateReference(tt.input)
			if got.Status != TemplateReferenceStatusAccepted {
				t.Fatalf("status = %q, want accepted: %#v", got.Status, got)
			}
			if got.Kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", got.Kind, tt.wantKind)
			}
			if got.Reference == nil {
				t.Fatal("reference = nil, want classified reference metadata")
			}
			if got.Reference.Kind != tt.wantKind {
				t.Fatalf("reference kind = %q, want %q", got.Reference.Kind, tt.wantKind)
			}
			if got.Reference.Ref != tt.wantRef {
				t.Fatalf("reference ref = %q, want %q", got.Reference.Ref, tt.wantRef)
			}
			if got.ReasonCode != tt.wantReason {
				t.Fatalf("reason = %q, want %q", got.ReasonCode, tt.wantReason)
			}
			if got.DigestPinned != tt.wantDigest {
				t.Fatalf("digestPinned = %v, want %v", got.DigestPinned, tt.wantDigest)
			}
			if got.Mutable == got.DigestPinned {
				t.Fatalf("mutable/digestPinned = %v/%v, want exactly one identity state", got.Mutable, got.DigestPinned)
			}
			if tt.wantDigest {
				if got.Reference.Digest == nil {
					t.Fatal("digest = nil, want supplied digest preserved")
				}
				if got.Reference.Digest.Algorithm != DigestAlgorithmSHA256 || got.Reference.Digest.Value != digestValue {
					t.Fatalf("digest = %#v, want sha256 %s", got.Reference.Digest, digestValue)
				}
			}
		})
	}
}

func TestClassifyTemplateReferenceRejectsMalformedAndUnsupportedInputsSafely(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantKind   ReferenceKind
		wantStatus TemplateReferenceStatus
		wantReason TemplateReferenceReasonCode
		fragments  []string
	}{
		{
			name:       "oci malformed digest",
			input:      "registry.example.io/acme/templates/codex-go@sha256:not-a-digest",
			wantKind:   ReferenceKindOCIArtifact,
			wantStatus: TemplateReferenceStatusMalformed,
			wantReason: TemplateReferenceReasonMalformedDigest,
			fragments:  []string{"not-a-digest"},
		},
		{
			name:       "git url auth and query",
			input:      "https://user:ghp_secret@github.com/acme/repo.git?token=sk-live-template",
			wantKind:   ReferenceKindGit,
			wantStatus: TemplateReferenceStatusUnsupported,
			wantReason: TemplateReferenceReasonUnsafeReference,
			fragments:  []string{"user:ghp_secret", "token=", "sk-live-template", "?token"},
		},
		{
			name:       "implicit docker hub style name",
			input:      "codex-go:latest",
			wantStatus: TemplateReferenceStatusUnsupported,
			wantReason: TemplateReferenceReasonUnsupportedReference,
			fragments:  []string{"docker.io", "library/codex-go"},
		},
		{
			name:       "unsupported scheme",
			input:      "ftp://example.invalid/acme/template.yaml?password=hunter2",
			wantStatus: TemplateReferenceStatusUnsupported,
			wantReason: TemplateReferenceReasonUnsupportedReference,
			fragments:  []string{"ftp://", "password=", "hunter2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyTemplateReference(tt.input)
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q: %#v", got.Status, tt.wantStatus, got)
			}
			if got.Kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", got.Kind, tt.wantKind)
			}
			if got.Reference != nil {
				t.Fatalf("reference = %#v, want nil for malformed/unsupported input", got.Reference)
			}
			if got.ReasonCode != tt.wantReason {
				t.Fatalf("reason = %q, want %q", got.ReasonCode, tt.wantReason)
			}
			if got.Mutable || got.DigestPinned {
				t.Fatalf("mutable/digestPinned = %v/%v, want neither for rejected input", got.Mutable, got.DigestPinned)
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Marshal(classification) error = %v", err)
			}
			for _, fragment := range tt.fragments {
				if strings.Contains(string(data), fragment) {
					t.Fatalf("classification JSON leaked %q in %s", fragment, data)
				}
			}
		})
	}
}

func TestUS004TemplateReferenceClassificationSeparatesDigestLockedAndMutableInput(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name             string
		input            string
		wantStatus       TemplateReferenceStatus
		wantDigestLocked bool
		wantMutable      bool
		wantReason       TemplateReferenceReasonCode
	}{
		{
			name:             "digest locked oci template",
			input:            "registry.example.io/acme/templates/codex-go@sha256:" + digest,
			wantStatus:       TemplateReferenceStatusAccepted,
			wantDigestLocked: true,
			wantReason:       TemplateReferenceReasonDigestPinned,
		},
		{
			name:        "mutable oci template remains advisory input",
			input:       "registry.example.io/acme/templates/codex-go:latest",
			wantStatus:  TemplateReferenceStatusAccepted,
			wantMutable: true,
			wantReason:  TemplateReferenceReasonMutableReference,
		},
		{
			name:       "malformed digest is not digest locked",
			input:      "registry.example.io/acme/templates/codex-go@sha256:not-a-digest",
			wantStatus: TemplateReferenceStatusMalformed,
			wantReason: TemplateReferenceReasonMalformedDigest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyTemplateReference(tt.input)
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q: %#v", got.Status, tt.wantStatus, got)
			}
			if got.DigestPinned != tt.wantDigestLocked || got.Mutable != tt.wantMutable {
				t.Fatalf("digestPinned/mutable = %v/%v, want %v/%v: %#v", got.DigestPinned, got.Mutable, tt.wantDigestLocked, tt.wantMutable, got)
			}
			if got.ReasonCode != tt.wantReason {
				t.Fatalf("reason = %q, want %q", got.ReasonCode, tt.wantReason)
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Marshal(classification) error = %v", err)
			}
			for _, forbidden := range []string{"not-a-digest", "token=", "Authorization", "/Users/"} {
				if strings.Contains(string(data), forbidden) {
					t.Fatalf("classification leaked %q: %s", forbidden, data)
				}
			}
		})
	}
}
