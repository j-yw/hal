//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
)

type minimalTemplateHTTPDoer func(*http.Request) (*http.Response, error)

func (do minimalTemplateHTTPDoer) Do(request *http.Request) (*http.Response, error) {
	return do(request)
}

type minimalTemplateFixture struct {
	association minimalTemplateAssociation
	options     registry.Options
	requests    atomic.Int32
}

func newMinimalTemplateFixture(t *testing.T) *minimalTemplateFixture {
	t.Helper()
	assets := minimalJailerSourceFixture(t)
	if err := assets.verified.ConfirmCurrent(context.Background()); err != nil {
		t.Fatal("actual local source control", err)
	}
	imageDigest := sha256Hex([]byte("independent declared runtime image manifest"))
	document := []byte(`apiVersion: sandbox-template.hal.dev/v1
kind: SandboxTemplate
metadata:
  id: minimal-template
runtime:
  driver: microvm
  isolationLevel: vm
  image:
    kind: oci_image
    ref: registry.example/hal/runtime:stable
    digest:
      algorithm: sha256
      value: ` + imageDigest + "\n")
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": registry.MediaTypeOCIManifest, "artifactType": registry.MediaTypeTemplateArtifact,
		"config": map[string]any{"mediaType": registry.MediaTypeOCIEmptyConfig, "digest": "sha256:" + strings.Repeat("0", 64), "size": 2},
		"layers": []any{map[string]any{"mediaType": registry.MediaTypeTemplateYAML, "digest": "sha256:" + sha256Hex(document), "size": len(document)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &minimalTemplateFixture{association: minimalTemplateAssociation{
		scope: sandboxruntime.MinimalLaunchScope{PolicyID: "launch-policy", Revision: 1, PrincipalID: "principal-1", WorkerID: "worker-1", HostID: "host-1",
			TemplatePolicyID: "template-policy", WorkspacePolicyID: "workspace-policy", NetworkPolicyID: "network-policy"},
		template: sandboxruntime.MinimalLaunchTemplateIdentity{RuntimeImage: "registry.example/hal/runtime:stable@sha256:" + imageDigest,
			TemplateDocumentSHA256: sha256Hex(document), TemplateManifestSHA256: sha256Hex(manifest), RuntimeImageSHA256: imageDigest},
		templateSource: "registry.example/hal/template@sha256:" + sha256Hex(manifest), bundleDir: assets.root, parentL7Dir: assets.parentDir, expected: assets.expected,
	}}
	fixture.options = registry.Options{AllowedRegistryOrigins: []string{"https://registry.example"}, Client: minimalTemplateHTTPDoer(func(request *http.Request) (*http.Response, error) {
		if request.Context().Err() != nil {
			return nil, request.Context().Err()
		}
		fixture.requests.Add(1)
		if request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host != "registry.example" {
			return nil, errors.New("unexpected fixture origin")
		}
		var body []byte
		var media string
		switch request.URL.Path {
		case "/v2/hal/template/manifests/sha256:" + sha256Hex(manifest):
			body, media = manifest, registry.MediaTypeOCIManifest
		case "/v2/hal/template/blobs/sha256:" + sha256Hex(document):
			body, media = document, registry.MediaTypeTemplateYAML
		default:
			return nil, errors.New("unexpected fixture path")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{media}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	return fixture
}

func minimalTemplateHints() sandboxruntime.MinimalLaunchSelectionHints {
	return sandboxruntime.MinimalLaunchSelectionHints{SandboxID: "sandbox-1", ExecutionID: "execution-1", SubmissionID: "submission-1", RuntimeID: "runtime-1", PlanID: "plan-1",
		TemplatePolicyID: "template-policy", WorkspacePolicyID: "workspace-policy"}
}

// This control exercises actual registry measurement and Workflow/Bind, never
// an injected Result. The runtime-image digest is declared, not fetched rootfs.
func minimalTemplateAcquisitionControl(t *testing.T, fixture *minimalTemplateFixture) {
	t.Helper()
	resolver, err := registry.NewResolver(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := selection.NewWorkflow(acquisition.NewOCIResolver(resolver)).Select(ctx, selection.Request{
		Source:    acquisition.TemplateSource{Kind: acquisition.SourceKindOCIArtifact, Reference: &sandboxtemplate.ImmutableRef{Kind: sandboxtemplate.ReferenceKindOCIArtifact, Ref: fixture.association.templateSource}},
		TrustMode: acquisition.TrustPolicyModeStrict,
	})
	if err != nil {
		t.Fatal("actual Workflow fixture control", err)
	}
	want := fixture.association.template
	if result.Trust.Decision != acquisition.TrustPolicyDecisionTrusted || result.Trust.Enforcement == nil || !result.Trust.Enforcement.StrictlyEnforced ||
		result.Lock.Document.Digest == nil || result.Lock.Document.Digest.Value != want.TemplateDocumentSHA256 || result.ManifestDigest == nil || result.ManifestDigest.Value != want.TemplateManifestSHA256 ||
		result.RuntimeImage != want.RuntimeImage || result.RuntimeDriver != "microvm" || result.IsolationLevel != "vm" || fixture.requests.Load() != 2 {
		t.Fatal("actual measured template/control roles differ")
	}
	if want.TemplateDocumentSHA256 == want.TemplateManifestSHA256 || want.RuntimeImageSHA256 == want.TemplateDocumentSHA256 || want.RuntimeImageSHA256 == fixture.association.expected.RootfsSHA256 {
		t.Fatal("fixture accidentally aliases distinct digest roles")
	}
	hints := minimalTemplateHints()
	if _, err := selection.Bind(result, selection.BindingRequest{ExecutionID: hints.ExecutionID, SandboxID: hints.SandboxID, RuntimeID: hints.RuntimeID,
		RuntimeDriver: "microvm", IsolationLevel: "vm", RuntimeImage: want.RuntimeImage, ManifestDigest: result.ManifestDigest}); err != nil {
		t.Fatal("actual Bind fixture control", err)
	}
}

func TestMinimalTemplateProviderMeasuredAcquisitionControl(t *testing.T) {
	minimalTemplateAcquisitionControl(t, newMinimalTemplateFixture(t))
}

func TestMinimalTemplateProviderOwnsFreshAcquisition(t *testing.T) {
	fixture := newMinimalTemplateFixture(t)
	minimalTemplateAcquisitionControl(t, fixture)
	provider, err := newMinimalLaunchProvider(fixture.association, fixture.options)
	if err != nil || provider == nil {
		t.Fatal("verified template and independently retained source have no concrete provider", err)
	}
	if fixture.requests.Load() != 2 {
		t.Fatal("constructor performed acquisition")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := provider.ResolveMinimalSelection(ctx, minimalTemplateHints())
	if err != nil || first == nil {
		t.Fatal("first actual provider acquisition", err)
	}
	defer first.Close()
	second, err := provider.ResolveMinimalSelection(ctx, minimalTemplateHints())
	if err != nil || second == nil {
		t.Fatal("second actual provider acquisition", err)
	}
	defer second.Close()
	one, err := first.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	two, err := second.Current(ctx)
	if err != nil || one.RuntimeGeneration == two.RuntimeGeneration || !sandboxruntime.ValidMinimalLaunchID(one.RuntimeGeneration) || !sandboxruntime.ValidMinimalLaunchID(two.RuntimeGeneration) || fixture.requests.Load() != 6 {
		t.Fatal("independent jobs did not get independent measured acquisitions/generations", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Current(ctx); err == nil {
		t.Fatal("closed source recovered authority")
	}
	if _, err := second.Current(ctx); err != nil {
		t.Fatal("first source close consumed second source", err)
	}
}
