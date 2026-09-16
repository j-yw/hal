//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
)

func TestMinimalTemplateProviderRejectsInvalidConfigurationBeforeIO(t *testing.T) {
	fixture := newMinimalTemplateFixture(t)
	cases := map[string]func(*minimalTemplateAssociation){
		"zero-revision":  func(a *minimalTemplateAssociation) { a.scope.Revision = 0 },
		"principal":      func(a *minimalTemplateAssociation) { a.scope.PrincipalID = "" },
		"host":           func(a *minimalTemplateAssociation) { a.scope.HostID = "unsafe/host" },
		"network-policy": func(a *minimalTemplateAssociation) { a.scope.NetworkPolicyID = "" },
		"image":          func(a *minimalTemplateAssociation) { a.template.RuntimeImage = "" },
		"document":       func(a *minimalTemplateAssociation) { a.template.TemplateDocumentSHA256 = "" },
		"source-tag":     func(a *minimalTemplateAssociation) { a.templateSource = "registry.example/hal/template:latest" },
		"source-pin": func(a *minimalTemplateAssociation) {
			a.templateSource = "registry.example/hal/template@sha256:" + strings.Repeat("f", 64)
		},
		"source-credentials":   func(a *minimalTemplateAssociation) { a.templateSource = "secret@" + a.templateSource },
		"relative-root":        func(a *minimalTemplateAssociation) { a.bundleDir = "relative" },
		"unclean-root":         func(a *minimalTemplateAssociation) { a.bundleDir += "/../child" },
		"broad-root":           func(a *minimalTemplateAssociation) { a.parentL7Dir = "/" },
		"control-root":         func(a *minimalTemplateAssociation) { a.bundleDir += "\x00private" },
		"expected-revision":    func(a *minimalTemplateAssociation) { a.expected.SourceRevision = "" },
		"expected-rootfs":      func(a *minimalTemplateAssociation) { a.expected.RootfsSHA256 = strings.Repeat("A", 64) },
		"expected-init":        func(a *minimalTemplateAssociation) { a.expected.GuestInitSHA256 = "" },
		"expected-agent":       func(a *minimalTemplateAssociation) { a.expected.GuestAgentSHA256 = "" },
		"expected-source-lock": func(a *minimalTemplateAssociation) { a.expected.SourceLockSHA256 = "" },
		"expected-inspection":  func(a *minimalTemplateAssociation) { a.expected.FinalInspectionSHA256 = "" },
		"expected-provenance":  func(a *minimalTemplateAssociation) { a.expected.ProvenanceSHA256 = "" },
		"expected-node":        func(a *minimalTemplateAssociation) { a.expected.Runtime.NodeSHA256 = "" },
		"expected-launcher":    func(a *minimalTemplateAssociation) { a.expected.Runtime.PiLauncherSHA256 = "" },
		"expected-tree":        func(a *minimalTemplateAssociation) { a.expected.Runtime.PiDependencyTreeSHA256 = "" },
		"expected-version":     func(a *minimalTemplateAssociation) { a.expected.Runtime.PiVersion = "" },
		"expected-package":     func(a *minimalTemplateAssociation) { a.expected.Runtime.PiPackage = "private value" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			entry := fixture.association
			mutate(&entry)
			if provider, err := newMinimalLaunchProvider(entry, fixture.options); provider != nil || err != sandboxruntime.ErrMinimalLaunchUnavailable {
				t.Fatal("invalid constructor accepted or leaked input", err)
			}
		})
	}
	options := fixture.options
	options.Cache = &minimalTemplateForbiddenCache{t: t}
	if provider, err := newMinimalLaunchProvider(fixture.association, options); err == nil || provider != nil {
		t.Fatal("read-only provider accepted a publishing cache")
	}
	if fixture.requests.Load() != 0 {
		t.Fatal("invalid constructor performed acquisition")
	}
}

type minimalTemplateForbiddenCache struct{ t *testing.T }

func (cache *minimalTemplateForbiddenCache) Load(context.Context, registry.CacheLookup) ([]byte, bool, error) {
	cache.t.Error("provider used forbidden cache")
	return nil, false, errors.New("forbidden")
}
func (cache *minimalTemplateForbiddenCache) Store(context.Context, registry.CacheEntry) error {
	cache.t.Error("provider published forbidden cache")
	return errors.New("forbidden")
}

func TestMinimalTemplateProviderRejectsInvalidCallsBeforeIO(t *testing.T) {
	fixture := newMinimalTemplateFixture(t)
	provider, err := newMinimalLaunchProvider(fixture.association, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, mutate := range []func(*sandboxruntime.MinimalLaunchSelectionHints){
		func(h *sandboxruntime.MinimalLaunchSelectionHints) { h.SandboxID = "" },
		func(h *sandboxruntime.MinimalLaunchSelectionHints) { h.ExecutionID = "unsafe/path" },
		func(h *sandboxruntime.MinimalLaunchSelectionHints) { h.SubmissionID = "" },
		func(h *sandboxruntime.MinimalLaunchSelectionHints) { h.RuntimeID = "" },
		func(h *sandboxruntime.MinimalLaunchSelectionHints) { h.PlanID = "" },
		func(h *sandboxruntime.MinimalLaunchSelectionHints) { h.TemplatePolicyID = "other-policy" },
		func(h *sandboxruntime.MinimalLaunchSelectionHints) { h.WorkspacePolicyID = "other-policy" },
	} {
		hints := minimalTemplateHints()
		mutate(&hints)
		if source, err := provider.ResolveMinimalSelection(ctx, hints); err == nil || source != nil {
			t.Fatal("invalid hints acquired ownership")
		}
	}
	canceled, cancelNow := context.WithTimeout(context.Background(), time.Second)
	cancelNow()
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	for _, call := range []struct {
		ctx   context.Context
		cause error
	}{{nil, nil}, {context.Background(), nil}, {canceled, context.Canceled}, {expired, context.DeadlineExceeded}} {
		if source, err := provider.ResolveMinimalSelection(call.ctx, minimalTemplateHints()); source != nil || err == nil || call.cause != nil && !errors.Is(err, call.cause) {
			t.Fatal("invalid context admitted or lost identity", err)
		}
	}
	copyProvider := &minimalLaunchProvider{self: provider, association: provider.association, workflow: provider.workflow}
	for _, invalid := range []*minimalLaunchProvider{nil, {}, copyProvider} {
		if source, err := invalid.ResolveMinimalSelection(ctx, minimalTemplateHints()); err == nil || source != nil {
			t.Fatal("nonoriginal provider accepted")
		}
	}
	if fixture.requests.Load() != 0 {
		t.Fatal("invalid call performed acquisition")
	}
}

func TestMinimalTemplateProviderAcquisitionRejectsMeasuredMismatchAndLoss(t *testing.T) {
	for _, fault := range []string{"document-pin", "image-pin", "expected-pin", "manifest-bytes", "layer-bytes", "media", "origin", "cancel", "panic"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newMinimalTemplateFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			switch fault {
			case "document-pin":
				fixture.association.template.TemplateDocumentSHA256 = strings.Repeat("f", 64)
			case "image-pin":
				fixture.association.template.RuntimeImageSHA256 = strings.Repeat("f", 64)
				fixture.association.template.RuntimeImage = "registry.example/hal/runtime:stable@sha256:" + strings.Repeat("f", 64)
			case "expected-pin":
				fixture.association.expected.RootfsSHA256 = strings.Repeat("f", 64)
			case "origin":
				fixture.options.AllowedRegistryOrigins = []string{"https://other.example"}
			default:
				original := fixture.options.Client
				fixture.options.Client = minimalTemplateHTTPDoer(func(request *http.Request) (*http.Response, error) {
					if fault == "panic" {
						panic("private credential panic")
					}
					response, err := original.Do(request)
					if err != nil {
						return response, err
					}
					if fault == "cancel" {
						cancel()
					}
					if fault == "media" {
						response.Header.Set("Content-Type", "application/private")
					}
					if fault == "manifest-bytes" && strings.Contains(request.URL.Path, "/manifests/") || fault == "layer-bytes" && strings.Contains(request.URL.Path, "/blobs/") {
						_ = response.Body.Close()
						response.Body = io.NopCloser(strings.NewReader("private corrupt input"))
					}
					return response, nil
				})
			}
			provider, err := newMinimalLaunchProvider(fixture.association, fixture.options)
			if err != nil {
				t.Fatal("invalid test constructor", err)
			}
			if source, err := provider.ResolveMinimalSelection(ctx, minimalTemplateHints()); source != nil || err == nil || strings.Contains(err.Error(), "private") || fault == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("bad acquisition accepted or leaked input", err)
			}
		})
	}
}

func TestMinimalTemplateProviderRetainsOriginalInputCopies(t *testing.T) {
	fixture := newMinimalTemplateFixture(t)
	want := fixture.association
	provider, err := newMinimalLaunchProvider(fixture.association, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	fixture.association = minimalTemplateAssociation{}
	fixture.options.AllowedRegistryOrigins[0] = "https://wrong.example"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	source, err := provider.ResolveMinimalSelection(ctx, minimalTemplateHints())
	if err != nil {
		t.Fatal("borrowed constructor values changed provider", err)
	}
	defer source.Close()
	identity, err := source.Current(ctx)
	if err != nil || identity.HostID != want.scope.HostID || identity.WorkerID != want.scope.WorkerID || identity.NetworkPolicyID != want.scope.NetworkPolicyID || provider.association != want {
		t.Fatal("immutable original association lost", err)
	}
	original := source.(*minimalTemplateSelection)
	copySource := &minimalTemplateSelection{self: original, provider: provider, assets: original.assets}
	if _, err := copySource.Current(ctx); err == nil || copySource.Close() == nil {
		t.Fatal("copied source acquired close/current authority")
	}
	if _, err := source.Current(ctx); err != nil {
		t.Fatal("copy rejection consumed original", err)
	}
}

func TestMinimalTemplateProviderCurrentRejectsActualRetainedReplacement(t *testing.T) {
	for _, target := range []string{"vmlinux", "rootfs.ext4", "provenance.json", "parent"} {
		t.Run(target, func(t *testing.T) {
			fixture := newMinimalTemplateFixture(t)
			provider, err := newMinimalLaunchProvider(fixture.association, fixture.options)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			source, err := provider.ResolveMinimalSelection(ctx, minimalTemplateHints())
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			path := filepath.Join(fixture.association.bundleDir, target)
			if target == "parent" {
				path = filepath.Join(fixture.association.parentL7Dir, "vmlinux")
			}
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := source.Current(ctx); err == nil {
				t.Fatal("byte-identical replacement recaptured as current")
			}
			if fixture.requests.Load() != 2 {
				t.Fatal("Current reacquired OCI selection")
			}
		})
	}
}

func TestMinimalTemplateProviderConcurrentSelectionsAndClose(t *testing.T) {
	fixture := newMinimalTemplateFixture(t)
	provider, err := newMinimalLaunchProvider(fixture.association, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var group sync.WaitGroup
	identities := make(chan string, 8)
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			source, err := provider.ResolveMinimalSelection(ctx, minimalTemplateHints())
			if err != nil {
				t.Error(err)
				return
			}
			defer source.Close()
			identity, err := source.Current(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			identities <- identity.RuntimeGeneration
			closed := make(chan error, 1)
			go func() { closed <- source.Close() }()
			_, _ = source.Current(ctx)
			if err := <-closed; err != nil {
				t.Error(err)
			}
			if _, err := source.Current(ctx); err == nil {
				t.Error("closed selection current")
			}
		}()
	}
	group.Wait()
	close(identities)
	seen := make(map[string]bool)
	for id := range identities {
		if seen[id] {
			t.Error("reused generation")
		}
		seen[id] = true
	}
	// Every Select measures its own manifest. The accepted resolver may
	// coalesce only concurrent identical layer reads even when Cache is nil;
	// that does not share a local retained distribution or runtime generation.
	if len(seen) != 8 || fixture.requests.Load() < 9 || fixture.requests.Load() > 16 {
		t.Fatal("missing independent acquisitions", len(seen), fixture.requests.Load())
	}
}

func TestMinimalTemplateProviderRejectsContradictoryMeasuredLocks(t *testing.T) {
	fixture := newMinimalTemplateFixture(t)
	resolver, err := registry.NewResolver(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, fault := range []string{"control", "duplicate-manifest", "duplicate-image", "warning", "advisory", "driver", "isolation", "image-projection", "document-algorithm"} {
		t.Run(fault, func(t *testing.T) {
			result, err := selection.NewWorkflow(acquisition.NewOCIResolver(resolver)).Select(ctx, selection.Request{Source: acquisition.TemplateSource{Kind: acquisition.SourceKindOCIArtifact, Reference: minimalTemplateReference(fixture.association)}, TrustMode: acquisition.TrustPolicyModeStrict})
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "duplicate-manifest", "duplicate-image":
				field := "metadata.reference"
				if fault == "duplicate-image" {
					field = "runtime.image"
				}
				for _, ref := range result.Lock.References {
					if ref.Field == field {
						result.Lock.References = append(result.Lock.References, ref)
						break
					}
				}
			case "warning":
				result.Trust.Warnings = append(result.Trust.Warnings, acquisition.TrustPolicyWarning{})
			case "advisory":
				result.Trust.Enforcement.StrictlyEnforced = false
			case "driver":
				result.RuntimeDriver = "rootless"
			case "isolation":
				result.IsolationLevel = "container"
			case "image-projection":
				result.RuntimeImage = "other"
			case "document-algorithm":
				result.Lock.Document.Digest.Algorithm = "other"
			}
			if minimalTemplateSelectionMatches(result, fixture.association.template, minimalTemplateHints()) != (fault == "control") {
				t.Fatal("contradictory projection accepted or real control rejected")
			}
		})
	}
}

// This is a direct validation test over a freshly acquired real Result; altered
// copies are never fed to the provider as acquisition authority.
func minimalTemplateReference(entry minimalTemplateAssociation) *sandboxtemplate.ImmutableRef {
	return &sandboxtemplate.ImmutableRef{Kind: sandboxtemplate.ReferenceKindOCIArtifact, Ref: entry.templateSource}
}
