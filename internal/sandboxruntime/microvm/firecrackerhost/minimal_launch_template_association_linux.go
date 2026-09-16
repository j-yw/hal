//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
)

// Constructor-owned deployment association, not an OCI-to-rootfs digest proof.
type minimalTemplateAssociation struct {
	scope                  sandboxruntime.MinimalLaunchScope
	template               sandboxruntime.MinimalLaunchTemplateIdentity
	templateSource         string
	bundleDir, parentL7Dir string
	expected               localresolver.L8MinimalExpectedIdentity
}

type minimalLaunchProvider struct {
	self        *minimalLaunchProvider
	association minimalTemplateAssociation
	workflow    selection.Workflow
}

// Construction is inert. Registry transport/credentials are borrowed trusted
// capabilities; this provider neither closes them nor publishes a cache entry.
func newMinimalLaunchProvider(association minimalTemplateAssociation, options registry.Options) (*minimalLaunchProvider, error) {
	if !validMinimalTemplateAssociation(association) || options.Cache != nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	resolver, err := registry.NewResolver(options)
	if err != nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	provider := &minimalLaunchProvider{association: association, workflow: selection.NewWorkflow(acquisition.NewOCIResolver(resolver))}
	provider.self = provider
	return provider, nil
}

func (provider *minimalLaunchProvider) ResolveMinimalSelection(ctx context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (result sandboxruntime.MinimalLaunchSelection, retErr error) {
	var source *minimalTemplateSelection
	defer func() {
		if recover() != nil {
			result, retErr = nil, sandboxruntime.ErrMinimalLaunchUnavailable
		}
		if result == nil && source != nil {
			retErr = errors.Join(retErr, source.Close())
		}
	}()
	if err := minimalTemplateContextError(ctx); err != nil {
		return nil, err
	}
	if provider == nil || provider.self != provider || !validMinimalTemplateHints(hints, provider.association.scope) {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	entry := provider.association
	selected, err := provider.workflow.Select(ctx, selection.Request{
		Source: acquisition.TemplateSource{Kind: acquisition.SourceKindOCIArtifact,
			Reference: &sandboxtemplate.ImmutableRef{Kind: sandboxtemplate.ReferenceKindOCIArtifact, Ref: entry.templateSource}},
		TrustMode: acquisition.TrustPolicyModeStrict,
	})
	if err != nil || !minimalTemplateSelectionMatches(selected, entry.template, hints) {
		return nil, minimalTemplateFailure(ctx)
	}
	if err := minimalTemplateContextError(ctx); err != nil {
		return nil, err
	}
	parent, err := localresolver.VerifyDistributionBundleContext(ctx, localresolver.DistributionRequest{RootDir: entry.parentL7Dir})
	if err != nil {
		return nil, minimalTemplateFailure(ctx)
	}
	verified, err := localresolver.VerifyL8MinimalDistributionBundleContext(ctx, localresolver.L8MinimalDistributionRequest{
		DistributionRequest: localresolver.DistributionRequest{RootDir: entry.bundleDir}, ParentL7: parent, Expected: entry.expected,
	})
	if err != nil {
		// The verifier attempts its own cleanup on failure and returns no owner.
		// Preserve failure without claiming absence or retrying acquisition.
		return nil, minimalTemplateFailure(ctx)
	}
	source = &minimalTemplateSelection{provider: provider, hints: hints, template: entry.template, assets: verified}
	source.self = source
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	source.identity = sandboxruntime.MinimalLaunchSelectionIdentity{
		WorkerID: entry.scope.WorkerID, HostID: entry.scope.HostID, RuntimeID: hints.RuntimeID,
		RuntimeGeneration: "minimal-" + hex.EncodeToString(generation[:]), PlanID: hints.PlanID,
		TemplatePolicyID: entry.scope.TemplatePolicyID, WorkspacePolicyID: entry.scope.WorkspacePolicyID, NetworkPolicyID: entry.scope.NetworkPolicyID,
	}
	if _, err := source.Current(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

// A selection owns only its fresh verified files. No launch lease is taken by
// acquisition/currentness, and no runtime or cleanup receipt exists here yet.
type minimalTemplateSelection struct {
	self     *minimalTemplateSelection
	provider *minimalLaunchProvider
	hints    sandboxruntime.MinimalLaunchSelectionHints
	template sandboxruntime.MinimalLaunchTemplateIdentity
	identity sandboxruntime.MinimalLaunchSelectionIdentity
	mu       sync.Mutex
	assets   localresolver.VerifiedL8MinimalDistribution
	closed   bool
	closeErr error
}

func (source *minimalTemplateSelection) Current(ctx context.Context) (sandboxruntime.MinimalLaunchSelectionIdentity, error) {
	if err := minimalTemplateContextError(ctx); err != nil {
		return sandboxruntime.MinimalLaunchSelectionIdentity{}, err
	}
	if source == nil || source.self != source || source.provider == nil || source.provider.self != source.provider {
		return sandboxruntime.MinimalLaunchSelectionIdentity{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed || source.template != source.provider.association.template || !validMinimalTemplateHints(source.hints, source.provider.association.scope) {
		return sandboxruntime.MinimalLaunchSelectionIdentity{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	if err := source.assets.ConfirmCurrent(ctx); err != nil {
		return sandboxruntime.MinimalLaunchSelectionIdentity{}, minimalTemplateFailure(ctx)
	}
	if err := minimalTemplateContextError(ctx); err != nil {
		return sandboxruntime.MinimalLaunchSelectionIdentity{}, err
	}
	return source.identity, nil
}

func (source *minimalTemplateSelection) Close() error {
	if source == nil || source.self != source {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.closed {
		source.closed = true
		if source.assets.Close() != nil {
			source.closeErr = sandboxruntime.ErrMinimalLaunchUnavailable
		}
	}
	return source.closeErr
}

func minimalTemplateContextError(ctx context.Context) error {
	if ctx == nil {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(sandboxruntime.ErrMinimalLaunchUnavailable, err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	if !time.Now().Before(deadline) {
		return errors.Join(sandboxruntime.ErrMinimalLaunchUnavailable, context.DeadlineExceeded)
	}
	return nil
}

func minimalTemplateFailure(ctx context.Context) error {
	if err := minimalTemplateContextError(ctx); err != nil {
		return err
	}
	return sandboxruntime.ErrMinimalLaunchUnavailable
}
