package l7network

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
)

type productionProxyEndpoint interface {
	Address() string
	Loss() <-chan struct{}
}

type productionProxyAdapter interface {
	networkenforcement.ProxyListenerAdapter
	LiveEndpoint() (productionProxyEndpoint, bool)
	ActiveLiveEndpoint(context.Context, productionProxyEndpoint, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error)
	StopLiveEndpoint(context.Context, productionProxyEndpoint, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error)
}

// ProductionProxy retains policyproxy.LiveEndpoint verbatim so listener
// generation and reserved port ownership cannot be reconstructed from an
// address string or stopped through a stale replacement handle. When partial
// setup cannot prove cleanup, it retains sanitized active metadata as a
// recovery generation so coordinator rollback can retry generic containment.
type ProductionProxy struct{ adapter productionProxyAdapter }

type productionProxyGeneration struct {
	endpoint     productionProxyEndpoint
	hasEndpoint  bool
	active       networkenforcement.ProxyListenerLifecycleMetadata
	recoveryOnly bool
}

func (g *productionProxyGeneration) Address() string {
	if g == nil || !g.hasEndpoint || interfaceIsNil(g.endpoint) {
		return ""
	}
	return g.endpoint.Address()
}

func (g *productionProxyGeneration) Loss() <-chan struct{} {
	if g == nil || !g.hasEndpoint || interfaceIsNil(g.endpoint) {
		return nil
	}
	return g.endpoint.Loss()
}

func NewProductionProxy(adapter *policyproxy.Adapter) (*ProductionProxy, error) {
	if adapter == nil {
		return nil, ErrInvalidConfiguration
	}
	return newProductionProxyWithAdapter(productionPolicyProxyAdapter{adapter: adapter})
}

func newProductionProxyWithAdapter(adapter productionProxyAdapter) (*ProductionProxy, error) {
	if interfaceIsNil(adapter) {
		return nil, ErrInvalidConfiguration
	}
	return &ProductionProxy{adapter: adapter}, nil
}

func (p *ProductionProxy) Start(ctx context.Context, plan networkenforcement.Plan) (ProxyGeneration, error) {
	if p == nil || interfaceIsNil(p.adapter) {
		return nil, ErrProxyUnavailable
	}
	capture := &productionProxyStartCapture{adapter: p.adapter}
	result, err := (networkenforcement.ProxyListenerLifecycleRunner{Adapter: capture}).Start(ctx, plan)
	if err != nil || result.Active == nil || result.Status != networkenforcement.LifecycleStatusActive {
		if result.Active != nil && proxyCleanupUncertain(result) {
			return recoveryProxyGeneration(*result.Active, capture), errors.Join(ErrProxyUnavailable, ErrCleanupIncomplete)
		}
		return nil, ErrProxyUnavailable
	}
	generation := recoveryProxyGeneration(*result.Active, capture)
	if !generation.hasEndpoint || generation.endpoint.Loss() == nil {
		if stopErr := p.stopGeneration(ctx, plan, generation); stopErr != nil {
			return generation, errors.Join(ErrProxyUnavailable, ErrCleanupIncomplete)
		}
		return nil, ErrProxyUnavailable
	}
	generation.recoveryOnly = false
	return generation, nil
}

func (p *ProductionProxy) Endpoint(generation ProxyGeneration) (string, error) {
	g, ok := generation.(*productionProxyGeneration)
	if p == nil || interfaceIsNil(p.adapter) || !ok || g == nil || !g.hasEndpoint || g.recoveryOnly || g.endpoint.Address() == "" {
		return "", ErrProxyUnavailable
	}
	return g.endpoint.Address(), nil
}

func (p *ProductionProxy) Active(ctx context.Context, plan networkenforcement.Plan, generation ProxyGeneration) error {
	g, ok := generation.(*productionProxyGeneration)
	if p == nil || interfaceIsNil(p.adapter) || !ok || g == nil || !g.hasEndpoint || g.recoveryOnly {
		return ErrProxyUnavailable
	}
	metadata, err := p.adapter.ActiveLiveEndpoint(ctx, g.endpoint, proxyRequest(plan, g.active))
	if err != nil || metadata.Status != networkenforcement.LifecycleStatusActive {
		return ErrProxyUnavailable
	}
	return nil
}

func (p *ProductionProxy) Stop(ctx context.Context, plan networkenforcement.Plan, generation ProxyGeneration) error {
	g, ok := generation.(*productionProxyGeneration)
	if p == nil || interfaceIsNil(p.adapter) || !ok || g == nil {
		return ErrCleanupIncomplete
	}
	return p.stopGeneration(ctx, plan, g)
}

func recoveryProxyGeneration(
	active networkenforcement.ProxyListenerLifecycleMetadata,
	capture *productionProxyStartCapture,
) *productionProxyGeneration {
	generation := &productionProxyGeneration{
		active: networkenforcement.SanitizeProxyListenerLifecycleMetadata(active), recoveryOnly: true,
	}
	if capture != nil && capture.captured && !interfaceIsNil(capture.endpoint) {
		generation.endpoint = capture.endpoint
		generation.hasEndpoint = true
	}
	return generation
}

func (p *ProductionProxy) stopGeneration(
	ctx context.Context,
	plan networkenforcement.Plan,
	generation *productionProxyGeneration,
) error {
	if !generation.hasEndpoint || interfaceIsNil(generation.endpoint) {
		return ErrCleanupIncomplete
	}
	metadata, err := p.adapter.StopLiveEndpoint(ctx, generation.endpoint, proxyRequest(plan, generation.active))
	if err != nil || metadata.Status != networkenforcement.LifecycleStatusStopped || len(metadata.WarningCodes) != 0 {
		return ErrCleanupIncomplete
	}
	return nil
}

type productionProxyStartCapture struct {
	adapter  productionProxyAdapter
	endpoint productionProxyEndpoint
	captured bool
}

func (c *productionProxyStartCapture) PrepareProxyListener(
	ctx context.Context,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return c.adapter.PrepareProxyListener(ctx, request)
}

func (c *productionProxyStartCapture) StartProxyListener(
	ctx context.Context,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	metadata, err := c.adapter.StartProxyListener(ctx, request)
	if err != nil {
		return metadata, err
	}
	endpoint, ok := c.adapter.LiveEndpoint()
	if !ok || interfaceIsNil(endpoint) {
		return metadata, ErrProxyUnavailable
	}
	c.endpoint, c.captured = endpoint, true
	return metadata, nil
}

func (c *productionProxyStartCapture) ActiveProxyListener(
	ctx context.Context,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	if !c.captured || interfaceIsNil(c.endpoint) {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, ErrProxyUnavailable
	}
	return c.adapter.ActiveLiveEndpoint(ctx, c.endpoint, request)
}

func (c *productionProxyStartCapture) StopProxyListener(
	ctx context.Context,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	if !c.captured || interfaceIsNil(c.endpoint) {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, ErrCleanupIncomplete
	}
	return c.adapter.StopLiveEndpoint(ctx, c.endpoint, request)
}

type productionPolicyProxyAdapter struct{ adapter *policyproxy.Adapter }

func (a productionPolicyProxyAdapter) PrepareProxyListener(
	ctx context.Context,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return a.adapter.PrepareProxyListener(ctx, request)
}

func (a productionPolicyProxyAdapter) StartProxyListener(
	ctx context.Context,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return a.adapter.StartProxyListener(ctx, request)
}

func (a productionPolicyProxyAdapter) ActiveProxyListener(
	ctx context.Context,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return a.adapter.ActiveProxyListener(ctx, request)
}

func (a productionPolicyProxyAdapter) StopProxyListener(
	ctx context.Context,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return a.adapter.StopProxyListener(ctx, request)
}

func (a productionPolicyProxyAdapter) LiveEndpoint() (productionProxyEndpoint, bool) {
	endpoint, ok := a.adapter.LiveEndpoint()
	return endpoint, ok
}

func (a productionPolicyProxyAdapter) ActiveLiveEndpoint(
	ctx context.Context,
	endpoint productionProxyEndpoint,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	exact, ok := endpoint.(policyproxy.LiveEndpoint)
	if !ok {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, ErrProxyUnavailable
	}
	return a.adapter.ActiveLiveEndpoint(ctx, exact, request)
}

func (a productionPolicyProxyAdapter) StopLiveEndpoint(
	ctx context.Context,
	endpoint productionProxyEndpoint,
	request networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	exact, ok := endpoint.(policyproxy.LiveEndpoint)
	if !ok {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, ErrCleanupIncomplete
	}
	return a.adapter.StopLiveEndpoint(ctx, exact, request)
}

func proxyCleanupUncertain(result networkenforcement.ProxyListenerLifecycleResult) bool {
	for _, warning := range result.WarningCodes {
		if warning == networkenforcement.LifecycleWarningCleanupFailed {
			return true
		}
	}
	if result.Active != nil {
		for _, warning := range result.Active.WarningCodes {
			if warning == networkenforcement.LifecycleWarningCleanupFailed {
				return true
			}
		}
	}
	return false
}

func proxyRequest(plan networkenforcement.Plan, active networkenforcement.ProxyListenerLifecycleMetadata) networkenforcement.ProxyListenerLifecycleRequest {
	active = networkenforcement.SanitizeProxyListenerLifecycleMetadata(active)
	return networkenforcement.ProxyListenerLifecycleRequest{Plan: networkenforcement.NewSanitizedPlan(plan), Requested: active, Active: active}
}
