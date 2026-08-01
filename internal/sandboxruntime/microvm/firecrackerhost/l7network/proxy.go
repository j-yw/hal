package l7network

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
)

type productionProxyAdapter interface {
	networkenforcement.ProxyListenerAdapter
	LiveEndpoint() (policyproxy.LiveEndpoint, bool)
	ActiveLiveEndpoint(context.Context, policyproxy.LiveEndpoint, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error)
	StopLiveEndpoint(context.Context, policyproxy.LiveEndpoint, networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error)
}

// ProductionProxy retains policyproxy.LiveEndpoint verbatim so listener
// generation and reserved port ownership cannot be reconstructed from an
// address string or stopped through a stale replacement handle. When partial
// setup cannot prove cleanup, it retains sanitized active metadata as a
// recovery generation so coordinator rollback can retry generic containment.
type ProductionProxy struct{ adapter productionProxyAdapter }

type productionProxyGeneration struct {
	endpoint     policyproxy.LiveEndpoint
	hasEndpoint  bool
	active       networkenforcement.ProxyListenerLifecycleMetadata
	recoveryOnly bool
}

func (g *productionProxyGeneration) Address() string       { return g.endpoint.Address() }
func (g *productionProxyGeneration) Loss() <-chan struct{} { return g.endpoint.Loss() }

func NewProductionProxy(adapter *policyproxy.Adapter) (*ProductionProxy, error) {
	return newProductionProxyWithAdapter(adapter)
}

func newProductionProxyWithAdapter(adapter productionProxyAdapter) (*ProductionProxy, error) {
	if interfaceIsNil(adapter) {
		return nil, ErrInvalidConfiguration
	}
	return &ProductionProxy{adapter: adapter}, nil
}

func (p *ProductionProxy) Start(ctx context.Context, plan networkenforcement.Plan) (ProxyGeneration, error) {
	if p == nil || p.adapter == nil {
		return nil, ErrProxyUnavailable
	}
	result, err := (networkenforcement.ProxyListenerLifecycleRunner{Adapter: p.adapter}).Start(ctx, plan)
	if err != nil || result.Active == nil || result.Status != networkenforcement.LifecycleStatusActive {
		if result.Active != nil && proxyCleanupUncertain(result) {
			return p.recoveryGeneration(*result.Active), errors.Join(ErrProxyUnavailable, ErrCleanupIncomplete)
		}
		return nil, ErrProxyUnavailable
	}
	endpoint, ok := p.adapter.LiveEndpoint()
	if !ok || endpoint.Loss() == nil {
		generation := &productionProxyGeneration{endpoint: endpoint, hasEndpoint: ok,
			active: networkenforcement.SanitizeProxyListenerLifecycleMetadata(*result.Active), recoveryOnly: !ok}
		if stopErr := p.stopGeneration(ctx, plan, generation); stopErr != nil {
			return generation, errors.Join(ErrProxyUnavailable, ErrCleanupIncomplete)
		}
		return nil, ErrProxyUnavailable
	}
	return &productionProxyGeneration{endpoint: endpoint, hasEndpoint: true,
		active: networkenforcement.SanitizeProxyListenerLifecycleMetadata(*result.Active)}, nil
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

func (p *ProductionProxy) recoveryGeneration(active networkenforcement.ProxyListenerLifecycleMetadata) *productionProxyGeneration {
	endpoint, ok := p.adapter.LiveEndpoint()
	return &productionProxyGeneration{endpoint: endpoint, hasEndpoint: ok,
		active: networkenforcement.SanitizeProxyListenerLifecycleMetadata(active), recoveryOnly: !ok}
}

func (p *ProductionProxy) stopGeneration(
	ctx context.Context,
	plan networkenforcement.Plan,
	generation *productionProxyGeneration,
) error {
	if generation.hasEndpoint && !generation.recoveryOnly {
		metadata, err := p.adapter.StopLiveEndpoint(ctx, generation.endpoint, proxyRequest(plan, generation.active))
		if err != nil || metadata.Status != networkenforcement.LifecycleStatusStopped || len(metadata.WarningCodes) != 0 {
			return ErrCleanupIncomplete
		}
		return nil
	}
	result, _ := (networkenforcement.ProxyListenerLifecycleRunner{Adapter: p.adapter}).Stop(ctx, plan, &generation.active)
	if result.Active == nil || result.Status != networkenforcement.LifecycleStatusStopped || proxyCleanupUncertain(result) {
		return ErrCleanupIncomplete
	}
	return nil
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
