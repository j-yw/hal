package l7network

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
)

// ProductionProxy retains policyproxy.LiveEndpoint verbatim so listener
// generation and reserved port ownership cannot be reconstructed from an
// address string or stopped through a stale replacement handle.
type ProductionProxy struct{ adapter *policyproxy.Adapter }

type productionProxyGeneration struct {
	endpoint policyproxy.LiveEndpoint
	active   networkenforcement.ProxyListenerLifecycleMetadata
}

func (g *productionProxyGeneration) Address() string       { return g.endpoint.Address() }
func (g *productionProxyGeneration) Loss() <-chan struct{} { return g.endpoint.Loss() }

func NewProductionProxy(adapter *policyproxy.Adapter) (*ProductionProxy, error) {
	if adapter == nil {
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
		return nil, ErrProxyUnavailable
	}
	endpoint, ok := p.adapter.LiveEndpoint()
	if !ok || endpoint.Loss() == nil {
		stopped, _ := (networkenforcement.ProxyListenerLifecycleRunner{Adapter: p.adapter}).Stop(ctx, plan, result.Active)
		if stopped.Active != nil && len(stopped.Active.WarningCodes) > 0 {
			return nil, errors.Join(ErrProxyUnavailable, ErrCleanupIncomplete)
		}
		return nil, ErrProxyUnavailable
	}
	return &productionProxyGeneration{endpoint: endpoint, active: *result.Active}, nil
}

func (p *ProductionProxy) Endpoint(generation ProxyGeneration) (string, error) {
	g, ok := generation.(*productionProxyGeneration)
	if p == nil || p.adapter == nil || !ok || g == nil || g.endpoint.Address() == "" {
		return "", ErrProxyUnavailable
	}
	return g.endpoint.Address(), nil
}

func (p *ProductionProxy) Active(ctx context.Context, plan networkenforcement.Plan, generation ProxyGeneration) error {
	g, ok := generation.(*productionProxyGeneration)
	if p == nil || p.adapter == nil || !ok || g == nil {
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
	if p == nil || p.adapter == nil || !ok || g == nil {
		return ErrCleanupIncomplete
	}
	metadata, err := p.adapter.StopLiveEndpoint(ctx, g.endpoint, proxyRequest(plan, g.active))
	if err != nil || metadata.Status != networkenforcement.LifecycleStatusStopped {
		return ErrCleanupIncomplete
	}
	return nil
}

func proxyRequest(plan networkenforcement.Plan, active networkenforcement.ProxyListenerLifecycleMetadata) networkenforcement.ProxyListenerLifecycleRequest {
	active = networkenforcement.SanitizeProxyListenerLifecycleMetadata(active)
	return networkenforcement.ProxyListenerLifecycleRequest{Plan: networkenforcement.NewSanitizedPlan(plan), Requested: active, Active: active}
}
