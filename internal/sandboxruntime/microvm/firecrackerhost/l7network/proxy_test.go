package l7network

import (
	"context"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
)

func TestProductionProxyRetainsRecoveryGenerationAfterUncertainStartCleanup(t *testing.T) {
	for _, tc := range []struct {
		name            string
		activeCheckFail bool
	}{
		{name: "active check rollback warning", activeCheckFail: true},
		{name: "missing exact endpoint rollback warning"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &uncertainCleanupProxyAdapter{activeCheckFail: tc.activeCheckFail, stopFailures: 1}
			proxy, err := newProductionProxyWithAdapter(adapter)
			if err != nil {
				t.Fatal(err)
			}
			generation, err := proxy.Start(context.Background(), testPlan())
			if !errors.Is(err, ErrProxyUnavailable) || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("Start() = %v, want unavailable plus cleanup incomplete", err)
			}
			if generation == nil {
				t.Fatal("Start() discarded recovery generation after uncertain cleanup")
			}
			if adapter.stopCalls != 1 {
				t.Fatalf("Start() stop calls = %d, want one failed containment attempt", adapter.stopCalls)
			}
			if err := proxy.Stop(context.Background(), testPlan(), generation); err != nil {
				t.Fatalf("Stop() recovery retry = %v", err)
			}
			if adapter.stopCalls != 2 {
				t.Fatalf("Stop() calls = %d, want retained recovery retry", adapter.stopCalls)
			}
		})
	}
}

type uncertainCleanupProxyAdapter struct {
	activeCheckFail bool
	stopFailures    int
	stopCalls       int
}

func (*uncertainCleanupProxyAdapter) PrepareProxyListener(
	context.Context,
	networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, nil
}

func (*uncertainCleanupProxyAdapter) StartProxyListener(
	context.Context,
	networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, nil
}

func (a *uncertainCleanupProxyAdapter) ActiveProxyListener(
	context.Context,
	networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	if a.activeCheckFail {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, errors.New("private active failure")
	}
	return networkenforcement.ProxyListenerLifecycleMetadata{}, nil
}

func (a *uncertainCleanupProxyAdapter) StopProxyListener(
	context.Context,
	networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	a.stopCalls++
	if a.stopCalls <= a.stopFailures {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, errors.New("private stop failure")
	}
	return networkenforcement.ProxyListenerLifecycleMetadata{Status: networkenforcement.LifecycleStatusStopped}, nil
}

func (*uncertainCleanupProxyAdapter) LiveEndpoint() (policyproxy.LiveEndpoint, bool) {
	return policyproxy.LiveEndpoint{}, false
}

func (*uncertainCleanupProxyAdapter) ActiveLiveEndpoint(
	context.Context,
	policyproxy.LiveEndpoint,
	networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, errors.New("unexpected exact active check")
}

func (*uncertainCleanupProxyAdapter) StopLiveEndpoint(
	context.Context,
	policyproxy.LiveEndpoint,
	networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, errors.New("unexpected exact stop")
}
