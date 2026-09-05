package l7network

import (
	"context"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestProductionProxyRetainsRecoveryGenerationAfterUncertainStartCleanup(t *testing.T) {
	for _, tc := range []struct {
		name            string
		activeCheckFail bool
		lossUnavailable bool
	}{
		{name: "active check rollback warning", activeCheckFail: true},
		{name: "missing loss signal rollback warning", lossUnavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &uncertainCleanupProxyAdapter{
				activeCheckFail: tc.activeCheckFail, lossUnavailable: tc.lossUnavailable, stopFailures: 1,
			}
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

func TestFirecrackerHostTopologyRetriesRetainedProductionProxyRecoveryGeneration(t *testing.T) {
	sequence := &callSequence{}
	adapter := &uncertainCleanupProxyAdapter{activeCheckFail: true, stopFailures: 1}
	proxy, err := newProductionProxyWithAdapter(adapter)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: defaultCleanupTimeout,
	})
	if _, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()}); !errors.Is(err, ErrProxyUnavailable) || errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Prepare() = %v, want unavailable after resolved rollback", err)
	}
	if adapter.stopCalls != 2 {
		t.Fatalf("Prepare() stop calls = %d, want initial failure plus coordinator rollback retry", adapter.stopCalls)
	}
}

func TestProductionProxyStaleRecoveryCannotStopReplacementGeneration(t *testing.T) {
	adapter := &uncertainCleanupProxyAdapter{activeCheckFail: true, stopFailures: 1}
	proxy, err := newProductionProxyWithAdapter(adapter)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := proxy.Start(context.Background(), testPlan())
	if !errors.Is(err, ErrCleanupIncomplete) || generation == nil {
		t.Fatalf("Start() = generation %T, error %v; want retained uncertain recovery", generation, err)
	}
	adapter.startReplacement()
	if err := proxy.Stop(context.Background(), testPlan(), generation); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("stale recovery Stop() = %v, want cleanup incomplete", err)
	}
	if adapter.replacementStopped {
		t.Fatal("stale recovery stopped replacement listener generation")
	}
	if adapter.genericStopCalls != 0 {
		t.Fatalf("stale recovery used %d plan-only generic stop calls", adapter.genericStopCalls)
	}
}

type uncertainCleanupProxyAdapter struct {
	activeCheckFail    bool
	lossUnavailable    bool
	stopFailures       int
	stopCalls          int
	genericStopCalls   int
	currentGeneration  int
	replacementLive    bool
	replacementStopped bool
}

func (a *uncertainCleanupProxyAdapter) startReplacement() {
	a.currentGeneration++
	a.replacementLive = true
}

func (*uncertainCleanupProxyAdapter) PrepareProxyListener(
	context.Context,
	networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	return networkenforcement.ProxyListenerLifecycleMetadata{}, nil
}

func (a *uncertainCleanupProxyAdapter) StartProxyListener(
	context.Context,
	networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	if a.currentGeneration == 0 {
		a.currentGeneration = 1
	}
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
	a.genericStopCalls++
	if a.replacementLive {
		a.replacementStopped = true
	}
	return networkenforcement.ProxyListenerLifecycleMetadata{Status: networkenforcement.LifecycleStatusStopped}, nil
}

type fakeProductionProxyEndpoint struct {
	generation int
	loss       <-chan struct{}
}

func (*fakeProductionProxyEndpoint) Address() string { return "127.0.0.1:43123" }
func (e *fakeProductionProxyEndpoint) Loss() <-chan struct{} {
	return e.loss
}

func (a *uncertainCleanupProxyAdapter) LiveEndpoint() (productionProxyEndpoint, bool) {
	if a.currentGeneration == 0 {
		return nil, false
	}
	var loss <-chan struct{}
	if !a.lossUnavailable {
		loss = make(chan struct{})
	}
	return &fakeProductionProxyEndpoint{generation: a.currentGeneration, loss: loss}, true
}

func (a *uncertainCleanupProxyAdapter) ActiveLiveEndpoint(
	_ context.Context,
	endpoint productionProxyEndpoint,
	_ networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	exact, ok := endpoint.(*fakeProductionProxyEndpoint)
	if !ok || exact.generation != a.currentGeneration {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, errors.New("stale generation")
	}
	if a.activeCheckFail {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, errors.New("private active failure")
	}
	return networkenforcement.ProxyListenerLifecycleMetadata{Status: networkenforcement.LifecycleStatusActive}, nil
}

func (a *uncertainCleanupProxyAdapter) StopLiveEndpoint(
	_ context.Context,
	endpoint productionProxyEndpoint,
	_ networkenforcement.ProxyListenerLifecycleRequest,
) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	a.stopCalls++
	if a.stopCalls <= a.stopFailures {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, errors.New("private stop failure")
	}
	exact, ok := endpoint.(*fakeProductionProxyEndpoint)
	if !ok || exact.generation != a.currentGeneration {
		return networkenforcement.ProxyListenerLifecycleMetadata{}, errors.New("stale generation")
	}
	if a.replacementLive {
		a.replacementStopped = true
	}
	a.currentGeneration = 0
	return networkenforcement.ProxyListenerLifecycleMetadata{Status: networkenforcement.LifecycleStatusStopped}, nil
}
