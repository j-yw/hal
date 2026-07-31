package l7network_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman/l7network"
)

func TestL7ComposedRootlessPodmanActivationCorrelatesProxyNamespaceRawPacketAndRules(t *testing.T) {
	sequence := &sequenceLog{}
	proxy := newFakeProxy(sequence)
	namespace := &fakeNamespaceResolver{sequence: sequence, result: validNamespaceResolution()}
	rules := &fakeRules{sequence: sequence}
	factory, err := l7network.NewFactory(l7network.FactoryOptions{
		Identity:                 testIdentity(),
		Plan:                     testPlan(),
		Proxy:                    proxy,
		NamespaceResolver:        namespace,
		Rules:                    rules,
		RawPacketVerifierFactory: fakeRawPacketVerifierFactory,
		GuestProxyAddress:        "169.254.77.2",
		TableName:                "hal_l7_a",
		CleanupTimeout:           time.Second,
	})
	if err != nil {
		t.Fatalf("NewFactory() unexpected error: %v", err)
	}
	preparation, err := factory.PrepareNetworkTopology(context.Background(), rootlesspodman.NetworkTopologyPrepareRequest{SandboxName: "hal-l7"})
	if err != nil {
		t.Fatalf("PrepareNetworkTopology() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(preparation.CreateArgs, []string{"--network", "pasta:--no-map-gw,--map-host-loopback=169.254.77.2,-t,none,-u,none,-T,none,-U,none"}) {
		t.Fatalf("CreateArgs = %#v", preparation.CreateArgs)
	}
	target := testTarget()
	proof, err := preparation.Session.Activate(context.Background(), rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: target})
	if err != nil {
		t.Fatalf("Activate() unexpected error: %v", err)
	}
	if proof.Identity != testIdentity() || proof.RuntimeID != target.ID || !proof.ProxyActive || !proof.RulesInspected || proof.RuleDigest == "" {
		t.Fatalf("Activate() proof = %#v, want exact active correlated proof", proof)
	}
	if got, want := sequence.snapshot(), []string{"proxy_start", "proxy_endpoint", "proxy_active", "namespace_resolve", "proxy_active", "rules_apply_inspect", "proxy_active"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("activation sequence = %#v, want %#v", got, want)
	}
	if rules.lastCorrelation != testCorrelation() {
		t.Fatalf("rules correlation = %#v, want %#v", rules.lastCorrelation, testCorrelation())
	}
	if rules.lastRawPacketVerifier != (fakeRawPacketVerifier{}) {
		t.Fatalf("raw packet verifier not bound into exact expected rule set")
	}
}

func TestL7ComposedRootlessPodmanRechecksProxyAndQuarantinesBeforeCleanup(t *testing.T) {
	sequence := &sequenceLog{}
	proxy := newFakeProxy(sequence)
	rules := &fakeRules{sequence: sequence}
	factory := mustFactory(t, l7network.FactoryOptions{
		Identity: testIdentity(), Plan: testPlan(), Proxy: proxy,
		NamespaceResolver: &fakeNamespaceResolver{sequence: sequence, result: validNamespaceResolution()},
		Rules:             rules, RawPacketVerifierFactory: fakeRawPacketVerifierFactory, GuestProxyAddress: "169.254.77.2", TableName: "hal_l7_a",
	})
	prepared, err := factory.PrepareNetworkTopology(context.Background(), rootlesspodman.NetworkTopologyPrepareRequest{SandboxName: "hal-l7"})
	if err != nil {
		t.Fatal(err)
	}
	req := rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: testTarget()}
	if _, err := prepared.Session.Activate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	sequence.reset()
	proxy.activeErr = errors.New("endpoint=/run/user/private.sock token=secret")
	if _, err := prepared.Session.Inspect(context.Background(), req); !errors.Is(err, l7network.ErrProxyUnavailable) {
		t.Fatalf("Inspect() error = %v, want ErrProxyUnavailable", err)
	} else if strings.Contains(err.Error(), "private.sock") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("Inspect() leaked private error: %v", err)
	}
	proxy.activeErr = nil
	if err := prepared.Session.Revoke(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Session.Cleanup(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got, want := sequence.snapshot(), []string{"proxy_active", "rules_quarantine", "rules_cleanup", "namespace_close", "proxy_stop"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("loss cleanup sequence = %#v, want %#v", got, want)
	}
}

func TestL7ComposedRootlessPodmanRejectsMismatchBeforeMutationAndCleansPartialStart(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*l7network.FactoryOptions)
	}{
		{name: "unsafe identity", mutate: func(o *l7network.FactoryOptions) { o.Identity.RuleGenerationID = "/private/rule" }},
		{name: "plan id mismatch", mutate: func(o *l7network.FactoryOptions) { o.Plan.ID = "other-plan" }},
		{name: "proxy session mismatch", mutate: func(o *l7network.FactoryOptions) { o.Plan.Proxy.ProxySessionID = "other-proxy" }},
		{name: "loopback guest mapping", mutate: func(o *l7network.FactoryOptions) { o.GuestProxyAddress = "127.0.0.1" }},
		{name: "missing namespace resolver", mutate: func(o *l7network.FactoryOptions) { o.NamespaceResolver = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sequence := &sequenceLog{}
			proxy := newFakeProxy(sequence)
			options := l7network.FactoryOptions{Identity: testIdentity(), Plan: testPlan(), Proxy: proxy,
				NamespaceResolver: &fakeNamespaceResolver{result: validNamespaceResolution()}, Rules: &fakeRules{},
				RawPacketVerifierFactory: fakeRawPacketVerifierFactory, GuestProxyAddress: "169.254.77.2", TableName: "hal_l7_a"}
			tt.mutate(&options)
			if _, err := l7network.NewFactory(options); !errors.Is(err, l7network.ErrInvalidConfiguration) {
				t.Fatalf("NewFactory() error = %v, want ErrInvalidConfiguration", err)
			}
			if got := sequence.snapshot(); len(got) != 0 {
				t.Fatalf("mutation before validation: %#v", got)
			}
		})
	}

	t.Run("partial proxy start", func(t *testing.T) {
		sequence := &sequenceLog{}
		proxy := newFakeProxy(sequence)
		proxy.endpointErr = errors.New("private endpoint failure")
		factory := mustFactory(t, l7network.FactoryOptions{Identity: testIdentity(), Plan: testPlan(), Proxy: proxy,
			NamespaceResolver: &fakeNamespaceResolver{result: validNamespaceResolution()}, Rules: &fakeRules{},
			RawPacketVerifierFactory: fakeRawPacketVerifierFactory, GuestProxyAddress: "169.254.77.2", TableName: "hal_l7_a"})
		if _, err := factory.PrepareNetworkTopology(context.Background(), rootlesspodman.NetworkTopologyPrepareRequest{SandboxName: "hal-l7"}); !errors.Is(err, l7network.ErrProxyUnavailable) {
			t.Fatalf("PrepareNetworkTopology() error = %v, want ErrProxyUnavailable", err)
		}
		if got, want := sequence.snapshot(), []string{"proxy_start", "proxy_endpoint", "proxy_stop"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("partial start sequence = %#v, want %#v", got, want)
		}
	})
}

func TestL7ComposedRootlessPodmanDefaultAndNonLinuxRemainFailClosed(t *testing.T) {
	driver := rootlesspodman.New(rootlesspodman.Options{})
	if driver == nil || driver.ID() != rootlesspodman.DriverID {
		t.Fatal("default constructor changed")
	}
	if _, err := l7network.NewProductionNamespaceResolver(l7network.ProductionNamespaceResolverOptions{}); err == nil {
		t.Fatal("empty production namespace resolver must fail closed")
	}
}

func TestL7ComposedRootlessPodmanPartialOwnershipAndCleanupRetry(t *testing.T) {
	t.Run("partial proxy generation is stopped and cleanup uncertainty survives", func(t *testing.T) {
		sequence := &sequenceLog{}
		proxy := newFakeProxy(sequence)
		proxy.startErr = errors.New("private start failure")
		proxy.stopErr = errors.New("private stop failure")
		factory := mustFactory(t, baseFactoryOptions(proxy, &fakeNamespaceResolver{result: validNamespaceResolution()}, &fakeRules{}))
		_, err := factory.PrepareNetworkTopology(context.Background(), rootlesspodman.NetworkTopologyPrepareRequest{SandboxName: "hal-l7"})
		if !errors.Is(err, l7network.ErrProxyUnavailable) || !errors.Is(err, l7network.ErrCleanupIncomplete) {
			t.Fatalf("PrepareNetworkTopology() error = %v, want proxy plus cleanup sentinels", err)
		}
		if got, want := sequence.snapshot(), []string{"proxy_start", "proxy_stop"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("partial proxy sequence = %#v, want %#v", got, want)
		}
	})

	t.Run("partial namespace is closed", func(t *testing.T) {
		sequence := &sequenceLog{}
		proxy := newFakeProxy(sequence)
		closer := &retryCloser{sequence: sequence}
		resolution := validNamespaceResolution()
		resolution.Close = closer
		resolver := &fakeNamespaceResolver{sequence: sequence, result: resolution, err: errors.New("private namespace drift")}
		factory := mustFactory(t, baseFactoryOptions(proxy, resolver, &fakeRules{sequence: sequence}))
		prepared, err := factory.PrepareNetworkTopology(context.Background(), rootlesspodman.NetworkTopologyPrepareRequest{SandboxName: "hal-l7"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prepared.Session.Activate(context.Background(), rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: testTarget()}); !errors.Is(err, l7network.ErrNamespaceUnverified) {
			t.Fatalf("Activate() error = %v, want ErrNamespaceUnverified", err)
		}
		if closer.calls != 1 {
			t.Fatalf("partial namespace close calls = %d, want 1", closer.calls)
		}
	})

	t.Run("failed closer is retained for cleanup retry", func(t *testing.T) {
		proxy := newFakeProxy(&sequenceLog{})
		closer := &retryCloser{failures: 1}
		resolution := validNamespaceResolution()
		resolution.Close = closer
		factory := mustFactory(t, baseFactoryOptions(proxy, &fakeNamespaceResolver{result: resolution}, &fakeRules{}))
		prepared, err := factory.PrepareNetworkTopology(context.Background(), rootlesspodman.NetworkTopologyPrepareRequest{SandboxName: "hal-l7"})
		if err != nil {
			t.Fatal(err)
		}
		req := rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: testTarget()}
		if _, err := prepared.Session.Activate(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if err := prepared.Session.Revoke(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if err := prepared.Session.Cleanup(context.Background(), req); !errors.Is(err, l7network.ErrCleanupIncomplete) {
			t.Fatalf("first Cleanup() = %v", err)
		}
		if err := prepared.Session.Cleanup(context.Background(), req); err != nil {
			t.Fatalf("retry Cleanup() = %v", err)
		}
		if closer.calls != 2 {
			t.Fatalf("closer calls = %d, want 2", closer.calls)
		}
	})
}

func TestL7ComposedRootlessPodmanCollisionAndLossBeforeEnvironmentFailClosed(t *testing.T) {
	proxy := newFakeProxy(&sequenceLog{})
	factory := mustFactory(t, baseFactoryOptions(proxy, &fakeNamespaceResolver{result: validNamespaceResolution()}, &fakeRules{})).(*l7network.Factory)
	prepared, err := factory.PrepareNetworkTopology(context.Background(), rootlesspodman.NetworkTopologyPrepareRequest{SandboxName: "hal-l7"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.PrepareNetworkTopology(context.Background(), rootlesspodman.NetworkTopologyPrepareRequest{SandboxName: "hal-l7"}); !errors.Is(err, l7network.ErrTopologyCollision) {
		t.Fatalf("second PrepareNetworkTopology() = %v, want collision", err)
	}
	req := rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: testTarget()}
	if _, err := prepared.Session.Activate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	close(proxy.endpoint.loss)
	if environment := prepared.Session.ProxyEnvironment(req); environment != nil {
		t.Fatalf("ProxyEnvironment() after generation loss = %#v, want nil", environment)
	}
}

func TestL7RootlessPodmanRestartReconcilerQuarantinesBeforeExactCleanupWithoutActiveProof(t *testing.T) {
	sequence := &sequenceLog{}
	rules := &fakeRules{sequence: sequence}
	runtime := &fakeRuntimeReconciler{sequence: sequence}
	reconciler, err := l7network.NewReconciler(l7network.ReconcilerOptions{Identity: testIdentity(),
		NamespaceResolver: &fakeNamespaceResolver{sequence: sequence, result: validNamespaceResolution()}, Rules: rules,
		RawPacketVerifierFactory: fakeRawPacketVerifierFactory, Runtime: runtime, GuestProxyAddress: "169.254.77.2", ProxyPort: 31077,
		TableName: "hal_l7_a", CleanupTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewReconciler() error: %v", err)
	}
	req := rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: testTarget()}
	if err := reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}
	if got, want := sequence.snapshot(), []string{"namespace_resolve", "rules_quarantine", "runtime_stop", "rules_cleanup", "namespace_close", "runtime_delete"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("restart sequence = %#v, want %#v", got, want)
	}
	mismatch := req
	mismatch.Identity.TopologyGenerationID = "other-generation"
	if err := reconciler.Reconcile(context.Background(), mismatch); !errors.Is(err, l7network.ErrIdentityMismatch) {
		t.Fatalf("mismatched Reconcile() = %v", err)
	}
}

func TestL7RootlessPodmanRestartReconcilerRetainsEnforcementUntilQuarantineAndStopSucceed(t *testing.T) {
	for _, tt := range []struct {
		name           string
		failQuarantine bool
		failStop       bool
		first          []string
		second         []string
	}{
		{name: "quarantine failure", failQuarantine: true, first: []string{"namespace_resolve", "rules_quarantine"}, second: []string{"rules_quarantine", "runtime_stop", "rules_cleanup", "namespace_close", "runtime_delete"}},
		{name: "stop failure", failStop: true, first: []string{"namespace_resolve", "rules_quarantine", "runtime_stop"}, second: []string{"runtime_stop", "rules_cleanup", "namespace_close", "runtime_delete"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sequence := &sequenceLog{}
			rules := &fakeRules{sequence: sequence}
			runtime := &fakeRuntimeReconciler{sequence: sequence}
			if tt.failQuarantine {
				rules.quarantineFailures = 1
			}
			if tt.failStop {
				runtime.stopFailures = 1
			}
			reconciler, err := l7network.NewReconciler(l7network.ReconcilerOptions{Identity: testIdentity(), NamespaceResolver: &fakeNamespaceResolver{sequence: sequence, result: validNamespaceResolution()}, Rules: rules, RawPacketVerifierFactory: fakeRawPacketVerifierFactory, Runtime: runtime, GuestProxyAddress: "169.254.77.2", ProxyPort: 31077, TableName: "hal_l7_a"})
			if err != nil {
				t.Fatal(err)
			}
			req := rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: testTarget()}
			if err := reconciler.Reconcile(context.Background(), req); !errors.Is(err, l7network.ErrCleanupIncomplete) {
				t.Fatalf("first Reconcile()=%v", err)
			}
			if got := sequence.snapshot(); !reflect.DeepEqual(got, tt.first) {
				t.Fatalf("first sequence=%#v want %#v", got, tt.first)
			}
			sequence.reset()
			if err := reconciler.Reconcile(context.Background(), req); err != nil {
				t.Fatalf("retry Reconcile()=%v", err)
			}
			if got := sequence.snapshot(); !reflect.DeepEqual(got, tt.second) {
				t.Fatalf("retry sequence=%#v want %#v", got, tt.second)
			}
		})
	}
}

func TestL7RootlessPodmanRestartReconcilerRejectsTargetSwapAcrossRetry(t *testing.T) {
	sequence := &sequenceLog{}
	rules := &fakeRules{sequence: sequence, quarantineFailures: 1}
	runtime := &fakeRuntimeReconciler{sequence: sequence}
	reconciler, err := l7network.NewReconciler(l7network.ReconcilerOptions{Identity: testIdentity(), NamespaceResolver: &fakeNamespaceResolver{sequence: sequence, result: validNamespaceResolution()}, Rules: rules, RawPacketVerifierFactory: fakeRawPacketVerifierFactory, Runtime: runtime, GuestProxyAddress: "169.254.77.2", ProxyPort: 31077, TableName: "hal_l7_a"})
	if err != nil {
		t.Fatal(err)
	}
	req := rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: testTarget()}
	if err := reconciler.Reconcile(context.Background(), req); !errors.Is(err, l7network.ErrCleanupIncomplete) {
		t.Fatalf("first Reconcile()=%v", err)
	}
	sequence.reset()
	swapped := req
	swapped.Target.ID = "container-generation-b"
	swapped.Target.Name = "hal-l7-b"
	swapped.Target.Runtime.RuntimeID = "container-generation-b"
	if err := reconciler.Reconcile(context.Background(), swapped); !errors.Is(err, l7network.ErrIdentityMismatch) {
		t.Fatalf("swapped retry=%v", err)
	}
	if got := sequence.snapshot(); len(got) != 0 {
		t.Fatalf("swapped retry mutated retained generation: %#v", got)
	}
	if err := reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("original retry=%v", err)
	}
}

func TestL7RootlessPodmanRestartReconcilerRetainsCloseFailureAfterExpectedRuleValidation(t *testing.T) {
	closer := &retryCloser{failures: 1}
	resolution := validNamespaceResolution()
	resolution.InterfaceName = "invalid/interface"
	resolution.Close = closer
	reconciler, err := l7network.NewReconciler(l7network.ReconcilerOptions{Identity: testIdentity(), NamespaceResolver: &fakeNamespaceResolver{result: resolution}, Rules: &fakeRules{}, RawPacketVerifierFactory: fakeRawPacketVerifierFactory, Runtime: &fakeRuntimeReconciler{}, GuestProxyAddress: "169.254.77.2", ProxyPort: 31077, TableName: "hal_l7_a"})
	if err != nil {
		t.Fatal(err)
	}
	req := rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: testTarget()}
	if err := reconciler.Reconcile(context.Background(), req); !errors.Is(err, l7network.ErrNamespaceUnverified) || !errors.Is(err, l7network.ErrCleanupIncomplete) {
		t.Fatalf("first Reconcile()=%v", err)
	}
	if closer.calls != 1 {
		t.Fatalf("first close calls=%d", closer.calls)
	}
	if err := reconciler.Reconcile(context.Background(), req); !errors.Is(err, l7network.ErrNamespaceUnverified) || errors.Is(err, l7network.ErrCleanupIncomplete) {
		t.Fatalf("retry Reconcile()=%v", err)
	}
	if closer.calls != 2 {
		t.Fatalf("retry close calls=%d", closer.calls)
	}
}

type fakeEndpoint struct {
	address string
	loss    chan struct{}
}

func (e *fakeEndpoint) Address() string       { return e.address }
func (e *fakeEndpoint) Loss() <-chan struct{} { return e.loss }

type fakeProxy struct {
	sequence    *sequenceLog
	endpoint    *fakeEndpoint
	activeErr   error
	endpointErr error
	startErr    error
	stopErr     error
}

func newFakeProxy(sequence *sequenceLog) *fakeProxy {
	return &fakeProxy{sequence: sequence, endpoint: &fakeEndpoint{address: "127.0.0.1:31077", loss: make(chan struct{})}}
}
func (p *fakeProxy) Start(context.Context, networkenforcement.Plan) (l7network.ProxyGeneration, error) {
	p.sequence.add("proxy_start")
	return p.endpoint, p.startErr
}
func (p *fakeProxy) Endpoint(l7network.ProxyGeneration) (string, error) {
	p.sequence.add("proxy_endpoint")
	if p.endpointErr != nil {
		return "", p.endpointErr
	}
	return p.endpoint.address, nil
}
func (p *fakeProxy) Active(context.Context, networkenforcement.Plan, l7network.ProxyGeneration) error {
	p.sequence.add("proxy_active")
	return p.activeErr
}
func (p *fakeProxy) Stop(context.Context, networkenforcement.Plan, l7network.ProxyGeneration) error {
	p.sequence.add("proxy_stop")
	return p.stopErr
}

type fakeNamespaceResolver struct {
	sequence *sequenceLog
	result   l7network.NamespaceResolution
	err      error
}

func (r *fakeNamespaceResolver) Resolve(context.Context, rootlesspodman.NetworkTopologyTargetRequest) (l7network.NamespaceResolution, error) {
	if r.sequence != nil {
		r.sequence.add("namespace_resolve")
	}
	if _, ok := r.result.Close.(fakeCloser); ok {
		r.result.Close = fakeCloser{sequence: r.sequence}
	}
	return r.result, r.err
}

type fakeCloser struct{ sequence *sequenceLog }

func (c fakeCloser) Close() error {
	if c.sequence != nil {
		c.sequence.add("namespace_close")
	}
	return nil
}

type retryCloser struct {
	sequence *sequenceLog
	failures int
	calls    int
}

type fakeRuntimeReconciler struct {
	sequence                *sequenceLog
	stopFailures, stopCalls int
}

func (r *fakeRuntimeReconciler) Stop(context.Context, rootlesspodman.NetworkTopologyTargetRequest) error {
	r.sequence.add("runtime_stop")
	if r.stopCalls < r.stopFailures {
		r.stopCalls++
		return errors.New("private stop failure")
	}
	r.stopCalls++
	return nil
}
func (r *fakeRuntimeReconciler) Delete(context.Context, rootlesspodman.NetworkTopologyTargetRequest) error {
	r.sequence.add("runtime_delete")
	return nil
}

func (c *retryCloser) Close() error {
	c.calls++
	if c.sequence != nil {
		c.sequence.add("namespace_close")
	}
	if c.calls <= c.failures {
		return errors.New("private close failure")
	}
	return nil
}

type fakeRules struct {
	sequence              *sequenceLog
	lastCorrelation       networkenforcement.EnforcementCorrelation
	lastRawPacketVerifier fakeRawPacketVerifier
	quarantineFailures    int
	quarantineCalls       int
}

func (r *fakeRules) ApplyAndInspect(_ context.Context, expected linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) {
	r.sequence.add("rules_apply_inspect")
	return r.metadata(expected), nil
}
func (r *fakeRules) Inspect(_ context.Context, expected linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) {
	r.sequence.add("rules_inspect")
	return r.metadata(expected), nil
}
func (r *fakeRules) Quarantine(context.Context, linuxrules.ExpectedRuleSet) error {
	r.sequence.add("rules_quarantine")
	if r.quarantineCalls < r.quarantineFailures {
		r.quarantineCalls++
		return errors.New("private quarantine failure")
	}
	r.quarantineCalls++
	return nil
}
func (r *fakeRules) Cleanup(context.Context, linuxrules.ExpectedRuleSet) error {
	r.sequence.add("rules_cleanup")
	return nil
}
func (r *fakeRules) metadata(expected linuxrules.ExpectedRuleSet) networkenforcement.RuleLifecycleMetadata {
	var encoded struct {
		Correlation networkenforcement.EnforcementCorrelation `json:"correlation"`
		RuleDigest  string                                    `json:"ruleDigest"`
	}
	payload, _ := expected.MarshalJSON()
	_ = json.Unmarshal(payload, &encoded)
	r.lastCorrelation = encoded.Correlation
	r.lastRawPacketVerifier = fakeRawPacketVerifier{}
	correlation := encoded.Correlation
	return networkenforcement.RuleLifecycleMetadata{ID: correlation.RuleGenerationID, PlanID: correlation.PlanID,
		Status: networkenforcement.LifecycleStatusActive, Correlation: &correlation,
		Inspection: &networkenforcement.InspectedRuleProof{ID: "proof-a", RuleDigest: encoded.RuleDigest, Status: networkenforcement.RuleInspectionStatusInspected,
			InspectedAtUnixMilli: 1000, Correlation: &correlation, Mechanisms: []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismFirewall},
			CapabilityLabels: []string{"default_deny"}, ReasonCode: networkenforcement.LifecycleReasonRuleInspected},
		LinkLayerIsolation: &networkenforcement.RawPacketIsolationProof{ID: "raw-proof-a", Status: networkenforcement.RawPacketIsolationStatusVerified,
			VerifiedAtUnixMilli: 1000, Correlation: &correlation, ReasonCode: networkenforcement.LifecycleReasonRawPacketIsolationVerified},
		ReasonCode: networkenforcement.LifecycleReasonActive}
}

type fakeRawPacketVerifier struct{}

func (fakeRawPacketVerifier) VerifyRawPacketIsolation(context.Context, networkenforcement.EnforcementCorrelation) (networkenforcement.RawPacketIsolationProof, error) {
	panic("called only by real rules adapter")
}

func fakeRawPacketVerifierFactory(rootlesspodman.NetworkTopologyTargetRequest) (linuxrules.RawPacketIsolationVerifier, error) {
	return fakeRawPacketVerifier{}, nil
}

type sequenceLog struct {
	mu     sync.Mutex
	values []string
}

func (s *sequenceLog) add(value string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values = append(s.values, value)
}
func (s *sequenceLog) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.values...)
}
func (s *sequenceLog) reset() { s.mu.Lock(); defer s.mu.Unlock(); s.values = nil }

func validNamespaceResolution() l7network.NamespaceResolution {
	return l7network.NamespaceResolution{Namespace: linuxrules.NewNamespaceHandle(10, 11), InterfaceName: "eth0", WorkloadIPv6Address: "fd00:7::2", GatewayIPv6Address: "fd00:7::1", IPv6PrefixBits: 64, Close: fakeCloser{}}
}
func testIdentity() rootlesspodman.NetworkTopologyIdentity {
	return rootlesspodman.NetworkTopologyIdentity{SandboxID: "sandbox-a", ExecutionID: "execution-a", WorkerID: "worker-a", RuntimeDriver: rootlesspodman.DriverID, RuntimeGenerationID: "runtime-generation-a", PlanID: "plan-a", PolicySnapshotID: "policy-a", ProxySessionID: "proxy-session-a", ProxyGenerationID: "proxy-generation-a", TopologyGenerationID: "topology-generation-a", RuleGenerationID: "rule-generation-a"}
}
func testCorrelation() networkenforcement.EnforcementCorrelation {
	i := testIdentity()
	return networkenforcement.EnforcementCorrelation{SandboxID: i.SandboxID, ExecutionID: i.ExecutionID, WorkerID: i.WorkerID, RuntimeID: i.RuntimeGenerationID, PlanID: i.PlanID, PolicySnapshotID: i.PolicySnapshotID, ProxySessionID: i.ProxySessionID, ProxyGenerationID: i.ProxyGenerationID, TopologyGenerationID: i.TopologyGenerationID, RuleGenerationID: i.RuleGenerationID}
}
func testPlan() networkenforcement.Plan {
	return networkenforcement.Plan{ID: "plan-a", Source: networkenforcement.PlanSourceRuntime, Operation: "l7_topology", PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{ID: "policy-a", Preset: networkenforcement.PolicyPresetDenyByDefault}, DefaultPosture: networkenforcement.DefaultPostureDenyByDefault, Proxy: &networkenforcement.ProxyRoutingIntent{HTTP: networkenforcement.ProxyRoutingModeRouteViaProxy, HTTPS: networkenforcement.ProxyRoutingModeRouteViaProxy, ProxySessionID: "proxy-session-a", Mechanism: networkenforcement.EnforcementMechanismProxy, Operations: []string{"proxy_listener"}}, Firewall: &networkenforcement.FirewallIntent{Mode: networkenforcement.FirewallIntentModeApply, Mechanism: networkenforcement.EnforcementMechanismFirewall, Operations: []string{"apply_rules", "inspect_rules"}}}
}
func testTarget() sandboxruntime.Target {
	return sandboxruntime.Target{ID: "container-generation-a", Name: "hal-l7", Provider: rootlesspodman.DriverID, Runtime: sandboxruntime.RuntimeState{Driver: rootlesspodman.DriverID, RuntimeID: "container-generation-a", IsolationLevel: rootlesspodman.IsolationLevel}}
}
func mustFactory(t *testing.T, options l7network.FactoryOptions) rootlesspodman.NetworkTopologyFactory {
	t.Helper()
	factory, err := l7network.NewFactory(options)
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func baseFactoryOptions(proxy l7network.Proxy, resolver l7network.NamespaceResolver, rules l7network.RuleAdapter) l7network.FactoryOptions {
	return l7network.FactoryOptions{Identity: testIdentity(), Plan: testPlan(), Proxy: proxy, NamespaceResolver: resolver,
		Rules: rules, RawPacketVerifierFactory: fakeRawPacketVerifierFactory, GuestProxyAddress: "169.254.77.2", TableName: "hal_l7_a"}
}
