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
		Identity:            testIdentity(),
		Plan:                testPlan(),
		Proxy:               proxy,
		NamespaceResolver:   namespace,
		Rules:               rules,
		RawPacketVerifier:   fakeRawPacketVerifier{},
		GuestProxyAddress:   "169.254.77.2",
		TableName:           "hal_l7_a",
		CleanupTimeout:      time.Second,
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
		Rules: rules, RawPacketVerifier: fakeRawPacketVerifier{}, GuestProxyAddress: "169.254.77.2", TableName: "hal_l7_a",
	})
	prepared, err := factory.PrepareNetworkTopology(context.Background(), rootlesspodman.NetworkTopologyPrepareRequest{SandboxName: "hal-l7"})
	if err != nil { t.Fatal(err) }
	req := rootlesspodman.NetworkTopologyTargetRequest{Identity: testIdentity(), Target: testTarget()}
	if _, err := prepared.Session.Activate(context.Background(), req); err != nil { t.Fatal(err) }
	sequence.reset()
	proxy.activeErr = errors.New("endpoint=/run/user/private.sock token=secret")
	if _, err := prepared.Session.Inspect(context.Background(), req); !errors.Is(err, l7network.ErrProxyUnavailable) {
		t.Fatalf("Inspect() error = %v, want ErrProxyUnavailable", err)
	} else if strings.Contains(err.Error(), "private.sock") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("Inspect() leaked private error: %v", err)
	}
	proxy.activeErr = nil
	if err := prepared.Session.Revoke(context.Background(), req); err != nil { t.Fatal(err) }
	if err := prepared.Session.Cleanup(context.Background(), req); err != nil { t.Fatal(err) }
	if got, want := sequence.snapshot(), []string{"proxy_active", "rules_quarantine", "rules_cleanup", "namespace_close", "proxy_stop"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("loss cleanup sequence = %#v, want %#v", got, want)
	}
}

func TestL7ComposedRootlessPodmanRejectsMismatchBeforeMutationAndCleansPartialStart(t *testing.T) {
	tests := []struct {
		name string
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
				RawPacketVerifier: fakeRawPacketVerifier{}, GuestProxyAddress: "169.254.77.2", TableName: "hal_l7_a"}
			tt.mutate(&options)
			if _, err := l7network.NewFactory(options); !errors.Is(err, l7network.ErrInvalidConfiguration) {
				t.Fatalf("NewFactory() error = %v, want ErrInvalidConfiguration", err)
			}
			if got := sequence.snapshot(); len(got) != 0 { t.Fatalf("mutation before validation: %#v", got) }
		})
	}

	t.Run("partial proxy start", func(t *testing.T) {
		sequence := &sequenceLog{}
		proxy := newFakeProxy(sequence)
		proxy.endpointErr = errors.New("private endpoint failure")
		factory := mustFactory(t, l7network.FactoryOptions{Identity: testIdentity(), Plan: testPlan(), Proxy: proxy,
			NamespaceResolver: &fakeNamespaceResolver{result: validNamespaceResolution()}, Rules: &fakeRules{},
			RawPacketVerifier: fakeRawPacketVerifier{}, GuestProxyAddress: "169.254.77.2", TableName: "hal_l7_a"})
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

type fakeEndpoint struct { address string; loss chan struct{} }
func (e *fakeEndpoint) Address() string { return e.address }
func (e *fakeEndpoint) Loss() <-chan struct{} { return e.loss }

type fakeProxy struct {
	sequence *sequenceLog
	endpoint *fakeEndpoint
	activeErr error
	endpointErr error
}
func newFakeProxy(sequence *sequenceLog) *fakeProxy { return &fakeProxy{sequence: sequence, endpoint: &fakeEndpoint{address: "127.0.0.1:31077", loss: make(chan struct{})}} }
func (p *fakeProxy) Start(context.Context, networkenforcement.Plan) (l7network.ProxyGeneration, error) { p.sequence.add("proxy_start"); return p.endpoint, nil }
func (p *fakeProxy) Endpoint(l7network.ProxyGeneration) (string, error) { p.sequence.add("proxy_endpoint"); if p.endpointErr != nil { return "", p.endpointErr }; return p.endpoint.address, nil }
func (p *fakeProxy) Active(context.Context, networkenforcement.Plan, l7network.ProxyGeneration) error { p.sequence.add("proxy_active"); return p.activeErr }
func (p *fakeProxy) Stop(context.Context, networkenforcement.Plan, l7network.ProxyGeneration) error { p.sequence.add("proxy_stop"); return nil }

type fakeNamespaceResolver struct { sequence *sequenceLog; result l7network.NamespaceResolution; err error }
func (r *fakeNamespaceResolver) Resolve(context.Context, rootlesspodman.NetworkTopologyTargetRequest) (l7network.NamespaceResolution, error) { if r.sequence != nil { r.sequence.add("namespace_resolve") }; return r.result, r.err }

type fakeCloser struct { sequence *sequenceLog }
func (c fakeCloser) Close() error { if c.sequence != nil { c.sequence.add("namespace_close") }; return nil }

type fakeRules struct { sequence *sequenceLog; lastCorrelation networkenforcement.EnforcementCorrelation; lastRawPacketVerifier fakeRawPacketVerifier }
func (r *fakeRules) ApplyAndInspect(_ context.Context, expected linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) { r.sequence.add("rules_apply_inspect"); return r.metadata(expected), nil }
func (r *fakeRules) Inspect(_ context.Context, expected linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) { r.sequence.add("rules_inspect"); return r.metadata(expected), nil }
func (r *fakeRules) Quarantine(context.Context, linuxrules.ExpectedRuleSet) error { r.sequence.add("rules_quarantine"); return nil }
func (r *fakeRules) Cleanup(context.Context, linuxrules.ExpectedRuleSet) error { r.sequence.add("rules_cleanup"); return nil }
func (r *fakeRules) metadata(expected linuxrules.ExpectedRuleSet) networkenforcement.RuleLifecycleMetadata {
	var encoded struct { Correlation networkenforcement.EnforcementCorrelation `json:"correlation"`; RuleDigest string `json:"ruleDigest"` }
	payload, _ := expected.MarshalJSON(); _ = json.Unmarshal(payload, &encoded)
	r.lastCorrelation = encoded.Correlation; r.lastRawPacketVerifier = fakeRawPacketVerifier{}
	correlation := encoded.Correlation
	return networkenforcement.RuleLifecycleMetadata{ID: correlation.RuleGenerationID, PlanID: correlation.PlanID,
		Status: networkenforcement.LifecycleStatusActive, Correlation: &correlation,
		Inspection: &networkenforcement.InspectedRuleProof{ID: "proof-a", RuleDigest: encoded.RuleDigest, Status: networkenforcement.RuleInspectionStatusInspected,
			InspectedAtUnixMilli: 1000, Correlation: &correlation, ReasonCode: networkenforcement.LifecycleReasonRuleInspected},
		LinkLayerIsolation: &networkenforcement.RawPacketIsolationProof{ID: "raw-proof-a", Status: networkenforcement.RawPacketIsolationStatusVerified,
			VerifiedAtUnixMilli: 1000, Correlation: &correlation, ReasonCode: networkenforcement.LifecycleReasonRawPacketIsolationVerified},
		ReasonCode: networkenforcement.LifecycleReasonActive}
}

type fakeRawPacketVerifier struct{}
func (fakeRawPacketVerifier) VerifyRawPacketIsolation(context.Context, networkenforcement.EnforcementCorrelation) (networkenforcement.RawPacketIsolationProof, error) { panic("called only by real rules adapter") }

type sequenceLog struct { mu sync.Mutex; values []string }
func (s *sequenceLog) add(value string) { if s == nil { return }; s.mu.Lock(); defer s.mu.Unlock(); s.values = append(s.values, value) }
func (s *sequenceLog) snapshot() []string { s.mu.Lock(); defer s.mu.Unlock(); return append([]string(nil), s.values...) }
func (s *sequenceLog) reset() { s.mu.Lock(); defer s.mu.Unlock(); s.values = nil }

func validNamespaceResolution() l7network.NamespaceResolution { return l7network.NamespaceResolution{Namespace: linuxrules.NewNamespaceHandle(10, 11), InterfaceName: "eth0", WorkloadIPv6Address: "fd00:7::2", GatewayIPv6Address: "fd00:7::1", IPv6PrefixBits: 64, Close: fakeCloser{}} }
func testIdentity() rootlesspodman.NetworkTopologyIdentity { return rootlesspodman.NetworkTopologyIdentity{SandboxID:"sandbox-a", ExecutionID:"execution-a", WorkerID:"worker-a", RuntimeDriver:rootlesspodman.DriverID, RuntimeGenerationID:"runtime-generation-a", PlanID:"plan-a", PolicySnapshotID:"policy-a", ProxySessionID:"proxy-session-a", ProxyGenerationID:"proxy-generation-a", TopologyGenerationID:"topology-generation-a", RuleGenerationID:"rule-generation-a"} }
func testCorrelation() networkenforcement.EnforcementCorrelation { i:=testIdentity(); return networkenforcement.EnforcementCorrelation{SandboxID:i.SandboxID,ExecutionID:i.ExecutionID,WorkerID:i.WorkerID,RuntimeID:i.RuntimeGenerationID,PlanID:i.PlanID,PolicySnapshotID:i.PolicySnapshotID,ProxySessionID:i.ProxySessionID,ProxyGenerationID:i.ProxyGenerationID,TopologyGenerationID:i.TopologyGenerationID,RuleGenerationID:i.RuleGenerationID} }
func testPlan() networkenforcement.Plan { return networkenforcement.Plan{ID:"plan-a",Source:networkenforcement.PlanSourceRuntime,Operation:"l7_topology",PolicySnapshot:&networkenforcement.PolicySnapshotIdentity{ID:"policy-a",Preset:networkenforcement.PolicyPresetDenyByDefault},DefaultPosture:networkenforcement.DefaultPostureDenyByDefault,Proxy:&networkenforcement.ProxyRoutingIntent{HTTP:networkenforcement.ProxyRoutingModeRouteViaProxy,HTTPS:networkenforcement.ProxyRoutingModeRouteViaProxy,ProxySessionID:"proxy-session-a",Mechanism:networkenforcement.EnforcementMechanismProxy,Operations:[]string{"proxy_listener"}},Firewall:&networkenforcement.FirewallIntent{Mode:networkenforcement.FirewallIntentModeApply,Mechanism:networkenforcement.EnforcementMechanismFirewall,Operations:[]string{"apply_rules","inspect_rules"}}} }
func testTarget() sandboxruntime.Target { return sandboxruntime.Target{ID:"container-generation-a",Name:"hal-l7",Provider:rootlesspodman.DriverID,Runtime:sandboxruntime.RuntimeState{Driver:rootlesspodman.DriverID,RuntimeID:"container-generation-a",IsolationLevel:rootlesspodman.IsolationLevel}} }
func mustFactory(t *testing.T, options l7network.FactoryOptions) rootlesspodman.NetworkTopologyFactory { t.Helper(); factory,err:=l7network.NewFactory(options); if err!=nil { t.Fatal(err) }; return factory }
