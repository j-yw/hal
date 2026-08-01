package l7network

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

func TestFirecrackerHostTopologyPreparesExactInspectedGenerationInOrder(t *testing.T) {
	sequence := &callSequence{}
	proxy := newFakeProxy(sequence)
	topology := newFakeTopology(sequence)
	tap := &fakeTAP{sequence: sequence}
	rules := &fakeRules{sequence: sequence}
	raw := &fakeRawPacketVerifier{sequence: sequence}
	journal := &fakeJournalStore{sequence: sequence}

	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: proxy, Topology: topology, TAP: tap, Rules: rules,
		RawPacketIsolation: raw, Journal: journal, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatalf("Prepare() unexpected error: %v", err)
	}
	metadata := session.Metadata()
	if metadata.Status != StatusInspected || !metadata.StructuralInspected || !metadata.TAPInspected ||
		!metadata.RulesInspected || !metadata.RawPacketIsolationVerified || metadata.RuleDigest == "" {
		t.Fatalf("Prepare() metadata = %#v, want sanitized inspected-only proof", metadata)
	}
	if metadata.Status == StatusActive {
		t.Fatal("host topology foundation must not publish active proof")
	}
	want := []string{
		"journal_acquire", "journal_save_proxy_starting", "proxy_start", "proxy_endpoint", "proxy_active",
		"journal_save_topology_starting", "topology_start", "topology_borrow", "journal_save_topology_prepared",
		"tap_create", "journal_save_tap_created", "tap_inspect", "raw_packet_verify", "proxy_active",
		"rules_apply_inspect", "journal_save_rules_inspected", "tap_inspect", "proxy_active", "journal_save_inspected",
	}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("prepare sequence = %#v, want %#v", got, want)
	}
	if tap.lastSpec.guestIPv4Prefix.Bits() != 30 || tap.lastSpec.guestIPv6Prefix.Bits() != 126 ||
		tap.lastSpec.gatewayIPv4 == tap.lastSpec.guestIPv4Prefix.Addr() || tap.lastSpec.gatewayIPv6 == tap.lastSpec.guestIPv6Prefix.Addr() {
		t.Fatalf("TAP static pairs = %#v, want non-base /30 and /126 pairs", tap.lastSpec)
	}
	if rules.lastProfile != linuxrules.RuleProfileForwardedTAP || rules.lastCorrelation != testCorrelation() {
		t.Fatalf("rules profile/correlation = %q %#v", rules.lastProfile, rules.lastCorrelation)
	}
}

func TestFirecrackerHostTopologyRequiresExactRawPacketProofAndQuarantinesDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fakeRawPacketVerifier)
	}{
		{name: "verifier failure", mutate: func(v *fakeRawPacketVerifier) { v.err = errors.New("pid=4242 token=secret") }},
		{name: "wrong generation", mutate: func(v *fakeRawPacketVerifier) { v.mismatch = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sequence := &callSequence{}
			raw := &fakeRawPacketVerifier{sequence: sequence}
			tc.mutate(raw)
			coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
				TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence}, RawPacketIsolation: raw,
				Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second})
			_, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
			if !errors.Is(err, ErrProofMismatch) {
				t.Fatalf("Prepare() error = %v, want ErrProofMismatch", err)
			}
			if strings.Contains(err.Error(), "4242") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("Prepare() leaked private verifier detail: %v", err)
			}
			got := sequence.snapshot()
			if contains(got, "rules_apply_inspect") {
				t.Fatalf("rules applied without raw-packet proof: %#v", got)
			}
			assertSubsequence(t, got, []string{"tap_delete", "topology_stop", "proxy_stop"})
		})
	}

	t.Run("inspection drift quarantines before returning", func(t *testing.T) {
		sequence := &callSequence{}
		proxy := newFakeProxy(sequence)
		tap := &fakeTAP{sequence: sequence}
		rules := &fakeRules{sequence: sequence}
		coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence), TAP: tap,
			Rules: rules, RawPacketIsolation: &fakeRawPacketVerifier{sequence: sequence}, Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second})
		session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
		if err != nil {
			t.Fatal(err)
		}
		sequence.reset()
		tap.inspectErr = errors.New("tap name /private/tap0 drift")
		if _, err := session.Inspect(context.Background(), testIdentity()); !errors.Is(err, ErrProofMismatch) {
			t.Fatalf("Inspect() error = %v, want ErrProofMismatch", err)
		}
		if got := sequence.snapshot(); !reflect.DeepEqual(got, []string{"proxy_active", "tap_inspect", "rules_quarantine", "journal_save_quarantined"}) {
			t.Fatalf("drift sequence = %#v", got)
		}
	})
}

func TestFirecrackerHostTopologyTwoStageCleanupIsExactRetryableAndPortLast(t *testing.T) {
	sequence := &callSequence{}
	proxy := newFakeProxy(sequence)
	topology := newFakeTopology(sequence)
	tap := &fakeTAP{sequence: sequence, deleteFailures: 1}
	rules := &fakeRules{sequence: sequence, cleanupFailures: 1}
	journal := &fakeJournalStore{sequence: sequence}
	coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: proxy, Topology: topology, TAP: tap, Rules: rules,
		RawPacketIsolation: &fakeRawPacketVerifier{sequence: sequence}, Journal: journal, CleanupTimeout: time.Second})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	sequence.reset()
	if err := session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), false); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("CleanupAfterVMQuiesced(false) = %v", err)
	}
	if got := sequence.snapshot(); len(got) != 0 {
		t.Fatalf("cleanup mutated before VM confirmation: %#v", got)
	}
	if err := session.Quarantine(context.Background(), testIdentity()); err != nil {
		t.Fatal(err)
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), true); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("first cleanup = %v, want retryable incomplete", err)
	}
	if contains(sequence.snapshot(), "tap_delete") || contains(sequence.snapshot(), "topology_stop") || contains(sequence.snapshot(), "proxy_stop") {
		t.Fatalf("cleanup advanced beyond failed rule removal: %#v", sequence.snapshot())
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), true); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("second cleanup = %v, want TAP retry", err)
	}
	if contains(sequence.snapshot(), "topology_stop") || contains(sequence.snapshot(), "proxy_stop") {
		t.Fatalf("cleanup advanced beyond failed TAP removal: %#v", sequence.snapshot())
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), true); err != nil {
		t.Fatalf("third cleanup = %v", err)
	}
	assertSubsequence(t, sequence.snapshot(), []string{
		"rules_quarantine", "journal_save_quarantined", "rules_cleanup", "rules_cleanup",
		"journal_save_rules_removed", "tap_delete", "tap_delete", "journal_save_tap_removed",
		"topology_stop", "journal_save_topology_removed", "proxy_stop", "journal_remove", "journal_release",
	})
	if session.Metadata().Status != StatusStopped {
		t.Fatalf("terminal status = %q", session.Metadata().Status)
	}

	sequence.reset()
	mismatch := testIdentity()
	mismatch.RuleGenerationID = "other-rule-generation"
	if err := session.CleanupAfterVMQuiesced(context.Background(), mismatch, true); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("mismatched cleanup = %v", err)
	}
	if len(sequence.snapshot()) != 0 {
		t.Fatalf("mismatched cleanup mutated state: %#v", sequence.snapshot())
	}
}

func TestFirecrackerHostTopologyRejectsUnsafeDuplicateOrMismatchedIdentityBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PrepareRequest)
	}{
		{name: "unsafe", mutate: func(r *PrepareRequest) { r.Identity.TopologyGenerationID = "/run/private/netns" }},
		{name: "duplicate", mutate: func(r *PrepareRequest) { r.Identity.RuleGenerationID = r.Identity.TopologyGenerationID }},
		{name: "plan", mutate: func(r *PrepareRequest) { r.Plan.ID = "other-plan" }},
		{name: "policy", mutate: func(r *PrepareRequest) { r.Plan.PolicySnapshot.ID = "other-policy" }},
		{name: "proxy", mutate: func(r *PrepareRequest) { r.Plan.Proxy.ProxySessionID = "other-proxy" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sequence := &callSequence{}
			coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
				TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence}, RawPacketIsolation: &fakeRawPacketVerifier{sequence: sequence},
				Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second})
			request := PrepareRequest{Identity: testIdentity(), Plan: testPlan()}
			tc.mutate(&request)
			if _, err := coordinator.Prepare(context.Background(), request); !errors.Is(err, ErrInvalidIdentity) {
				t.Fatalf("Prepare() = %v, want ErrInvalidIdentity", err)
			}
			if got := sequence.snapshot(); len(got) != 0 {
				t.Fatalf("invalid request mutated state: %#v", got)
			}
		})
	}
}

func TestFirecrackerHostTopologyMetadataOmitsAllLiveState(t *testing.T) {
	sequence := &callSequence{}
	coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence}, RawPacketIsolation: &fakeRawPacketVerifier{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"127.0.0.1", "43123", "tap-private0", "192.0.2.2", "172.31.255", "fd00:", "/proc/", "namespace", "active"} {
		if strings.Contains(strings.ToLower(string(payload)), strings.ToLower(forbidden)) {
			t.Fatalf("session JSON leaked %q: %s", forbidden, payload)
		}
	}
}

func TestFirecrackerHostTopologyDisabledIsInert(t *testing.T) {
	coordinator, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled Prepare() = %v", err)
	}
}

type fakeGeneration struct {
	address string
	loss    chan struct{}
}

func (g *fakeGeneration) Address() string       { return g.address }
func (g *fakeGeneration) Loss() <-chan struct{} { return g.loss }

type fakeProxy struct {
	sequence  *callSequence
	current   *fakeGeneration
	activeErr error
}

func newFakeProxy(sequence *callSequence) *fakeProxy {
	return &fakeProxy{sequence: sequence, current: &fakeGeneration{address: "127.0.0.1:43123", loss: make(chan struct{})}}
}

func (p *fakeProxy) Start(context.Context, networkenforcement.Plan) (ProxyGeneration, error) {
	p.sequence.add("proxy_start")
	return p.current, nil
}
func (p *fakeProxy) Endpoint(g ProxyGeneration) (string, error) {
	p.sequence.add("proxy_endpoint")
	if g != p.current {
		return "", errors.New("wrong proxy generation")
	}
	return p.current.address, nil
}
func (p *fakeProxy) Active(context.Context, networkenforcement.Plan, ProxyGeneration) error {
	p.sequence.add("proxy_active")
	return p.activeErr
}
func (p *fakeProxy) Stop(context.Context, networkenforcement.Plan, ProxyGeneration) error {
	p.sequence.add("proxy_stop")
	return nil
}

type fakeTopology struct {
	sequence *callSequence
	session  *fakeTopologySession
}

func newFakeTopology(sequence *callSequence) *fakeTopology {
	return &fakeTopology{sequence: sequence, session: &fakeTopologySession{sequence: sequence}}
}

func (t *fakeTopology) Start(_ context.Context, request linuxtopology.StartRequest) (TopologySession, error) {
	t.sequence.add("topology_start")
	t.session.identity = request.Identity
	return t.session, nil
}
func (t *fakeTopology) Stop(context.Context, linuxtopology.Identity) (linuxtopology.Metadata, error) {
	t.sequence.add("topology_stop")
	return linuxtopology.Metadata{Status: linuxtopology.StatusStopped}, nil
}

type fakeTopologySession struct {
	sequence *callSequence
	identity linuxtopology.Identity
}

func (s *fakeTopologySession) Metadata() linuxtopology.Metadata {
	return linuxtopology.Metadata{Identity: s.identity, Status: linuxtopology.StatusPrepared, StructuralInspected: true, MappingReachable: true}
}
func (s *fakeTopologySession) BorrowNamespace() (NamespaceLease, error) {
	s.sequence.add("topology_borrow")
	return &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, nil
}

type fakeNamespaceLease struct{ rules linuxrules.NamespaceHandle }

func (l *fakeNamespaceLease) RuleNamespace() linuxrules.NamespaceHandle { return l.rules }
func (*fakeNamespaceLease) Close() error                                { return nil }

type fakeTAP struct {
	sequence       *callSequence
	lastSpec       tapSpec
	inspectErr     error
	deleteFailures int
	deleteCalls    int
}

func (t *fakeTAP) CreateConfigure(_ context.Context, _ NamespaceLease, spec tapSpec) (tapState, error) {
	t.sequence.add("tap_create")
	t.lastSpec = spec
	return tapState{name: "tap-private0", generation: spec.generation, fingerprint: spec.fingerprint()}, nil
}
func (t *fakeTAP) Inspect(_ context.Context, _ NamespaceLease, _ tapState, spec tapSpec) error {
	t.sequence.add("tap_inspect")
	t.lastSpec = spec
	return t.inspectErr
}
func (t *fakeTAP) Delete(_ context.Context, _ NamespaceLease, _ tapState, _ tapSpec) error {
	t.sequence.add("tap_delete")
	t.deleteCalls++
	if t.deleteCalls <= t.deleteFailures {
		return errors.New("private TAP cleanup failure")
	}
	return nil
}

type fakeRules struct {
	sequence        *callSequence
	lastCorrelation networkenforcement.EnforcementCorrelation
	lastProfile     linuxrules.RuleProfile
	cleanupFailures int
	cleanupCalls    int
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
	return nil
}
func (r *fakeRules) Cleanup(context.Context, linuxrules.ExpectedRuleSet) error {
	r.sequence.add("rules_cleanup")
	r.cleanupCalls++
	if r.cleanupCalls <= r.cleanupFailures {
		return errors.New("private rule cleanup failure")
	}
	return nil
}
func (r *fakeRules) metadata(expected linuxrules.ExpectedRuleSet) networkenforcement.RuleLifecycleMetadata {
	var data struct {
		Correlation networkenforcement.EnforcementCorrelation `json:"correlation"`
		Profile     linuxrules.RuleProfile                    `json:"profile"`
		RuleDigest  string                                    `json:"ruleDigest"`
	}
	payload, _ := expected.MarshalJSON()
	_ = json.Unmarshal(payload, &data)
	r.lastCorrelation, r.lastProfile = data.Correlation, data.Profile
	c := data.Correlation
	return networkenforcement.RuleLifecycleMetadata{ID: c.RuleGenerationID, PlanID: c.PlanID, Status: networkenforcement.LifecycleStatusActive,
		Correlation: &c, Inspection: &networkenforcement.InspectedRuleProof{ID: "rule-proof-a", RuleDigest: data.RuleDigest,
			Status: networkenforcement.RuleInspectionStatusInspected, InspectedAtUnixMilli: 1000, Correlation: &c,
			Mechanisms:       []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismFirewall},
			CapabilityLabels: []string{"default_deny"}, ReasonCode: networkenforcement.LifecycleReasonRuleInspected},
		ReasonCode: networkenforcement.LifecycleReasonActive}
}

type fakeRawPacketVerifier struct {
	sequence *callSequence
	err      error
	mismatch bool
}

func (v *fakeRawPacketVerifier) VerifyRawPacketIsolation(_ context.Context, correlation networkenforcement.EnforcementCorrelation) (networkenforcement.RawPacketIsolationProof, error) {
	v.sequence.add("raw_packet_verify")
	if v.err != nil {
		return networkenforcement.RawPacketIsolationProof{}, v.err
	}
	if v.mismatch {
		correlation.RuleGenerationID = "wrong-generation"
	}
	return networkenforcement.RawPacketIsolationProof{ID: "raw-proof-a", Status: networkenforcement.RawPacketIsolationStatusVerified,
		VerifiedAtUnixMilli: 1000, Correlation: &correlation, ReasonCode: networkenforcement.LifecycleReasonRawPacketIsolationVerified}, nil
}

type fakeJournalStore struct{ sequence *callSequence }

func (s *fakeJournalStore) Acquire(context.Context, Identity) (JournalLease, error) {
	s.sequence.add("journal_acquire")
	return &fakeJournalLease{sequence: s.sequence}, nil
}

type fakeJournalLease struct{ sequence *callSequence }

func (l *fakeJournalLease) Load() (journalRecord, error) { return journalRecord{}, ErrJournalNotFound }
func (l *fakeJournalLease) Save(_ context.Context, record journalRecord) error {
	l.sequence.add("journal_save_" + string(record.stage))
	return nil
}
func (l *fakeJournalLease) Remove() error  { l.sequence.add("journal_remove"); return nil }
func (l *fakeJournalLease) Release() error { l.sequence.add("journal_release"); return nil }

type callSequence struct {
	mu     sync.Mutex
	values []string
}

func (s *callSequence) add(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values = append(s.values, value)
}
func (s *callSequence) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.values...)
}
func (s *callSequence) reset() { s.mu.Lock(); defer s.mu.Unlock(); s.values = nil }

func testIdentity() Identity {
	return Identity{SandboxID: "sandbox-a", ExecutionID: "execution-a", WorkerID: "worker-a", RuntimeGenerationID: "runtime-a",
		PlanID: "plan-a", PolicySnapshotID: "policy-a", ProxySessionID: "proxy-session-a", ProxyGenerationID: "proxy-generation-a",
		TopologyGenerationID: "topology-generation-a", RuleGenerationID: "rule-generation-a"}
}
func testCorrelation() networkenforcement.EnforcementCorrelation {
	i := testIdentity()
	return networkenforcement.EnforcementCorrelation{SandboxID: i.SandboxID, ExecutionID: i.ExecutionID, WorkerID: i.WorkerID,
		RuntimeID: i.RuntimeGenerationID, PlanID: i.PlanID, PolicySnapshotID: i.PolicySnapshotID, ProxySessionID: i.ProxySessionID,
		ProxyGenerationID: i.ProxyGenerationID, TopologyGenerationID: i.TopologyGenerationID, RuleGenerationID: i.RuleGenerationID}
}
func testPlan() networkenforcement.Plan {
	return networkenforcement.Plan{ID: "plan-a", Source: networkenforcement.PlanSourceRuntime, Operation: "l7_firecracker_host_topology",
		PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{ID: "policy-a", Preset: networkenforcement.PolicyPresetDenyByDefault},
		DefaultPosture: networkenforcement.DefaultPostureDenyByDefault,
		Proxy: &networkenforcement.ProxyRoutingIntent{HTTP: networkenforcement.ProxyRoutingModeRouteViaProxy, HTTPS: networkenforcement.ProxyRoutingModeRouteViaProxy,
			ProxySessionID: "proxy-session-a", Mechanism: networkenforcement.EnforcementMechanismProxy, Operations: []string{"proxy_listener"}},
		Firewall: &networkenforcement.FirewallIntent{Mode: networkenforcement.FirewallIntentModeApply,
			Mechanism: networkenforcement.EnforcementMechanismFirewall, Operations: []string{"apply_rules", "inspect_rules"}}}
}
func mustCoordinator(t *testing.T, options Options) *Coordinator {
	t.Helper()
	coordinator, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func assertSubsequence(t *testing.T, values, want []string) {
	t.Helper()
	index := 0
	for _, value := range values {
		if index < len(want) && value == want[index] {
			index++
		}
	}
	if index != len(want) {
		t.Fatalf("sequence %#v does not contain ordered %#v", values, want)
	}
}
