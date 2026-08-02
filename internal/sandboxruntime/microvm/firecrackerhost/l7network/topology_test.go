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

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
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
	journal := &fakeJournalStore{sequence: sequence}

	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: proxy, Topology: topology, TAP: tap, Rules: rules,
		Journal: journal, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatalf("Prepare() unexpected error: %v; sequence=%#v", err, sequence.snapshot())
	}
	metadata := session.Metadata()
	if metadata.Status != StatusHostPrepared || !metadata.StructuralInspected || !metadata.TAPInspected ||
		!metadata.RulesInspected || metadata.RawPacketIsolationVerified || metadata.RuleDigest == "" {
		t.Fatalf("Prepare() metadata = %#v, want sanitized host-prepared proof", metadata)
	}
	if metadata.Status == StatusActive {
		t.Fatal("host topology foundation must not publish active proof")
	}
	want := []string{
		"journal_acquire", "journal_save_proxy_starting", "proxy_start", "proxy_endpoint", "proxy_active",
		"journal_save_topology_starting", "topology_start", "topology_borrow", "journal_save_topology_prepared",
		"tap_create", "journal_save_tap_created", "tap_inspect", "proxy_active",
		"rules_apply_inspect", "journal_save_rules_inspected", "tap_inspect", "proxy_active",
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

func TestFirecrackerHostTopologyIPv6ProxyMappingMatchesGuestBootContract(t *testing.T) {
	proxyAddress, proxyPort, guestAddress, err := validatedProxyEndpoint("[::1]:43123")
	if err != nil || proxyAddress != guestAddress || proxyPort != 43123 {
		t.Fatalf("validatedProxyEndpoint(IPv6) = %v, %d, %v, %v", proxyAddress, proxyPort, guestAddress, err)
	}
	spec := staticTAPSpec(testIdentity(), proxyAddress, proxyPort)
	session := preparedLaunchHandoffSession(testIdentity(), spec, &fakeProcessNamespaceLease{})
	descriptor, err := session.LaunchDescriptor(testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	_, ipv4, ipv4Gateway, ipv6, ipv6Gateway, proxyURL, ok := descriptor.StaticNetwork()
	if !ok {
		t.Fatal("IPv6 proxy mapping did not produce a static launch handoff")
	}
	commandLine := "hal_l7_net_if=eth0 hal_l7_ipv4=" + ipv4 + " hal_l7_ipv4_gateway=" + ipv4Gateway +
		" hal_l7_ipv6=" + ipv6 + " hal_l7_ipv6_gateway=" + ipv6Gateway + " hal_l7_proxy=" + proxyURL
	boot, present, err := guestnetwork.ParseBootCommandLine(commandLine)
	if err != nil || !present || boot.ProxyURL() != proxyURL {
		t.Fatalf("guest rejected host-generated IPv6 proxy handoff: present=%t error=%v", present, err)
	}
}

func TestFirecrackerHostTopologyPostReadinessRequiresExactRawPacketProofAndQuarantinesDrift(t *testing.T) {
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
				TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
				GuestIsolation: raw, Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second})
			session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
			if err != nil {
				t.Fatal(err)
			}
			sequence.reset()
			ready := true
			binding := &fakeRunningGuestBinding{correlation: testCorrelation(), proofID: "guest-ready-proof-existing", ready: &ready}
			_, err = session.InspectAfterGuestReady(context.Background(), testIdentity(), binding)
			if !errors.Is(err, ErrProofMismatch) {
				t.Fatalf("InspectAfterGuestReady() error = %v, want ErrProofMismatch", err)
			}
			if strings.Contains(err.Error(), "4242") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("Prepare() leaked private verifier detail: %v", err)
			}
			got := sequence.snapshot()
			assertSubsequence(t, got, []string{"guest_raw_packet_verify", "rules_quarantine", "journal_save_quarantined"})
		})
	}

	t.Run("inspection drift quarantines before returning", func(t *testing.T) {
		sequence := &callSequence{}
		proxy := newFakeProxy(sequence)
		tap := &fakeTAP{sequence: sequence}
		rules := &fakeRules{sequence: sequence}
		ready := true
		binding := &fakeRunningGuestBinding{correlation: testCorrelation(), proofID: "guest-ready-proof-inspect", ready: &ready}
		verifier := &fakeRawPacketVerifier{sequence: sequence}
		coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence), TAP: tap,
			Rules: rules, GuestIsolation: verifier, Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second})
		session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.InspectAfterGuestReady(context.Background(), testIdentity(), binding); err != nil {
			t.Fatal(err)
		}
		sequence.reset()
		tap.inspectErr = errors.New("tap name /private/tap0 drift")
		if _, err := session.Inspect(context.Background(), testIdentity()); !errors.Is(err, ErrProofMismatch) {
			t.Fatalf("Inspect() error = %v, want ErrProofMismatch", err)
		}
		if got := sequence.snapshot(); !reflect.DeepEqual(got, []string{"guest_raw_packet_verify", "proxy_active", "tap_inspect", "rules_quarantine", "journal_save_quarantined"}) {
			t.Fatalf("drift sequence = %#v", got)
		}
	})
}

func TestFirecrackerHostTopologyProxyLossRevokesAndQuarantinesExactGeneration(t *testing.T) {
	sequence := &callSequence{}
	proxy := newFakeProxy(sequence)
	coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	sequence.reset()
	close(proxy.current.loss)
	deadline := time.Now().Add(time.Second)
	for session.Metadata().Status != StatusQuarantined && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if session.Metadata().Status != StatusQuarantined {
		t.Fatalf("proxy loss status = %q", session.Metadata().Status)
	}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, []string{"rules_quarantine", "journal_save_quarantined"}) {
		t.Fatalf("proxy loss sequence = %#v", got)
	}
}

func TestFirecrackerHostTopologyTwoStageCleanupIsExactRetryableAndPortLast(t *testing.T) {
	sequence := &callSequence{}
	proxy := newFakeProxy(sequence)
	topology := newFakeTopology(sequence)
	tap := &fakeTAP{sequence: sequence, deleteFailures: 1}
	rules := &fakeRules{sequence: sequence, cleanupFailures: 1}
	journal := &fakeJournalStore{sequence: sequence}
	coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: proxy, Topology: topology, TAP: tap, Rules: rules,
		Journal: journal, CleanupTimeout: time.Second})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	sequence.reset()
	if err := session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), nil); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("CleanupAfterVMQuiesced(false) = %v", err)
	}
	if got := sequence.snapshot(); len(got) != 0 {
		t.Fatalf("cleanup mutated before VM confirmation: %#v", got)
	}
	if err := session.Quarantine(context.Background(), testIdentity()); err != nil {
		t.Fatal(err)
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), testTerminatedVMBinding()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("first cleanup = %v, want retryable incomplete", err)
	}
	if contains(sequence.snapshot(), "tap_delete") || contains(sequence.snapshot(), "topology_stop") || contains(sequence.snapshot(), "proxy_stop") {
		t.Fatalf("cleanup advanced beyond failed rule removal: %#v", sequence.snapshot())
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), testTerminatedVMBinding()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("second cleanup = %v, want TAP retry", err)
	}
	if contains(sequence.snapshot(), "topology_stop") || contains(sequence.snapshot(), "proxy_stop") {
		t.Fatalf("cleanup advanced beyond failed TAP removal: %#v", sequence.snapshot())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := session.CleanupAfterVMQuiesced(canceled, testIdentity(), testTerminatedVMBinding()); err != nil {
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
	if err := session.CleanupAfterVMQuiesced(context.Background(), mismatch, testTerminatedVMBinding()); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("mismatched cleanup = %v", err)
	}
	if len(sequence.snapshot()) != 0 {
		t.Fatalf("mismatched cleanup mutated state: %#v", sequence.snapshot())
	}
}

func TestFirecrackerHostTopologyFailedPrepareCleanupRetriesWithoutVMProof(t *testing.T) {
	sequence := &callSequence{}
	proxy := newFakeProxy(sequence)
	proxy.endpointErr = errors.New("private endpoint failure")
	proxy.stopFailures = 1
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if session == nil || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Prepare() = session %T, error %v; want retained cleanup-incomplete session", session, err)
	}
	if err := session.RetryFailedPrepareCleanup(context.Background(), testIdentity()); err != nil {
		t.Fatalf("RetryFailedPrepareCleanup() = %v", err)
	}
	secondIdentity := alternateIdentity()
	proxy.endpointErr = nil
	if _, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: secondIdentity, Plan: planForIdentity(secondIdentity)}); err != nil {
		t.Fatalf("Prepare(next generation) = %v, want released coordinator", err)
	}
}

func TestFirecrackerHostTopologyAbortBeforeVMRetriesRetainedPrepareCleanup(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configure  func(*Options, *callSequence)
		afterAbort func(*Options)
	}{
		{name: "rollback", configure: func(options *Options, sequence *callSequence) {
			proxy := newFakeProxy(sequence)
			proxy.endpointErr = errors.New("private endpoint failure")
			proxy.stopFailures = 1
			options.Proxy = proxy
		}, afterAbort: func(options *Options) {
			options.Proxy.(*fakeProxy).endpointErr = nil
		}},
		{name: "journal release", configure: func(options *Options, sequence *callSequence) {
			options.Journal = &releaseRetryJournalStore{
				sequence: sequence, firstSaveErr: errors.New("private journal save failure"), firstReleaseFailures: 1,
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sequence := &callSequence{}
			options := validCoordinatorOptions(sequence)
			tc.configure(&options, sequence)
			coordinator := mustCoordinator(t, options)
			session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
			if session == nil || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("Prepare() = session %T, error %v; want retained cleanup", session, err)
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if err := session.AbortBeforeVM(canceled, testIdentity()); err != nil {
				t.Fatalf("AbortBeforeVM(retained) = %v", err)
			}
			if got := session.Metadata().Status; got != StatusStopped {
				t.Fatalf("AbortBeforeVM status = %q, want %q", got, StatusStopped)
			}
			if tc.afterAbort != nil {
				tc.afterAbort(&options)
			}
			next := alternateIdentity()
			if _, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: next, Plan: planForIdentity(next)}); err != nil {
				t.Fatalf("Prepare(after retained abort) = %v", err)
			}
		})
	}
}

func TestFirecrackerHostTopologyFailedPrepareRetryRetainsNamespaceLease(t *testing.T) {
	sequence := &callSequence{}
	topology := newRetryNamespaceTopology(sequence)
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: newFakeProxy(sequence), Topology: topology,
		TAP:   &fakeTAP{sequence: sequence, createErr: errors.New("private TAP creation failure")},
		Rules: &fakeRules{sequence: sequence}, Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if session == nil || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Prepare() = session %T, error %v; want retained cleanup-incomplete session", session, err)
	}
	if topology.lease.closeCalls != 1 || topology.lease.closed {
		t.Fatalf("first rollback namespace close = calls %d, closed %t; want retained failed handle", topology.lease.closeCalls, topology.lease.closed)
	}
	sequence.reset()
	if err := session.RetryFailedPrepareCleanup(context.Background(), testIdentity()); err != nil {
		t.Fatalf("RetryFailedPrepareCleanup() = %v", err)
	}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, []string{
		"namespace_close", "topology_stop", "proxy_stop", "journal_remove", "journal_release",
	}) {
		t.Fatalf("retry cleanup sequence = %#v", got)
	}
	if topology.lease.closeCalls != 2 || !topology.lease.closed {
		t.Fatalf("retried namespace close = calls %d, closed %t; want exact handle released", topology.lease.closeCalls, topology.lease.closed)
	}
}

func TestFirecrackerHostTopologyCurrentSessionClearIsCompareAndSwap(t *testing.T) {
	coordinator := &Coordinator{}
	oldSession := &Session{coordinator: coordinator}
	newSession := &Session{coordinator: coordinator}
	coordinator.current = newSession
	coordinator.clearCurrentSession(oldSession)
	if coordinator.current != newSession {
		t.Fatal("stale cleanup cleared a newer coordinator session")
	}
}

func TestFirecrackerHostTopologyCleanupRejectsBareQuiescenceAssertion(t *testing.T) {
	sequence := &callSequence{}
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Quarantine(context.Background(), testIdentity()); err != nil {
		t.Fatal(err)
	}
	sequence.reset()
	if err := session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), nil); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("CleanupAfterVMQuiesced(nil) = %v, want authoritative ErrVMNotQuiesced", err)
	}
	if got := sequence.snapshot(); len(got) != 0 {
		t.Fatalf("bare boolean authorized cleanup mutations: %#v", got)
	}
}

func TestFirecrackerHostTopologyCleanupRequiresExactStoppedAndReapedVMProof(t *testing.T) {
	tests := []struct {
		name     string
		verifier *fakeVMTerminationVerifier
		binding  TerminatedVMBinding
	}{
		{name: "missing binding", verifier: &fakeVMTerminationVerifier{stopped: true, reaped: true}},
		{name: "verifier failure", verifier: &fakeVMTerminationVerifier{err: errors.New("pid=4242 private process detail")}, binding: testTerminatedVMBinding()},
		{name: "still running", verifier: &fakeVMTerminationVerifier{reaped: true}, binding: testTerminatedVMBinding()},
		{name: "not reaped", verifier: &fakeVMTerminationVerifier{stopped: true}, binding: testTerminatedVMBinding()},
		{name: "wrong generation", verifier: &fakeVMTerminationVerifier{stopped: true, reaped: true, mismatch: true}, binding: testTerminatedVMBinding()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sequence := &callSequence{}
			coordinator := mustCoordinator(t, Options{
				Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
				TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
				VMTermination: tc.verifier, Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
			})
			session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
			if err != nil {
				t.Fatal(err)
			}
			if err := session.Quarantine(context.Background(), testIdentity()); err != nil {
				t.Fatal(err)
			}
			sequence.reset()
			err = session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), tc.binding)
			if !errors.Is(err, ErrVMNotQuiesced) {
				t.Fatalf("CleanupAfterVMQuiesced() = %v, want ErrVMNotQuiesced", err)
			}
			if strings.Contains(err.Error(), "4242") || strings.Contains(err.Error(), "private") {
				t.Fatalf("cleanup leaked verifier detail: %v", err)
			}
			if got := sequence.snapshot(); len(got) != 0 {
				t.Fatalf("rejected VM proof mutated host topology: %#v", got)
			}
		})
	}
}

func TestFirecrackerHostTopologyRetainsPartialTopologySessionForRollback(t *testing.T) {
	sequence := &callSequence{}
	topology := newFakeTopology(sequence)
	topology.startErr = ErrCleanupIncomplete
	topology.returnSessionOnStartError = true
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: newFakeProxy(sequence), Topology: topology,
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	if _, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()}); !errors.Is(err, ErrTopologyPrepareFailed) {
		t.Fatalf("Prepare() = %v, want ErrTopologyPrepareFailed after resolved rollback", err)
	}
	if got := sequence.snapshot(); !contains(got, "topology_stop") {
		t.Fatalf("partial topology session was not retained for exact rollback: %#v", got)
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
				TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
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

func TestFirecrackerHostTopologyRollsBackEveryPreparationBoundaryInReverseOrder(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeProxy, *fakeTopology, *fakeTAP, *fakeRules)
		want   []string
	}{
		{name: "proxy endpoint", mutate: func(p *fakeProxy, _ *fakeTopology, _ *fakeTAP, _ *fakeRules) {
			p.endpointErr = errors.New("private endpoint")
		}, want: []string{"proxy_stop"}},
		{name: "topology start", mutate: func(_ *fakeProxy, t *fakeTopology, _ *fakeTAP, _ *fakeRules) {
			t.startErr = errors.New("private namespace")
		}, want: []string{"proxy_stop"}},
		{name: "namespace borrow", mutate: func(_ *fakeProxy, t *fakeTopology, _ *fakeTAP, _ *fakeRules) {
			t.session.borrowErr = errors.New("private fd")
		}, want: []string{"topology_stop", "proxy_stop"}},
		{name: "tap create", mutate: func(_ *fakeProxy, _ *fakeTopology, tap *fakeTAP, _ *fakeRules) {
			tap.createErr = errors.New("private tap")
		}, want: []string{"topology_stop", "proxy_stop"}},
		{name: "tap inspect", mutate: func(_ *fakeProxy, _ *fakeTopology, tap *fakeTAP, _ *fakeRules) {
			tap.inspectErr = errors.New("private route")
		}, want: []string{"tap_delete", "topology_stop", "proxy_stop"}},
		{name: "rule apply", mutate: func(_ *fakeProxy, _ *fakeTopology, _ *fakeTAP, rules *fakeRules) {
			rules.applyErr = errors.New("private nft body")
		}, want: []string{"rules_quarantine", "rules_cleanup", "tap_delete", "topology_stop", "proxy_stop"}},
		{name: "final proxy proof", mutate: func(p *fakeProxy, _ *fakeTopology, _ *fakeTAP, _ *fakeRules) { p.activeFailAt = 3 }, want: []string{"rules_quarantine", "rules_cleanup", "tap_delete", "topology_stop", "proxy_stop"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sequence := &callSequence{}
			proxy, topology, tap, rules := newFakeProxy(sequence), newFakeTopology(sequence), &fakeTAP{sequence: sequence}, &fakeRules{sequence: sequence}
			tc.mutate(proxy, topology, tap, rules)
			coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: proxy, Topology: topology, TAP: tap, Rules: rules,
				Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second})
			_, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
			if err == nil {
				t.Fatal("Prepare() unexpectedly succeeded")
			}
			for _, forbidden := range []string{"private endpoint", "private namespace", "private fd", "private tap", "private route", "private nft body"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("Prepare() leaked %q: %v", forbidden, err)
				}
			}
			assertSubsequence(t, sequence.snapshot(), tc.want)
		})
	}
}

func TestFirecrackerHostTopologyMetadataOmitsAllLiveState(t *testing.T) {
	sequence := &callSequence{}
	coordinator := mustCoordinator(t, Options{Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
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
	sequence     *callSequence
	current      *fakeGeneration
	activeErr    error
	endpointErr  error
	activeFailAt int
	activeCalls  int
	activeHook   func()
	stopFailures int
	stopCalls    int
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
	if p.endpointErr != nil {
		return "", p.endpointErr
	}
	if g != p.current {
		return "", errors.New("wrong proxy generation")
	}
	return p.current.address, nil
}
func (p *fakeProxy) Active(context.Context, networkenforcement.Plan, ProxyGeneration) error {
	p.sequence.add("proxy_active")
	p.activeCalls++
	if p.activeHook != nil {
		p.activeHook()
		p.activeHook = nil
	}
	if p.activeFailAt > 0 && p.activeCalls == p.activeFailAt {
		return errors.New("private active generation")
	}
	return p.activeErr
}
func (p *fakeProxy) Stop(context.Context, networkenforcement.Plan, ProxyGeneration) error {
	p.sequence.add("proxy_stop")
	p.stopCalls++
	if p.stopCalls <= p.stopFailures {
		return errors.New("private proxy cleanup failure")
	}
	return nil
}

type fakeTopology struct {
	sequence                  *callSequence
	session                   *fakeTopologySession
	startErr                  error
	returnSessionOnStartError bool
}

func newFakeTopology(sequence *callSequence) *fakeTopology {
	return &fakeTopology{sequence: sequence, session: &fakeTopologySession{
		sequence: sequence,
		losses:   make(chan linuxtopology.Loss, 1),
	}}
}

func (t *fakeTopology) Start(_ context.Context, request linuxtopology.StartRequest) (TopologySession, error) {
	t.sequence.add("topology_start")
	if t.startErr != nil {
		if t.returnSessionOnStartError {
			t.session.identity = request.Identity
			return t.session, t.startErr
		}
		return nil, t.startErr
	}
	t.session.identity = request.Identity
	return t.session, nil
}
func (t *fakeTopology) Stop(context.Context, linuxtopology.Identity) (linuxtopology.Metadata, error) {
	t.sequence.add("topology_stop")
	return linuxtopology.Metadata{Status: linuxtopology.StatusStopped}, nil
}

type fakeTopologySession struct {
	sequence  *callSequence
	identity  linuxtopology.Identity
	borrowErr error
	losses    chan linuxtopology.Loss
}

func (s *fakeTopologySession) Metadata() linuxtopology.Metadata {
	return linuxtopology.Metadata{Identity: s.identity, Status: linuxtopology.StatusPrepared, StructuralInspected: true, MappingReachable: true}
}
func (s *fakeTopologySession) BorrowNamespace() (NamespaceLease, error) {
	s.sequence.add("topology_borrow")
	if s.borrowErr != nil {
		return nil, s.borrowErr
	}
	return &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, nil
}
func (s *fakeTopologySession) Losses() <-chan linuxtopology.Loss {
	if s == nil {
		return nil
	}
	return s.losses
}

type fakeNamespaceLease struct{ rules linuxrules.NamespaceHandle }

func (l *fakeNamespaceLease) RuleNamespace() linuxrules.NamespaceHandle { return l.rules }
func (*fakeNamespaceLease) Close() error                                { return nil }

type retryNamespaceTopology struct {
	sequence *callSequence
	session  *retryNamespaceSession
	lease    *retryNamespaceLease
}

func newRetryNamespaceTopology(sequence *callSequence) *retryNamespaceTopology {
	lease := &retryNamespaceLease{sequence: sequence, closeFailures: 1}
	return &retryNamespaceTopology{sequence: sequence, lease: lease,
		session: &retryNamespaceSession{sequence: sequence, lease: lease, losses: make(chan linuxtopology.Loss, 1)}}
}

func (t *retryNamespaceTopology) Start(_ context.Context, request linuxtopology.StartRequest) (TopologySession, error) {
	t.sequence.add("topology_start")
	t.session.identity = request.Identity
	return t.session, nil
}

func (t *retryNamespaceTopology) Stop(context.Context, linuxtopology.Identity) (linuxtopology.Metadata, error) {
	t.sequence.add("topology_stop")
	if !t.lease.closed {
		return linuxtopology.Metadata{}, errors.New("private namespace borrow remains open")
	}
	return linuxtopology.Metadata{Status: linuxtopology.StatusStopped}, nil
}

type retryNamespaceSession struct {
	sequence  *callSequence
	identity  linuxtopology.Identity
	lease     *retryNamespaceLease
	borrowErr error
	losses    chan linuxtopology.Loss
}

func (s *retryNamespaceSession) Metadata() linuxtopology.Metadata {
	return linuxtopology.Metadata{Identity: s.identity, Status: linuxtopology.StatusPrepared, StructuralInspected: true, MappingReachable: true}
}

func (s *retryNamespaceSession) Losses() <-chan linuxtopology.Loss { return s.losses }

func (s *retryNamespaceSession) BorrowNamespace() (NamespaceLease, error) {
	s.sequence.add("topology_borrow")
	return s.lease, s.borrowErr
}

type retryNamespaceLease struct {
	sequence      *callSequence
	closeFailures int
	closeCalls    int
	closed        bool
}

func (*retryNamespaceLease) RuleNamespace() linuxrules.NamespaceHandle {
	return linuxrules.NewNamespaceHandle(10, 11)
}

func (l *retryNamespaceLease) Close() error {
	l.sequence.add("namespace_close")
	l.closeCalls++
	if l.closeCalls <= l.closeFailures {
		return errors.New("private namespace close failure")
	}
	l.closed = true
	return nil
}

type fakeTAP struct {
	sequence               *callSequence
	lastSpec               tapSpec
	inspectErr             error
	deleteFailures         int
	deleteCalls            int
	createErr              error
	returnStateOnCreateErr bool
}

func (t *fakeTAP) CreateConfigure(_ context.Context, _ NamespaceLease, spec tapSpec) (tapState, error) {
	t.sequence.add("tap_create")
	state := tapState{name: spec.name, generation: spec.generation, fingerprint: spec.fingerprint(), ifIndex: 41}
	if t.createErr != nil {
		if t.returnStateOnCreateErr {
			return state, t.createErr
		}
		return tapState{}, t.createErr
	}
	t.lastSpec = spec
	return state, nil
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
	applyErr        error
}

func (r *fakeRules) ApplyAndInspect(_ context.Context, expected linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error) {
	r.sequence.add("rules_apply_inspect")
	if r.applyErr != nil {
		return networkenforcement.RuleLifecycleMetadata{}, r.applyErr
	}
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

func (v *fakeRawPacketVerifier) VerifyRunningGuestRawPacketIsolation(_ context.Context, request RunningGuestRawPacketIsolationRequest) (RunningGuestRawPacketIsolationProof, error) {
	if v.sequence != nil {
		v.sequence.add("guest_raw_packet_verify")
	}
	if v.err != nil {
		return RunningGuestRawPacketIsolationProof{}, v.err
	}
	correlation := request.Correlation
	if v.mismatch {
		correlation.RuleGenerationID = "wrong-generation"
	}
	return RunningGuestRawPacketIsolationProof{ReadinessProofID: request.ReadinessProofID,
		RawPacketProof: networkenforcement.RawPacketIsolationProof{ID: "raw-proof-a", Status: networkenforcement.RawPacketIsolationStatusVerified,
			VerifiedAtUnixMilli: 1000, Correlation: &correlation, ReasonCode: networkenforcement.LifecycleReasonRawPacketIsolationVerified}}, nil
}

type fakeTerminatedVMBinding struct {
	correlation networkenforcement.EnforcementCorrelation
	proofID     string
}

func (b *fakeTerminatedVMBinding) VMCorrelation() networkenforcement.EnforcementCorrelation {
	return b.correlation
}
func (b *fakeTerminatedVMBinding) VMTerminationProofID() string { return b.proofID }

type fakeVMTerminationVerifier struct {
	err      error
	stopped  bool
	reaped   bool
	mismatch bool
}

func (v *fakeVMTerminationVerifier) VerifyVMTermination(_ context.Context, request VMTerminationRequest) (VMTerminationProof, error) {
	if v.err != nil {
		return VMTerminationProof{}, v.err
	}
	correlation := request.Correlation
	if v.mismatch {
		correlation.RuntimeID = "other-runtime-generation"
	}
	return VMTerminationProof{ID: "vm-termination-proof-a", TerminationProofID: request.TerminationProofID,
		Correlation: correlation, Stopped: v.stopped, Reaped: v.reaped}, nil
}

func testTerminatedVMBinding() *fakeTerminatedVMBinding {
	return &fakeTerminatedVMBinding{correlation: testCorrelation(), proofID: "vm-terminated-a"}
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
	if options.GuestIsolation == nil {
		options.GuestIsolation = &fakeRawPacketVerifier{}
	}
	if options.VMTermination == nil {
		options.VMTermination = &fakeVMTerminationVerifier{stopped: true, reaped: true}
	}
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
