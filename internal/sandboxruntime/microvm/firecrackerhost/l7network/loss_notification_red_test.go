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

func TestFirecrackerHostTopologyPublishesProxyLossOnlyAfterQuarantine(t *testing.T) {
	for _, mode := range []string{"send", "close"} {
		t.Run(mode, func(t *testing.T) {
			sequence := &callSequence{}
			proxy := newFakeProxy(sequence)
			rules := &gatedQuarantineRules{
				fakeRules: &fakeRules{sequence: sequence},
				started:   make(chan struct{}),
				release:   make(chan struct{}),
			}
			coordinator := mustCoordinator(t, Options{
				Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence),
				TAP: &fakeTAP{sequence: sequence}, Rules: rules,
				Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
			})
			session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
			if err != nil {
				t.Fatal(err)
			}
			notification := session.Loss()
			if notification == nil {
				t.Fatal("Session.Loss() = nil")
			}
			sequence.reset()

			switch mode {
			case "send":
				go func() { proxy.current.loss <- struct{}{} }()
			case "close":
				close(proxy.current.loss)
			}

			select {
			case <-rules.started:
			case <-time.After(time.Second):
				t.Fatal("proxy loss was not consumed by the session quarantine owner")
			}
			select {
			case <-notification:
				t.Fatal("Session.Loss() published before quarantine completed")
			default:
			}

			close(rules.release)
			var result any
			select {
			case received, ok := <-notification:
				if !ok {
					t.Fatal("Session.Loss() closed without a quarantine result")
				}
				result = received
			case <-time.After(time.Second):
				t.Fatal("Session.Loss() did not publish quarantine completion")
			}
			assertProxyLossResult(t, result, StatusQuarantined, nil)
			if _, ok := <-notification; ok {
				t.Fatal("Session.Loss() published more than one result")
			}
			want := []string{"rules_quarantine", "journal_save_quarantined"}
			if got := sequence.snapshot(); !reflect.DeepEqual(got, want) {
				t.Fatalf("proxy loss sequence = %#v, want %#v", got, want)
			}
		})
	}
}

func TestFirecrackerHostTopologyPublishesTopologyLossOnlyAfterQuarantine(t *testing.T) {
	sequence := &callSequence{}
	topology := newFakeTopology(sequence)
	rules := &gatedQuarantineRules{
		fakeRules: &fakeRules{sequence: sequence},
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: newFakeProxy(sequence), Topology: topology,
		TAP: &fakeTAP{sequence: sequence}, Rules: rules,
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	notification := session.Loss()
	sequence.reset()

	go func() {
		topology.session.losses <- linuxtopology.Loss{
			TopologyGenerationID: testIdentity().TopologyGenerationID,
			Component:            linuxtopology.ProcessRoleMapping,
			Reason:               linuxtopology.LossReasonProcessExited,
		}
	}()

	select {
	case <-rules.started:
	case <-time.After(time.Second):
		t.Fatal("topology loss was not consumed by the session quarantine owner")
	}
	select {
	case <-notification:
		t.Fatal("Session.Loss() published before topology-loss quarantine completed")
	default:
	}

	close(rules.release)
	select {
	case result, ok := <-notification:
		if !ok {
			t.Fatal("Session.Loss() closed without a topology-loss quarantine result")
		}
		assertProxyLossResult(t, any(result), StatusQuarantined, nil)
	case <-time.After(time.Second):
		t.Fatal("Session.Loss() did not publish topology-loss quarantine completion")
	}
	if got, want := sequence.snapshot(), []string{"rules_quarantine", "journal_save_quarantined"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("topology loss sequence = %#v, want %#v", got, want)
	}
}

func TestFirecrackerHostTopologyRejectsTopologyWithoutLossSignal(t *testing.T) {
	sequence := &callSequence{}
	topology := newFakeTopology(sequence)
	topology.session.losses = nil
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: newFakeProxy(sequence), Topology: topology,
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	if session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()}); session != nil || !errors.Is(err, ErrTopologyPrepareFailed) {
		t.Fatalf("Prepare() = session %T, error %v, want no session and ErrTopologyPrepareFailed", session, err)
	}
	if got := sequence.snapshot(); !contains(got, "topology_stop") || !contains(got, "proxy_stop") {
		t.Fatalf("missing topology loss signal did not roll back exact resources: %#v", got)
	}
}

func TestFirecrackerHostTopologyRejectsLossPendingBeforePreparedPublication(t *testing.T) {
	tests := []struct {
		name    string
		trigger func(*fakeProxy, *fakeTopology)
		wantErr error
	}{
		{
			name: "proxy generation",
			trigger: func(proxy *fakeProxy, _ *fakeTopology) {
				close(proxy.current.loss)
			},
			wantErr: ErrProxyUnavailable,
		},
		{
			name: "topology generation",
			trigger: func(_ *fakeProxy, topology *fakeTopology) {
				topology.session.losses <- linuxtopology.Loss{
					TopologyGenerationID: testIdentity().TopologyGenerationID,
					Component:            linuxtopology.ProcessRoleKeeper,
					Reason:               linuxtopology.LossReasonProcessExited,
				}
			},
			wantErr: ErrTopologyPrepareFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sequence := &callSequence{}
			proxy := newFakeProxy(sequence)
			topology := newFakeTopology(sequence)
			test.trigger(proxy, topology)
			coordinator := mustCoordinator(t, Options{
				Enabled: true, Proxy: proxy, Topology: topology,
				TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
				Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
			})
			session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
			if session != nil || !errors.Is(err, test.wantErr) {
				t.Fatalf("Prepare() = session %T, error %v, want no session and %v", session, err, test.wantErr)
			}
			if got := sequence.snapshot(); !contains(got, "rules_quarantine") || !contains(got, "rules_cleanup") ||
				!contains(got, "topology_stop") || !contains(got, "proxy_stop") {
				t.Fatalf("pending loss did not roll back exact resources: %#v", got)
			}
		})
	}
}

func TestFirecrackerHostTopologyProxyLossPublishesSanitizedQuarantineFailure(t *testing.T) {
	sequence := &callSequence{}
	proxy := newFakeProxy(sequence)
	rules := &gatedQuarantineRules{
		fakeRules: &fakeRules{sequence: sequence},
		started:   make(chan struct{}),
		release:   make(chan struct{}),
		err:       errors.New("private rule adapter failure at /host/path"),
	}
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: rules,
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	notification := session.Loss()
	close(proxy.current.loss)
	select {
	case <-rules.started:
	case <-time.After(time.Second):
		t.Fatal("proxy loss was not consumed by the session quarantine owner")
	}
	select {
	case <-notification:
		t.Fatal("Session.Loss() published before failed quarantine completed")
	default:
	}
	close(rules.release)
	select {
	case result, ok := <-notification:
		if !ok {
			t.Fatal("Session.Loss() closed without a failure result")
		}
		assertProxyLossResult(t, any(result), StatusCleanupIncomplete, ErrQuarantineFailed)
	case <-time.After(time.Second):
		t.Fatal("Session.Loss() did not publish failed quarantine completion")
	}
}

func TestFirecrackerHostTopologyProxyLossPublishesExactlyOnceForRepeatedSignals(t *testing.T) {
	sequence := &callSequence{}
	proxy := newFakeProxy(sequence)
	proxy.current.loss = make(chan struct{}, 3)
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	notification := session.Loss()
	proxy.current.loss <- struct{}{}
	proxy.current.loss <- struct{}{}
	proxy.current.loss <- struct{}{}
	select {
	case result, ok := <-notification:
		if !ok {
			t.Fatal("Session.Loss() closed without a quarantine result")
		}
		assertProxyLossResult(t, any(result), StatusQuarantined, nil)
	case <-time.After(time.Second):
		t.Fatal("Session.Loss() did not publish repeated-signal result")
	}
	if _, ok := <-notification; ok {
		t.Fatal("Session.Loss() published more than one repeated-signal result")
	}
}

func TestFirecrackerHostTopologyNormalCleanupPublishesStoppedProxyResultWithoutDeadlock(t *testing.T) {
	sequence := &callSequence{}
	proxy := &closingStopProxy{fakeProxy: newFakeProxy(sequence)}
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
		Journal:       &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	notification := session.Loss()
	if err := session.Quarantine(context.Background(), testIdentity()); err != nil {
		t.Fatal(err)
	}
	cleanupDone := make(chan error, 1)
	go func() {
		cleanupDone <- session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), testTerminatedVMBinding())
	}()
	select {
	case err := <-cleanupDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("normal cleanup deadlocked with proxy loss watcher")
	}
	select {
	case result, ok := <-notification:
		if !ok {
			t.Fatal("Session.Loss() closed without normal-stop result")
		}
		assertProxyLossResult(t, any(result), StatusStopped, nil)
	case <-time.After(time.Second):
		t.Fatal("proxy loss watcher leaked after normal Proxy.Stop")
	}
	if _, ok := <-notification; ok {
		t.Fatal("normal cleanup published more than one proxy result")
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), testIdentity(), testTerminatedVMBinding()); err != nil {
		t.Fatal(err)
	}
	if proxy.stopCalls != 1 {
		t.Fatalf("Proxy.Stop calls = %d, want exactly one", proxy.stopCalls)
	}
}

type closingStopProxy struct {
	*fakeProxy
	closeOnce sync.Once
}

func (p *closingStopProxy) Stop(ctx context.Context, plan networkenforcement.Plan, generation ProxyGeneration) error {
	err := p.fakeProxy.Stop(ctx, plan, generation)
	if err == nil {
		p.closeOnce.Do(func() { close(p.current.loss) })
	}
	return err
}

type proxyLossResultView interface {
	Metadata() Metadata
	Err() error
}

func assertProxyLossResult(t *testing.T, raw any, wantStatus Status, wantErr error) {
	t.Helper()
	result, ok := raw.(proxyLossResultView)
	if !ok {
		t.Fatalf("Session.Loss() result type = %T, want typed proxy loss result", raw)
	}
	if metadata := result.Metadata(); metadata.Status != wantStatus {
		t.Fatalf("Session.Loss() metadata = %#v, want status %q", metadata, wantStatus)
	}
	if err := result.Err(); !errors.Is(err, wantErr) || (wantErr == nil && err != nil) {
		t.Fatalf("Session.Loss() error = %v, want %v", err, wantErr)
	} else if wantErr != nil && err.Error() != wantErr.Error() {
		t.Fatalf("Session.Loss() error = %q, want sanitized sentinel %q", err, wantErr)
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"private", "/host/path", "adapter failure"} {
		if strings.Contains(string(payload), unsafe) {
			t.Fatalf("Session.Loss() JSON leaked %q in %s", unsafe, payload)
		}
	}
}

type gatedQuarantineRules struct {
	*fakeRules
	started chan struct{}
	release chan struct{}
	err     error
}

func (r *gatedQuarantineRules) Quarantine(ctx context.Context, expected linuxrules.ExpectedRuleSet) error {
	r.sequence.add("rules_quarantine")
	close(r.started)
	select {
	case <-r.release:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
