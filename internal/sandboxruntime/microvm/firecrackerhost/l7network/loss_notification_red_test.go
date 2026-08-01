package l7network

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
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
