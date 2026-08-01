package l7network

import (
	"context"
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
			select {
			case <-notification:
			case <-time.After(time.Second):
				t.Fatal("Session.Loss() did not publish quarantine completion")
			}
			if metadata := session.Metadata(); metadata.Status != StatusQuarantined {
				t.Fatalf("proxy loss metadata = %#v, want quarantined result", metadata)
			}
			want := []string{"rules_quarantine", "journal_save_quarantined"}
			if got := sequence.snapshot(); !reflect.DeepEqual(got, want) {
				t.Fatalf("proxy loss sequence = %#v, want %#v", got, want)
			}
		})
	}
}

type gatedQuarantineRules struct {
	*fakeRules
	started chan struct{}
	release chan struct{}
}

func (r *gatedQuarantineRules) Quarantine(ctx context.Context, expected linuxrules.ExpectedRuleSet) error {
	r.sequence.add("rules_quarantine")
	close(r.started)
	select {
	case <-r.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
