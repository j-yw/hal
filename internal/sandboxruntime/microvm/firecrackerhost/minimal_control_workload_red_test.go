//go:build linux

package firecrackerhost

import (
	"context"
	"testing"
	"time"
)

func TestMinimalHostWorkloadOriginalAuthenticatedReadiness(t *testing.T) {
	a := newMinimalControlAdmissionFixture(t)
	var captured *minimalControlController
	var key []byte
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		key = admission.controllerKey
		f := newMinimalControllerFixture(t, admission)
		return withMinimalWorkloadController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
			captured = c
			ready := minimalControllerRequireReady(t, c)
			transport, err := ready.workloadTransport()
			if err != nil || transport == nil {
				t.Fatal("original authenticated selected readiness has no workload transport", err)
			}
			copy := *ready
			if value, err := copy.workloadTransport(); err == nil || value != nil {
				t.Fatal("copied readiness minted workload authority")
			}
			if c.Close() != nil {
				t.Fatal("original controller did not join")
			}
			if value, err := ready.workloadTransport(); err == nil || value != nil {
				t.Fatal("closed readiness recovered workload authority")
			}
			return nil
		})
	})
	if code != 0 || captured == nil {
		t.Fatal("selected controller scope did not complete", code)
	}
	minimalControllerRequireJoined(t, captured, key)
}

func TestMinimalHostWorkloadLegacyAndZeroStayUnavailable(t *testing.T) {
	for _, ready := range []*minimalControlReadiness{nil, {}} {
		if value, err := ready.workloadTransport(); err == nil || value != nil {
			t.Fatal("zero readiness accepted")
		}
	}
	a := newMinimalControlAdmissionFixture(t)
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		f := newMinimalControllerFixture(t, admission)
		return withMinimalControlController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
			ready := minimalControllerRequireReady(t, c)
			if value, err := ready.workloadTransport(); err == nil || value != nil || !ready.Current() {
				t.Fatal("legacy readiness changed or granted work")
			}
			return nil
		})
	})
	if code != 0 {
		t.Fatal("legacy bootstrap control failed", code)
	}
}
