package sandbox

import (
	"path/filepath"
	"testing"
	"time"
)

func TestReleaseExactHostReservationIdentityAndIdempotency(t *testing.T) {
	tests := []struct {
		name     string
		boundID  string
		status   string
		mutate   func(*SandboxLeaseExactReleaseRequest, *string)
		wantFail bool
	}{
		{name: "pre-create reservation"},
		{name: "bound reservation", boundID: "sandbox-created"},
		{name: "already released", status: SandboxLeaseStatusReleased},
		{name: "already expired", status: SandboxLeaseStatusExpired},
		{name: "same instant different zone", mutate: func(r *SandboxLeaseExactReleaseRequest, _ *string) { r.AcquiredAt = r.AcquiredAt.UTC() }},
		{name: "bound replacement", boundID: "sandbox-replaced", wantFail: true},
		{name: "missing host", mutate: func(_ *SandboxLeaseExactReleaseRequest, h *string) { *h = "" }, wantFail: true},
		{name: "wrong host", mutate: func(_ *SandboxLeaseExactReleaseRequest, h *string) { *h = "other-worker" }, wantFail: true},
		{name: "non-host resource", mutate: func(r *SandboxLeaseExactReleaseRequest, _ *string) { r.ResourceKey = "runtime:worker" }, wantFail: true},
		{name: "missing runtime binding", mutate: func(r *SandboxLeaseExactReleaseRequest, _ *string) { r.SandboxID = "" }, wantFail: true},
		{name: "wrong lease id", mutate: func(r *SandboxLeaseExactReleaseRequest, _ *string) { r.ID = "lease-other" }, wantFail: true},
		{name: "wrong name", mutate: func(r *SandboxLeaseExactReleaseRequest, _ *string) { r.SandboxName = "other" }, wantFail: true},
		{name: "wrong run", mutate: func(r *SandboxLeaseExactReleaseRequest, _ *string) { r.RunID = "run-other" }, wantFail: true},
		{name: "wrong purpose", mutate: func(r *SandboxLeaseExactReleaseRequest, _ *string) { r.Purpose = SandboxLeasePurposeAuto }, wantFail: true},
		{name: "missing time", mutate: func(r *SandboxLeaseExactReleaseRequest, _ *string) { r.AcquiredAt = time.Time{} }, wantFail: true},
		{name: "changed instant", mutate: func(r *SandboxLeaseExactReleaseRequest, _ *string) { r.AcquiredAt = r.AcquiredAt.Add(time.Nanosecond) }, wantFail: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := setSandboxHome(t)
			now := time.Date(2026, 9, 6, 12, 39, 29, 296385185, time.FixedZone("local", 8*60*60))
			store := NewSandboxLeaseStore(func() time.Time { return now })
			lease, err := store.Acquire(SandboxLeaseAcquireRequest{
				ID: "lease-reservation", SandboxID: tt.boundID, SandboxName: "alpha", ResourceKey: "host:worker",
				Holder: "private-holder", Purpose: SandboxLeasePurposeRun, RunID: "run-reservation",
			}, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if tt.status != "" {
				lease.Status = tt.status
				writeLeaseFixture(t, home, lease)
			}
			exact := SandboxLeaseExactReleaseRequest{
				ID: lease.ID, SandboxID: "sandbox-created", SandboxName: lease.SandboxName,
				ResourceKey: lease.ResourceKey, Purpose: lease.Purpose, RunID: lease.RunID, AcquiredAt: lease.AcquiredAt,
			}
			hostID := "worker"
			if tt.mutate != nil {
				tt.mutate(&exact, &hostID)
			}
			for attempt := 0; attempt < 2; attempt++ {
				_, err = store.ReleaseExactHostReservation(exact, hostID)
				if (err != nil) != tt.wantFail {
					t.Fatalf("release attempt %d error = %v, want failure %v", attempt+1, err, tt.wantFail)
				}
			}
			current, err := store.Load(lease.ID)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus := lease.Status
			if !tt.wantFail && wantStatus == SandboxLeaseStatusActive {
				wantStatus = SandboxLeaseStatusReleased
			}
			if !tt.wantFail {
				if _, err := store.Heartbeat(lease.ID, time.Hour); err == nil {
					t.Fatal("heartbeat reactivated a terminal host reservation")
				}
				current, err = store.Load(lease.ID)
				if err != nil {
					t.Fatal(err)
				}
			}
			if current.Status != wantStatus || current.SandboxID != lease.SandboxID ||
				!current.AcquiredAt.Equal(lease.AcquiredAt) || !current.ExpiresAt.Equal(lease.ExpiresAt) ||
				!current.HeartbeatAt.Equal(lease.HeartbeatAt) {
				t.Fatal("release changed stable reservation identity or unexpected status")
			}
		})
	}
}

func TestReleaseExactStillRejectsPreCreateHostReservation(t *testing.T) {
	setSandboxHome(t)
	store := NewSandboxLeaseStore(nil)
	lease, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID: "lease-pre-create", SandboxName: "alpha", ResourceKey: "host:worker", Holder: "private-holder",
		Purpose: SandboxLeasePurposeRun, RunID: "run-pre-create",
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseExact(SandboxLeaseExactReleaseRequest{
		ID: lease.ID, SandboxID: "sandbox-created", SandboxName: lease.SandboxName, ResourceKey: lease.ResourceKey,
		Purpose: lease.Purpose, RunID: lease.RunID, AcquiredAt: lease.AcquiredAt,
	}); err == nil {
		t.Fatal("ordinary exact release silently accepted an unbound reservation")
	}
	current, err := store.Load(lease.ID)
	if err != nil || current.Status != SandboxLeaseStatusActive {
		t.Fatalf("ordinary exact release changed the lease: %v", err)
	}
}

func TestReleaseExactHostReservationRevalidatesUnderStoreLock(t *testing.T) {
	home := setSandboxHome(t)
	store := NewSandboxLeaseStore(nil)
	lease, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID: "lease-locked-reservation", SandboxName: "alpha", ResourceKey: "host:worker", Holder: "private-holder",
		Purpose: SandboxLeasePurposeRun, RunID: "run-reservation",
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exact := SandboxLeaseExactReleaseRequest{
		ID: lease.ID, SandboxID: "sandbox-created", SandboxName: lease.SandboxName, ResourceKey: lease.ResourceKey,
		Purpose: lease.Purpose, RunID: lease.RunID, AcquiredAt: lease.AcquiredAt,
	}
	lock, err := lockSandboxLeaseStoreFile(filepath.Join(home, sandboxLeasesDirName, sandboxLeaseLockFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	released := make(chan error, 1)
	go func() {
		_, releaseErr := store.ReleaseExactHostReservation(exact, "worker")
		released <- releaseErr
	}()
	select {
	case err := <-released:
		t.Fatalf("host reservation release bypassed the store lock: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	// Another locked owner bound this reservation to a different container.
	// The waiting release must read and reject that identity after locking.
	lease.SandboxID = "sandbox-replaced"
	writeLeaseFixture(t, home, lease)
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-released:
		if err == nil {
			t.Fatal("release accepted a replaced reservation after acquiring the lock")
		}
	case <-time.After(time.Second):
		t.Fatal("release did not finish after unlocking")
	}
	current, err := store.Load(lease.ID)
	if err != nil || current.Status != SandboxLeaseStatusActive || current.SandboxID != lease.SandboxID {
		t.Fatalf("locked replacement was changed: %v", err)
	}
}
