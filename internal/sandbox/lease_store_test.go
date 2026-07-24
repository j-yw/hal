package sandbox

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAcquireLeasePersistsActiveLease(t *testing.T) {
	home := setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	lease, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxID:   "sandbox-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		RunID:       "run-01",
	}, 30*time.Minute)
	if err != nil {
		t.Fatalf("Acquire() unexpected error: %v", err)
	}
	if lease.Status != SandboxLeaseStatusActive {
		t.Fatalf("lease status = %q, want %q", lease.Status, SandboxLeaseStatusActive)
	}
	if !lease.AcquiredAt.Equal(now) || !lease.HeartbeatAt.Equal(now) {
		t.Fatalf("lease timestamps acquired=%s heartbeat=%s, want %s", lease.AcquiredAt, lease.HeartbeatAt, now)
	}
	if want := now.Add(30 * time.Minute); !lease.ExpiresAt.Equal(want) {
		t.Fatalf("lease ExpiresAt = %s, want %s", lease.ExpiresAt, want)
	}

	leasePath := filepath.Join(home, sandboxLeasesDirName, "lease-01.json")
	info, err := os.Stat(leasePath)
	if err != nil {
		t.Fatalf("expected lease file to exist: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("lease file perms = %o, want %o", info.Mode().Perm(), 0o600)
	}

	dirInfo, err := os.Stat(filepath.Join(home, sandboxLeasesDirName))
	if err != nil {
		t.Fatalf("expected lease dir to exist: %v", err)
	}
	if runtime.GOOS != "windows" && dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("lease dir perms = %o, want %o", dirInfo.Mode().Perm(), 0o700)
	}
	assertNoTempFiles(t, filepath.Join(home, sandboxLeasesDirName))

	loaded, err := store.Load("lease-01")
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if loaded.ID != lease.ID || loaded.ResourceKey != lease.ResourceKey || loaded.RunID != lease.RunID {
		t.Fatalf("loaded lease = %#v, want %#v", loaded, lease)
	}
}

func TestReleaseExactLeaseValidatesIdentityAndUsesStoreLock(t *testing.T) {
	setSandboxHome(t)
	now := time.Date(2026, 7, 25, 5, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })
	lease, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-l3-exact",
		SandboxID:   "sandbox-alpha",
		SandboxName: "alpha",
		ResourceKey: "host:worker-l3",
		Holder:      "holder-l3",
		Purpose:     SandboxLeasePurposeRun,
		RunID:       "run-alpha",
	}, time.Hour)
	if err != nil {
		t.Fatalf("Acquire() error: %v", err)
	}
	exact := SandboxLeaseExactReleaseRequest{
		ID:          lease.ID,
		SandboxName: lease.SandboxName,
		ResourceKey: lease.ResourceKey,
		Purpose:     lease.Purpose,
		RunID:       lease.RunID,
		AcquiredAt:  lease.AcquiredAt,
	}

	mismatch := exact
	mismatch.RunID = "run-other"
	if _, err := store.ReleaseExact(mismatch); err == nil {
		t.Fatal("ReleaseExact(mismatch) error = nil")
	}
	active, err := store.Load(lease.ID)
	if err != nil {
		t.Fatalf("Load(active) error: %v", err)
	}
	if active.Status != SandboxLeaseStatusActive {
		t.Fatalf("mismatched exact release status = %q, want active", active.Status)
	}

	leaseDir, err := sandboxLeasesDirPath()
	if err != nil {
		t.Fatalf("sandboxLeasesDirPath() error: %v", err)
	}
	lock, err := lockSandboxLeaseStoreFile(filepath.Join(leaseDir, sandboxLeaseLockFileName))
	if err != nil {
		t.Fatalf("lock lease store: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, releaseErr := store.ReleaseExact(exact)
		result <- releaseErr
	}()
	select {
	case err := <-result:
		_ = lock.Close()
		t.Fatalf("ReleaseExact() returned before store lock was released: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("unlock lease store: %v", err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("ReleaseExact() error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReleaseExact() remained blocked after store lock release")
	}
	released, err := store.ReleaseExact(exact)
	if err != nil {
		t.Fatalf("ReleaseExact(idempotent) error: %v", err)
	}
	if released.Status != SandboxLeaseStatusReleased {
		t.Fatalf("ReleaseExact() status = %q, want released", released.Status)
	}
}

func TestExpireLeasesUsesSameStoreLockAsExactRelease(t *testing.T) {
	setSandboxHome(t)
	now := time.Date(2026, 7, 25, 6, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })
	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-l3-expiry-lock",
		SandboxID:   "sandbox-alpha",
		SandboxName: "alpha",
		ResourceKey: "host:worker-l3",
		Holder:      "holder-l3",
		Purpose:     SandboxLeasePurposeRun,
		RunID:       "run-alpha",
	}, time.Hour); err != nil {
		t.Fatalf("Acquire() error: %v", err)
	}
	leaseDir, err := sandboxLeasesDirPath()
	if err != nil {
		t.Fatalf("sandboxLeasesDirPath() error: %v", err)
	}
	lock, err := lockSandboxLeaseStoreFile(filepath.Join(leaseDir, sandboxLeaseLockFileName))
	if err != nil {
		t.Fatalf("lock lease store: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, expireErr := store.ExpireLeases()
		result <- expireErr
	}()
	select {
	case err := <-result:
		_ = lock.Close()
		t.Fatalf("ExpireLeases() returned before store lock was released: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("unlock lease store: %v", err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("ExpireLeases() error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ExpireLeases() remained blocked after store lock release")
	}
}

func TestAcquireLeaseValidationLeavesNoFiles(t *testing.T) {
	home := setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	valid := SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
	}
	tests := []struct {
		name   string
		mutate func(*SandboxLeaseAcquireRequest)
	}{
		{name: "missing id", mutate: func(r *SandboxLeaseAcquireRequest) { r.ID = "" }},
		{name: "missing resource key", mutate: func(r *SandboxLeaseAcquireRequest) { r.ResourceKey = "" }},
		{name: "missing holder", mutate: func(r *SandboxLeaseAcquireRequest) { r.Holder = "" }},
		{name: "missing purpose", mutate: func(r *SandboxLeaseAcquireRequest) { r.Purpose = "" }},
		{name: "unsafe id", mutate: func(r *SandboxLeaseAcquireRequest) { r.ID = "../lease" }},
		{name: "unsupported resource prefix", mutate: func(r *SandboxLeaseAcquireRequest) { r.ResourceKey = "other:value" }},
		{name: "empty resource suffix", mutate: func(r *SandboxLeaseAcquireRequest) { r.ResourceKey = "host:" }},
		{name: "unsupported purpose", mutate: func(r *SandboxLeaseAcquireRequest) { r.Purpose = "deploy" }},
		{name: "missing sandbox name", mutate: func(r *SandboxLeaseAcquireRequest) { r.SandboxName = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := valid
			tt.mutate(&req)
			if _, err := store.Acquire(req, 30*time.Minute); err == nil {
				t.Fatal("Acquire() error = nil, want validation error")
			}
			assertNoStoreFiles(t, filepath.Join(home, sandboxLeasesDirName))
		})
	}
}

func TestAcquireLeaseAllowsNonSandboxResourcesWithoutSandboxName(t *testing.T) {
	setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	for _, resourceKey := range []string{"workspace:abc123", "host:host-01", "runtime:runtime-01"} {
		leaseID := strings.ReplaceAll(resourceKey, ":", "-")
		lease, err := store.Acquire(SandboxLeaseAcquireRequest{
			ID:          leaseID,
			ResourceKey: resourceKey,
			Holder:      "worker-01",
			Purpose:     SandboxLeasePurposeAuto,
		}, 15*time.Minute)
		if err != nil {
			t.Fatalf("Acquire(%q) unexpected error: %v", resourceKey, err)
		}
		if lease.SandboxName != "" {
			t.Fatalf("Acquire(%q) SandboxName = %q, want empty", resourceKey, lease.SandboxName)
		}
	}
}

func TestListLeasesMissingDirAndSorted(t *testing.T) {
	home := setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	leases, err := store.List()
	if err != nil {
		t.Fatalf("List() on missing dir unexpected error: %v", err)
	}
	if len(leases) != 0 {
		t.Fatalf("List() len = %d, want 0", len(leases))
	}

	for _, lease := range []*SandboxLease{
		{ID: "lease-c", ResourceKey: "workspace:z", Holder: "worker-01", Purpose: SandboxLeasePurposeAuto, Status: SandboxLeaseStatusActive},
		{ID: "lease-b", ResourceKey: "host:a", Holder: "worker-01", Purpose: SandboxLeasePurposeAuto, Status: SandboxLeaseStatusActive},
		{ID: "lease-a", ResourceKey: "host:a", Holder: "worker-02", Purpose: SandboxLeasePurposeFactory, Status: SandboxLeaseStatusReleased},
	} {
		writeLeaseFixture(t, home, lease)
	}

	leases, err = store.List()
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	got := []string{leases[0].ID, leases[1].ID, leases[2].ID}
	want := []string{"lease-a", "lease-b", "lease-c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("List() order = %v, want %v", got, want)
	}
}

func TestRemoveLease(t *testing.T) {
	setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}
	if err := store.Remove("lease-01"); err != nil {
		t.Fatalf("Remove() failed: %v", err)
	}
	if _, err := store.Load("lease-01"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load() after remove error = %v, want fs.ErrNotExist", err)
	}
	if err := store.Remove("lease-01"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Remove() missing error = %v, want fs.ErrNotExist", err)
	}
}

func TestLoadAndListLeasesPreserveCorruptJSON(t *testing.T) {
	home := setSandboxHome(t)
	store := NewSandboxLeaseStore(func() time.Time {
		return time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	})
	leaseDir := filepath.Join(home, sandboxLeasesDirName)
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() failed: %v", err)
	}
	leasePath := filepath.Join(leaseDir, "lease-01.json")
	corrupt := []byte("{not-json\n")
	if err := os.WriteFile(leasePath, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	if _, err := store.Load("lease-01"); err == nil || !strings.Contains(err.Error(), "parse lease") {
		t.Fatalf("Load() error = %v, want parse lease error", err)
	}
	assertFileBytes(t, leasePath, corrupt)

	if _, err := store.List(); err == nil || !strings.Contains(err.Error(), "parse lease") {
		t.Fatalf("List() error = %v, want parse lease error", err)
	}
	assertFileBytes(t, leasePath, corrupt)
}

func TestAcquireLeaseConflictsOnActiveResourceKey(t *testing.T) {
	home := setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire() first lease failed: %v", err)
	}

	_, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-02",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-02",
		Purpose:     SandboxLeasePurposeAuto,
	}, 30*time.Minute)
	if err == nil {
		t.Fatal("Acquire() conflict error = nil")
	}
	if !strings.Contains(err.Error(), "active lease") {
		t.Fatalf("Acquire() conflict error = %q, want active lease", err.Error())
	}
	var conflict *SandboxLeaseConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("Acquire() conflict error type = %T, want *SandboxLeaseConflictError", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, sandboxLeasesDirName, "lease-02.json")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("conflicting lease file stat error = %v, want fs.ErrNotExist", statErr)
	}
	assertNoTempFiles(t, filepath.Join(home, sandboxLeasesDirName))
}

func TestAcquireLeaseConflictUsesResourceKeyOnly(t *testing.T) {
	setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxName: "shared-name",
		ResourceKey: "sandbox:shared-name",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire() first lease failed: %v", err)
	}

	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-02",
		SandboxName: "shared-name",
		ResourceKey: "host:host-01",
		Holder:      "worker-02",
		Purpose:     SandboxLeasePurposeFactory,
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire() with same SandboxName and different ResourceKey failed: %v", err)
	}
}

func TestAcquireLeaseIgnoresReleasedAndExpiredLeases(t *testing.T) {
	home := setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	writeLeaseFixture(t, home, &SandboxLease{
		ID:          "released-lease",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		Status:      SandboxLeaseStatusReleased,
	})
	writeLeaseFixture(t, home, &SandboxLease{
		ID:          "expired-lease",
		SandboxName: "worker-box",
		ResourceKey: "sandbox:worker-box",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		Status:      SandboxLeaseStatusExpired,
	})

	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-02",
		Purpose:     SandboxLeasePurposeAuto,
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire() after released lease failed: %v", err)
	}
	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-02",
		SandboxName: "worker-box",
		ResourceKey: "sandbox:worker-box",
		Holder:      "worker-02",
		Purpose:     SandboxLeasePurposeAuto,
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire() after expired lease failed: %v", err)
	}
}

func TestAcquireLeaseConflictScanPreservesCorruptJSON(t *testing.T) {
	home := setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })
	leaseDir := filepath.Join(home, sandboxLeasesDirName)
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() failed: %v", err)
	}
	corruptPath := filepath.Join(leaseDir, "broken.json")
	corrupt := []byte("{not-json\n")
	if err := os.WriteFile(corruptPath, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	_, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
	}, 30*time.Minute)
	if err == nil || !strings.Contains(err.Error(), "parse lease") {
		t.Fatalf("Acquire() error = %v, want parse lease error", err)
	}
	assertFileBytes(t, corruptPath, corrupt)
	if _, statErr := os.Stat(filepath.Join(leaseDir, "lease-01.json")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("lease file stat error = %v, want fs.ErrNotExist", statErr)
	}
	assertNoTempFiles(t, leaseDir)
}

func TestHeartbeatLeaseUpdatesFreshnessOnly(t *testing.T) {
	setSandboxHome(t)
	current := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return current })

	lease, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxID:   "sandbox-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		RunID:       "run-01",
	}, 30*time.Minute)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}
	acquiredAt := lease.AcquiredAt

	current = current.Add(10 * time.Minute)
	heartbeat, err := store.Heartbeat("lease-01", 45*time.Minute)
	if err != nil {
		t.Fatalf("Heartbeat() failed: %v", err)
	}
	if !heartbeat.AcquiredAt.Equal(acquiredAt) {
		t.Fatalf("Heartbeat() AcquiredAt = %s, want %s", heartbeat.AcquiredAt, acquiredAt)
	}
	if !heartbeat.HeartbeatAt.Equal(current) {
		t.Fatalf("Heartbeat() HeartbeatAt = %s, want %s", heartbeat.HeartbeatAt, current)
	}
	if want := current.Add(45 * time.Minute); !heartbeat.ExpiresAt.Equal(want) {
		t.Fatalf("Heartbeat() ExpiresAt = %s, want %s", heartbeat.ExpiresAt, want)
	}
	if heartbeat.ID != lease.ID || heartbeat.ResourceKey != lease.ResourceKey || heartbeat.Holder != lease.Holder ||
		heartbeat.Purpose != lease.Purpose || heartbeat.RunID != lease.RunID || heartbeat.SandboxID != lease.SandboxID ||
		heartbeat.SandboxName != lease.SandboxName || heartbeat.Status != lease.Status {
		t.Fatalf("Heartbeat() changed identity fields: before=%#v after=%#v", lease, heartbeat)
	}
}

func TestHeartbeatLeaseStateErrorsPreserveFiles(t *testing.T) {
	home := setSandboxHome(t)
	store := NewSandboxLeaseStore(func() time.Time {
		return time.Date(2026, 6, 30, 12, 30, 0, 0, time.UTC)
	})

	if _, err := store.Heartbeat("missing", 30*time.Minute); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Heartbeat() missing error = %v, want fs.ErrNotExist", err)
	}

	for _, status := range []string{SandboxLeaseStatusReleased, SandboxLeaseStatusExpired} {
		t.Run(status, func(t *testing.T) {
			lease := &SandboxLease{
				ID:          "lease-" + status,
				SandboxName: "api-backend",
				ResourceKey: "sandbox:" + status,
				Holder:      "worker-01",
				Purpose:     SandboxLeasePurposeRun,
				Status:      status,
			}
			writeLeaseFixture(t, home, lease)
			path := filepath.Join(home, sandboxLeasesDirName, lease.ID+sandboxStateFileExt)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile() failed: %v", err)
			}

			if _, err := store.Heartbeat(lease.ID, 30*time.Minute); err == nil {
				t.Fatal("Heartbeat() error = nil, want state error")
			}
			assertFileBytes(t, path, before)
			assertNoTempFiles(t, filepath.Join(home, sandboxLeasesDirName))
		})
	}
}

func TestReleaseLeaseLifecycle(t *testing.T) {
	home := setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	lease, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
	}, 30*time.Minute)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	released, err := store.Release("lease-01")
	if err != nil {
		t.Fatalf("Release() failed: %v", err)
	}
	if released.Status != SandboxLeaseStatusReleased {
		t.Fatalf("Release() status = %q, want %q", released.Status, SandboxLeaseStatusReleased)
	}
	if !released.AcquiredAt.Equal(lease.AcquiredAt) || !released.HeartbeatAt.Equal(lease.HeartbeatAt) || !released.ExpiresAt.Equal(lease.ExpiresAt) {
		t.Fatalf("Release() changed timestamps: before=%#v after=%#v", lease, released)
	}
	path := filepath.Join(home, sandboxLeasesDirName, "lease-01.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("release should keep durable file: %v", err)
	}

	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-02",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-02",
		Purpose:     SandboxLeasePurposeAuto,
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire() after release failed: %v", err)
	}
}

func TestReleaseLeaseIdempotentAndStateErrors(t *testing.T) {
	home := setSandboxHome(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return now })

	if _, err := store.Release("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Release() missing error = %v, want fs.ErrNotExist", err)
	}

	releasedFixture := &SandboxLease{
		ID:          "released-lease",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		Status:      SandboxLeaseStatusReleased,
	}
	writeLeaseFixture(t, home, releasedFixture)
	releasedPath := filepath.Join(home, sandboxLeasesDirName, releasedFixture.ID+sandboxStateFileExt)
	beforeReleased, err := os.ReadFile(releasedPath)
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}
	released, err := store.Release(releasedFixture.ID)
	if err != nil {
		t.Fatalf("Release() already released returned error: %v", err)
	}
	if released.Status != SandboxLeaseStatusReleased {
		t.Fatalf("Release() already released status = %q", released.Status)
	}
	assertFileBytes(t, releasedPath, beforeReleased)

	expiredFixture := &SandboxLease{
		ID:          "expired-lease",
		SandboxName: "worker-box",
		ResourceKey: "sandbox:worker-box",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		Status:      SandboxLeaseStatusExpired,
	}
	writeLeaseFixture(t, home, expiredFixture)
	expiredPath := filepath.Join(home, sandboxLeasesDirName, expiredFixture.ID+sandboxStateFileExt)
	beforeExpired, err := os.ReadFile(expiredPath)
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}
	if _, err := store.Release(expiredFixture.ID); err == nil {
		t.Fatal("Release() expired error = nil, want state error")
	}
	assertFileBytes(t, expiredPath, beforeExpired)
	assertNoTempFiles(t, filepath.Join(home, sandboxLeasesDirName))
}

func TestExpireLeasesMarksStaleActiveLeases(t *testing.T) {
	home := setSandboxHome(t)
	current := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	store := NewSandboxLeaseStore(func() time.Time { return current })

	writeLeaseFixture(t, home, &SandboxLease{
		ID:          "stale-active",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		Status:      SandboxLeaseStatusActive,
		ExpiresAt:   current,
	})
	writeLeaseFixture(t, home, &SandboxLease{
		ID:          "fresh-active",
		SandboxName: "worker-box",
		ResourceKey: "sandbox:worker-box",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		Status:      SandboxLeaseStatusActive,
		ExpiresAt:   current.Add(time.Minute),
	})
	writeLeaseFixture(t, home, &SandboxLease{
		ID:          "released-lease",
		SandboxName: "released-box",
		ResourceKey: "sandbox:released-box",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		Status:      SandboxLeaseStatusReleased,
		ExpiresAt:   current.Add(-time.Hour),
	})
	writeLeaseFixture(t, home, &SandboxLease{
		ID:          "expired-lease",
		SandboxName: "expired-box",
		ResourceKey: "sandbox:expired-box",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		Status:      SandboxLeaseStatusExpired,
		ExpiresAt:   current.Add(-time.Hour),
	})

	expired, err := store.ExpireLeases()
	if err != nil {
		t.Fatalf("ExpireLeases() failed: %v", err)
	}
	if len(expired) != 1 || expired[0].ID != "stale-active" {
		t.Fatalf("ExpireLeases() expired = %#v, want stale-active only", expired)
	}
	assertLeaseStatus(t, store, "stale-active", SandboxLeaseStatusExpired)
	assertLeaseStatus(t, store, "fresh-active", SandboxLeaseStatusActive)
	assertLeaseStatus(t, store, "released-lease", SandboxLeaseStatusReleased)
	assertLeaseStatus(t, store, "expired-lease", SandboxLeaseStatusExpired)

	if _, err := os.Stat(filepath.Join(home, sandboxLeasesDirName, "stale-active.json")); err != nil {
		t.Fatalf("expired lease file should remain: %v", err)
	}
	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "new-lease",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-02",
		Purpose:     SandboxLeasePurposeAuto,
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire() after expiration failed: %v", err)
	}
	assertNoTempFiles(t, filepath.Join(home, sandboxLeasesDirName))
}

func TestExpireLeasesPreservesCorruptJSON(t *testing.T) {
	home := setSandboxHome(t)
	store := NewSandboxLeaseStore(func() time.Time {
		return time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	})
	leaseDir := filepath.Join(home, sandboxLeasesDirName)
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() failed: %v", err)
	}
	corruptPath := filepath.Join(leaseDir, "broken.json")
	corrupt := []byte("{not-json\n")
	if err := os.WriteFile(corruptPath, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	if _, err := store.ExpireLeases(); err == nil || !strings.Contains(err.Error(), "parse lease") {
		t.Fatalf("ExpireLeases() error = %v, want parse lease error", err)
	}
	assertFileBytes(t, corruptPath, corrupt)
	assertNoTempFiles(t, leaseDir)
}

func writeLeaseFixture(t *testing.T, home string, lease *SandboxLease) {
	t.Helper()

	if lease.AcquiredAt.IsZero() {
		lease.AcquiredAt = time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	}
	if lease.HeartbeatAt.IsZero() {
		lease.HeartbeatAt = lease.AcquiredAt
	}
	if lease.ExpiresAt.IsZero() {
		lease.ExpiresAt = lease.AcquiredAt.Add(30 * time.Minute)
	}
	data, err := json.MarshalIndent(lease, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() failed: %v", err)
	}
	data = append(data, '\n')

	leaseDir := filepath.Join(home, sandboxLeasesDirName)
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(leaseDir, lease.ID+sandboxStateFileExt), data, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}
}

func assertLeaseStatus(t *testing.T, store *SandboxLeaseStore, id, want string) {
	t.Helper()

	lease, err := store.Load(id)
	if err != nil {
		t.Fatalf("Load(%q) failed: %v", id, err)
	}
	if lease.Status != want {
		t.Fatalf("Load(%q) status = %q, want %q", id, lease.Status, want)
	}
}
