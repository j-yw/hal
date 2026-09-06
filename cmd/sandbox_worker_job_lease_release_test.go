package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxtarget"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestL3HostReservationReleaseFinalizesRunAutoAndRecovery(t *testing.T) {
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		for _, recovery := range []bool{false, true} {
			mode := "foreground"
			if recovery {
				mode = "recovery"
			}
			t.Run(string(purpose)+"/"+mode, func(t *testing.T) {
				store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
				manifest, err := store.LoadManifest(executionID)
				if err != nil {
					t.Fatal(err)
				}
				manifest.Purpose = purpose
				leaseStore, target := seedL3PreCreateHostReservation(t, manifest)
				// Reproduce the live boundary: output is already durable, but no
				// lease release or terminal publication has been checkpointed.
				checkpointAt := terminal.FinishedAt.Add(time.Second)
				manifest.Finalization = &sandboxexecution.FinalizationMetadata{
					ContractVersion:  sandboxexecution.FinalizationContractVersion,
					State:            sandboxexecution.FinalizationStateBlocked,
					SyncOutRequested: true,
					TerminalJobState: sandboxworker.JobStateSucceeded,
					ReasonCode:       "lease_release_failed",
					StartedAt:        &checkpointAt,
					UpdatedAt:        checkpointAt,
					Checkpoints: sandboxexecution.FinalizationCheckpoints{
						Artifacts: sandboxexecution.FinalizationCheckpoint{Completed: true, CompletedAt: &checkpointAt},
						SyncOut:   sandboxexecution.FinalizationCheckpoint{Completed: true, CompletedAt: &checkpointAt},
					},
				}
				saveL3Manifest(t, store, manifest)
				driver := &fakeSandboxWorkerJobDriver{statusJobs: []sandboxworker.Job{*terminal}}
				now := func() time.Time { return checkpointAt.Add(time.Second) }
				finalize := func() error {
					if recovery {
						deps := defaultSandboxL3FinalizationDeps()
						deps.now = now
						deps.observeJob = func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
							return cloneL3WorkerJob(terminal), nil
						}
						return finalizeSandboxL3Execution(context.Background(), store, executionID, true, deps)
					}
					if purpose == sandboxexecution.PurposeRun {
						return finalizeRunSandboxWorkerJob(context.Background(), store,
							runSandboxRequest{ExecutionID: executionID},
							runSandboxExecutionResult{RuntimeDriver: driver}, target,
							runSandboxDeps{now: now, durableLeaseStore: true})
					}
					return finalizeAutoSandboxWorkerJob(context.Background(), store,
						autoSandboxRequest{ExecutionID: executionID},
						autoSandboxExecutionResult{RuntimeDriver: driver}, target, nil,
						autoSandboxDeps{now: now, durableLeaseStore: true})
				}
				for attempt := 0; attempt < 2; attempt++ {
					if err := finalize(); err != nil {
						t.Fatalf("finalization attempt %d: %v", attempt+1, err)
					}
				}
				completed, err := store.LoadManifest(executionID)
				if err != nil {
					t.Fatal(err)
				}
				if completed.Status != sandboxexecution.StatusSucceeded || completed.Finalization.State != sandboxexecution.FinalizationStateCompleted ||
					!completed.Finalization.Checkpoints.LeaseRelease.Completed || !completed.Finalization.Checkpoints.TerminalPublication.Completed {
					t.Fatalf("status/finalization = %s/%+v", completed.Status, completed.Finalization)
				}
				if !completed.Finalization.Checkpoints.Artifacts.CompletedAt.Equal(checkpointAt) ||
					!completed.Finalization.Checkpoints.SyncOut.CompletedAt.Equal(checkpointAt) || completed.SyncOutApply != nil {
					t.Fatal("release replayed completed output work or applied output")
				}
				if driver.startCalls != 0 || driver.logsCalls != 0 || driver.copyOutCalls != 0 || driver.execCalls != 0 {
					t.Fatal("release replayed runtime work")
				}
				if err := releaseSandboxL3DurableLease(context.Background(), completed); err != nil {
					t.Fatalf("idempotent exact reservation release: %v", err)
				}
				assertL3ReservationStatus(t, leaseStore, manifest.Lease.ID, sandbox.SandboxLeaseStatusReleased)
				assertL3ReservationStatus(t, leaseStore, "lease-decoy", sandbox.SandboxLeaseStatusActive)
			})
		}
	}
}

func TestL3HostReservationReleaseRejectsIdentityMismatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sandboxexecution.Manifest)
	}{
		{"missing reference host", func(m *sandboxexecution.Manifest) { m.Lease.HostID = "" }},
		{"wrong reference host", func(m *sandboxexecution.Manifest) { m.Lease.HostID = "other-worker" }},
		{"missing manifest host", func(m *sandboxexecution.Manifest) { m.Host = nil }},
		{"wrong manifest host", func(m *sandboxexecution.Manifest) { m.Host.ID = "other-worker" }},
		{"wrong resource", func(m *sandboxexecution.Manifest) { m.Lease.ResourceKey = "host:other-worker" }},
		{"wrong acquired instant", func(m *sandboxexecution.Manifest) { m.Lease.AcquiredAt = m.Lease.AcquiredAt.Add(time.Nanosecond) }},
		{"wrong run", func(m *sandboxexecution.Manifest) { m.Lease.RunID = "other-run" }},
		{"wrong name", func(m *sandboxexecution.Manifest) { m.SandboxName = "other-sandbox" }},
		{"wrong lease", func(m *sandboxexecution.Manifest) { m.Lease.ID = "lease-decoy" }},
		{"wrong purpose", func(m *sandboxexecution.Manifest) { m.Purpose = sandboxexecution.PurposeAuto }},
		{"missing sandbox id", func(m *sandboxexecution.Manifest) { m.SandboxID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := l3Manifest("run-reservation", "alpha", time.Date(2026, 7, 25, 4, 0, 0, 0, time.UTC), "job-reservation", sandboxworker.JobStateRunning, 0)
			leaseStore, _ := seedL3PreCreateHostReservation(t, manifest)
			leaseID := manifest.Lease.ID
			tt.mutate(manifest)
			err := releaseSandboxL3DurableLease(context.Background(), manifest)
			if err == nil {
				t.Fatal("mismatched reservation was released")
			}
			for _, forbidden := range []string{leaseID, "other-worker", "other-sandbox", "holder", "private", "token="} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("release error disclosed identity or secret-bearing data: %q", err.Error())
				}
			}
			assertL3ReservationStatus(t, leaseStore, leaseID, sandbox.SandboxLeaseStatusActive)
			assertL3ReservationStatus(t, leaseStore, "lease-decoy", sandbox.SandboxLeaseStatusActive)
		})
	}
}

func seedL3PreCreateHostReservation(t *testing.T, manifest *sandboxexecution.Manifest) (*sandbox.SandboxLeaseStore, *sandbox.SandboxState) {
	t.Helper()
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	// Exercise the real scheduler acquisition seam before Create assigns ID,
	// including a local-zone timestamp later decoded through manifest JSON.
	acquiredAt := manifest.StartedAt.In(time.FixedZone("smoke-local", 8*60*60))
	leaseStore := sandbox.NewSandboxLeaseStore(func() time.Time { return acquiredAt })
	target := &sandbox.SandboxState{Name: manifest.SandboxName, Host: manifest.Host, Runtime: manifest.Runtime}
	lease, err := acquireSandboxCommandLease(sandboxCommandScheduledTargetRequest{
		Purpose: string(manifest.Purpose), RunID: manifest.ID,
	}, target, sandboxtarget.SchedulerLeaseRequirement{
		ResourceKey: "host:" + manifest.Host.ID, Purpose: sandboxtarget.Purpose(manifest.Purpose),
	}, sandboxCommandScheduledTargetDeps{acquireLease: leaseStore.Acquire})
	if err != nil {
		t.Fatal(err)
	}
	if lease.SandboxID != "" {
		t.Fatal("scheduler fixture did not reserve before runtime creation")
	}
	target.ID = manifest.SandboxID
	target.Lease = sandboxLeaseRefFromLease(lease, target)
	manifest.Lease = target.Lease
	if _, err := leaseStore.Acquire(sandbox.SandboxLeaseAcquireRequest{
		ID: "lease-decoy", SandboxID: "decoy", SandboxName: "decoy", ResourceKey: "host:decoy",
		Holder: "private-holder", Purpose: sandbox.SandboxLeasePurposeRun, RunID: "run-decoy",
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	return leaseStore, target
}

func assertL3ReservationStatus(t *testing.T, store *sandbox.SandboxLeaseStore, id, status string) {
	t.Helper()
	lease, err := store.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Status != status {
		t.Fatalf("lease status = %q, want %q", lease.Status, status)
	}
}
