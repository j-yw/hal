package cmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestL3RecoveryCommandsFinalizeConcreteDurableActionsWithoutForbiddenWork(t *testing.T) {
	for _, commandName := range []string{"recover", "sync-out"} {
		t.Run(commandName, func(t *testing.T) {
			script := &l3WorkerScript{
				jobState:         sandboxworker.JobStateSucceeded,
				logCursor:        1,
				panicOnForbidden: true,
				pages: map[uint64]sandboxworker.JobLogsResponse{
					0: {
						ContractVersion: sandboxworker.JobContractVersion,
						JobID:           "job-alpha",
						Records: []sandboxworker.JobLogRecord{{
							Cursor:    1,
							Stream:    sandboxworker.JobLogStreamStdout,
							Data:      "terminal output\n",
							Timestamp: time.Date(2026, 7, 25, 2, 0, 2, 0, time.UTC),
						}},
						NextCursor: 1,
					},
				},
			}
			harness := newL3WorkerHarness(t, script)
			harness.seed("alpha", "run-alpha", "job-alpha")
			leaseStore := seedL3RecoveryLease(t, "run-alpha", "alpha")

			originalFactories := defaultSandboxRuntimeDriverFactories
			defaultSandboxRuntimeDriverFactories = func() sandboxRuntimeDriverFactories {
				return sandboxRuntimeDriverFactories{
					sshMachine: func(sandbox.Provider) sandboxruntime.Driver {
						panic("L3 recovery resolved a provider")
					},
					rootlessPodman: func() sandboxruntime.Driver {
						panic("L3 recovery constructed a host runtime")
					},
					microVM: func() sandboxruntime.Driver {
						panic("L3 recovery constructed a microVM runtime")
					},
				}
			}
			t.Cleanup(func() {
				defaultSandboxRuntimeDriverFactories = originalFactories
			})

			for attempt := 0; attempt < 2; attempt++ {
				stdout, stderr, err := runL3SandboxLeaf(
					context.Background(),
					commandName,
					[]string{"alpha", "--run", "run-alpha"},
				)
				if err != nil {
					t.Fatalf("%s attempt %d: %v\nstdout:\n%s\nstderr:\n%s", commandName, attempt+1, err, stdout, stderr)
				}
			}

			store, err := sandboxexecution.DefaultStore()
			if err != nil {
				t.Fatalf("open execution store: %v", err)
			}
			manifest, err := store.LoadManifest("run-alpha")
			if err != nil {
				t.Fatalf("load finalized manifest: %v", err)
			}
			if manifest.Status != sandboxexecution.StatusSucceeded ||
				manifest.Finalization == nil ||
				manifest.Finalization.State != sandboxexecution.FinalizationStateCompleted {
				t.Fatalf("finalized manifest = %#v", manifest)
			}
			checkpoints := manifest.Finalization.Checkpoints
			if !checkpoints.Artifacts.Completed || !checkpoints.LeaseRelease.Completed ||
				!checkpoints.TerminalPublication.Completed {
				t.Fatalf("finalization checkpoints = %#v", checkpoints)
			}
			if commandName == "sync-out" {
				if !manifest.Finalization.SyncOutRequested || !checkpoints.SyncOut.Completed {
					t.Fatalf("sync-out finalization = %#v", manifest.Finalization)
				}
				if manifest.SyncOut == nil {
					t.Fatal("sync-out summary was not persisted")
				}
				if manifest.SyncOutApply != nil {
					t.Fatalf("sync-out recovery implicitly applied to the host: %#v", manifest.SyncOutApply)
				}
				assertL3RecoverySyncOutSummarySafe(t, manifest.SyncOut)
			} else if manifest.SyncOut != nil || checkpoints.SyncOut.Completed {
				t.Fatalf("ordinary recovery persisted sync-out state: %#v / %#v", manifest.SyncOut, checkpoints.SyncOut)
			}
			assertL3RecoveryArtifactsUnique(t, manifest)

			released, err := leaseStore.Load("lease-run-alpha")
			if err != nil {
				t.Fatalf("load released lease: %v", err)
			}
			if released.Status != sandbox.SandboxLeaseStatusReleased {
				t.Fatalf("exact lease status = %q, want released", released.Status)
			}
			decoy, err := leaseStore.Load("lease-decoy")
			if err != nil {
				t.Fatalf("load decoy lease: %v", err)
			}
			if decoy.Status != sandbox.SandboxLeaseStatusActive {
				t.Fatalf("unrelated lease status = %q, want active", decoy.Status)
			}
			if _, err := os.Stat(harness.hostMutationMarker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s invoked provider/apply host mutation; marker stat error = %v", commandName, err)
			}
		})
	}
}

func TestL3RecoveryUnknownAndInterruptedNeverCrossConcreteActionBoundaries(t *testing.T) {
	for _, state := range []string{sandboxworker.JobStateUnknown, sandboxworker.JobStateInterrupted} {
		t.Run(state, func(t *testing.T) {
			harness := newL3WorkerHarness(t, &l3WorkerScript{
				jobState:               state,
				panicOnForbidden:       true,
				panicUnlessObservation: true,
				pages:                  map[uint64]sandboxworker.JobLogsResponse{},
			})
			harness.seed("alpha", "run-alpha", "job-alpha")
			leaseStore := seedL3RecoveryLease(t, "run-alpha", "alpha")

			_, _, err := runL3SandboxLeaf(
				context.Background(),
				"sync-out",
				[]string{"alpha", "--run", "run-alpha"},
			)
			if err == nil || !strings.Contains(err.Error(), "terminal_proof_unavailable") {
				t.Fatalf("%s recovery error = %v, want terminal proof boundary", state, err)
			}

			store, storeErr := sandboxexecution.DefaultStore()
			if storeErr != nil {
				t.Fatalf("open execution store: %v", storeErr)
			}
			manifest, loadErr := store.LoadManifest("run-alpha")
			if loadErr != nil {
				t.Fatalf("load blocked manifest: %v", loadErr)
			}
			if manifest.Finalization == nil ||
				manifest.Finalization.State != sandboxexecution.FinalizationStateBlocked ||
				manifest.Finalization.ReasonCode != "terminal_proof_unavailable" ||
				manifest.Finalization.Checkpoints.Artifacts.Completed ||
				manifest.Finalization.Checkpoints.SyncOut.Completed ||
				manifest.Finalization.Checkpoints.LeaseRelease.Completed {
				t.Fatalf("%s blocked finalization = %#v", state, manifest.Finalization)
			}
			lease, leaseErr := leaseStore.Load("lease-run-alpha")
			if leaseErr != nil {
				t.Fatalf("load exact lease: %v", leaseErr)
			}
			if lease.Status != sandbox.SandboxLeaseStatusActive {
				t.Fatalf("%s exact lease status = %q, want active", state, lease.Status)
			}
			if manifest.SyncOut != nil || manifest.SyncOutApply != nil {
				t.Fatalf("%s persisted mutable sync-out state: %#v / %#v", state, manifest.SyncOut, manifest.SyncOutApply)
			}
			if _, statErr := os.Stat(harness.hostMutationMarker); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s invoked provider/apply host mutation; marker stat error = %v", state, statErr)
			}
		})
	}
}

func seedL3RecoveryLease(t *testing.T, executionID, sandboxName string) *sandbox.SandboxLeaseStore {
	t.Helper()
	now := time.Date(2026, 7, 25, 2, 0, 0, 0, time.UTC)
	store := sandbox.NewSandboxLeaseStore(func() time.Time { return now })
	exact, err := store.Acquire(sandbox.SandboxLeaseAcquireRequest{
		ID:          "lease-" + executionID,
		SandboxID:   "sandbox-" + sandboxName,
		SandboxName: sandboxName,
		ResourceKey: "host:worker-l3",
		Holder:      "holder-" + executionID,
		Purpose:     sandbox.SandboxLeasePurposeRun,
		RunID:       executionID,
	}, time.Hour)
	if err != nil {
		t.Fatalf("acquire exact recovery lease: %v", err)
	}
	if _, err := store.Acquire(sandbox.SandboxLeaseAcquireRequest{
		ID:          "lease-decoy",
		SandboxID:   "sandbox-decoy",
		SandboxName: "decoy",
		ResourceKey: "runtime:decoy",
		Holder:      "holder-decoy",
		Purpose:     sandbox.SandboxLeasePurposeRun,
		RunID:       "run-decoy",
	}, time.Hour); err != nil {
		t.Fatalf("acquire decoy recovery lease: %v", err)
	}

	executionStore, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	manifest, err := executionStore.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("load recovery manifest: %v", err)
	}
	manifest.Workspace = &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		Branch:      "feature/l3-recovery",
		SyncRef:     "base-l3-recovery",
	}
	manifest.Lease = &sandbox.SandboxLeaseRef{
		ID:            exact.ID,
		HostID:        "worker-l3",
		HostName:      "worker-l3",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
		ResourceKey:   exact.ResourceKey,
		Purpose:       exact.Purpose,
		RunID:         exact.RunID,
		AcquiredAt:    exact.AcquiredAt,
		ExpiresAt:     exact.ExpiresAt,
	}
	if err := executionStore.SaveManifest(manifest); err != nil {
		t.Fatalf("save recovery lease reference: %v", err)
	}
	return store
}

func assertL3RecoveryArtifactsUnique(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	if manifest.ArtifactMetadata == nil {
		t.Fatal("artifact metadata was not persisted")
	}
	seen := map[string]bool{}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		key := artifact.ID + "\x00" + artifact.Path
		if seen[key] {
			t.Errorf("artifact metadata duplicated stable identity %q", key)
		}
		seen[key] = true
	}
	for _, requiredID := range []string{"prd", "progress", "recovery-patch", "reports-archive"} {
		found := false
		for _, artifact := range manifest.ArtifactMetadata.Collected {
			if artifact.ID == requiredID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("artifact metadata missing %q: %#v", requiredID, manifest.ArtifactMetadata.Collected)
		}
	}
}

func assertL3RecoverySyncOutSummarySafe(t *testing.T, summary *sandboxworkspace.SyncOutSummary) {
	t.Helper()
	payload := strings.ToLower(strings.TrimSpace(summary.Workspace.InputSource + " " + summary.Workspace.Branch + " " + summary.Workspace.SyncRef))
	for _, forbidden := range []string{"/home/", "/tmp/", "token=", "https://"} {
		if strings.Contains(payload, forbidden) {
			t.Errorf("sync-out summary leaked %q: %#v", forbidden, summary)
		}
	}
}
