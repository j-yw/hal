//go:build linux

package firecrackerhost

import (
	"context"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8RuntimeOwnerRecoveryBindingStopReapDirectWaitOfTestChild(t *testing.T) {
	path, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep executable unavailable")
	}
	command := exec.Command(path, "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := false
	defer func() {
		if !reaped {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	seed := l8RuntimeOwnerTestSeed()
	now := time.Now().UTC()
	var waitOnce sync.Once
	binding := &l8RuntimeOwnerRecoveryBinding{
		seed: seed,
		now:  func() time.Time { return now },
		proveAbsence: func(ctx context.Context) (l8RuntimeOwnerAbsenceObservation, error) {
			observation, err := containL8RuntimeOwnerChild(l8RuntimeOwnerContainmentOps{
				RecordStopping: func() (uint64, error) { return 1, nil },
				Terminate:      func() error { return command.Process.Signal(syscall.SIGTERM) },
				Wait: func(waitCtx context.Context) (bool, error) {
					done := make(chan struct{})
					go func() {
						waitOnce.Do(func() {
							_ = command.Wait()
							reaped = true
						})
						close(done)
					}()
					select {
					case <-done:
						return true, nil
					case <-waitCtx.Done():
						return false, nil
					}
				},
				Kill:            func() error { return command.Process.Kill() },
				RecordAbsent:    func(l8RuntimeOwnerAbsenceObservation) (uint64, error) { return 1, nil },
				RecordUncertain: func() (uint64, error) { return 1, nil },
				Now:             func() time.Time { return now },
			})
			return observation, err
		},
	}
	proof, err := binding.StopReapJobCredentialRuntime(context.Background())
	if err != nil {
		t.Fatalf("direct-wait stop/reap: %v", err)
	}
	if err := sandboxruntime.ValidateJobCredentialRuntimeAbsenceProof(proof, seed, now); err != nil {
		t.Fatalf("direct-wait proof: %v", err)
	}
	if !reaped {
		t.Fatal("direct-wait stop/reap did not Wait the child")
	}
}

func TestL8RuntimeOwnerRecoveryBindingStopReapReplacementDoubleProc(t *testing.T) {
	bootID, err := readL8RuntimeOwnerHostBootID()
	if err != nil {
		t.Fatal(err)
	}
	seed := l8RuntimeOwnerTestSeed()
	record := l8RuntimeOwnerTestRecord(t, seed, bootID)
	record.State, record.ControllerState, record.Revision = "running", "unclaimed", 2
	record.AbsenceKind, record.AbsenceRevision, record.AbsenceObservedAtUnixNano = "", 0, 0
	record.FirecrackerPID = 1<<30 - 7
	now := time.Now().UTC()
	binding := &l8RuntimeOwnerRecoveryBinding{
		seed: seed,
		now:  func() time.Time { return now },
		proveAbsence: func(context.Context) (l8RuntimeOwnerAbsenceObservation, error) {
			return containL8RuntimeOwnerReplacement(record, l8RuntimeOwnerReplacementOps{
				CurrentBootID: func() (string, error) { return bootID, nil },
				InspectSupervisor: func(uint32) (l8RuntimeOwnerProcessObservation, bool, error) {
					return l8RuntimeOwnerProcessObservation{}, false, nil
				},
				InspectChild: func(uint32) (l8RuntimeOwnerProcessObservation, bool, error) {
					return l8RuntimeOwnerProcessObservation{}, false, nil
				},
				ProcessAbsent: func(uint32) (bool, error) { return true, nil },
				AcquisitionBarrier: func() error {
					absent, err := inspectL8RuntimeOwnerProcessAbsent(record.FirecrackerPID)
					if err != nil || !absent {
						return errL8RuntimeOwnerInvalid
					}
					return nil
				},
				RecordAbsent:    func(l8RuntimeOwnerAbsenceObservation) (uint64, error) { return record.Revision + 1, nil },
				RecordUncertain: func() (uint64, error) { return record.Revision + 1, nil },
				Now:             func() time.Time { return now },
			})
		},
	}
	proof, err := binding.StopReapJobCredentialRuntime(context.Background())
	if err != nil {
		t.Fatalf("replacement double-/proc stop/reap: %v", err)
	}
	if err := sandboxruntime.ValidateJobCredentialRuntimeAbsenceProof(proof, seed, now); err != nil {
		t.Fatalf("replacement proof: %v", err)
	}
}
