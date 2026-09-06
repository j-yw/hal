package sandboxworker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestMinimalLaunchStartupRejectsLegacyRecoveryConfiguration(t *testing.T) {
	fixture := newMinimalLaunchDispatchFixture(t)
	options := fixture.options()
	options.RecoveryProvider = &minimalLaunchLegacyRecoveryProbe{}
	service, err := NewL8DurableService(options)
	if service != nil {
		service.Close()
	}
	if service != nil || !errors.Is(err, ErrL8ServiceUnavailable) {
		t.Fatalf("selected constructor accepted legacy recovery configuration: service=%t error=%v", service != nil, err)
	}
	if _, err := os.Stat(fixture.stateDir); !os.IsNotExist(err) {
		t.Fatalf("unsupported recovery pairing mutated state directory: %v", err)
	}
}

func TestMinimalLaunchStartupRejectsLegacyDiscriminatorBeforeReconciliation(t *testing.T) {
	for _, mutation := range []string{"same identity", "different worker", "different daemon"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newMinimalLaunchDispatchFixture(t)
			store, err := newJobStoreV2(fixture.stateDir)
			if err != nil {
				t.Fatal(err)
			}
			key, err := jobRequestKeyV2(fixture.request.DriverID, "principal-l8-worker", l8WorkerV2DaemonGeneration, *fixture.request.JobStartV2)
			if err != nil {
				t.Fatal(err)
			}
			state := storedJobStateV2{
				JobV2: JobV2{
					ContractVersion: JobContractVersionV2, ID: "job-legacy-prelaunch",
					SubmissionKey: jobSubmissionKeyV2("principal-l8-worker", l8WorkerV2DaemonGeneration, *fixture.request.JobStartV2),
					WorkerID:      "worker-l8-neutral", RuntimeDriver: RuntimeDriverMicroVM,
					State: JobStateQueued, SubmittedAt: time.Now().UTC(),
				},
				RequestKey: key, PrincipalID: "principal-l8-worker", DaemonGeneration: l8WorkerV2DaemonGeneration,
			}
			if mutation == "different worker" {
				state.JobV2.WorkerID = "other-worker"
			}
			if mutation == "different daemon" {
				state.DaemonGeneration = "other-daemon"
			}
			if err := store.save(state); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(fixture.stateDir, state.JobV2.ID+".json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewL8DurableService(fixture.options())
			if service != nil {
				service.Close()
			}
			after, readErr := os.ReadFile(path)
			if service != nil || err == nil || readErr != nil || !bytes.Equal(before, after) {
				t.Fatalf("selected startup reconciled legacy state: service=%t error=%v changed=%t read=%v", service != nil, err, !bytes.Equal(before, after), readErr)
			}
			if fixture.provider.startCalls != 0 || fixture.provider.recoverCalls != 0 {
				t.Fatal("selected startup called provider for a legacy record")
			}
		})
	}
}

func TestMinimalLaunchStartupDoesNotRecoverForeignLegacyCredentialState(t *testing.T) {
	fixture := newMinimalLaunchDispatchFixture(t)
	manager, err := newJobManagerV2(jobManagerV2Options{StateDir: fixture.stateDir, WorkerID: "other-worker", DaemonGeneration: l8WorkerV2DaemonGeneration})
	if err != nil {
		t.Fatal(err)
	}
	seed := l8D6RecentLifecycleSeed(t, fixture.request)
	seed.WorkerID = "other-worker"
	if _, _, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-l8-worker", *fixture.request.JobStartV2, seed); err != nil {
		manager.close()
		t.Fatal(err)
	}
	manager.close()
	probe := &minimalLaunchLegacyRecoveryProbe{}
	options := fixture.options()
	options.RecoveryProvider = probe
	service, err := NewL8DurableService(options)
	if service != nil {
		service.Close()
	}
	if service != nil || err == nil || probe.calls != 0 {
		t.Fatalf("selected foreign legacy recovery: service=%t error=%v callback calls=%d, want none", service != nil, err, probe.calls)
	}
}

type minimalLaunchLegacyRecoveryProbe struct{ calls int }

func (probe *minimalLaunchLegacyRecoveryProbe) BindJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialIdentitySeed) (sandboxruntime.JobCredentialRuntimeRecoveryBinding, error) {
	probe.calls++
	return nil, errors.New("test legacy recovery must not be called")
}
