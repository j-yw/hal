//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package sandboxworker

import (
	"path/filepath"
	"testing"
)

func TestWorkerServiceOmitsDurableJobsWithoutStateLockSupport(t *testing.T) {
	registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: RuntimeDriverRootlessPodman})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:    "worker-without-job-locks",
		HostKind:    HostKindLocal,
		Registry:    registry,
		JobStateDir: filepath.Join(t.TempDir(), "jobs"),
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	if service.jobs != nil {
		t.Fatal("service enabled durable jobs without an exclusive state lock")
	}
	for _, operation := range []string{OperationJobStart, OperationJobStatus, OperationJobLogs, OperationJobCancel} {
		if stringSliceContains(service.Capabilities().SupportedOperations, operation) {
			t.Fatalf("service advertised unavailable operation %q", operation)
		}
	}
}
