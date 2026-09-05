package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestSandboxSchedulerRejectionsStayEndpointSafe(t *testing.T) {
	now := time.Date(2026, 7, 1, 11, 0, 0, 0, time.UTC)
	unsafeEndpoint := workerUnsafeRemoteEndpoint()
	unsafePath := "/Users/alice/.ssh/id_rsa"
	unsafeToken := "ghp_scheduler_secret_123"
	unsafeRemote := "https://alice:" + unsafeToken + "@github.com/org/repo.git"

	tests := []struct {
		name string
		deps sandboxCommandScheduledTargetDeps
	}{
		{
			name: "host list failure",
			deps: sandboxCommandScheduledTargetDeps{
				listHosts: func() ([]*sandbox.SandboxHost, error) {
					return nil, fmt.Errorf("dial %s with key %s and token %s", unsafeEndpoint, unsafePath, unsafeToken)
				},
				listLeases: func() ([]*sandbox.SandboxLease, error) { return nil, nil },
				now:        func() time.Time { return now },
			},
		},
		{
			name: "lease list failure",
			deps: sandboxCommandScheduledTargetDeps{
				listHosts: func() ([]*sandbox.SandboxHost, error) {
					return []*sandbox.SandboxHost{sandboxSchedulerSafetyHost("worker-safety", unsafeEndpoint)}, nil
				},
				listLeases: func() ([]*sandbox.SandboxLease, error) {
					return nil, fmt.Errorf("read %s through %s for %s", unsafePath, unsafeEndpoint, unsafeRemote)
				},
				now: func() time.Time { return now },
			},
		},
		{
			name: "unhealthy host",
			deps: sandboxCommandScheduledTargetDeps{
				listHosts: func() ([]*sandbox.SandboxHost, error) {
					host := sandboxSchedulerSafetyHost("worker-safety", unsafeEndpoint)
					host.Health.Status = "degraded:" + unsafeEndpoint
					host.Health.Message = "token " + unsafeToken + " path " + unsafePath
					return []*sandbox.SandboxHost{host}, nil
				},
				listLeases: func() ([]*sandbox.SandboxLease, error) { return nil, nil },
				now:        func() time.Time { return now },
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveSandboxCommandScheduledTarget(sandboxCommandScheduledTargetRequest{
				Purpose:        sandbox.SandboxLeasePurposeRun,
				SandboxHostID:  "worker-safety",
				SandboxRuntime: sandboxruntime.DriverRootlessPodman,
				ProjectDir:     t.TempDir(),
				Repository:     unsafeRemote,
				Branch:         "feature/scheduler-safety",
				RunID:          "scheduler-safety-run",
			}, tt.deps)
			if err == nil {
				t.Fatal("resolveSandboxCommandScheduledTarget() error = nil, want scheduler rejection")
			}
			assertSchedulerSafetyStringOmits(t, err.Error(), unsafeEndpoint, unsafePath, unsafeToken, unsafeRemote, "alice:"+unsafeToken)
		})
	}
}

func TestSandboxSchedulerLeaseAcquisitionErrorIsSanitizedAndUnwrapsCause(t *testing.T) {
	now := time.Date(2026, 7, 1, 11, 5, 0, 0, time.UTC)
	unsafeErr := errors.New("write unix:///tmp/private/worker-1.sock under /Users/alice/.hal with token ghp_scheduler_secret_456")

	_, err := resolveSandboxCommandScheduledTarget(sandboxCommandScheduledTargetRequest{
		Purpose:        sandbox.SandboxLeasePurposeRun,
		SandboxHostID:  "worker-safety",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		ProjectDir:     t.TempDir(),
		Branch:         "feature/scheduler-safety",
		RunID:          "scheduler-safety-lease",
	}, sandboxCommandScheduledTargetDeps{
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{sandboxSchedulerSafetyHost("worker-safety", workerSafeUnixEndpoint())}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) { return nil, nil },
		now:        func() time.Time { return now },
		acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
			return nil, unsafeErr
		},
	})
	if err == nil {
		t.Fatal("resolveSandboxCommandScheduledTarget() error = nil, want lease acquisition failure")
	}
	if !errors.Is(err, unsafeErr) {
		t.Fatalf("error does not unwrap original acquisition cause: %v", err)
	}
	if err.Error() != "acquire sandbox lease failed" {
		t.Fatalf("error = %q, want stable sanitized acquisition failure", err.Error())
	}
	assertSchedulerSafetyStringOmits(t, err.Error(), "unix:///tmp/private/worker-1.sock", "/Users/alice/.hal", "ghp_scheduler_secret_456")
}

func TestSandboxSchedulerLeaseMetadataOmitsHolderEndpointAndRepositoryDetails(t *testing.T) {
	now := time.Date(2026, 7, 1, 11, 10, 0, 0, time.UTC)
	unsafeHolder := "run:holder-token-ghp_scheduler_secret_789"
	unsafeRemote := "https://alice:ghp_scheduler_secret_789@example.com/org/repo.git"

	target, err := resolveSandboxCommandScheduledTarget(sandboxCommandScheduledTargetRequest{
		Purpose:        sandbox.SandboxLeasePurposeFactory,
		SandboxHostID:  "worker-safety",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		ProjectDir:     t.TempDir(),
		Repository:     unsafeRemote,
		Branch:         "feature/scheduler-safety",
		RunID:          "scheduler-safety-metadata",
	}, sandboxCommandScheduledTargetDeps{
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{sandboxSchedulerSafetyHost("worker-safety", workerSafeUnixEndpoint())}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) { return nil, nil },
		now:        func() time.Time { return now },
		acquireLease: func(req sandbox.SandboxLeaseAcquireRequest, ttl time.Duration) (*sandbox.SandboxLease, error) {
			return &sandbox.SandboxLease{
				ID:          req.ID,
				SandboxName: req.SandboxName,
				ResourceKey: req.ResourceKey,
				Holder:      unsafeHolder,
				Purpose:     req.Purpose,
				RunID:       req.RunID,
				AcquiredAt:  now,
				ExpiresAt:   now.Add(ttl),
				HeartbeatAt: now,
				Status:      sandbox.SandboxLeaseStatusActive,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("resolveSandboxCommandScheduledTarget() error: %v", err)
	}
	if target == nil || target.Lease == nil {
		t.Fatalf("target lease = %#v, want safe lease ref", target)
	}
	if target.Lease.Holder != "" {
		t.Fatalf("target lease holder = %q, want redacted", target.Lease.Holder)
	}

	payload, err := json.Marshal(target.Lease)
	if err != nil {
		t.Fatalf("json.Marshal(lease) error: %v", err)
	}
	assertSchedulerSafetyStringOmits(t, string(payload), unsafeHolder, "ghp_scheduler_secret_789", workerSafeUnixEndpoint(), unsafeRemote, "example.com")
}

func sandboxSchedulerSafetyHost(id, endpoint string) *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:       id,
		Name:     "worker safety",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: endpoint,
		SupportedRuntimes: []string{
			sandboxruntime.DriverRootlessPodman,
		},
		Capacity: &sandbox.HostCapacity{
			MaxConcurrentSandboxes: 2,
		},
		Health: &sandbox.HostHealth{
			Status: "healthy",
		},
		Security: workerRootlessHostSecurity(),
	}
}

func assertSchedulerSafetyStringOmits(t *testing.T, value string, forbidden ...string) {
	t.Helper()
	for _, needle := range forbidden {
		if strings.TrimSpace(needle) == "" {
			continue
		}
		if strings.Contains(value, needle) {
			t.Fatalf("value leaked %q: %s", needle, value)
		}
	}
}
