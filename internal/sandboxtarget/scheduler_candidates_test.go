package sandboxtarget

import (
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestEnumerateSchedulerCandidatesUsesInjectedCachedHostLister(t *testing.T) {
	var listed bool
	candidates := EnumerateSchedulerCandidates(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			listed = true
			return []*sandbox.SandboxHost{
				{ID: "worker-z", Name: "zeta", Kind: sandbox.SandboxHostKindWorker},
				nil,
				{ID: "worker-b", Name: "builder", Kind: sandbox.SandboxHostKindWorker},
				{ID: "worker-a", Name: "builder", Kind: sandbox.SandboxHostKindWorker},
			}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called during scheduler candidate enumeration")
			return nil, nil
		},
		LoadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("LoadSandbox should not be called during scheduler candidate enumeration")
			return nil, nil
		},
	})

	if !listed {
		t.Fatal("cached host lister was not called")
	}
	if candidates.Failed() || candidates.Empty() {
		t.Fatalf("candidates = %#v, want cached host candidates", candidates)
	}
	got := schedulerCandidateHostIDs(candidates.Candidates)
	want := []string{"worker-a", "worker-b", "worker-z"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("candidate host order = %v, want %v", got, want)
	}
	for _, candidate := range candidates.Candidates {
		if candidate.Host == nil {
			t.Fatalf("candidate = %#v, want durable host metadata", candidate)
		}
		if candidate.Identity.HostID != candidate.Host.ID || candidate.Identity.HostName != candidate.Host.Name || candidate.Identity.HostKind != candidate.Host.Kind {
			t.Fatalf("candidate identity/host = %#v/%#v, want host identity from cached metadata", candidate.Identity, candidate.Host)
		}
		if candidate.Identity.RuntimeDriver != "" || candidate.Identity.RuntimeID != "" || candidate.Identity.IsolationLevel != "" {
			t.Fatalf("candidate identity = %#v, want host-only identity before runtime filtering", candidate.Identity)
		}
	}
}

func TestScheduleSelectsFirstCachedCandidateByNameThenID(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{ID: "worker-z", Name: "zeta", Kind: sandbox.SandboxHostKindWorker},
				{ID: "worker-b", Name: "builder", Kind: sandbox.SandboxHostKindWorker},
				{ID: "worker-a", Name: "builder", Kind: sandbox.SandboxHostKindWorker},
			}, nil
		},
	})

	if !result.Selected() || result.Rejected() {
		t.Fatalf("result = %#v, want selected cached host candidate", result)
	}
	if result.DecisionReason != SchedulerDecisionReasonRankedCandidate {
		t.Fatalf("decision reason = %q, want %q", result.DecisionReason, SchedulerDecisionReasonRankedCandidate)
	}
	if result.Selection.Identity.HostID != "worker-a" || result.Selection.Identity.HostName != "builder" {
		t.Fatalf("selection identity = %#v, want name-then-ID first host", result.Selection.Identity)
	}
	if result.Selection.Host == nil || result.Selection.Host.ID != "worker-a" {
		t.Fatalf("selection host = %#v, want cloned cached host metadata", result.Selection.Host)
	}
}

func TestEnumerateSchedulerCandidatesRejectsMissingCachedHostLister(t *testing.T) {
	candidates := EnumerateSchedulerCandidates(SchedulerRequest{
		Intent:        SchedulerIntentExplicitTarget,
		HostID:        " worker-a ",
		RuntimeDriver: " rootless_podman ",
	}, CachedState{})

	if !candidates.Failed() {
		t.Fatalf("candidates = %#v, want invalid request rejection", candidates)
	}
	if candidates.Rejection.Reason != FailureReasonInvalidRequest ||
		candidates.Rejection.HostID != "worker-a" ||
		candidates.Rejection.RuntimeDriver != "rootless_podman" ||
		candidates.Rejection.Error() != "cached host lister is required" {
		t.Fatalf("rejection = %#v, want deterministic missing-lister rejection", candidates.Rejection)
	}
}

func TestEnumerateSchedulerCandidatesRejectsEmptyCachedHostSet(t *testing.T) {
	for _, tt := range []struct {
		name  string
		hosts []*sandbox.SandboxHost
	}{
		{name: "nil slice", hosts: nil},
		{name: "empty slice", hosts: []*sandbox.SandboxHost{}},
		{name: "nil hosts only", hosts: []*sandbox.SandboxHost{nil, nil}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			candidates := EnumerateSchedulerCandidates(SchedulerRequest{
				Intent: SchedulerIntentAnyEligibleTarget,
			}, CachedState{
				ListHosts: func() ([]*sandbox.SandboxHost, error) {
					return tt.hosts, nil
				},
			})

			if !candidates.Failed() || !candidates.Empty() {
				t.Fatalf("candidates = %#v, want deterministic empty-host rejection", candidates)
			}
			if candidates.Rejection.Reason != FailureReasonHostNotFound ||
				candidates.Rejection.Error() != "no cached sandbox hosts" {
				t.Fatalf("rejection = %#v, want no cached hosts rejection", candidates.Rejection)
			}
		})
	}
}

func TestSchedulePropagatesEmptyCachedHostSetAsSchedulerRejection(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return nil, nil
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want rejected scheduler result", result)
	}
	if result.Rejection.Reason != FailureReasonHostNotFound ||
		result.Rejection.Error() != "no cached sandbox hosts" {
		t.Fatalf("rejection = %#v, want no cached hosts rejection", result.Rejection)
	}
}

func TestEnumerateSchedulerCandidatesListFailureIsEndpointSafe(t *testing.T) {
	candidates := EnumerateSchedulerCandidates(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return nil, errors.New("open /tmp/private-worker.sock: token=super-secret")
		},
	})

	if !candidates.Failed() {
		t.Fatalf("candidates = %#v, want cached host list failure", candidates)
	}
	if candidates.Rejection.Reason != FailureReasonInvalidRequest ||
		candidates.Rejection.Error() != "list cached sandbox hosts failed" {
		t.Fatalf("rejection = %#v, want stable list failure rejection", candidates.Rejection)
	}
	for _, leaked := range []string{"/tmp/private-worker.sock", "super-secret"} {
		if strings.Contains(candidates.Rejection.Error(), leaked) {
			t.Fatalf("rejection %q leaked %q", candidates.Rejection.Error(), leaked)
		}
	}
}

func TestEnumerateSchedulerCandidatesReturnsIndependentHostCopies(t *testing.T) {
	cachedHost := &sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Labels:            map[string]string{"pool": "ci"},
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
		Health:            &sandbox.HostHealth{Status: "healthy"},
		Security: &sandbox.SandboxSecurity{
			Secrets: &sandbox.SandboxSecretSecurity{
				ActiveModes: []string{sandbox.SandboxSecretModeEnv},
			},
		},
	}

	candidates := EnumerateSchedulerCandidates(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{cachedHost}, nil
		},
	})
	if candidates.Failed() || len(candidates.Candidates) != 1 {
		t.Fatalf("candidates = %#v, want one cached host candidate", candidates)
	}

	candidateHost := candidates.Candidates[0].Host
	if candidateHost == cachedHost ||
		candidateHost.Labels == nil ||
		candidateHost.Capacity == cachedHost.Capacity ||
		candidateHost.Health == cachedHost.Health ||
		candidateHost.Security == cachedHost.Security ||
		candidateHost.Security.Secrets == cachedHost.Security.Secrets {
		t.Fatalf("candidate host = %#v, want independent copy of cached host", candidateHost)
	}

	cachedHost.Labels["pool"] = "mutated"
	cachedHost.SupportedRuntimes[0] = sandbox.SandboxRuntimeDriverSSHMachine
	cachedHost.Capacity.MaxConcurrentSandboxes = 9
	cachedHost.Health.Status = "unhealthy"
	cachedHost.Security.Secrets.ActiveModes[0] = sandbox.SandboxSecretModeHTTPProxy

	if candidateHost.Labels["pool"] != "ci" ||
		candidateHost.SupportedRuntimes[0] != sandbox.SandboxRuntimeDriverRootlessPodman ||
		candidateHost.Capacity.MaxConcurrentSandboxes != 2 ||
		candidateHost.Health.Status != "healthy" ||
		candidateHost.Security.Secrets.ActiveModes[0] != sandbox.SandboxSecretModeEnv {
		t.Fatalf("candidate host mutated with cached source: %#v", candidateHost)
	}
}

func schedulerCandidateHostIDs(candidates []SchedulerCandidate) []string {
	ids := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		ids = append(ids, candidate.Identity.HostID)
	}
	return ids
}
