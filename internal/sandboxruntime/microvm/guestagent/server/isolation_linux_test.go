package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

type fakeLinuxIsolationBoundary struct {
	mu        sync.Mutex
	status    []byte
	statusErr error
	groups    []int
	groupsErr error
	rawErr    error
	order     []string
}

func (boundary *fakeLinuxIsolationBoundary) ReadSelfStatus(context.Context, int64) ([]byte, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.order = append(boundary.order, "status")
	return append([]byte(nil), boundary.status...), boundary.statusErr
}

func (boundary *fakeLinuxIsolationBoundary) SupplementaryGroups(context.Context) ([]int, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.order = append(boundary.order, "groups")
	return append([]int(nil), boundary.groups...), boundary.groupsErr
}

func (boundary *fakeLinuxIsolationBoundary) AttemptRawPacketSocket(context.Context) error {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.order = append(boundary.order, "raw_socket")
	return boundary.rawErr
}

type fakeLinuxNetworkVerifier struct {
	boundary *fakeLinuxIsolationBoundary
	result   NetworkIsolationProofResult
	err      error
}

func (verifier *fakeLinuxNetworkVerifier) VerifyNetworkIsolation(context.Context) (NetworkIsolationProofResult, error) {
	verifier.boundary.mu.Lock()
	verifier.boundary.order = append(verifier.boundary.order, "network")
	verifier.boundary.mu.Unlock()
	return verifier.result, verifier.err
}

func TestL7LinuxIsolationVerifierRequiresEveryProcessPropertyAndDenialErrno(t *testing.T) {
	valid := validLinuxIsolationStatus()
	tests := []struct {
		name      string
		status    string
		groups    []int
		rawErr    error
		wantError bool
	}{
		{name: "permission denied", status: valid, rawErr: unix.EPERM},
		{name: "access denied", status: valid, rawErr: unix.EACCES},
		{name: "raw socket succeeded", status: valid, wantError: true},
		{name: "wrong raw socket errno", status: valid, rawErr: unix.EAFNOSUPPORT, wantError: true},
		{name: "supplementary group", status: valid, groups: []int{1000}, rawErr: unix.EPERM, wantError: true},
		{name: "wrong effective identity", status: strings.Replace(valid, "Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t0\t1000\t1000", 1), rawErr: unix.EPERM, wantError: true},
		{name: "no new privs disabled", status: strings.Replace(valid, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), rawErr: unix.EPERM, wantError: true},
	}
	for _, capability := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		tests = append(tests,
			struct {
				name      string
				status    string
				groups    []int
				rawErr    error
				wantError bool
			}{name: capability + " nonzero", status: strings.Replace(valid, capability+":\t0000000000000000", capability+":\t0000000000000001", 1), rawErr: unix.EPERM, wantError: true},
			struct {
				name      string
				status    string
				groups    []int
				rawErr    error
				wantError bool
			}{name: capability + " missing", status: strings.Replace(valid, capability+":\t0000000000000000\n", "", 1), rawErr: unix.EPERM, wantError: true},
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			boundary := &fakeLinuxIsolationBoundary{status: []byte(tt.status), groups: tt.groups, rawErr: tt.rawErr}
			verifier, err := NewLinuxIsolationVerifier(LinuxIsolationVerifierOptions{ProcessBoundary: boundary})
			if err != nil {
				t.Fatal(err)
			}
			result, err := verifier.VerifyIsolation(context.Background(), guestagent.IsolationProofRequest{Generation: "generation"})
			if tt.wantError {
				if err == nil || result != (IsolationProofResult{}) {
					t.Fatalf("VerifyIsolation() = %#v, %v, want fail-closed", result, err)
				}
				return
			}
			if err != nil || !result.RestrictedIdentity || !result.CapabilitiesCleared || !result.NoNewPrivileges || !result.SupplementaryGroupsCleared || !result.RawPacketSocketDenied || result.Network.Status != guestagent.IsolationProofStatusUnavailable {
				t.Fatalf("VerifyIsolation() = %#v, %v, want verified process proof", result, err)
			}
		})
	}
}

func TestL7LinuxIsolationVerifierBoundaryOrderAndNetworkHook(t *testing.T) {
	boundary := &fakeLinuxIsolationBoundary{status: []byte(validLinuxIsolationStatus()), rawErr: unix.EPERM}
	network := &fakeLinuxNetworkVerifier{boundary: boundary, result: NetworkIsolationProofResult{
		Status: guestagent.IsolationProofStatusVerified, SingleInterface: true, StaticRoutes: true, ProxyReachable: true,
	}}
	verifier, err := NewLinuxIsolationVerifier(LinuxIsolationVerifierOptions{ProcessBoundary: boundary, NetworkVerifier: network})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		result, err := verifier.VerifyIsolation(context.Background(), guestagent.IsolationProofRequest{Generation: "generation"})
		if err != nil || result.Network.Status != guestagent.IsolationProofStatusVerified {
			t.Fatalf("VerifyIsolation() repetition %d = %#v, %v", i, result, err)
		}
	}
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	for index, operation := range boundary.order {
		want := []string{"status", "groups", "raw_socket", "network"}[index%4]
		if operation != want {
			t.Fatalf("boundary order[%d] = %q, want %q", index, operation, want)
		}
	}
}

func TestL7LinuxIsolationVerifierRejectsBoundaryFailuresWithoutLeakingCause(t *testing.T) {
	for _, boundary := range []*fakeLinuxIsolationBoundary{
		{statusErr: errors.New("read /proc/self/status token=ghp_secret")},
		{status: []byte(validLinuxIsolationStatus()), groupsErr: errors.New("groups /home/alice")},
	} {
		verifier, err := NewLinuxIsolationVerifier(LinuxIsolationVerifierOptions{ProcessBoundary: boundary})
		if err != nil {
			t.Fatal(err)
		}
		_, err = verifier.VerifyIsolation(context.Background(), guestagent.IsolationProofRequest{Generation: "generation"})
		if err == nil {
			t.Fatal("VerifyIsolation() error = nil, want failure")
		}
		for _, leaked := range []string{"/proc/", "ghp_secret", "/home/alice"} {
			if strings.Contains(err.Error(), leaked) {
				t.Fatalf("error leaked %q: %v", leaked, err)
			}
		}
	}
}

func validLinuxIsolationStatus() string {
	return "Name:\thal-guest-agent\n" +
		"Uid:\t1000\t1000\t1000\t1000\n" +
		"Gid:\t1000\t1000\t1000\t1000\n" +
		"CapInh:\t0000000000000000\n" +
		"CapPrm:\t0000000000000000\n" +
		"CapEff:\t0000000000000000\n" +
		"CapBnd:\t0000000000000000\n" +
		"CapAmb:\t0000000000000000\n" +
		"NoNewPrivs:\t1\n"
}
