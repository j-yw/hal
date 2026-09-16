package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

// These boundaries record calls only; no case reads host process state, opens
// a raw socket, mutates privilege, or inspects live guest/host networking.
type workloadLinuxBoundary struct {
	status       string
	statusErr    error
	groups       []int
	groupsErr    error
	rawErr       error
	network      NetworkIsolationProofResult
	networkErr   error
	cancelAfter  string
	cancel       context.CancelFunc
	ctx          context.Context
	order        []string
	wrongContext bool
	maximum      int64
}

func (boundary *workloadLinuxBoundary) record(ctx context.Context, operation string) {
	boundary.order = append(boundary.order, operation)
	boundary.wrongContext = boundary.wrongContext || ctx != boundary.ctx
	if boundary.cancelAfter == operation {
		boundary.cancel()
	}
}

func (boundary *workloadLinuxBoundary) ReadSelfStatus(ctx context.Context, maximum int64) ([]byte, error) {
	boundary.record(ctx, "status")
	boundary.maximum = maximum
	return []byte(boundary.status), boundary.statusErr
}

func (boundary *workloadLinuxBoundary) SupplementaryGroups(ctx context.Context) ([]int, error) {
	boundary.record(ctx, "groups")
	return boundary.groups, boundary.groupsErr
}

func (boundary *workloadLinuxBoundary) AttemptRawPacketSocket(ctx context.Context) error {
	boundary.record(ctx, "raw")
	return boundary.rawErr
}

func (boundary *workloadLinuxBoundary) VerifyNetworkIsolation(ctx context.Context) (NetworkIsolationProofResult, error) {
	boundary.record(ctx, "network")
	return boundary.network, boundary.networkErr
}

func TestWorkloadLinuxIsolationBodyEquivalence(t *testing.T) {
	valid := validLinuxIsolationStatus()
	verified := IsolationProofResult{
		RestrictedIdentity: true, CapabilitiesCleared: true, NoNewPrivileges: true,
		SupplementaryGroupsCleared: true, RawPacketSocketDenied: true,
		Network: NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusVerified,
			SingleInterface: true, StaticRoutes: true, ProxyReachable: true},
	}
	boundaryError := errors.New("token=private-boundary-error /private/fixture")
	type testCase struct {
		name      string
		change    func(*workloadLinuxBoundary)
		context   string
		want      IsolationProofResult
		wantErr   error
		wantOrder string
	}
	tests := []testCase{
		{name: "verified EPERM", want: verified, wantOrder: "status,groups,raw,network"},
		{name: "verified EACCES", change: func(b *workloadLinuxBoundary) { b.rawErr = unix.EACCES }, want: verified, wantOrder: "status,groups,raw,network"},
		{name: "wrapped denial", change: func(b *workloadLinuxBoundary) { b.rawErr = fmt.Errorf("wrapped: %w", unix.EPERM) }, want: verified, wantOrder: "status,groups,raw,network"},
		{name: "nil context", context: "nil", want: verified, wantOrder: "status,groups,raw,network"},
		{name: "pre canceled", context: "canceled", wantErr: context.Canceled},
		{name: "already expired", context: "expired", wantErr: context.DeadlineExceeded},
		{name: "status error", change: func(b *workloadLinuxBoundary) { b.statusErr = boundaryError }, wantErr: errLinuxIsolationUnverified, wantOrder: "status"},
		{name: "groups error", change: func(b *workloadLinuxBoundary) { b.groupsErr = boundaryError }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups"},
		{name: "supplementary group", change: func(b *workloadLinuxBoundary) { b.groups = []int{1000} }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups"},
		{name: "explicit empty groups", change: func(b *workloadLinuxBoundary) { b.groups = []int{} }, want: verified, wantOrder: "status,groups,raw,network"},
		{name: "raw socket succeeded", change: func(b *workloadLinuxBoundary) { b.rawErr = nil }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw"},
		{name: "wrong raw errno", change: func(b *workloadLinuxBoundary) { b.rawErr = unix.EAFNOSUPPORT }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw"},
		{name: "raw error cause", change: func(b *workloadLinuxBoundary) { b.rawErr = boundaryError }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw"},
		{name: "network error", change: func(b *workloadLinuxBoundary) { b.networkErr = boundaryError }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw,network"},
		{name: "network unavailable", change: func(b *workloadLinuxBoundary) { b.network.Status = guestagent.IsolationProofStatusUnavailable }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw,network"},
		{name: "network unknown status", change: func(b *workloadLinuxBoundary) { b.network.Status = "unknown" }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw,network"},
		{name: "multiple interfaces", change: func(b *workloadLinuxBoundary) { b.network.SingleInterface = false }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw,network"},
		{name: "routes missing", change: func(b *workloadLinuxBoundary) { b.network.StaticRoutes = false }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw,network"},
		{name: "proxy unreachable", change: func(b *workloadLinuxBoundary) { b.network.ProxyReachable = false }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw,network"},
		// Preserve the old body exactly: the selected Server checks context again
		// after the final callback, before publishing proof or invoking work.
		{name: "cancel in final successful network callback", change: func(b *workloadLinuxBoundary) { b.cancelAfter = "network" }, want: verified, wantOrder: "status,groups,raw,network"},
		{name: "cancel and network failure", change: func(b *workloadLinuxBoundary) { b.cancelAfter = "network"; b.networkErr = boundaryError }, wantErr: errLinuxIsolationUnverified, wantOrder: "status,groups,raw,network"},
	}
	for _, operation := range []string{"status", "groups", "raw"} {
		order := map[string]string{"status": "status", "groups": "status,groups", "raw": "status,groups,raw"}[operation]
		tests = append(tests, testCase{name: "cancel after " + operation, change: func(b *workloadLinuxBoundary) { b.cancelAfter = operation }, wantErr: context.Canceled, wantOrder: order})
		tests = append(tests, testCase{name: "cancel and failure at " + operation, change: func(b *workloadLinuxBoundary) {
			b.cancelAfter = operation
			switch operation {
			case "status":
				b.statusErr = boundaryError
			case "groups":
				b.groupsErr = boundaryError
			case "raw":
				b.rawErr = boundaryError
			}
		}, wantErr: errLinuxIsolationUnverified, wantOrder: order})
	}
	statusCases := map[string]string{
		"empty": "", "too large": strings.Repeat("x", int(maximumLinuxSelfStatusBytes)) + "\n",
		"missing newline": strings.TrimSuffix(valid, "\n"), "NUL": valid + "\x00\n",
		"CR":                     strings.Replace(valid, "Name:", "Name:\r", 1),
		"no new privileges zero": strings.Replace(valid, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1),
		"missing identity value": strings.Replace(valid, "1000\t1000\t1000\t1000", "1000\t1000\t1000", 1),
	}
	for _, field := range []string{"Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"} {
		for _, line := range strings.Split(valid, "\n") {
			if strings.HasPrefix(line, field+":") {
				statusCases[field+" missing"] = strings.Replace(valid, line+"\n", "", 1)
				statusCases[field+" duplicate"] = valid + line + "\n"
			}
		}
	}
	for _, field := range []string{"Uid", "Gid"} {
		for index := 0; index < 4; index++ {
			values := []string{"1000", "1000", "1000", "1000"}
			values[index] = "0"
			statusCases[fmt.Sprintf("%s identity %d", field, index)] = strings.Replace(valid, field+":\t1000\t1000\t1000\t1000", field+":\t"+strings.Join(values, "\t"), 1)
		}
	}
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		for _, bad := range []string{"0000000000000001", "000000000000000", "00000000000000000", "000000000000000x"} {
			statusCases[field+" "+bad] = strings.Replace(valid, field+":\t0000000000000000", field+":\t"+bad, 1)
		}
	}
	statusNames := make([]string, 0, len(statusCases))
	for name := range statusCases {
		statusNames = append(statusNames, name)
	}
	sort.Strings(statusNames)
	for _, name := range statusNames {
		status := statusCases[name]
		tests = append(tests, testCase{name: "status " + name, change: func(b *workloadLinuxBoundary) { b.status = status }, wantErr: errLinuxIsolationUnverified, wantOrder: "status"})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, selected := range []bool{false, true} {
				t.Run(map[bool]string{false: "legacy", true: "workload"}[selected], func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if tt.context == "canceled" {
						cancel()
					}
					if tt.context == "expired" {
						var expire context.CancelFunc
						ctx, expire = context.WithDeadline(context.Background(), time.Unix(0, 0))
						defer expire()
					}
					if tt.context == "nil" {
						ctx = context.Background()
					}
					boundary := &workloadLinuxBoundary{status: valid, rawErr: unix.EPERM, network: verified.Network, ctx: ctx, cancel: cancel}
					if tt.change != nil {
						tt.change(boundary)
					}
					options := LinuxIsolationVerifierOptions{ProcessBoundary: boundary, NetworkVerifier: boundary}
					var inspect func(context.Context) (IsolationProofResult, error)
					if selected {
						verifier, err := NewLinuxWorkloadIsolationVerifier(options)
						if err != nil || !configuredDependency(verifier) {
							t.Fatal("selected construction failed")
						}
						inspect = verifier.VerifyWorkloadIsolation
					} else {
						verifier, err := NewLinuxIsolationVerifier(options)
						if err != nil {
							t.Fatal("legacy construction failed")
						}
						inspect = func(ctx context.Context) (IsolationProofResult, error) {
							return verifier.VerifyIsolation(ctx, guestagent.IsolationProofRequest{})
						}
					}
					if len(boundary.order) != 0 {
						t.Fatal("constructor inspected a boundary")
					}
					if tt.context == "nil" {
						ctx = nil
					}
					result, err := inspect(ctx)
					if result != tt.want || err != tt.wantErr || strings.Join(boundary.order, ",") != tt.wantOrder {
						t.Fatalf("result or callback order mismatch: error=%v order=%v", err, boundary.order)
					}
					if boundary.wrongContext || (len(boundary.order) > 0 && boundary.maximum != 64<<10) {
						t.Fatal("changed context or status bound")
					}
				})
			}
		})
	}
}

func TestWorkloadLinuxIsolationRequiresNetworkAndPreservesLegacy(t *testing.T) {
	var typedNil *workloadLinuxBoundary
	for _, network := range []NetworkIsolationVerifier{nil, typedNil} {
		options := LinuxIsolationVerifierOptions{NetworkVerifier: network}
		verifier, err := NewLinuxWorkloadIsolationVerifier(options)
		if verifier != nil || err != errLinuxIsolationUnverified {
			t.Error("selected constructor accepted missing network inspection")
		}
		boundary := &workloadLinuxBoundary{status: validLinuxIsolationStatus(), rawErr: unix.EPERM, ctx: context.Background()}
		options.ProcessBoundary = boundary
		legacy, err := NewLinuxIsolationVerifier(options)
		if err != nil {
			t.Fatal("legacy constructor no longer permits process-only inspection")
		}
		result, err := legacy.VerifyIsolation(context.Background(), guestagent.IsolationProofRequest{})
		if err != nil || !processIsolationVerified(result) || result.Network.Status != guestagent.IsolationProofStatusUnavailable || strings.Join(boundary.order, ",") != "status,groups,raw" {
			t.Fatal("legacy process-only behavior changed")
		}
	}
}

func TestWorkloadLinuxIsolationConstructorRetainsBoundariesWithoutInspection(t *testing.T) {
	var typedNil *workloadLinuxBoundary
	for _, process := range []LinuxProcessIsolationBoundary{nil, typedNil, &workloadLinuxBoundary{}} {
		network := &workloadLinuxBoundary{}
		verifier, err := NewLinuxWorkloadIsolationVerifier(LinuxIsolationVerifierOptions{ProcessBoundary: process, NetworkVerifier: network})
		if err != nil || !configuredDependency(verifier) {
			t.Fatal("valid constructor failed")
		}
		if _, legacy := verifier.(IsolationVerifier); legacy {
			t.Fatal("selected wrapper also implements legacy request interface")
		}
		concrete, ok := verifier.(*linuxWorkloadIsolationVerifier)
		if !ok || concrete.verifier == nil {
			t.Fatal("missing original concrete inspector")
		}
		if concrete.verifier.network != network || len(network.order) != 0 {
			t.Fatal("network identity changed or was inspected")
		}
		if configuredDependency(process) {
			if concrete.verifier.process != process {
				t.Fatal("explicit process boundary replaced")
			}
		} else if _, ok := concrete.verifier.process.(liveLinuxProcessIsolationBoundary); !ok {
			t.Fatal("missing exact existing live process default")
		}
	}
}

func TestWorkloadLinuxIsolationRunsFreshChecks(t *testing.T) {
	boundary := &workloadLinuxBoundary{status: validLinuxIsolationStatus(), rawErr: unix.EPERM, ctx: context.Background(), network: NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusVerified, SingleInterface: true, StaticRoutes: true, ProxyReachable: true}}
	verifier, err := NewLinuxWorkloadIsolationVerifier(LinuxIsolationVerifierOptions{ProcessBoundary: boundary, NetworkVerifier: boundary})
	if err != nil {
		t.Fatal("constructor failed")
	}
	for i := 0; i < 3; i++ {
		if _, err := verifier.VerifyWorkloadIsolation(context.Background()); err != nil {
			t.Fatal("fresh valid inspection failed")
		}
	}
	want := []string{"status", "groups", "raw", "network", "status", "groups", "raw", "network", "status", "groups", "raw", "network"}
	if !reflect.DeepEqual(boundary.order, want) {
		t.Fatal("repeated checks used a cached proof")
	}
	boundary.network.ProxyReachable = false
	if result, err := verifier.VerifyWorkloadIsolation(context.Background()); result != (IsolationProofResult{}) || err != errLinuxIsolationUnverified || len(boundary.order) != 16 {
		t.Fatal("changed topology retained prior proof")
	}
}

func TestWorkloadLinuxIsolationNilAndZeroFailClosed(t *testing.T) {
	for _, verifier := range []*linuxWorkloadIsolationVerifier{nil, {}} {
		result, err := verifier.VerifyWorkloadIsolation(context.Background())
		if result != (IsolationProofResult{}) || err != errLinuxIsolationUnverified {
			t.Fatal("nil or zero verifier did not fail closed")
		}
	}
}
