package minimalcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"golang.org/x/sys/unix"
)

const inspectionRedRequest = `{"operation":"inspect_isolation","protocolVersion":"guest-agent-minimal-v1"}`

// These observations exercise the concrete Linux verifier's actual algorithm,
// not host privilege, process state, raw sockets or real guest networking.
type inspectionRedObservations struct {
	process [4]atomic.Int32 // status, groups, denied raw socket, network
	ready   atomic.Int32
	copy    atomic.Int32
	env     atomic.Int32
	backend *workloadTransportBackend
}

func (observations *inspectionRedObservations) ReadSelfStatus(ctx context.Context, maximum int64) ([]byte, error) {
	observations.process[0].Add(1)
	if ctx == nil || ctx.Err() != nil || maximum != 64<<10 {
		return nil, errors.New("invalid bounded inspection context")
	}
	return []byte("Name:\thal-guest-agent\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n" +
		"CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n" +
		"CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"), nil
}

func (observations *inspectionRedObservations) SupplementaryGroups(context.Context) ([]int, error) {
	observations.process[1].Add(1)
	return nil, nil
}

func (observations *inspectionRedObservations) AttemptRawPacketSocket(context.Context) error {
	observations.process[2].Add(1)
	return unix.EPERM
}

func (observations *inspectionRedObservations) VerifyNetworkIsolation(context.Context) (server.NetworkIsolationProofResult, error) {
	observations.process[3].Add(1)
	return server.NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusVerified,
		SingleInterface: true, StaticRoutes: true, ProxyReachable: true}, nil
}

func (observations *inspectionRedObservations) Resolve(context.Context, guestagent.EnvironmentEntry) (string, error) {
	observations.env.Add(1)
	return "", errors.New("inspection must not resolve environment")
}

func (observations *inspectionRedObservations) counts() [8]int32 {
	return [8]int32{observations.process[0].Load(), observations.process[1].Load(), observations.process[2].Load(),
		observations.process[3].Load(), observations.ready.Load(), observations.backend.calls.Load(), observations.copy.Load(), observations.env.Load()}
}

func newInspectionRedFixture(t *testing.T) (*bootstrapFixture, *inspectionRedObservations) {
	t.Helper()
	observations := &inspectionRedObservations{}
	verifier, err := server.NewLinuxWorkloadIsolationVerifier(server.LinuxIsolationVerifierOptions{
		ProcessBoundary: observations, NetworkVerifier: observations})
	if err != nil {
		t.Fatal("actual concrete no-request verifier construction failed")
	}
	backend := &workloadTransportBackend{ready: func(context.Context) error { observations.ready.Add(1); return nil },
		copyIn: func(context.Context, server.CopyInPlan) (server.CopyResult, error) {
			observations.copy.Add(1)
			return server.CopyResult{}, errors.New("unexpected inspection copy")
		}, copyOut: func(context.Context, server.CopyOutPlan) (server.CopyResult, error) {
			observations.copy.Add(1)
			return server.CopyResult{}, errors.New("unexpected inspection copy")
		}}
	observations.backend = backend
	if observations.counts() != [8]int32{} {
		t.Fatal("construction performed inspection or backend work")
	}
	fixture := newWorkloadTransportFixture(t, backend, func(options *server.Options) {
		options.WorkloadIsolationVerifier = verifier
		options.EnvironmentResolver = observations
	})
	return fixture, observations
}

func TestSelectedInspectionAuthenticatedFreshProofWithoutBackendWork(t *testing.T) {
	for _, previousExec := range []bool{false, true} {
		name := "first workload ordinal"
		if previousExec {
			name = "same session after actual exec"
		}
		t.Run(name, func(t *testing.T) {
			fixture, observations := newInspectionRedFixture(t)
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			clear(fixture.readiness(t, peer, state, fixture.binding))
			if !state.Established() || observations.counts() != [8]int32{1, 1, 1, 1, 1, 0, 0, 0} {
				t.Fatal("actual encrypted readiness did not complete exactly one preparation")
			}
			ordinal := uint64(1)
			if previousExec {
				wire := workloadRecord(t, fixture, state, workloadInnerExec(t), ordinal)
				write(t, peer, wire)
				clear(wire)
				inner := workloadResponse(t, fixture, peer, state, ordinal)
				var response guestagent.ExecResponse
				if json.Unmarshal(inner, &response) != nil || guestagent.ValidateExecResponse(response) != nil || response.ExitCode != 7 {
					t.Fatal("original selected exec prerequisite failed")
				}
				clear(inner)
				ordinal++
			}
			before := observations.counts()
			if len(inspectionRedRequest) != 76 {
				t.Fatal("canonical inspection fixture is not the accepted 76 bytes")
			}
			wire := workloadRecord(t, fixture, state, []byte(inspectionRedRequest), ordinal)
			write(t, peer, wire)
			clear(wire)
			inner := workloadResponse(t, fixture, peer, state, ordinal)
			defer clear(inner)
			proof := guestagent.IsolationProof{Generation: fixture.binding.fields["topologyGenerationId"],
				RuntimeGeneration: fixture.binding.fields["runtimeGeneration"], Status: guestagent.IsolationProofStatusVerified,
				RestrictedIdentity: true, CapabilitiesCleared: true, NoNewPrivileges: true,
				SupplementaryGroupsCleared: true, RawPacketSocketDenied: true,
				Network: &guestagent.NetworkIsolationProof{Status: guestagent.IsolationProofStatusVerified,
					SingleInterface: true, StaticRoutes: true, ProxyReachable: true}}
			want, err := json.Marshal(struct {
				Operation       string                    `json:"operation"`
				ProtocolVersion string                    `json:"protocolVersion"`
				IsolationProof  guestagent.IsolationProof `json:"isolationProof"`
			}{"inspect_isolation", ProtocolVersion, proof})
			if err != nil {
				t.Fatal("canonical response fixture failed")
			}
			defer clear(want)
			if len(inner) == 0 || len(inner) > 2048 || !bytes.Equal(inner, want) {
				var rejection guestagent.ErrorResponse
				if json.Unmarshal(inner, &rejection) == nil && rejection.Error != nil {
					t.Logf("actual authenticated workload response rejected inspection: code=%s", rejection.Error.Code)
				}
				t.Error("same-session inspection did not return the exact fresh boot-bound proof")
			}
			wantCounts := before
			for index := 0; index < 4; index++ {
				wantCounts[index]++
			}
			if after := observations.counts(); after != wantCounts {
				t.Errorf("inspection did not perform exactly one fresh status/groups/raw/network pass with no backend/environment work: before=%v after=%v want=%v", before, after, wantCounts)
			}
		})
	}
}

func TestSelectedInspectionKeepsInnerReadinessRejected(t *testing.T) {
	fixture, observations := newInspectionRedFixture(t)
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	clear(fixture.readiness(t, peer, state, fixture.binding))
	before := observations.counts()
	if before != [8]int32{1, 1, 1, 1, 1, 0, 0, 0} {
		t.Fatal("actual initial preparation prerequisite failed")
	}
	wire := workloadRecord(t, fixture, state, []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness"}`), 1)
	write(t, peer, wire)
	clear(wire)
	inner := workloadResponse(t, fixture, peer, state, 1)
	defer clear(inner)
	var response guestagent.ErrorResponse
	if json.Unmarshal(inner, &response) != nil || response.Error == nil || response.Error.Code != guestagent.ErrorCodeUnknownOperation || observations.counts() != before {
		t.Fatal("selected inner readiness performed work or bypassed its original rejection")
	}
}

func TestSelectedInspectionKeepsLegacyBootstrapReadinessOnly(t *testing.T) {
	fixture := newBootstrapFixture(t, nil)
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	clear(fixture.readiness(t, peer, state, fixture.binding))
	wire := workloadRecord(t, fixture, state, []byte(inspectionRedRequest), 1)
	write(t, peer, wire)
	clear(wire)
	assertClosed(t, peer)
	if fixture.wait(t) == nil || fixture.listener.accepts.Load() != 1 {
		t.Fatal("legacy bootstrap accepted inspection or another session")
	}
}
