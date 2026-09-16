//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"golang.org/x/sys/unix"
)

const minimalHostInspectionRequest = `{"operation":"inspect_isolation","protocolVersion":"guest-agent-minimal-v1"}`
const minimalHostInspectionOperation = guestagent.Operation("inspect_isolation")

// Bounded fake OS observations feed the real no-request Linux verifier. Neither
// this fixture nor its returned guest proof attests this host's actual isolation.
type minimalHostInspectionObservations struct {
	process [4]atomic.Int32 // status, groups, denied raw socket, network
	ready   atomic.Int32
	env     atomic.Int32
	backend *minimalJointBackend
}

func (o *minimalHostInspectionObservations) ReadSelfStatus(ctx context.Context, maximum int64) ([]byte, error) {
	o.process[0].Add(1)
	if ctx == nil || ctx.Err() != nil || maximum != 64<<10 {
		return nil, errors.New("invalid bounded inspection")
	}
	return []byte("Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n" +
		"CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n" +
		"CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"), nil
}

func (o *minimalHostInspectionObservations) SupplementaryGroups(context.Context) ([]int, error) {
	o.process[1].Add(1)
	return nil, nil
}

func (o *minimalHostInspectionObservations) AttemptRawPacketSocket(context.Context) error {
	o.process[2].Add(1)
	return unix.EPERM
}

func (o *minimalHostInspectionObservations) VerifyNetworkIsolation(context.Context) (server.NetworkIsolationProofResult, error) {
	o.process[3].Add(1)
	return server.NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusVerified,
		SingleInterface: true, StaticRoutes: true, ProxyReachable: true}, nil
}

func (o *minimalHostInspectionObservations) Resolve(context.Context, guestagent.EnvironmentEntry) (string, error) {
	o.env.Add(1)
	return "", errors.New("unexpected environment resolution")
}

func (o *minimalHostInspectionObservations) counts() [7]int32 {
	return [7]int32{o.process[0].Load(), o.process[1].Load(), o.process[2].Load(), o.process[3].Load(),
		o.ready.Load(), o.backend.calls.Load(), o.env.Load()}
}

// Keep the original supervisor/controller/manager/producer fixture unchanged.
// Only construct its guest with counted dependencies before serving, as f.guest
// does; no host readiness, record, event, process handle or proof is substituted.
func minimalHostInspectionGuest(t *testing.T, f *minimalSupervisorJointFixture) (*minimalHostInspectionObservations, func()) {
	t.Helper()
	listener := f.listener.Load()
	if listener == nil || !f.private.Load() {
		t.Fatal("original prepared listener missing")
	}
	fc, err := readMinimalControlFirecrackerConfig(f.admission.borrowed[6], f.admission.config.Config)
	if err != nil {
		t.Fatal("retained boot config unavailable")
	}
	boot, present, err := minimalcontrol.ParseBootCommandLine(fc.BootSource.BootArgs)
	if err != nil || !present {
		t.Fatal("retained selected guest boot missing")
	}
	o := &minimalHostInspectionObservations{}
	o.backend = &minimalJointBackend{ready: func(context.Context) error { o.ready.Add(1); return nil },
		exec: func(context.Context, server.ExecPlan) (server.ExecResult, error) {
			return server.ExecResult{ExitCode: 7}, nil
		}}
	verifier, err := server.NewLinuxWorkloadIsolationVerifier(server.LinuxIsolationVerifierOptions{ProcessBoundary: o, NetworkVerifier: o})
	if err != nil {
		t.Fatal("actual Linux workload verifier construction")
	}
	ctx, cancel := context.WithCancel(f.owned.minimalPreparation.ctx)
	transport, err := minimalcontrol.NewWorkloadTransport(minimalcontrol.BootstrapOptions{Listener: listener, Boot: boot,
		OwnerDone: ctx.Done(), Random: bytes.NewReader(bytes.Repeat([]byte{73}, 96))})
	if err != nil {
		cancel()
		t.Fatal("actual guest workload transport construction")
	}
	guest, err := server.New(server.Options{Transport: transport, Backend: o.backend, WorkloadIsolationVerifier: verifier,
		EnvironmentResolver: o, RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true})
	if err != nil {
		cancel()
		t.Fatal("actual guest Server construction")
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = guest.Serve(ctx) }()
	return o, func() {
		cancel()
		_ = listener.Close()
		minimalJointAwait(t, done, "inspection guest joined")
		if o.backend.closes.Load() != 1 {
			t.Error("inspection guest backend close not joined exactly once")
		}
	}
}

func minimalHostInspectionCarrier(operation guestagent.Operation) guestagent.TransportRequest {
	// Existing generic carrier metadata stays v1; only the selected inner JSON
	// has minimal-v1, and the private header operation must be code 4.
	return guestagent.TransportRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: operation,
		Encoded: []byte(minimalHostInspectionRequest), MaxResponseBytes: 2048}
}

func TestMinimalHostInspectionOriginalProducerFreshBoundProof(t *testing.T) {
	for _, previousExec := range []bool{false, true} {
		name := "first-ordinal"
		if previousExec {
			name = "after-real-exec"
		}
		t.Run(name, func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				o, rescue := minimalHostInspectionGuest(t, f)
				defer rescue()
				client, candidate := minimalSupervisorWorkClient(t, f)
				if o.counts() != [7]int32{1, 1, 1, 1, 1, 0, 0} {
					t.Fatal("actual encrypted readiness did not prepare exactly once")
				}
				if previousExec {
					result, err := client.Exec(context.Background(), minimalJointExecRequest())
					if err != nil || result.ExitCode != 7 || o.counts() != [7]int32{2, 2, 2, 2, 1, 1, 0} {
						t.Fatal("original authenticated Exec compatibility prerequisite")
					}
				}
				serving := f.serving(t)
				serving.mu.Lock()
				pair := serving.server
				serving.mu.Unlock()
				if pair == nil || !pair.ready.Current() || candidate.event.sessionID != pair.ready.sessionID ||
					candidate.event.readinessBindingSHA256 != pair.binding {
					t.Fatal("original producer and authenticated readiness correlation missing")
				}
				before, originalH := o.counts(), pair.ready.hardExpiry
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				admitted := time.Now()
				response, err := candidate.RoundTrip(ctx, minimalHostInspectionCarrier(minimalHostInspectionOperation))
				defer clear(response.Encoded)
				if err != nil || len(response.Encoded) == 0 {
					t.Log("actual original producer rejected the selected inspection carrier after real encrypted readiness")
					t.Error("original producer did not return selected code-4 inspection")
				} else {
					var reply struct {
						Operation              string                    `json:"operation"`
						ProtocolVersion        string                    `json:"protocolVersion"`
						IsolationProof         guestagent.IsolationProof `json:"isolationProof"`
						HardExpiryUnixNano     int64                     `json:"hardExpiryUnixNano"`
						RemainingLifetimeNanos int64                     `json:"remainingLifetimeNanos"`
					}
					decodeErr := json.Unmarshal(response.Encoded, &reply)
					canonical, marshalErr := json.Marshal(reply)
					defer clear(canonical)
					proof := reply.IsolationProof
					if decodeErr != nil || marshalErr != nil || !bytes.Equal(canonical, response.Encoded) || len(response.Encoded) > 2048 ||
						reply.Operation != string(minimalHostInspectionOperation) || reply.ProtocolVersion != minimalcontrol.ProtocolVersion ||
						proof.Generation != f.admission.config.Control.Prelaunch["topologyGenerationId"] || proof.RuntimeGeneration != f.admission.config.Job.RuntimeGeneration ||
						proof.Status != guestagent.IsolationProofStatusVerified || !proof.RestrictedIdentity || !proof.CapabilitiesCleared || !proof.NoNewPrivileges ||
						!proof.SupplementaryGroupsCleared || !proof.RawPacketSocketDenied || proof.Network == nil ||
						proof.Network.Status != guestagent.IsolationProofStatusVerified || !proof.Network.SingleInterface || !proof.Network.StaticRoutes || !proof.Network.ProxyReachable ||
						reply.HardExpiryUnixNano != originalH.UnixNano() || reply.RemainingLifetimeNanos <= 0 || reply.RemainingLifetimeNanos > int64(35*time.Minute) ||
						admitted.Add(time.Duration(reply.RemainingLifetimeNanos)).After(originalH) || ctx.Err() != nil || !pair.ready.Current() {
						t.Error("inspection response is not exact, fresh, current and bound to original host H")
					}
					wantOrdinal := uint64(1)
					if previousExec {
						wantOrdinal++
					}
					f.producer.mu.Lock()
					producerOrdinal := f.producer.ordinal
					f.producer.mu.Unlock()
					pair.mu.Lock()
					serverOrdinal := pair.ordinal
					pair.mu.Unlock()
					pair.ready.controller.mu.Lock()
					guestOrdinal := pair.ready.controller.workOrdinal
					pair.ready.controller.mu.Unlock()
					if producerOrdinal != wantOrdinal || serverOrdinal != wantOrdinal || guestOrdinal != wantOrdinal {
						t.Error("inspection did not use the original shared workload ordinal at all three boundaries")
					}
				}
				want := before
				for index := 0; index < 4; index++ {
					want[index]++
				}
				if after := o.counts(); after != want {
					t.Errorf("inspection must add one real verifier pass and no Ready/backend/environment work: before=%v after=%v want=%v", before, after, want)
				}
				f.producer.retire()
				minimalSupervisorWorkJoined(t, f)
			})
		})
	}
}

func TestMinimalHostInspectionRejectsHiddenExecCopyCarrier(t *testing.T) {
	for _, operation := range []guestagent.Operation{guestagent.OperationExec, guestagent.OperationCopyIn, guestagent.OperationCopyOut} {
		t.Run(string(operation), func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				o, rescue := minimalHostInspectionGuest(t, f)
				defer rescue()
				_, candidate := minimalSupervisorWorkClient(t, f)
				before := o.counts()
				if before != [7]int32{1, 1, 1, 1, 1, 0, 0} {
					t.Fatal("actual encrypted preparation prerequisite")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				response, err := candidate.RoundTrip(ctx, minimalHostInspectionCarrier(operation))
				defer clear(response.Encoded)
				if err == nil || len(response.Encoded) != 0 {
					t.Error("original Exec/Copy carrier accepted hidden selected inspection")
				}
				if after := o.counts(); after != before {
					t.Errorf("mismatched carrier reached fresh guest verification: before=%v after=%v", before, after)
				}
				f.producer.retire()
				minimalSupervisorWorkJoined(t, f)
			})
		})
	}
}

func TestMinimalHostInspectionPreCanceledAndRetiredOwnerControls(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		o, rescue := minimalHostInspectionGuest(t, f)
		defer rescue()
		client, candidate := minimalSupervisorWorkClient(t, f)
		before := o.counts()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		response, err := candidate.RoundTrip(ctx, minimalHostInspectionCarrier(minimalHostInspectionOperation))
		defer clear(response.Encoded)
		if err == nil || len(response.Encoded) != 0 || o.counts() != before {
			t.Fatal("pre-canceled inspection sent work or returned proof")
		}
		result, err := client.Exec(context.Background(), minimalJointExecRequest())
		if err != nil || result.ExitCode != 7 || o.counts() != [7]int32{2, 2, 2, 2, 1, 1, 0} {
			t.Fatal("pre-canceled inspection poisoned ordinary authenticated Exec")
		}
		f.producer.retire()
		minimalSupervisorWorkJoined(t, f)
		before = o.counts()
		response, err = candidate.RoundTrip(context.Background(), minimalHostInspectionCarrier(minimalHostInspectionOperation))
		defer clear(response.Encoded)
		if err == nil || len(response.Encoded) != 0 || o.counts() != before {
			t.Fatal("retired original owner returned proof or admitted verification")
		}
	})
}
