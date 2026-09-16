//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

type minimalPreexecAssemblyFixture struct {
	base                                                             *minimalPreexecFixture
	host                                                             *minimalPreexecHost
	ops                                                              minimalPreexecOps
	namespace                                                        *minimalPreexecTestNamespace
	seed                                                             *minimalSeedProducerFixture
	command                                                          *minimalL7ConfigTestTAP
	networkCalls, seedCalls, entropyCalls, duplicateCalls, sealCalls atomic.Int32
}

func newMinimalPreexecAssemblyFixture(t *testing.T) *minimalPreexecAssemblyFixture {
	t.Helper()
	f := &minimalPreexecAssemblyFixture{base: newMinimalPreexecFixture(t)}
	var err error
	f.host, err = newMinimalPreexecHostForUID(f.base.preparation, f.base.handoff.provider, f.base.inputs, uint32(os.Geteuid()))
	if f.host != nil {
		t.Cleanup(func() { _ = f.host.close() })
	}
	if err != nil || f.host == nil {
		t.Fatal("actual ordinary-UID host construction", err)
	}
	f.namespace = newMinimalPreexecTestNamespace(t)
	f.seed = newMinimalSeedProducerFixture(t)
	f.command = &minimalL7ConfigTestTAP{}
	f.ops = minimalPreexecOps{
		network: func(input minimalPreexecHostInputs, identity l7network.Identity, plan networkenforcement.Plan) (*l7network.Coordinator, error) {
			f.networkCalls.Add(1)
			claim := f.base.reservation.Identity()
			if identity.SandboxID != claim.SandboxID || identity.ExecutionID != claim.ExecutionID || identity.WorkerID != claim.WorkerID || identity.RuntimeGenerationID != claim.RuntimeGeneration ||
				identity.PolicySnapshotID != f.base.inputs.proxy.Policy.PlanMetadata().PolicySnapshot.ID || identity.PlanID == claim.PlanID || plan.ID != identity.PlanID || plan.Proxy.ProxySessionID != identity.ProxySessionID {
				return nil, errors.New("incorrect real preparation identity")
			}
			tapOptions := input.tap
			tapOptions.Command = f.command
			tap, err := l7network.NewLinuxTAP(tapOptions)
			if err != nil {
				return nil, err
			}
			return l7network.New(l7network.Options{Enabled: true,
				Proxy:    &minimalL7ConfigTestProxy{endpoint: "127.0.0.1:43123", loss: make(chan struct{})},
				Topology: &minimalPreexecTestTopology{namespace: f.namespace}, TAP: tap, Rules: minimalL7ConfigTestRules{},
				GuestIsolation: minimalL7ConfigTestNoGuest{}, VMTermination: minimalL7ConfigTestNoGuest{}, StateDir: input.networkStateDirectory, CleanupTimeout: time.Second})
		},
		seed: func(ctx context.Context) (*minimalControllerSeedOwner, error) {
			f.seedCalls.Add(1)
			return newMinimalControllerSeedWithOps(ctx, uint32(os.Geteuid()), f.seed.ops)
		},
		entropy: func(buffer []byte) (int, error) {
			n := f.entropyCalls.Add(1)
			return readMinimalControllerEntropy(buffer, func(actual []byte, _ int) (int, error) {
				for i := range actual {
					actual[i] = byte(n)
				}
				return len(actual), nil
			})
		},
		duplicate: func(file *os.File) (*os.File, error) {
			f.duplicateCalls.Add(1)
			return duplicateJailerRecoveryFile(file)
		},
		seal: func(ctx context.Context, payload []byte) (*os.File, error) {
			f.sealCalls.Add(1)
			return sealJailerRecoveryBytes(ctx, payload)
		},
	}
	// Explicit cleanup below is the evidence; this final registered cleanup is
	// only rescue, before borrowed fixture capabilities are closed.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = f.base.owner.Finalize(ctx)
	})
	return f
}

func TestMinimalPreexecAssemblesOnOriginalClaimedOwner(t *testing.T) {
	f := newMinimalPreexecAssemblyFixture(t)
	owner, lease, assets := f.base.owner, f.base.owner.lease, f.base.owner.files
	if owner.preparation != f.base.preparation || owner.preparationDeadline != f.base.p || owner.reservation != f.base.reservation {
		t.Fatal("Claim did not retain the exact original reservation/context/P")
	}
	if err := owner.prepareMinimalInputsWithOps(f.host, f.ops); err != nil {
		t.Fatal("missing same-owner pre-exec assembly after genuine host/Claim controls", err)
	}
	a := owner.attempt
	if a == nil || a.owner != owner || a.host != f.host || !a.prepared || a.session == nil || a.coordinator == nil || a.seed == nil ||
		owner != f.base.probe.owner || owner.lease != lease || owner.files != assets || owner.Identity() != f.base.reservation.Identity() || owner.context != f.base.reservation.OwnedContext() {
		t.Fatal("assembly replaced its original owner, lease, context or retained preparation")
	}
	if deadline, ok := a.ctx.Deadline(); !ok || deadline != f.base.p || a.config.Control.PreparationDeadlineUnixNano != f.base.p.UnixNano() {
		t.Fatal("assembly rebased original P")
	}
	if len(a.config.Control.Prelaunch) != 25 || a.config.Control.Prelaunch["imageDigest"] != "sha256-"+owner.measured[1].SHA256 ||
		a.config.Control.Prelaunch["planId"] != owner.identity.PlanID || a.config.Control.Prelaunch["networkPlanId"] != a.networkIdentity.PlanID ||
		a.config.Control.Prelaunch["admissionGrantId"] != owner.request.AdmissionGrantID || a.config.Control.LaunchGrantID != owner.identity.LaunchGrantID {
		t.Fatal("assembly conflated original launch/request/image/network identities")
	}
	if metadata := a.session.Metadata(); metadata.Status != l7network.StatusHostPrepared || metadata.RawPacketIsolationVerified || metadata.Identity != a.networkIdentity {
		t.Fatal("assembled Session is not the actual pre-exec-only preparation")
	}
	minimalPreexecAssertNamespacePair(t, f.namespace.files, a.namespace)
	if f.networkCalls.Load() != 1 || f.seedCalls.Load() != 1 || f.duplicateCalls.Load() != 3 || f.sealCalls.Load() != 2 || f.entropyCalls.Load() != 9 {
		t.Fatal("assembly did not execute each actual bounded construction stage")
	}
	f.seed.assertWiped()
	if err := owner.prepareMinimalInputsWithOps(f.host, f.ops); err == nil || owner.attempt != a || f.networkCalls.Load() != 1 {
		t.Fatal("same owner admitted a second assembly")
	}
	if err := f.base.handoff.selected.Close(); err != nil || lease.ConfirmCurrent(f.base.preparation) != nil {
		t.Fatal("selection alias retired transferred ownership")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if receipt, err := owner.Finalize(ctx); receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || owner.closeErr != nil {
		t.Fatal("pre-exec finalization failed or manufactured terminal receipt", err)
	}
	if !a.filesClosed || !a.rollbackComplete || !f.namespace.closed || !f.command.removed || !owner.assetsClosed {
		t.Fatal("original Finalize did not complete reached pre-VM rollback and owned FD cleanup")
	}
	if owner.attempt != a || !reflect.DeepEqual(owner.Identity(), f.base.reservation.Identity()) {
		t.Fatal("cleanup discarded or replaced its original owner/attempt identity")
	}
	minimalPreexecAssertBorrowedInputs(t, f.base.inputs)
}
