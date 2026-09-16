//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"golang.org/x/sys/unix"
)

type minimalPreexecAssemblyFixture struct {
	base                                                             *minimalPreexecFixture
	host                                                             *minimalPreexecHost
	ops                                                              minimalPreexecOps
	namespace                                                        *minimalPreexecTestNamespace
	seed                                                             *minimalSeedProducerFixture
	command                                                          *minimalL7ConfigTestTAP
	configureNetwork                                                 func(*l7network.Options)
	networkCalls, seedCalls, entropyCalls, duplicateCalls, sealCalls atomic.Int32
}

func newMinimalPreexecAssemblyFixture(t *testing.T, original ...*minimalPreexecFixture) *minimalPreexecAssemblyFixture {
	t.Helper()
	f := &minimalPreexecAssemblyFixture{}
	if len(original) == 0 {
		f.base = newMinimalPreexecAssemblyClaim(t)
	} else {
		f.base = original[0]
	}
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
				t.Logf("network callback identity equality: snapshot=%t plan=%t proxy=%t", identity.PolicySnapshotID == f.base.inputs.proxy.Policy.PlanMetadata().PolicySnapshot.ID, plan.ID == identity.PlanID, plan.Proxy.ProxySessionID == identity.ProxySessionID)
				return nil, errors.New("incorrect real preparation identity")
			}
			tapOptions := input.tap
			tapOptions.Command = f.command
			tap, err := l7network.NewLinuxTAP(tapOptions)
			if err != nil {
				return nil, err
			}
			options := l7network.Options{Enabled: true,
				Proxy:    &minimalL7ConfigTestProxy{endpoint: "127.0.0.1:43123", loss: make(chan struct{})},
				Topology: &minimalPreexecTestTopology{namespace: f.namespace}, TAP: tap, Rules: minimalL7ConfigTestRules{},
				GuestIsolation: minimalL7ConfigTestNoGuest{}, VMTermination: minimalL7ConfigTestNoGuest{}, StateDir: input.networkStateDirectory, CleanupTimeout: time.Second}
			if f.configureNetwork != nil {
				f.configureNetwork(&options)
			}
			return l7network.New(options)
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

// Select valid strict Firecracker paths BEFORE Reserve/Claim. The original RED
// fixture remains byte-identical; no claimed identity is repaired in place.
func newMinimalPreexecAssemblyClaim(t *testing.T, shared ...*minimalTemplateHandoffFixture) *minimalPreexecFixture {
	t.Helper()
	h := &minimalTemplateHandoffFixture{}
	if len(shared) == 0 {
		h.inputs = newMinimalTemplateFixture(t)
	} else {
		h.inputs = shared[0].inputs
	}
	var cancel context.CancelFunc
	h.ctx, cancel = context.WithTimeout(context.Background(), 4*time.Second)
	t.Cleanup(cancel)
	h.owned, cancel = context.WithTimeout(context.Background(), 6*time.Second)
	t.Cleanup(cancel)
	var err error
	if len(shared) == 0 {
		h.provider, err = newMinimalLaunchProvider(h.inputs.association, h.inputs.options)
	} else {
		h.provider = shared[0].provider
	}
	if err != nil {
		t.Fatal(err)
	}
	probe := &minimalTemplateHandoffProbe{minimalLaunchProvider: h.provider, snapshot: snapshotJailerRecoveryAsset}
	h.binding, err = sandboxruntime.NewMinimalLaunchProviderBinding(probe)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("preexec-authority", "preexec-authority-generation")
	if err != nil {
		t.Fatal(err)
	}
	h.principal, err = authority.IssueAuthenticatedWorkerPrincipal(h.inputs.association.scope.PrincipalID, 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	h.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(authority, h.binding, []sandboxruntime.MinimalLaunchScope{h.inputs.association.scope})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.authorizer.Close)
	hints := minimalTemplateHints()
	hints.RuntimeID = "fc-preexec-job"
	if len(shared) != 0 {
		hints.RuntimeID += "-two"
		hints.SandboxID += "-two"
		hints.ExecutionID += "-two"
		hints.SubmissionID += "-two"
		hints.PlanID += "-two"
	}
	h.selected, err = h.authorizer.ResolveSelection(h.ctx, h.principal, h.inputs.association.scope.WorkerID, hints, h.inputs.association.template)
	if err != nil || probe.source == nil {
		t.Fatal("actual fc-prefixed selection", err)
	}
	t.Cleanup(func() { _ = h.selected.Close() })
	r, err := h.selected.Reserve(h.ctx, h.owned, "preexec-job", "preexec-job-generation", "request-v2-"+strings.Repeat("c", 64), time.Now().Add(3*time.Second),
		sandboxruntime.MinimalLaunchRequestCorrelation{AdmissionGrantID: "original-admission", AdmissionGrantRevision: 7})
	if err != nil || r.ArmDispatch(h.ctx, r.Identity()) != nil {
		t.Fatal("actual same selection Reserve/Arm", err)
	}
	t.Cleanup(r.Revoke)
	f := &minimalPreexecFixture{handoff: h, probe: probe, reservation: r, preparation: r.Context()}
	f.p, _ = r.Context().Deadline()
	f.owner = startMinimalTemplateProbe(t, h, probe, r)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = f.owner.Finalize(ctx)
	})
	if len(shared) == 0 {
		f.assertClaimed(t)
	} else if f.owner != probe.owner || probe.source.owner != f.owner || f.owner.lease == nil || f.owner.lease.ConfirmCurrent(f.preparation) != nil ||
		f.owner.Identity() != r.Identity() || f.owner.context != r.OwnedContext() || h.selected.Current(f.preparation) != nil || h.inputs.requests.Load() != 4 {
		t.Fatal("second genuine provider acquisition/Claim control failed")
	}
	f.inputs = minimalPreexecHostFixtureInputs(t, h.inputs.association.scope.NetworkPolicyID)
	return f
}

func TestMinimalPreexecAssemblesOnOriginalClaimedOwner(t *testing.T) {
	f := newMinimalPreexecAssemblyFixture(t)
	owner, lease, assets := f.base.owner, f.base.owner.lease, f.base.owner.files
	if owner.preparation != f.base.preparation || owner.preparationDeadline != f.base.p || owner.reservation != f.base.reservation {
		t.Fatal("Claim did not retain the exact original reservation/context/P")
	}
	if err := owner.prepareMinimalInputsWithOps(f.host, f.ops); err != nil {
		t.Logf("reached stages: duplicates=%d entropy=%d network=%d seed=%d seals=%d", f.duplicateCalls.Load(), f.entropyCalls.Load(), f.networkCalls.Load(), f.seedCalls.Load(), f.sealCalls.Load())
		if a := owner.attempt; a != nil {
			t.Logf("retained stages: coordinator=%t session=%t prepare-returned=%t prepare-success=%t user=%t net=%t", a.coordinator != nil, a.session != nil, a.prepareReturned, a.successfulPrepare, a.namespace[0] != nil, a.namespace[1] != nil)
			if a.session != nil {
				t.Logf("retained Session status=%s", a.session.Metadata().Status)
			}
		}
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
	claim, scope, n := f.base.reservation.Identity(), f.base.handoff.inputs.association.scope, a.networkIdentity
	expected := map[string]string{
		"sandboxId": claim.SandboxID, "executionId": claim.ExecutionID, "workerId": claim.WorkerID, "hostId": claim.HostID,
		"runtimeId": claim.RuntimeID, "runtimeGeneration": claim.RuntimeGeneration, "workerJobId": claim.WorkerJobID,
		"submissionId": claim.SubmissionID, "planId": claim.PlanID, "jobGeneration": claim.JobGeneration, "principalId": claim.PrincipalID,
		"runtimeDriver": "microvm", "admissionGrantId": "original-admission", "admissionRevision": "7",
		"templatePolicyId": scope.TemplatePolicyID, "workspacePolicyId": scope.WorkspacePolicyID,
		"networkPlanId": n.PlanID, "policySnapshotId": n.PolicySnapshotID, "proxySessionId": n.ProxySessionID,
		"proxyGenerationId": n.ProxyGenerationID, "topologyGenerationId": n.TopologyGenerationID, "ruleGenerationId": n.RuleGenerationID,
		"bootGeneration": a.publicGenerations[0], "imageGeneration": a.publicGenerations[1], "imageDigest": "sha256-" + f.base.handoff.inputs.association.expected.RootfsSHA256,
	}
	if !reflect.DeepEqual(a.config.Control.Prelaunch, expected) || a.config.Control.LaunchPolicyRevision != strconv.FormatUint(claim.LaunchPolicyRevision, 10) {
		t.Fatal("not every selected value came from its original independent source")
	}
	payload, err := io.ReadAll(io.NewSectionReader(a.configFile, 0, l8RuntimeOwnerSupervisorConfigLimit+1))
	decoded, public, decodeErr := decodeMinimalControlSupervisorConfig(payload)
	fc, fcErr := readMinimalControlFirecrackerConfig(int(a.fcFile.Fd()), a.config.Config)
	if err != nil || decodeErr != nil || fcErr != nil || !reflect.DeepEqual(decoded, a.config) || sha256.Sum256(payload) != a.configDigest ||
		validateMinimalControlFirecrackerConfig(fc, decoded, public) != nil || fc.MachineConfig.VCPUCount != f.base.inputs.vcpus || int64(fc.MachineConfig.MemSizeMiB) != f.base.inputs.memoryMiB ||
		fc.BootSource.KernelImagePath != "/boot/vmlinux" || len(fc.Drives) != 1 || fc.Drives[0].PathOnHost != "/images/rootfs.ext4" || fc.Vsock == nil || fc.Vsock.GuestCID != 3 {
		t.Fatal("actual sealed selected/FC config readback failed")
	}
	if entries, err := a.directory.ReadDir(-1); err != nil || len(entries) != 0 {
		t.Fatal("per-job directory is not an actual new empty directory", err)
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
	minimalPreexecFinalizeFixture(t, f)
	var entry unix.Stat_t
	if unix.Fstatat(int(f.base.inputs.stateRoot.Fd()), claim.RuntimeGeneration, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		uint64(entry.Dev) != a.directoryPin.Device || entry.Ino != a.directoryPin.Inode || entry.Mode&0o7777 != 0o700 {
		t.Fatal("documented empty directory retention lost its original identity")
	}
}
