//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"golang.org/x/sys/unix"
)

func TestMinimalPreexecActualClaimedOwnerControl(t *testing.T) {
	f := newMinimalPreexecFixture(t)
	lease, snapshots := f.owner.lease, f.owner.files
	if again, err := f.probe.source.assets.TakeLaunchLease(f.preparation); again != nil || err == nil {
		t.Fatal("original distribution allowed a second transfer")
	}
	if err := f.handoff.selected.Close(); err != nil || lease.ConfirmCurrent(f.preparation) != nil ||
		f.owner.lease != lease || f.owner.files != snapshots {
		t.Fatal("selection alias Close retired or replaced the original asset owner")
	}
	for range 2 {
		if receipt, err := f.owner.Finalize(f.preparation); receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) ||
			!errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || f.owner.closeErr != nil {
			t.Fatal("asset-only finalization invented runtime/cleanup success", err)
		}
	}
	for _, file := range snapshots {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("actual original snapshot remained open after Finalize")
		}
	}
	if lease.ConfirmCurrent(f.preparation) == nil {
		t.Fatal("actual original lease remained current after Finalize")
	}
	t.Log("reached actual acquisition, consumed Claim, one lease, original snapshots and asset-only Finalize")
}

func TestMinimalPreexecActualHostFDControl(t *testing.T) {
	input := minimalPreexecHostFixtureInputs(t, "network-policy")
	minimalPreexecAssertBorrowedInputs(t, input)
	for _, borrowed := range []*os.File{input.stateRoot, input.stableKey, input.executable} {
		duplicate, err := duplicateJailerRecoveryFile(borrowed)
		if duplicate != nil {
			t.Cleanup(func() { _ = duplicate.Close() })
		}
		if err != nil {
			t.Fatal("actual duplicate", err)
		}
		originalInfo, originalErr := borrowed.Stat()
		duplicateInfo, duplicateErr := duplicate.Stat()
		flags, flagErr := unix.FcntlInt(duplicate.Fd(), unix.F_GETFD, 0)
		if originalErr != nil || duplicateErr != nil || flagErr != nil || !os.SameFile(originalInfo, duplicateInfo) ||
			duplicate == borrowed || duplicate.Fd() == borrowed.Fd() || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("owned duplicate lost actual identity or CLOEXEC")
		}
		if err := duplicate.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// The unchanged reader consumes only this owned duplicate. The source
	// remains borrowed, linked, and unrelated to the controller seed.
	fd, err := unix.FcntlInt(input.stableKey.Fd(), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadL8RuntimeOwnerStableKeyFD(fd, uint32(os.Geteuid()), realL8RuntimeOwnerKeyFDOps())
	defer clear(key)
	if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{0x6b}, 32)) {
		t.Fatal("actual retained stable-key reader control", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("unchanged key reader did not consume its owned duplicate")
	}
	minimalPreexecAssertBorrowedInputs(t, input)
	t.Log("reached actual ordinary-UID FD validators, same-object duplication and stable-key reader; no root/executable provenance claim")
}

func TestMinimalPreexecActualSeedControl(t *testing.T) {
	f := newMinimalSeedProducerFixture(t)
	seed, err := newMinimalControllerSeedWithOps(context.Background(), uint32(os.Geteuid()), f.ops)
	if seed != nil {
		t.Cleanup(func() { _ = seed.close() })
	}
	if err != nil || seed == nil {
		t.Fatal("actual bounded seed algorithm did not produce its real owner", err)
	}
	file, err := seed.borrowFile()
	if err != nil {
		t.Fatal(err)
	}
	minimalSeedProducerAssertFD(t, int(file.Fd()), uint32(os.Geteuid()))
	minimalSeedProducerRoundTrip(t, file, seed.publicKey(), minimalSeedProducerTestSeed())
	for _, stage := range []string{"entropy", "derive", "create", "write", "chmod", "seal", "open"} {
		if f.calls[stage] != 1 {
			t.Fatalf("seed stage %s reached %d times, want one", stage, f.calls[stage])
		}
	}
	f.assertWiped()
	if seed.close() != nil || seed.close() != nil {
		t.Fatal("actual seed ownership did not close idempotently")
	}
	f.assertClosed()
	t.Log("reached real memfd/Ed25519/loader with one explicit fake entropy draw and wiped aliases")
}

// This control is deliberately independent of the missing host constructor.
// No prepared Session, descriptor or replacement owner is injected into it.
func TestMinimalPreexecActualL7AndNamespaceControl(t *testing.T) {
	f := newMinimalPreexecFixture(t)
	identity := l7RuntimeControllerIdentity("preexec-control")
	claim := f.owner.Identity()
	identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.RuntimeGenerationID =
		claim.SandboxID, claim.ExecutionID, claim.WorkerID, claim.RuntimeGeneration
	identity.PolicySnapshotID = f.inputs.proxy.Policy.PlanMetadata().PolicySnapshot.ID
	if identity.PlanID == claim.PlanID || f.inputs.networkPolicyID != f.handoff.inputs.association.scope.NetworkPolicyID {
		t.Fatal("fixture conflated launch Plan, network Plan or scope policy")
	}
	namespace := newMinimalPreexecTestNamespace(t)
	proxy := &minimalL7ConfigTestProxy{endpoint: "127.0.0.1:43123", loss: make(chan struct{})}
	command := &minimalL7ConfigTestTAP{}
	tapOptions := f.inputs.tap
	tapOptions.Command = command
	tap, err := l7network.NewLinuxTAP(tapOptions)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := l7network.New(l7network.Options{
		Enabled: true, Proxy: proxy, Topology: &minimalPreexecTestTopology{namespace: namespace}, TAP: tap,
		Rules: minimalL7ConfigTestRules{}, GuestIsolation: minimalL7ConfigTestNoGuest{}, VMTermination: minimalL7ConfigTestNoGuest{},
		StateDir: f.inputs.networkStateDirectory, CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatal("actual Coordinator constructor", err)
	}
	session, err := coordinator.Prepare(f.preparation, l7network.PrepareRequest{Identity: identity, Plan: l7RuntimeControllerPlan(identity)})
	if session != nil {
		t.Cleanup(func() { _ = session.AbortBeforeVM(context.Background(), identity) })
	}
	if err != nil || session == nil {
		t.Fatal("actual fake-backed Coordinator.Prepare", err)
	}
	// Successful Prepare armed the notification. A failed partial Prepare is
	// never presumed to have a watcher/notification to await.
	notified := false
	observeLoss := func() {
		if notified {
			return
		}
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		for {
			select {
			case _, open := <-session.Loss():
				if !open {
					notified = true
					return
				}
			case <-timer.C:
				t.Error("actual loss notification did not complete after fake proxy Stop")
				return
			}
		}
	}
	t.Cleanup(func() {
		_ = session.AbortBeforeVM(context.Background(), identity)
		observeLoss()
	})
	metadata := session.Metadata()
	if metadata.Identity != identity || metadata.Status != l7network.StatusHostPrepared || metadata.RawPacketIsolationVerified || command.name == "" {
		t.Fatal("actual host preparation was not reached or invented guest proof")
	}
	descriptor, err := session.LaunchDescriptor(identity)
	if err != nil {
		t.Fatal(err)
	}
	if topology, runtime, ok := descriptor.ProofGenerations(); !ok || topology != identity.TopologyGenerationID || runtime != claim.RuntimeGeneration {
		t.Fatal("actual descriptor lost original job generation")
	}
	if _, device, mac, ok := descriptor.NetworkInterface(); !ok || device != command.name || mac != command.mac {
		t.Fatal("descriptor NIC does not match the actual TAP parser's configured fixture")
	}
	if guest, ipv4, gateway4, ipv6, gateway6, endpoint, ok := descriptor.StaticNetwork(); !ok ||
		guest != "eth0" || ipv4 != "172.31.255.2/30" || ipv6 != "fd00:6861:6c::2/126" ||
		gateway4 != command.source4 || gateway6 != command.source6 || endpoint != "http://192.0.2.2:43123" {
		t.Fatal("actual descriptor lost static guest addressing or host-to-guest proxy mapping")
	}
	view, err := session.ProcessNamespace(identity)
	if err != nil {
		t.Fatal(err)
	}
	user, network, err := view.DuplicateForNamespaceProcess()
	for _, file := range []*os.File{user, network} {
		if file != nil {
			t.Cleanup(func() { _ = file.Close() })
		}
	}
	if err != nil || user == nil || network == nil {
		t.Fatal("actual same-Session namespace duplication", err)
	}
	minimalPreexecAssertNamespacePair(t, namespace.files, [2]*os.File{user, network})
	if err := session.AbortBeforeVM(context.Background(), identity); err != nil {
		t.Fatal("actual pre-VM rollback", err)
	}
	observeLoss()
	if !namespace.closed || namespace.closes != 1 || namespace.duplicate != 1 || !command.removed {
		t.Fatal("reached rollback did not close its original namespace borrow and fake TAP once")
	}
	for _, file := range namespace.files {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("actual rollback left its namespace borrow open")
		}
	}
	for _, file := range []*os.File{user, network} {
		if _, err := file.Stat(); err != nil {
			t.Fatal("rollback invalidated independently owned namespace duplicates", err)
		}
	}
	if _, err := session.ProcessNamespace(identity); err == nil {
		t.Fatal("retired Session still issued a namespace view")
	}
	f.assertClaimed(t)
	t.Log("reached actual L7 Prepare/descriptor/namespace duplicates/Abort with fake host boundaries; Loss notification is not a whole-runtime task join")
}

func TestMinimalPreexecProductionRootBoundaryControl(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("ordinary-UID rejection is not exercised under root; no root admission claim")
		return
	}
	f := newMinimalPreexecFixture(t)
	host, err := newMinimalPreexecHost(f.preparation, f.handoff.provider, f.inputs)
	if host != nil {
		t.Cleanup(func() { _ = host.close() })
	}
	if host != nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) {
		t.Fatal("production constructor accepted an actual ordinary UID")
	}
	minimalPreexecAssertBorrowedInputs(t, f.inputs)
	f.assertClaimed(t)
	t.Log("reached actual nonroot production rejection without replacing the root observation")
}

func TestMinimalPreexecRetainsTrustedHostInputs(t *testing.T) {
	f := newMinimalPreexecFixture(t)
	minimalPreexecAssertBorrowedInputs(t, f.inputs)
	host, err := newMinimalPreexecHostForUID(f.preparation, f.handoff.provider, f.inputs, uint32(os.Geteuid()))
	if host != nil {
		t.Cleanup(func() { _ = host.close() })
	}
	if err != nil || host == nil {
		t.Fatal("missing trusted pre-exec host construction after actual acquisition/Claim/sealed-asset/host-FD controls", err)
	}
	// These assertions are beyond the first RED. No assembly is called: its
	// genuine same-owner/P/25-field forward fixture still needs reviewed fake
	// command/network boundaries, never the default host-operation options.
	owned := []*os.File{host.stateRoot, host.stableKey, host.executable}
	borrowed := []*os.File{f.inputs.stateRoot, f.inputs.stableKey, f.inputs.executable}
	for i, file := range owned {
		if file == nil || file == borrowed[i] || file.Fd() == borrowed[i].Fd() {
			t.Fatal("constructor did not retain an independently owned input duplicate")
		}
		original, originalErr := borrowed[i].Stat()
		duplicate, duplicateErr := file.Stat()
		flags, flagErr := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if originalErr != nil || duplicateErr != nil || flagErr != nil || !os.SameFile(original, duplicate) || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("host duplicate differs from the actual deployment input")
		}
	}
	if host.close() != nil || host.close() != nil {
		t.Fatal("trusted host close is not successful and idempotent")
	}
	for _, file := range owned {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("host close retained an owned input duplicate")
		}
	}
	minimalPreexecAssertBorrowedInputs(t, f.inputs)
	f.assertClaimed(t)
}
