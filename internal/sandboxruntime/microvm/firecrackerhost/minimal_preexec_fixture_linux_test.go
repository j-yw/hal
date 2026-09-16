//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
	"golang.org/x/sys/unix"
)

type minimalPreexecFixture struct {
	handoff     *minimalTemplateHandoffFixture
	probe       *minimalTemplateHandoffProbe
	reservation *sandboxruntime.MinimalLaunchReservation
	owner       *minimalTemplateAssetOwner
	preparation context.Context
	p           time.Time
	inputs      minimalPreexecHostInputs
}

func newMinimalPreexecFixture(t *testing.T) *minimalPreexecFixture {
	t.Helper()
	handoff, probe, reservation := newMinimalTemplateHandoffProbe(t, nil)
	f := &minimalPreexecFixture{handoff: handoff, probe: probe, reservation: reservation,
		preparation: reservation.Context()}
	var ok bool
	f.p, ok = f.preparation.Deadline()
	ownedDeadline, ownedOK := reservation.OwnedContext().Deadline()
	if !ok || !ownedOK || !f.p.Before(ownedDeadline) {
		t.Fatal("fixture lacks distinct original preparation and owner lifetimes")
	}
	f.owner = startMinimalTemplateProbe(t, handoff, probe, reservation)
	f.assertClaimed(t)
	f.inputs = minimalPreexecHostFixtureInputs(t, handoff.inputs.association.scope.NetworkPolicyID)
	return f
}

func (f *minimalPreexecFixture) assertClaimed(t *testing.T) {
	t.Helper()
	request, err := f.reservation.RequestCorrelation()
	if err != nil || f.owner != f.probe.owner || f.probe.source.owner != f.owner ||
		f.owner.Identity() != f.reservation.Identity() || f.owner.context != f.reservation.OwnedContext() ||
		f.owner.template != f.handoff.inputs.association.template || f.owner.request != request ||
		f.handoff.inputs.requests.Load() != 2 || f.preparation != f.reservation.Context() || f.preparation.Err() != nil {
		t.Fatal("actual acquisition/Start lost the original claim, owner, request or context")
	}
	if p, ok := f.reservation.Context().Deadline(); !ok || p != f.p {
		t.Fatal("original preparation deadline changed")
	}
	if f.owner.lease == nil || f.owner.lease.ConfirmCurrent(f.preparation) != nil ||
		f.probe.source.assets.ConfirmCurrent(f.preparation) == nil || f.handoff.selected.Current(f.preparation) != nil {
		t.Fatal("post-transfer currentness does not use the original retained lease")
	}
	if _, err := f.reservation.ClaimLaunch(f.preparation); err == nil {
		t.Fatal("actual Start did not consume the original Claim")
	}
	if f.owner.measured[1].SHA256 != f.handoff.inputs.association.expected.RootfsSHA256 ||
		f.owner.measured[1].SHA256 == f.owner.template.RuntimeImageSHA256 {
		t.Fatal("raw rootfs and independently declared OCI image digests were conflated")
	}
	assertMinimalTemplateSnapshot(t, f.owner.files[0], f.owner.measured[0], 128<<20)
	assertMinimalTemplateSnapshot(t, f.owner.files[1], f.owner.measured[1], 4<<30)
}

func minimalPreexecHostFixtureInputs(t *testing.T, policyID string) minimalPreexecHostInputs {
	t.Helper()
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal("provision private fixture root", err)
	}
	rootFD, err := openL8RuntimeOwnerDirectory(rootPath)
	if err != nil {
		t.Fatal("actual private owner-state root", err)
	}
	root := os.NewFile(uintptr(rootFD), "preexec-test-root")
	t.Cleanup(func() { _ = root.Close() })
	keyBytes := bytes.Repeat([]byte{0x6b}, 32) // Test-only stable key, unrelated to the seed.
	t.Cleanup(func() { clear(keyBytes) })
	key, err := os.OpenFile(filepath.Join(rootPath, "stable-key"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if key != nil {
		t.Cleanup(func() { _ = key.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	if n, err := key.Write(keyBytes); err != nil || n != len(keyBytes) {
		t.Fatal("test stable-key write", err)
	}
	// This is a genuine sealed snapshot of independently hashed fixture bytes,
	// not a native executable build, ELF validation or root deployment proof.
	executableBytes := []byte("independent pre-exec supervisor snapshot fixture")
	expected := sha256.Sum256(executableBytes)
	executable, err := snapshotStrictJailerExecutable(bytes.NewReader(executableBytes), expected)
	if executable != nil {
		t.Cleanup(func() { _ = executable.Close() })
	}
	if err != nil {
		t.Fatal("actual sealed executable snapshot primitive", err)
	}
	identity := l7RuntimeControllerIdentity("configured-policy")
	policy := networkenforcement.NewPolicyProxyPolicyInput(l7RuntimeControllerPlan(identity), nil)
	return minimalPreexecHostInputs{
		policy: jailerRecoveryHostPolicy{IdentityDirectory: rootPath, UID: 10001, GID: 10001,
			TrustedAnchor: "/prepared", ChrootBase: "/prepared/jails", JailerPath: "/prepared/jailer", FirecrackerPath: "/prepared/firecracker",
			JailerSHA256: strings.Repeat("a", 64), FirecrackerSHA256: strings.Repeat("b", 64), CgroupAnchor: "/sys/fs/cgroup/hal",
			CPUQuota: 100000, CPUPeriod: 100000, MemoryMax: 512 << 20, PidsMax: 64},
		vcpus: 1, memoryMiB: 128, baseBootArguments: "console=ttyS0 panic=1", jailPathBase: "/run",
		stateRoot: root, stableKey: key, executable: executable, executableSHA256: expected,
		networkPolicyID: policyID, proxy: policyproxy.Config{Policy: policy, ListenAddress: "127.0.0.1:0"},
		topology: linuxtopology.Config{Enabled: true, StateDir: t.TempDir(), CleanupTimeout: time.Second,
			Tools: linuxtopology.ToolPaths{Unshare: "/usr/bin/unshare", Pasta: "/usr/bin/pasta", Nsenter: "/usr/bin/nsenter", IP: "/usr/bin/ip", NC: "/usr/bin/nc", Keeper: "/usr/bin/sleep"}},
		tap:                   l7network.TAPOptions{IPPath: "/usr/bin/ip", SysctlPath: "/usr/bin/sysctl", NsenterPath: "/usr/bin/nsenter"},
		rules:                 linuxrules.ProductionExecutorOptions{NSenterPath: "/usr/bin/nsenter", NFTPath: "/usr/bin/nft"},
		networkStateDirectory: t.TempDir(), cleanupTimeout: time.Second,
	}
}

func minimalPreexecAssertBorrowedInputs(t *testing.T, input minimalPreexecHostInputs) {
	t.Helper()
	if err := validateL8RuntimeOwnerDirectoryFD(int(input.stateRoot.Fd())); err != nil {
		t.Fatal("borrowed directory unavailable", err)
	}
	identity, err := realL8RuntimeOwnerKeyFDOps().Stat(int(input.stableKey.Fd()))
	if err != nil || !validL8RuntimeOwnerKeyIdentity(identity, uint32(os.Geteuid())) {
		t.Fatal("borrowed stable-key metadata changed", err)
	}
	if err := validateStrictJailerExecutableSnapshot(input.executable); err != nil {
		t.Fatal("borrowed executable unavailable", err)
	}
	bytes, err := io.ReadAll(io.NewSectionReader(input.executable, 0, maxStrictJailerExecutableBytes+1))
	if err != nil || sha256.Sum256(bytes) != input.executableSHA256 {
		t.Fatal("actual executable differs from independently trusted fixture digest", err)
	}
}

// Only this fake topology owns the ordinary current-namespace borrows. It does
// not create/enter a namespace or claim a distinct sandbox namespace. The real
// Coordinator obtains actual duplicates of these exact retained descriptors.
type minimalPreexecTestTopology struct {
	minimalL7ConfigTestTopology
	namespace *minimalPreexecTestNamespace
}

func (f *minimalPreexecTestTopology) Start(ctx context.Context, request linuxtopology.StartRequest) (l7network.TopologySession, error) {
	_, err := f.minimalL7ConfigTestTopology.Start(ctx, request)
	return f, err
}
func (f *minimalPreexecTestTopology) BorrowNamespace() (l7network.NamespaceLease, error) {
	return f.namespace, nil
}

type minimalPreexecTestNamespace struct {
	mu        sync.Mutex
	files     [2]*os.File
	closed    bool
	duplicate int
	closes    int
}

func newMinimalPreexecTestNamespace(t *testing.T) *minimalPreexecTestNamespace {
	t.Helper()
	n := &minimalPreexecTestNamespace{}
	t.Cleanup(func() { _ = n.Close() }) // Rescue only; reached Abort must close first.
	for i, path := range []string{"/proc/self/ns/user", "/proc/self/ns/net"} {
		file, err := os.Open(path)
		n.files[i] = file
		if err != nil {
			t.Fatal("ordinary namespace borrow", err)
		}
	}
	return n
}

func (n *minimalPreexecTestNamespace) RuleNamespace() linuxrules.NamespaceHandle {
	n.mu.Lock()
	defer n.mu.Unlock()
	return linuxrules.NewNamespaceHandle(int(n.files[0].Fd()), int(n.files[1].Fd()))
}

func (n *minimalPreexecTestNamespace) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, nil, os.ErrClosed
	}
	n.duplicate++
	user, err := duplicateJailerRecoveryFile(n.files[0])
	if err != nil {
		return user, nil, err
	}
	network, err := duplicateJailerRecoveryFile(n.files[1])
	return user, network, err
}

func (n *minimalPreexecTestNamespace) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	n.closes++
	var err error
	for _, file := range n.files {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}
	return err
}

func minimalPreexecAssertNamespacePair(t *testing.T, originals, duplicates [2]*os.File) {
	t.Helper()
	if err := validateL8RuntimeOwnerNamespacePair(int(duplicates[0].Fd()), int(duplicates[1].Fd())); err != nil {
		t.Fatal("actual nsfs pair validator", err)
	}
	for i, file := range duplicates {
		original, err := l8RuntimeOwnerStatNamespaceFD(int(originals[i].Fd()))
		duplicate, duplicateErr := l8RuntimeOwnerStatNamespaceFD(int(file.Fd()))
		kind, kindErr := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_NSTYPE)
		if err != nil || duplicateErr != nil || kindErr != nil || original != duplicate ||
			file == originals[i] || file.Fd() == originals[i].Fd() || kind != []int{unix.CLONE_NEWUSER, unix.CLONE_NEWNET}[i] {
			t.Fatal("namespace handoff is not a distinct descriptor for the same actual object")
		}
	}
}
