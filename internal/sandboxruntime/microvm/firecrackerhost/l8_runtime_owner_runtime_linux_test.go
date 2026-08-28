//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestL8RuntimeOwnerLinuxRecordStorePersistsExactFSM(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	seed := l8RuntimeOwnerTestSeed()
	bootID := "01234567-89ab-cdef-0123-456789abcdef"
	store := &l8RuntimeOwnerLinuxRecordStore{directoryFD: directoryFD, seed: seed, bootID: bootID}
	if absent, err := store.RecordAbsent(context.Background()); err != nil || !absent {
		t.Fatalf("initial record absence = %t, %v", absent, err)
	}
	genesis := l8RuntimeOwnerTestGenesis(l8RuntimeOwnerTestRecord(t, seed, bootID))
	if created, err := store.CreateGenesis(context.Background(), genesis); err != nil || created != genesis {
		t.Fatalf("create genesis = %#v, %v", created, err)
	}
	if absent, err := store.RecordAbsent(context.Background()); err != nil || absent {
		t.Fatalf("present record absence = %t, %v", absent, err)
	}
	invalidStore := &l8RuntimeOwnerLinuxRecordStore{directoryFD: -1, seed: seed, bootID: bootID}
	if absent, err := invalidStore.RecordAbsent(context.Background()); !errors.Is(err, errL8RuntimeOwnerInvalid) || absent {
		t.Fatalf("uncertain record absence = %t, %v", absent, err)
	}
	if _, err := store.CreateGenesis(context.Background(), genesis); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("duplicate genesis = %v", err)
	}
	revisionOne := genesis
	revisionOne.Revision = 1
	revisionOne.FirecrackerPID = 5001
	revisionOne.FirecrackerStartTime = 7001
	if updated, err := store.Transition(context.Background(), 0, revisionOne); err != nil || updated != revisionOne {
		t.Fatalf("revision one = %#v, %v", updated, err)
	}
	running := revisionOne
	running.Revision = 2
	running.State = "running"
	running.ControllerState = "unclaimed"
	if updated, err := store.Transition(context.Background(), 1, running); err != nil || updated != running {
		t.Fatalf("running = %#v, %v", updated, err)
	}
	if loaded, err := store.Load(context.Background()); err != nil || loaded != running {
		t.Fatalf("load = %#v, %v", loaded, err)
	}
	if _, err := store.Transition(context.Background(), 1, running); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("stale transition = %v", err)
	}
}

func TestL8RuntimeOwnerLinuxConfigAndAssetsRequireSealedReadOnlyDescriptors(t *testing.T) {
	kernel := []byte("kernel-image")
	rootfs := []byte("rootfs-image")
	kernelFD := newL8RuntimeOwnerTestSealedFD(t, "kernel", kernel)
	defer unix.Close(kernelFD)
	rootfsFD := newL8RuntimeOwnerTestSealedFD(t, "rootfs", rootfs)
	defer unix.Close(rootfsFD)
	config := l8RuntimeOwnerTestSupervisorConfig()
	config.Kernel = l8RuntimeOwnerTestAssetIdentity(t, "kernel", kernelFD, kernel)
	config.Rootfs = l8RuntimeOwnerTestAssetIdentity(t, "rootfs", rootfsFD, rootfs)
	payload, err := encodeL8RuntimeOwnerSupervisorConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	configFD := newL8RuntimeOwnerTestSealedFD(t, "config", payload)
	defer unix.Close(configFD)
	decoded, err := readL8RuntimeOwnerSupervisorConfigFD(configFD)
	if err != nil || !l8RuntimeOwnerSupervisorConfigsEqual(decoded, config) {
		t.Fatalf("config = %#v, %v", decoded, err)
	}
	if err := validateL8RuntimeOwnerAssetFD(kernelFD, config.Kernel); err != nil {
		t.Fatal(err)
	}
	mutated := config.Kernel
	mutated.Digest = hex.EncodeToString(make([]byte, sha256.Size))
	if err := validateL8RuntimeOwnerAssetFD(kernelFD, mutated); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("digest substitution = %v", err)
	}
}

func TestL8RuntimeOwnerLinuxReconnectListenerIsPrivateAndSameUID(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	identity := l8RuntimeOwnerTestToken(17)
	listenerFD, name, err := openL8RuntimeOwnerReconnectListener(directoryFD, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(listenerFD)
	defer unix.Unlinkat(directoryFD, name, 0)
	info, err := os.Lstat(filepath.Join(directory, name))
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("listener = %#v, %v", info, err)
	}
	clientFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(clientFD)
	if err := unix.Connect(clientFD, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(directoryFD) + "/" + name}); err != nil {
		t.Fatal(err)
	}
	acceptedFD, _, err := unix.Accept4(listenerFD, unix.SOCK_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(acceptedFD)
	uid, err := l8RuntimeOwnerPeerUID(acceptedFD)
	if err != nil || uid != uint32(os.Geteuid()) {
		t.Fatalf("peer uid = %d, %v", uid, err)
	}
}

func TestL8RuntimeOwnerLinuxSupervisorProductionCompositionReachesTransport(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)

	kernel := []byte("kernel-image")
	rootfs := []byte("rootfs-image")
	kernelFD := newL8RuntimeOwnerTestSealedFD(t, "kernel", kernel)
	defer unix.Close(kernelFD)
	rootfsFD := newL8RuntimeOwnerTestSealedFD(t, "rootfs", rootfs)
	defer unix.Close(rootfsFD)
	config := l8RuntimeOwnerTestSupervisorConfig()
	config.DaemonUID = uint32(os.Geteuid())
	config.Kernel = l8RuntimeOwnerTestAssetIdentity(t, "kernel", kernelFD, kernel)
	config.Rootfs = l8RuntimeOwnerTestAssetIdentity(t, "rootfs", rootfsFD, rootfs)
	payload, err := encodeL8RuntimeOwnerSupervisorConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	configFD := newL8RuntimeOwnerTestSealedFD(t, "config", payload)
	defer unix.Close(configFD)

	keyPath := filepath.Join(directory, "owner-key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := os.Open(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	control, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(control[0])
	defer unix.Close(control[1])

	owned, err := newL8RuntimeOwnerLinuxRuntime([6]int{control[0], directoryFD, configFD, kernelFD, rootfsFD, int(key.Fd())})
	if err != nil {
		t.Fatal(err)
	}
	defer owned.close()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		name := entry.Name()
		if len(name) > len(l8RuntimeOwnerReconnectPrefix)+len(l8RuntimeOwnerReconnectSuffix) &&
			name[:len(l8RuntimeOwnerReconnectPrefix)] == l8RuntimeOwnerReconnectPrefix &&
			name[len(name)-len(l8RuntimeOwnerReconnectSuffix):] == l8RuntimeOwnerReconnectSuffix {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("production supervisor composition did not publish its reconnect transport")
	}
}

func newL8RuntimeOwnerTestSealedFD(t *testing.T, name string, payload []byte) int {
	t.Helper()
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fd, payload); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, l8RuntimeOwnerRequiredSeals); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	readOnly, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	_ = unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	return readOnly
}

func l8RuntimeOwnerTestAssetIdentity(t *testing.T, kind string, fd int, payload []byte) l8RuntimeOwnerDescriptorIdentityV1 {
	t.Helper()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		t.Fatal("stat asset")
	}
	digest := sha256.Sum256(payload)
	return l8RuntimeOwnerDescriptorIdentityV1{Kind: kind, Device: uint64(stat.Dev), Inode: stat.Ino, Digest: hex.EncodeToString(digest[:])}
}
