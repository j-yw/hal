//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"golang.org/x/sys/unix"
)

var minimalControlTestRoles = []string{"control-socket", "owner-directory", "supervisor-config", "kernel-asset", "rootfs-asset", "owner-root-key", "firecracker-config", "minimal-controller-key"}

// Real ordinary FDs and kernel sealing/permission observations, not a root
// supervisor, namespace handoff, L7 owner, store, gate or launch fixture.
type minimalControlAdmissionFixture struct {
	t          *testing.T
	config     minimalControlSupervisorConfig
	files      [8]*os.File
	payload    []byte
	opened     []uintptr
	closed     []int
	imports    map[int]*os.File
	legacy     int
	admissions int
	failRole   int
	seedUID    uint32
}

func newMinimalControlAdmissionFixture(t *testing.T) *minimalControlAdmissionFixture {
	t.Helper()
	f := &minimalControlAdmissionFixture{t: t, imports: make(map[int]*os.File), seedUID: uint32(os.Geteuid())}
	t.Cleanup(func() {
		for _, file := range f.files {
			if file != nil {
				_ = file.Close()
			}
		}
	})
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.files[0] = os.NewFile(uintptr(pair[0]), "minimal-test-control")
	t.Cleanup(func() { _ = unix.Close(pair[1]) })
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.files[1] = directory
	f.config.jailerRecoverySupervisorConfig = jailerRecoveryTestSupervisorConfig(t)
	f.config.Version = minimalControlSupervisorConfigVersion
	f.config.Roles = slices.Clone(minimalControlTestRoles)
	for i, data := range [][]byte{[]byte("measured-test-kernel"), []byte("measured-test-rootfs")} {
		f.files[i+3] = minimalControlTestMemfd(t, data, l8RuntimeOwnerRequiredSeals, 0o400, true)
		asset := minimalControlTestMeasuredAsset(t, f.files[i+3], []string{"kernel", "rootfs"}[i], data)
		if i == 0 {
			f.config.Kernel = asset
		} else {
			f.config.Rootfs = asset
		}
	}
	rootKey, err := os.CreateTemp(t.TempDir(), "recovery-test-material-")
	if err != nil {
		t.Fatal(err)
	}
	f.files[5] = rootKey
	if _, err := rootKey.Write(bytes.Repeat([]byte{17}, 32)); err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{41}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	f.files[7] = minimalControlTestMemfd(t, seed, l8RuntimeOwnerRequiredSeals, 0o400, true)
	clear(seed)
	j := f.config.Job
	fields := map[string]string{
		"sandboxId": j.SandboxID, "executionId": j.ExecutionID, "workerId": j.WorkerID, "hostId": j.HostID,
		"runtimeDriver": "microvm", "runtimeId": j.RuntimeID, "runtimeGeneration": j.RuntimeGeneration,
		"bootGeneration": "boot-1", "imageGeneration": "image-1", "imageDigest": "sha256-" + f.config.Rootfs.SHA256,
		"workerJobId": "worker-job-1", "submissionId": "submission-1", "planId": "worker-plan-1", "jobGeneration": "job-1",
		"admissionGrantId": "credential-intent-1", "admissionRevision": "7", "principalId": "principal-1",
		"templatePolicyId": "template-policy-1", "workspacePolicyId": "workspace-policy-1", "networkPlanId": "network-plan-1",
		"policySnapshotId": "policy-1", "proxySessionId": "proxy-1", "proxyGenerationId": "proxy-generation-1",
		"topologyGenerationId": "topology-1", "ruleGenerationId": "rules-1",
	}
	identity := session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		RuntimeID: j.RuntimeID, RuntimeGeneration: j.RuntimeGeneration, BootGeneration: "boot-1", ImageGeneration: "image-1",
		ControllerKeyGeneration: "controller-key-1", GuestBootNonce: [32]byte{42}}
	image, _ := hex.DecodeString(f.config.Rootfs.SHA256)
	copy(identity.ImageSHA256[:], image)
	c := &f.config.Control
	c.Prelaunch = fields
	c.ControllerPublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	c.ControllerKeyGeneration = identity.ControllerKeyGeneration
	c.BootNonce = base64.RawURLEncoding.EncodeToString(identity.GuestBootNonce[:])
	c.PreparationDeadlineUnixNano = time.Now().Add(time.Minute).UnixNano()
	c.LaunchGrantID, c.LaunchPolicyRevision = "launch-grant-1", "3"
	c.NetworkInterface = minimalL7NetworkInterface{InterfaceID: "net1", HostDeviceName: "hftapfixture", GuestMAC: "02:00:00:00:00:01"}
	c.StaticNetwork = [6]string{"eth0", "192.0.2.2/30", "192.0.2.1", "fd00::2/126", "fd00::1", "http://192.0.2.1:3128"}
	c.Namespace = minimalControlNamespaces{UserDevice: 11, UserInode: 12, NetworkDevice: 11, NetworkInode: 13}
	boot, err := minimalcontrol.RenderBootCommandLine("console=ttyS0 "+minimalL7BootFragment(c.StaticNetwork), identity, key.Public().(ed25519.PublicKey), fields)
	if err != nil {
		t.Fatal(err)
	}
	bootJSON, _ := json.Marshal(boot)
	nicJSON, _ := json.Marshal([]minimalL7NetworkInterface{c.NetworkInterface})
	fc := strings.Replace(validCoordinatorConfig(), `"kernel_image_path":"/boot/vmlinux"`, `"kernel_image_path":"/boot/vmlinux","boot_args":`+string(bootJSON), 1)
	fc = strings.TrimSuffix(fc, "}") + `,"network-interfaces":` + string(nicJSON) + "}"
	f.files[6] = minimalControlTestMemfd(t, []byte(fc), l8RuntimeOwnerRequiredSeals, 0o400, true)
	f.config.Config = minimalControlTestMeasuredAsset(t, f.files[6], "config", []byte(fc))
	f.reseal(nil)
	return f
}

func minimalControlTestMemfd(t *testing.T, payload []byte, seals int, mode uint32, readOnly bool) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("minimal-admission-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "minimal-admission-test")
	if n, err := file.Write(payload); err != nil || n != len(payload) || unix.Fchmod(fd, mode) != nil {
		_ = file.Close()
		t.Fatal("prepare ordinary memfd")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if !readOnly {
		return file
	}
	readFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(readFD), "minimal-admission-readonly-test")
}

func minimalControlTestMeasuredAsset(t *testing.T, file *os.File, kind string, payload []byte) jailerRecoveryAsset {
	t.Helper()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil {
		t.Fatal("stat measured fixture")
	}
	digest := sha256.Sum256(payload)
	return jailerRecoveryAsset{Kind: kind, Device: uint64(stat.Dev), Inode: stat.Ino, Size: stat.Size, SHA256: hex.EncodeToString(digest[:])}
}

func (f *minimalControlAdmissionFixture) reseal(payload []byte) {
	f.t.Helper()
	if payload == nil {
		var err error
		payload, err = json.Marshal(f.config)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	if f.files[2] != nil {
		_ = f.files[2].Close()
	}
	f.payload = bytes.Clone(payload)
	f.files[2] = minimalControlTestMemfd(f.t, payload, l8RuntimeOwnerRequiredSeals, 0o400, true)
}

func (f *minimalControlAdmissionFixture) run(mode string, consume func(*minimalControlSupervisorAdmission) error) int {
	f.t.Helper()
	open := func(number uintptr, role string) (int, error) {
		f.opened = append(f.opened, number)
		if number < 3 || number > 10 || role != minimalControlTestRoles[number-3] {
			f.t.Fatalf("unexpected import: number=%d role=%q", number, role)
		}
		if int(number) == f.failRole || f.files[number-3] == nil {
			return -1, errL8RuntimeOwnerInvalid
		}
		file := f.files[number-3]
		fd := int(file.Fd())
		if _, duplicate := f.imports[fd]; duplicate {
			f.t.Fatal("same descriptor imported twice")
		}
		f.imports[fd] = file
		// Match the actual Linux wrapper: own and set CLOEXEC; do not duplicate.
		if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			delete(f.imports, fd)
			_ = file.Close()
			return -1, err
		}
		return fd, nil
	}
	closeFD := func(fd int) error {
		file := f.imports[fd]
		if file == nil {
			f.t.Errorf("double/unowned close: %d", fd)
			return errL8RuntimeOwnerInvalid
		}
		if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
			f.t.Error("import was not CLOEXEC before consumption/close")
		}
		delete(f.imports, fd)
		f.closed = append(f.closed, fd)
		return file.Close()
	}
	code := runPrivateL8RuntimeOwnerExecutableWithOps([]string{mode}, l8RuntimeOwnerExecutableOps{
		OpenFD: open, CloseFD: closeFD,
		RunSupervisor: func([6]int) error { f.legacy++; return nil },
		RunChildGate:  func([6]int) error { f.legacy++; return nil },
		SelectSupervisor: func(fds [6]int) (bool, error) {
			// Production passes fixed root UID 0. This injected expected UID
			// allows real unprivileged FD metadata checks, not root authority.
			return withMinimalControlSupervisorAdmission(fds, open, closeFD, f.seedUID, func(admission *minimalControlSupervisorAdmission) error {
				f.admissions++
				return consume(admission)
			})
		},
	})
	if len(f.imports) != 0 {
		f.t.Errorf("partial imports remain owned: %d", len(f.imports))
	}
	return code
}

func requireMinimalControlAdmission(t *testing.T) {
	t.Helper()
	f := newMinimalControlAdmissionFixture(t)
	code := f.run("supervise", func(*minimalControlSupervisorAdmission) error { return nil })
	if code != 0 || f.admissions != 1 || f.legacy != 0 {
		t.Fatalf("positive admission prerequisite missing: exit=%d admitted=%d legacy=%d; later negative not reached", code, f.admissions, f.legacy)
	}
}

func TestMinimalControlConfigActualEightRoleAdmission(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	seedFD := int(f.files[7].Fd())
	// ExtraFiles are initially inheritable. The selected import must establish
	// CLOEXEC on both late roles rather than requiring a pre-exec flag to survive.
	for _, file := range f.files[6:] {
		if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, 0); err != nil {
			t.Fatal(err)
		}
	}
	var retainedKey []byte
	var successor *os.File
	defer func() {
		if successor != nil {
			_ = successor.Close()
		}
	}()
	code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		if admission == nil || !reflect.DeepEqual(admission.config, f.config) || admission.configDigest != sha256.Sum256(f.payload) {
			t.Fatal("admission did not retain the exact complete eight-config bytes")
		}
		if !slices.Equal(f.opened, []uintptr{3, 4, 5, 6, 7, 8, 9, 10}) {
			t.Fatal("not exactly eight roles before observation")
		}
		if _, err := unix.FcntlInt(uintptr(seedFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatal("seed FD still open at admission observer")
		}
		if len(admission.controllerKey) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(admission.controllerKey.Public().(ed25519.PublicKey)) != f.config.Control.ControllerPublicKey {
			t.Fatal("private key does not match pinned public key")
		}
		retainedKey = admission.controllerKey
		// Reuse the consumed number: deferred cleanup must not close a later
		// unrelated descriptor after the seed import has been retired.
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if fd != seedFD {
			if unix.Dup3(fd, seedFD, unix.O_CLOEXEC) != nil {
				t.Fatal("reuse consumed seed number")
			}
			_ = unix.Close(fd)
		}
		successor = os.NewFile(uintptr(seedFD), "unrelated-successor-canary")
		return nil
	})
	if code != 0 || f.admissions != 1 || f.legacy != 0 {
		t.Fatalf("actual eight-role admission unavailable: exit=%d admitted=%d legacy=%d", code, f.admissions, f.legacy)
	}
	if !bytes.Equal(retainedKey, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("callback-scoped signing key was not wiped")
	}
	if _, err := successor.Stat(); err != nil {
		t.Fatal("consumed seed cleanup closed unrelated reused descriptor")
	}
}

func TestMinimalControlConfigPartialImportsCloseWithoutFallback(t *testing.T) {
	for number := 3; number <= 10; number++ {
		t.Run(strconv.Itoa(number), func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			f.failRole = number
			code := f.run("supervise", func(*minimalControlSupervisorAdmission) error { t.Fatal("partial import admitted"); return nil })
			if code != 127 || f.legacy != 0 || !slices.Contains(f.opened, uintptr(number)) || len(f.closed) != number-3 {
				t.Fatalf("partial import did not reach/close exact boundary: exit=%d opened=%v closed=%d legacy=%d", code, f.opened, len(f.closed), f.legacy)
			}
		})
	}
}

func TestMinimalControlConfigUnavailableRuntimeRemainsClosed(t *testing.T) {
	requireMinimalControlAdmission(t)
	f := newMinimalControlAdmissionFixture(t)
	var key []byte
	code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		key = admission.controllerKey
		return unavailableMinimalControlSupervisor(admission)
	})
	if code != 127 || f.admissions != 1 || f.legacy != 0 || !bytes.Equal(key, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("byte admission manufactured runtime success or retained signing key")
	}
}

func TestMinimalControlConfigLegacyAndGateSentinels(t *testing.T) {
	for _, mode := range []string{"six-role", "seven-role", "child-gate"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			switch mode {
			case "six-role":
				payload, err := encodeL8RuntimeOwnerSupervisorConfig(l8RuntimeOwnerTestSupervisorConfig())
				if err != nil {
					t.Fatal(err)
				}
				f.reseal(payload)
			case "seven-role":
				payload, _ := json.Marshal(jailerRecoveryTestSupervisorConfig(t))
				f.reseal(payload)
			}
			arg := "supervise"
			if mode == "child-gate" {
				arg = mode
			}
			code := f.run(arg, func(*minimalControlSupervisorAdmission) error {
				t.Fatal("legacy/gate selected minimal admission")
				return nil
			})
			if code != 0 || f.legacy != 1 || f.admissions != 0 || !slices.Equal(f.opened, []uintptr{3, 4, 5, 6, 7, 8}) {
				t.Fatalf("existing callback route changed: exit=%d legacy=%d imports=%v", code, f.legacy, f.opened)
			}
		})
	}
}
