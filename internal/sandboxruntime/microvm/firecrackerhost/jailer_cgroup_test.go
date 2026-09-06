package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeJailerCgroupFilesystem struct {
	isCreated     bool
	values        map[string]string
	fail          string
	events        *[]string
	holdPopulated bool
	closed        bool
}

func newFakeJailerCgroupFilesystem() *fakeJailerCgroupFilesystem {
	return &fakeJailerCgroupFilesystem{values: map[string]string{"cgroup.events": "populated 0\nfrozen 0\n"}}
}
func (fs *fakeJailerCgroupFilesystem) event(name string) error {
	if fs.events != nil {
		*fs.events = append(*fs.events, name)
	}
	if fs.fail == name {
		return errJailerCgroup
	}
	return nil
}
func (fs *fakeJailerCgroupFilesystem) create(string) error {
	fs.isCreated = true
	return fs.event("create")
}
func (fs *fakeJailerCgroupFilesystem) created() bool { return fs.isCreated }
func (fs *fakeJailerCgroupFilesystem) verify() error { return fs.event("verify-cgroup") }
func (fs *fakeJailerCgroupFilesystem) read(name string) (string, error) {
	return fs.values[name], fs.event("read:" + name)
}
func (fs *fakeJailerCgroupFilesystem) write(name, value string) error {
	if err := fs.event("write:" + name); err != nil {
		return err
	}
	fs.values[name] = value
	if name == "cgroup.kill" && !fs.holdPopulated {
		fs.values["cgroup.events"] = "populated 0\nfrozen 0\n"
	}
	return nil
}
func (fs *fakeJailerCgroupFilesystem) duplicate() (*os.File, error) {
	if err := fs.event("duplicate"); err != nil {
		return nil, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	_ = writer.Close()
	return reader, nil
}
func (fs *fakeJailerCgroupFilesystem) remove() error {
	if err := fs.event("remove-cgroup"); err != nil {
		return err
	}
	fs.isCreated = false
	return nil
}
func (fs *fakeJailerCgroupFilesystem) close() error {
	if err := fs.event("close-cgroup"); err != nil {
		return err
	}
	fs.closed = true
	return nil
}

func testJailerCgroupResources() *strictJailerCgroupResources {
	return &strictJailerCgroupResources{anchor: "/trusted/cgroups", cpuQuota: 100000, cpuPeriod: 100000, memoryMax: 256 << 20, swapMax: 0, pidsMax: 128}
}
func testJailerCgroupRequest() strictJailerCgroupRequest {
	return strictJailerCgroupRequest{resources: *testJailerCgroupResources(), runtimeID: "run-1", configSHA256: strings.Repeat("a", 64), guestMemoryMiB: 128}
}
func prepareFakeJailerCgroup(ctx context.Context, request strictJailerCgroupRequest, fs *fakeJailerCgroupFilesystem) (*strictJailerCgroupLease, error) {
	return prepareStrictJailerCgroupWithFilesystem(ctx, request, uint64(os.Getpagesize()), func(string) (strictJailerCgroupFilesystem, error) { return fs, nil })
}

// Existing strict-only fixtures now explicitly provide resource preparation.
// This is not a production nil/default fallback.
func newJailerCgroupTestCoordinator(deps strictJailerCoordinatorDependencies) *strictJailerCoordinator {
	// Strict fixtures explicitly inject a fake prepared identity; the real
	// constructor still rejects absent host-owned identity configuration.
	deps.identity, _ = newFakeJailerIdentityAuthority()
	deps.recovery = newFakeJailerRecoveryAuthority()
	deps.prepareCgroup = func(ctx context.Context, request strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
		return prepareFakeJailerCgroup(ctx, request, newFakeJailerCgroupFilesystem())
	}
	return newStrictJailerCoordinatorWithDependencies(deps)
}

func testJailerCgroupLease(t *testing.T, runtimeID string) *strictJailerCgroupLease {
	t.Helper()
	request := testJailerCgroupRequest()
	request.runtimeID = runtimeID
	lease, err := prepareFakeJailerCgroup(context.Background(), request, newFakeJailerCgroupFilesystem())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.quiesce(context.Background()); _ = lease.release() })
	return lease
}

func TestJailerCgroupFiniteLimitsAndBinding(t *testing.T) {
	for _, name := range []string{"valid", "zero quota", "zero period", "period small", "period large", "quota large", "zero memory", "memory large", "memory unaligned", "swap unaligned", "swap large", "zero pids", "pids large", "missing anchor", "root anchor", "unclean anchor", "relative anchor", "runtime", "digest", "guest memory"} {
		t.Run(name, func(t *testing.T) {
			r := testJailerCgroupRequest()
			switch name {
			case "zero quota":
				r.resources.cpuQuota = 0
			case "zero period":
				r.resources.cpuPeriod = 0
			case "period small":
				r.resources.cpuPeriod = 999
			case "period large":
				r.resources.cpuPeriod = 1000001
			case "quota large":
				r.resources.cpuQuota = 102400001
			case "zero memory":
				r.resources.memoryMax = 0
			case "memory large":
				r.resources.memoryMax = 1 << 41
			case "memory unaligned":
				r.resources.memoryMax++
			case "swap unaligned":
				r.resources.swapMax = 1
			case "swap large":
				r.resources.swapMax = 1 << 41
			case "zero pids":
				r.resources.pidsMax = 0
			case "pids large":
				r.resources.pidsMax = 1 << 21
			case "missing anchor":
				r.resources.anchor = ""
			case "root anchor":
				r.resources.anchor = "/"
			case "unclean anchor":
				r.resources.anchor = "/safe/../unsafe"
			case "relative anchor":
				r.resources.anchor = "safe"
			case "runtime":
				r.runtimeID = "../other"
			case "digest":
				r.configSHA256 = "wrong"
			case "guest memory":
				r.guestMemoryMiB = 512
			}
			fs := newFakeJailerCgroupFilesystem()
			lease, err := prepareFakeJailerCgroup(context.Background(), r, fs)
			if name != "valid" {
				if err == nil || lease != nil || fs.created() {
					t.Fatal("invalid request allocated authority")
				}
				return
			}
			if err != nil || !lease.matches(r.runtimeID, r.configSHA256) || lease.matches("other", r.configSHA256) || lease.matches(r.runtimeID, strings.Repeat("b", 64)) {
				t.Fatal("binding mismatch")
			}
			if err := lease.quiesce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := lease.release(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestJailerCgroupPreparationFailureRetainsExactCleanup(t *testing.T) {
	for _, operation := range []string{"create", "verify-cgroup", "write:cpu.max", "write:memory.max", "write:memory.swap.max", "write:pids.max", "read:cpu.max", "read:memory.max", "read:memory.swap.max", "read:pids.max"} {
		t.Run(operation, func(t *testing.T) {
			fs := newFakeJailerCgroupFilesystem()
			fs.fail = operation
			lease, err := prepareFakeJailerCgroup(context.Background(), testJailerCgroupRequest(), fs)
			if err == nil || lease == nil || lease.prepared {
				t.Fatal("partial preparation lost or accepted")
			}
			fs.fail = ""
			if lease.quiesce(context.Background()) != nil || lease.release() != nil || !fs.closed {
				t.Fatal("partial cleanup failed")
			}
		})
	}
}

func TestJailerCgroupLaunchRevalidatesReadbackAndClosesDuplicate(t *testing.T) {
	fs := newFakeJailerCgroupFilesystem()
	lease, err := prepareFakeJailerCgroup(context.Background(), testJailerCgroupRequest(), fs)
	if err != nil {
		t.Fatal(err)
	}
	var borrowed *os.File
	if err := lease.withLaunchFD(context.Background(), "run-1", func(fd *os.File) error { borrowed = fd; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := borrowed.Stat(); err == nil {
		t.Fatal("launch duplicate leaked")
	}
	fs.values["memory.max"] = "max\n"
	if err := lease.withLaunchFD(context.Background(), "run-1", func(*os.File) error { t.Fatal("changed limit launched"); return nil }); err == nil {
		t.Fatal("changed limit accepted")
	}
	if lease.quiesce(context.Background()) != nil || lease.release() != nil {
		t.Fatal("cleanup failed")
	}
	if lease.withLaunchFD(context.Background(), "run-1", func(*os.File) error { return nil }) == nil {
		t.Fatal("released lease relaunched")
	}
}

func TestJailerCgroupPopulatedOrUncertainCleanupCannotRelease(t *testing.T) {
	fs := newFakeJailerCgroupFilesystem()
	lease, err := prepareFakeJailerCgroup(context.Background(), testJailerCgroupRequest(), fs)
	if err != nil {
		t.Fatal(err)
	}
	fs.holdPopulated = true
	fs.values["cgroup.events"] = "populated 1\nfrozen 0\n"
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if lease.quiesce(ctx) == nil || lease.release() == nil || !fs.created() {
		t.Fatal("populated authority released")
	}
	fs.holdPopulated = false
	if lease.quiesce(context.Background()) != nil {
		t.Fatal("kill/empty retry failed")
	}
	fs.fail = "remove-cgroup"
	if lease.release() == nil || lease.released {
		t.Fatal("failed remove released authority")
	}
	fs.fail = ""
	if lease.release() != nil || lease.release() != nil || !fs.closed {
		t.Fatal("repeated cleanup failed")
	}
}

func TestJailerCgroupEventsFailClosed(t *testing.T) {
	for _, value := range []string{"", "frozen 0\n", "populated 2\n", "populated 0", "populated 0\npopulated 0\n", "populated 0\nunknown 1\n", strings.Repeat("x", 4097)} {
		if _, err := jailerCgroupEmpty(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	if empty, err := jailerCgroupEmpty("populated 1\nfrozen 0\n"); err != nil || empty {
		t.Fatal("populated not preserved")
	}
}

func TestJailerCgroupCancellationBeforePreparation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lease, err := prepareStrictJailerCgroupWithFilesystem(ctx, testJailerCgroupRequest(), 4096, func(string) (strictJailerCgroupFilesystem, error) {
		t.Fatal("canceled preparation opened anchor")
		return nil, errors.New("unexpected")
	})
	if err == nil || lease != nil {
		t.Fatal("canceled preparation accepted")
	}
}

func TestJailerCgroupCancelledOrPartialOpenRetainsOnlyCloseAuthority(t *testing.T) {
	for _, cancelOpen := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		fs := newFakeJailerCgroupFilesystem()
		lease, err := prepareStrictJailerCgroupWithFilesystem(ctx, testJailerCgroupRequest(), 4096, func(string) (strictJailerCgroupFilesystem, error) {
			if cancelOpen {
				cancel()
				return fs, nil
			}
			return fs, errJailerCgroup
		})
		cancel()
		if err == nil || lease == nil || fs.created() {
			t.Fatal("partial/canceled open created child or lost descriptors")
		}
		if lease.quiesce(context.Background()) != nil || lease.release() != nil || !fs.closed {
			t.Fatal("partial anchor close failed")
		}
	}
}

func TestJailerCgroupAllChangedReadbacksDenyFirstLaunch(t *testing.T) {
	for _, name := range []string{"cpu.max", "memory.max", "memory.swap.max", "pids.max"} {
		t.Run(name, func(t *testing.T) {
			fs := newFakeJailerCgroupFilesystem()
			lease, err := prepareFakeJailerCgroup(context.Background(), testJailerCgroupRequest(), fs)
			if err != nil {
				t.Fatal(err)
			}
			fs.values[name] = "max\n"
			if lease.withLaunchFD(context.Background(), "run-1", func(*os.File) error { t.Fatal("changed readback launched"); return nil }) == nil {
				t.Fatal("changed readback accepted")
			}
			if lease.quiesce(context.Background()) != nil || lease.release() != nil {
				t.Fatal("readback rejection cleanup failed")
			}
		})
	}
}

func TestJailerCgroupRequiredControllers(t *testing.T) {
	if !jailerCgroupControllersEnabled("cpu memory pids\n") {
		t.Fatal("enabled controllers rejected")
	}
	for _, value := range []string{"", "cpu memory\n", "cpu pids\n", "memory pids\n", "+cpu memory pids\n", "cpu memory pids cpu\n", "cpu memory pids"} {
		if jailerCgroupControllersEnabled(value) {
			t.Fatalf("accepted %q", value)
		}
	}
}
