//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"

	"golang.org/x/sys/unix"
)

func strictJailerTestExecutablePair(t *testing.T, jailerPath, firecrackerPath string) *strictJailerExecutablePair {
	t.Helper()
	pair := &strictJailerExecutablePair{}
	for index, path := range [2]string{jailerPath, firecrackerPath} {
		payload := []byte("measured test-only executable " + path)
		digest := sha256.Sum256(payload)
		file, err := snapshotStrictJailerExecutable(bytes.NewReader(payload), digest)
		if err != nil {
			t.Fatal(err)
		}
		pair.entries[index] = strictJailerExecutable{path: path, file: file, digest: digest}
	}
	t.Cleanup(func() { _ = pair.close() })
	return pair
}

func TestStrictJailerExecutableSnapshotSurvivesSourceReplacementAndRejectsMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jailer")
	payload := []byte("measured immutable executable")
	if err := os.WriteFile(path, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotStrictJailerExecutable(source, sha256.Sum256(payload))
	_ = source.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement attacker executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".original", []byte("in-place changed original inode"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(snapshot)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("snapshot changed after source replacement: %q, %v", got, err)
	}
	for name, mutate := range map[string]func() error{
		"write":  func() error { _, err := snapshot.WriteAt([]byte("x"), 0); return err },
		"grow":   func() error { return snapshot.Truncate(int64(len(payload) + 1)) },
		"shrink": func() error { return snapshot.Truncate(1) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := mutate(); !errors.Is(err, unix.EPERM) {
				t.Fatalf("sealed mutation = %v, want EPERM", err)
			}
		})
	}
	if err := validateStrictJailerExecutableSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestStrictJailerExecutablePinRejectsInspectionAndAcquisitionDrift(t *testing.T) {
	for _, name := range []string{"jailer inode", "firecracker inode", "payload", "parent symlink", "leaf symlink", "owner", "writable", "oversized"} {
		t.Run(name, func(t *testing.T) {
			filesystem, request := validStrictJailerHostInspectionFixture()
			inspection, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
			if err != nil {
				t.Fatal(err)
			}
			path := request.firecrackerPath
			if name == "jailer inode" {
				path = request.jailerPath
			}
			info := filesystem.infos[path].(fakeStrictJailerHostFileInfo)
			switch name {
			case "jailer inode", "firecracker inode":
				info.identity = "replaced-inode"
			case "payload":
				filesystem.payloads[path] = []byte("changed bytes on same inode")
			case "parent symlink":
				filesystem.resolved[filepath.Dir(path)] = "/untrusted/replacement"
			case "leaf symlink":
				filesystem.openErrors[path] = unix.ELOOP
			case "owner":
				info.ownerUID = 1000
			case "writable":
				info.mode = 0o777
			case "oversized":
				info.size = maxStrictJailerExecutableBytes + 1
			}
			filesystem.infos[path] = info
			tracked := &strictJailerTrackedInspectionFilesystem{strictJailerHostInspectionFilesystem: filesystem}
			before := strictJailerOpenFDCount(t)
			pair, err := pinStrictJailerExecutablesWithFilesystem(inspection, tracked)
			if pair != nil {
				_ = pair.close()
				t.Fatal("changed executable acquisition returned authority")
			}
			if !errors.Is(err, errStrictJailerExecutablesInvalid) {
				t.Fatalf("changed acquisition = %v", err)
			}
			if tracked.opened != tracked.closed {
				t.Fatalf("source descriptor leak: opened %d closed %d", tracked.opened, tracked.closed)
			}
			if got := strictJailerOpenFDCount(t); got != before {
				t.Fatalf("snapshot descriptor leak: before %d after %d", before, got)
			}
		})
	}
}

func TestStrictJailerExecutablePinOwnsExactlyTwoSnapshotsAndClosesSources(t *testing.T) {
	filesystem, request := validStrictJailerHostInspectionFixture()
	inspection, err := inspectStrictJailerHostWithFilesystem(request, filesystem)
	if err != nil {
		t.Fatal(err)
	}
	tracked := &strictJailerTrackedInspectionFilesystem{strictJailerHostInspectionFilesystem: filesystem}
	before := strictJailerOpenFDCount(t)
	pair, err := pinStrictJailerExecutablesWithFilesystem(inspection, tracked)
	if err != nil {
		t.Fatal(err)
	}
	if tracked.opened != 2 || tracked.closed != 2 || strictJailerOpenFDCount(t) != before+2 {
		t.Fatal("snapshot acquisition did not close both sources and retain exactly two files")
	}
	if err := pair.close(); err != nil {
		t.Fatal(err)
	}
	if err := pair.close(); err != nil || strictJailerOpenFDCount(t) != before {
		t.Fatalf("snapshot close was not terminal/idempotent: %v", err)
	}
}

func TestStrictJailerExecutableLeaseHasIndependentCloseOnExecLifetime(t *testing.T) {
	pair := strictJailerTestExecutablePair(t, "/opt/hal/bin/jailer", "/opt/hal/bin/firecracker")
	command := strictJailerCommand{jailerPath: pair.entries[0].path, firecrackerPath: pair.entries[1].path}
	lease, err := pair.duplicateForLaunch(command)
	if err != nil {
		t.Fatal(err)
	}
	if err := pair.close(); err != nil {
		t.Fatal(err)
	}
	for _, entry := range lease.entries {
		if err := validateStrictJailerExecutableSnapshot(entry.file); err != nil {
			t.Fatal("closing source pair invalidated independently owned launch descriptor")
		}
	}
	if next, err := pair.duplicateForLaunch(command); next != nil || err == nil {
		t.Fatal("closed owner permitted a new launch")
	}
	files := [2]*os.File{lease.entries[0].file, lease.entries[1].file}
	if err := lease.close(); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if _, err := file.Stat(); err == nil {
			t.Fatal("launch lease leaked its descriptor")
		}
	}
}

func TestStrictJailerExecutableLeaseRejectsPathDriftAndPartialInvalidity(t *testing.T) {
	for _, name := range []string{"jailer path", "firecracker path", "closed second", "unsealed second"} {
		t.Run(name, func(t *testing.T) {
			pair := strictJailerTestExecutablePair(t, "/opt/hal/bin/jailer", "/opt/hal/bin/firecracker")
			command := strictJailerCommand{jailerPath: pair.entries[0].path, firecrackerPath: pair.entries[1].path}
			switch name {
			case "jailer path":
				command.jailerPath = "/opt/hal/bin/other-jailer"
			case "firecracker path":
				command.firecrackerPath = "/opt/hal/bin/other-firecracker"
			case "closed second":
				_ = pair.entries[1].file.Close()
			case "unsealed second":
				_ = pair.entries[1].file.Close()
				file, err := os.CreateTemp(t.TempDir(), "unsealed")
				if err != nil {
					t.Fatal(err)
				}
				pair.entries[1].file = file
			}
			before := strictJailerOpenFDCount(t)
			lease, err := pair.duplicateForLaunch(command)
			if lease != nil || err == nil {
				t.Fatal("invalid pair granted executable lease")
			}
			if strictJailerOpenFDCount(t) != before {
				t.Fatal("partial duplication leaked first descriptor")
			}
		})
	}
}

func TestStrictJailerExecutableSnapshotRejectsWrongDigestReadErrorAndBoundsInput(t *testing.T) {
	before := strictJailerOpenFDCount(t)
	for _, source := range []io.Reader{strings.NewReader("wrong bytes"), strictJailerExecutableErrorReader{}} {
		file, err := snapshotStrictJailerExecutable(source, sha256.Sum256([]byte("expected")))
		if file != nil || err == nil {
			t.Fatal("invalid snapshot was accepted")
		}
	}
	reader := &strictJailerExecutableZeroReader{}
	file, err := snapshotStrictJailerExecutable(reader, sha256.Sum256([]byte("expected")))
	if file != nil || err == nil || reader.count != maxStrictJailerExecutableBytes+1 {
		t.Fatalf("unbounded input: %d bytes, err %v", reader.count, err)
	}
	if strictJailerOpenFDCount(t) != before {
		t.Fatal("failed snapshot leaked descriptor")
	}
}

func TestStrictJailerExecutableMountsArePrivateAndFailClosedAtEveryStep(t *testing.T) {
	steps := []string{"unshare-mount", "private-recursive", "bind-jailer", "bind-firecracker", "verify-jailer", "verify-firecracker"}
	for failAt := -1; failAt < len(steps); failAt++ {
		t.Run(string(rune('A'+failAt+1)), func(t *testing.T) {
			var events []string
			step := func(name string) error {
				events = append(events, name)
				if len(events)-1 == failAt {
					return errors.New("private unsafe path /host/executable")
				}
				return nil
			}
			lease := &strictJailerExecutableLease{entries: [2]strictJailerExecutable{{path: "jailer"}, {path: "firecracker"}}}
			err := mountStrictJailerExecutables(lease, strictJailerExecutableMountOps{
				unshare:     func() error { return step(steps[0]) },
				makePrivate: func() error { return step(steps[1]) },
				bind:        func(entry strictJailerExecutable) error { return step("bind-" + entry.path) },
				verify:      func(entry strictJailerExecutable) error { return step("verify-" + entry.path) },
			})
			want := steps
			if failAt >= 0 {
				want = steps[:failAt+1]
			}
			if !reflect.DeepEqual(events, want) || (err != nil) != (failAt >= 0) {
				t.Fatalf("mount sequence = %v error %v, want %v", events, err, want)
			}
			if err != nil && strings.Contains(err.Error(), "/host") {
				t.Fatal("mount error leaked host path")
			}
		})
	}
}

func TestStrictJailerExecutablePinFailureNeverReachesExec(t *testing.T) {
	started := false
	var published error
	runStrictJailerOSExecLaunch(strictJailerOSExecLaunchOps{
		lockOSThread: func() {}, unshareFilesystem: func() error { return nil },
		setNetworkNamespace:  func() error { return nil },
		pinExecutables:       func() error { return errors.New("unavailable pin /host/binary") },
		umask:                func(int) int { t.Fatal("umask after failed pin"); return 0 },
		armParentDeathSignal: func() { t.Fatal("armed after failed pin") },
		start:                func() error { started = true; return nil },
		publishStarted:       func(err error) { published = err },
		wait:                 func() error { t.Fatal("wait after failed pin"); return nil },
		publishCompleted:     func(error) { t.Fatal("completion after failed pin") },
	})
	if started || !errors.Is(published, errStrictJailerNamespaceStartFailed) {
		t.Fatal("pin failure did not prevent launch")
	}
}

func TestStrictJailerExecutableRealStarterClosesLaunchFDsOnStartFailure(t *testing.T) {
	network, writer := atomicJailerTestPipe(t)
	defer network.Close()
	defer writer.Close()
	plan := atomicJailerTestPlan(t, "run-alpha")
	pair := strictJailerTestExecutablePair(t, plan.process.Executable, plan.process.Args[3])
	before := strictJailerOpenFDCount(t)
	starter := OSExecNamespaceProcessStarter{startCommand: func(*exec.Cmd) error {
		if strictJailerOpenFDCount(t) != before+2 {
			t.Fatal("exec did not own exactly two independent snapshots")
		}
		return errors.New("injected start failure")
	}}
	_, err := starter.startStrictJailerNamespaceProcess(context.Background(), strictJailerNamespaceProcessStartRequest{
		executable: plan.process.Executable, args: plan.process.Args, networkNamespace: network, executables: pair,
	})
	if !errors.Is(err, errStrictJailerNamespaceStartFailed) || strictJailerOpenFDCount(t) != before {
		t.Fatal("failed start leaked executable lease")
	}
}

func TestStrictJailerExecutableMountPathRejectsSymlinksAndUntrustedParents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jailer")
	if err := os.WriteFile(path, []byte("not launchable"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{link, path, "relative", "/"} {
		if err := validateStrictJailerExecutableMountPath(candidate); err == nil {
			t.Fatalf("accepted symlink/untrusted mount path %q", candidate)
		}
	}
}

func TestStrictJailerExecutableCoordinatorReleasesPairOnEveryStartReturn(t *testing.T) {
	for _, failAt := range []string{"inspect", "authority", "filesystem", "stage", "verify", "plan", "start", "success"} {
		t.Run(failAt, func(t *testing.T) {
			request := validStrictJailerCoordinatorRequest(t)
			inspection := validCoordinatorInspection()
			pair := strictJailerTestExecutablePair(t, inspection.canonicalJailerPath, inspection.canonicalFirecrackerPath)
			inspection.executables = pair
			before := strictJailerOpenFDCount(t)
			var events []string
			root := &coordinatorFakeRoot{events: &events}
			lifecycle := &coordinatorFakeLifecycle{events: &events}
			if failAt == "verify" {
				root.verifyErr = errors.New("injected verify failure")
			}
			if failAt == "start" {
				lifecycle.startErr = errors.New("injected start failure")
			}
			coordinator := newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
				inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
					if failAt == "inspect" {
						return inspection, errors.New("injected inspect failure")
					}
					if failAt == "authority" {
						inspection.canonicalFirecrackerPath = "/mismatched/firecracker"
					}
					return inspection, nil
				},
				newFilesystem: func(jailerStagingAuthority) (jailerStagingFilesystem, error) {
					if failAt == "filesystem" {
						return nil, errors.New("injected filesystem failure")
					}
					return &coordinatorFakeFS{events: &events}, nil
				},
				stage: func(jailerStagingFilesystem, jailerStagingRequest) (jailerStagingResult, error) {
					if failAt == "stage" {
						return jailerStagingResult{}, errors.New("injected stage failure")
					}
					return jailerStagingResult{lease: &jailerStagingLease{root: root}}, nil
				},
				plan: func(request strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
					if failAt == "plan" {
						return strictJailerLaunchPlan{}, errors.New("injected plan failure")
					}
					return planStrictJailerLaunch(request)
				},
				lifecycle: lifecycle,
			})
			_, err := coordinator.start(context.Background(), request)
			if (err != nil) != (failAt != "success") {
				t.Fatalf("start error = %v for %s", err, failAt)
			}
			if !pair.closed || strictJailerOpenFDCount(t) != before-2 {
				t.Fatal("coordinator return leaked snapshot ownership")
			}
			if failAt == "start" || failAt == "success" {
				if lifecycle.lastStart.executables != pair {
					t.Fatal("lifecycle received another executable owner")
				}
			}
		})
	}
}

func TestStrictJailerExecutableLifecycleCarriesPairWithoutChangingCommand(t *testing.T) {
	plan := atomicJailerTestPlan(t, "run-alpha")
	pair := strictJailerTestExecutablePair(t, plan.process.Executable, plan.process.Args[3])
	network, writer := atomicJailerTestPipe(t)
	defer writer.Close()
	provider := &atomicJailerNamespaceProvider{nextNetwork: network}
	starter := &strictJailerCaptureExecutableStarter{t: t, expected: pair}
	runner, err := newStrictJailerNamespaceRunner(strictJailerNamespaceRunnerOptions{namespace: provider, starter: starter})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := newStrictJailerLifecycle(runner)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = lifecycle.start(context.Background(), strictJailerLifecycleStartRequest{launchPlan: plan, hostPaths: plan.hostPathPlan(), executables: pair})
	if !starter.called {
		t.Fatal("lifecycle never passed executable owner to runner")
	}
}

type strictJailerCaptureExecutableStarter struct {
	t        *testing.T
	expected *strictJailerExecutablePair
	called   bool
}

func (starter *strictJailerCaptureExecutableStarter) startStrictJailerNamespaceProcess(_ context.Context, request strictJailerNamespaceProcessStartRequest) (HostProcess, error) {
	starter.called = true
	if request.executables != starter.expected {
		starter.t.Fatal("executable owner was lost or substituted")
	}
	command, err := parseStrictJailerCommand(firecracker.ProcessRunnerStartRequest{Executable: request.executable, Args: request.args})
	if err != nil {
		starter.t.Fatal(err)
	}
	lease, err := request.executables.duplicateForLaunch(command)
	if err != nil {
		starter.t.Fatal(err)
	}
	_ = lease.close()
	return nil, errors.New("injected stop before process creation")
}

func strictJailerOpenFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

type strictJailerTrackedInspectionFilesystem struct {
	strictJailerHostInspectionFilesystem
	opened, closed int
}

func (filesystem *strictJailerTrackedInspectionFilesystem) OpenNoFollow(path string) (strictJailerHostInspectionFile, error) {
	file, err := filesystem.strictJailerHostInspectionFilesystem.OpenNoFollow(path)
	if err != nil {
		return nil, err
	}
	filesystem.opened++
	return &strictJailerTrackedInspectionFile{strictJailerHostInspectionFile: file, filesystem: filesystem}, nil
}

type strictJailerTrackedInspectionFile struct {
	strictJailerHostInspectionFile
	filesystem *strictJailerTrackedInspectionFilesystem
}

func (file *strictJailerTrackedInspectionFile) Close() error {
	file.filesystem.closed++
	return file.strictJailerHostInspectionFile.Close()
}

type strictJailerExecutableErrorReader struct{}

func (strictJailerExecutableErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("injected read error")
}

type strictJailerExecutableZeroReader struct{ count int64 }

func (reader *strictJailerExecutableZeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	reader.count += int64(len(buffer))
	return len(buffer), nil
}
