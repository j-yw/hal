package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

type coordinatorFakeRoot struct {
	events       *[]string
	verifyErr    error
	removeErrors []error
}

func (*coordinatorFakeRoot) createDirectory(string, os.FileMode, uint32, uint32) error { return nil }
func (*coordinatorFakeRoot) createFileExclusive(string) (jailerStagingFile, error)      { return nil, errors.New("unused") }
func (root *coordinatorFakeRoot) verifyOwned() error {
	*root.events = append(*root.events, "verify")
	return root.verifyErr
}
func (root *coordinatorFakeRoot) removeOwned() error {
	*root.events = append(*root.events, "release")
	if len(root.removeErrors) == 0 {
		return nil
	}
	err := root.removeErrors[0]
	root.removeErrors = root.removeErrors[1:]
	return err
}
func (*coordinatorFakeRoot) close() error { return nil }

type coordinatorFakeFS struct{ events *[]string }

func (*coordinatorFakeFS) createExclusiveRoot(jailerStagingRootRequest) (jailerStagingRoot, error) {
	return nil, errors.New("unused")
}
func (filesystem *coordinatorFakeFS) close() error {
	*filesystem.events = append(*filesystem.events, "fs-close")
	return nil
}

type coordinatorFakeLifecycle struct {
	events            *[]string
	startErr          error
	stopErrors        []error
	retryStartErrors  []error
	process           strictJailerLifecycleProcess
	lastStart         strictJailerLifecycleStartRequest
}

func (lifecycle *coordinatorFakeLifecycle) start(_ context.Context, request strictJailerLifecycleStartRequest) (strictJailerLifecycleProcess, error) {
	*lifecycle.events = append(*lifecycle.events, "start")
	lifecycle.lastStart = request
	return lifecycle.process, lifecycle.startErr
}
func (lifecycle *coordinatorFakeLifecycle) stop(context.Context, strictJailerLifecycleProcess) error {
	*lifecycle.events = append(*lifecycle.events, "stop")
	if len(lifecycle.stopErrors) == 0 {
		return nil
	}
	err := lifecycle.stopErrors[0]
	lifecycle.stopErrors = lifecycle.stopErrors[1:]
	return err
}
func (lifecycle *coordinatorFakeLifecycle) retryUncertainStartCleanup(context.Context) error {
	*lifecycle.events = append(*lifecycle.events, "retry-process")
	if len(lifecycle.retryStartErrors) == 0 {
		return nil
	}
	err := lifecycle.retryStartErrors[0]
	lifecycle.retryStartErrors = lifecycle.retryStartErrors[1:]
	return err
}

func TestStrictJailerCoordinatorStartsInExactOrderAndKeepsPrivateShape(t *testing.T) {
	events := []string{}
	root := &coordinatorFakeRoot{events: &events}
	lifecycle := &coordinatorFakeLifecycle{events: &events, process: strictJailerLifecycleProcess{runtimeUID: 1001}}
	request := validStrictJailerCoordinatorRequest(t)
	coordinator := newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
		inspect: func(got strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
			events = append(events, "inspect")
			if got != request.inspection {
				t.Fatal("inspection request changed")
			}
			return validCoordinatorInspection(), nil
		},
		newFilesystem: func(authority jailerStagingAuthority) (jailerStagingFilesystem, error) {
			events = append(events, "filesystem")
			if authority.JailRootHostPath != "/srv/jailer/firecracker/run-1/root" || authority.RuntimeID != "run-1" {
				t.Fatalf("unexpected staging authority: %#v", authority)
			}
			return &coordinatorFakeFS{events: &events}, nil
		},
		stage: func(_ jailerStagingFilesystem, got jailerStagingRequest) (jailerStagingResult, error) {
			events = append(events, "stage")
			if got.Kernel.JailPath != "/boot/vmlinux" || got.Rootfs.JailPath != "/images/rootfs.ext4" || len(got.Support) != 2 {
				t.Fatalf("unexpected staging request: %#v", got)
			}
			return jailerStagingResult{lease: &jailerStagingLease{root: root}}, nil
		},
		plan: func(got strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
			events = append(events, "plan")
			if got.HostPaths.ConfigPath != "/srv/jailer/firecracker/run-1/root/run/config.json" || got.JailPaths != request.jailPaths {
				t.Fatalf("unexpected path correlation: %#v", got)
			}
			if got.Firecracker.Executable != "/opt/firecracker" || len(got.Firecracker.Environment) != 0 || len(got.Firecracker.InheritedFiles) != 0 {
				t.Fatalf("unsafe process request: %#v", got.Firecracker)
			}
			return strictJailerLaunchPlan{hostPaths: got.HostPaths}, nil
		},
		lifecycle: lifecycle,
	})

	session, err := coordinator.start(context.Background(), request)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if got, want := events, []string{"inspect", "filesystem", "stage", "verify", "plan", "start"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if encoded, _ := json.Marshal(coordinator); string(encoded) != "{}" {
		t.Fatalf("coordinator JSON = %s", encoded)
	}
	if encoded, _ := json.Marshal(session); string(encoded) != "{}" {
		t.Fatalf("session JSON = %s", encoded)
	}
	if _, err := coordinator.start(context.Background(), request); !errors.Is(err, errStrictJailerCoordinatorBusy) {
		t.Fatalf("second start error = %v", err)
	}
	if err := coordinator.stop(context.Background(), session); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got, want := events[len(events)-2:], []string{"stop", "release"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stop events = %v", got)
	}
}

func TestStrictJailerCoordinatorRejectsInvalidConfigBeforeDependencies(t *testing.T) {
	base := validStrictJailerCoordinatorRequest(t)
	tests := map[string]func(*strictJailerCoordinatorRequest){
		"config path": func(r *strictJailerCoordinatorRequest) { r.config.JailPath = "/run/other.json" },
		"kernel": func(r *strictJailerCoordinatorRequest) { replaceCoordinatorConfig(t, r, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/wrong"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true}]}`) },
		"two drives": func(r *strictJailerCoordinatorRequest) { replaceCoordinatorConfig(t, r, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true},{"drive_id":"other","path_on_host":"/images/other","is_root_device":false}]}`) },
		"root drive": func(r *strictJailerCoordinatorRequest) { replaceCoordinatorConfig(t, r, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/wrong","is_root_device":true}]}`) },
		"vsock": func(r *strictJailerCoordinatorRequest) { replaceCoordinatorConfig(t, r, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true}],"vsock":{"guest_cid":3,"uds_path":"/run/wrong.vsock"}}`) },
		"missing metrics": func(r *strictJailerCoordinatorRequest) { r.support = r.support[:1] },
		"reserved api": func(r *strictJailerCoordinatorRequest) { r.kernel.JailPath = r.jailPaths.APISocketPath },
		"reserved vsock": func(r *strictJailerCoordinatorRequest) { r.rootfs.JailPath = r.jailPaths.VsockSocketPath },
		"reserved executable": func(r *strictJailerCoordinatorRequest) { r.support[0].JailPath = "/firecracker" },
		"reserved dev": func(r *strictJailerCoordinatorRequest) { r.support[0].JailPath = "/dev/log" },
		"digest": func(r *strictJailerCoordinatorRequest) { r.config.SHA256 = strings.Repeat("0", sha256.Size*2) },
		"trailing JSON": func(r *strictJailerCoordinatorRequest) { replaceCoordinatorConfig(t, r, validCoordinatorConfig()+` {}`) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := cloneCoordinatorRequest(base)
			mutate(&request)
			called := false
			coordinator := newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
				inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) { called = true; return strictJailerHostInspectionResult{}, nil },
			})
			if _, err := coordinator.start(context.Background(), request); !errors.Is(err, errStrictJailerCoordinatorInvalid) {
				t.Fatalf("start error = %v", err)
			}
			if called {
				t.Fatal("invalid config reached a dependency")
			}
		})
	}
}

func TestStrictJailerCoordinatorCleanupStateMachine(t *testing.T) {
	tests := []struct {
		name            string
		startErr        error
		stopErrors      []error
		retryErrors     []error
		removeErrors    []error
		wantStartEvents []string
		wantRetryEvents []string
	}{
		{name: "contained start", startErr: errors.New("sensitive contained failure"), wantStartEvents: []string{"start", "release"}},
		{name: "uncertain start", startErr: errStrictJailerNamespaceCleanupIncomplete, wantStartEvents: []string{"start"}, wantRetryEvents: []string{"retry-process", "release"}},
		{name: "stop retry", stopErrors: []error{errors.New("sensitive stop failure"), nil}, wantStartEvents: []string{"start", "stop"}, wantRetryEvents: []string{"stop", "release"}},
		{name: "root retry", removeErrors: []error{errors.New("sensitive remove failure"), nil}, wantStartEvents: []string{"start", "stop", "release"}, wantRetryEvents: []string{"release"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			root := &coordinatorFakeRoot{events: &events, removeErrors: append([]error(nil), test.removeErrors...)}
			lifecycle := &coordinatorFakeLifecycle{events: &events, startErr: test.startErr, stopErrors: append([]error(nil), test.stopErrors...), retryStartErrors: append([]error(nil), test.retryErrors...)}
			coordinator := coordinatorForStateTest(&events, root, lifecycle)
			session, startErr := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
			if test.startErr == nil {
				if startErr != nil { t.Fatalf("start: %v", startErr) }
				stopErr := coordinator.stop(context.Background(), session)
				if len(test.stopErrors) > 0 || len(test.removeErrors) > 0 {
					if stopErr == nil { t.Fatal("expected stop error") }
				}
			} else if startErr == nil {
				t.Fatal("expected start error")
			}
			prefix := events[len(events)-len(test.wantStartEvents):]
			if !reflect.DeepEqual(prefix, test.wantStartEvents) { t.Fatalf("initial tail = %v, want %v", prefix, test.wantStartEvents) }
			if len(test.wantRetryEvents) == 0 { return }
			if _, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); !errors.Is(err, errStrictJailerCoordinatorBusy) { t.Fatalf("pending start = %v", err) }
			before := len(events)
			if err := coordinator.retryCleanup(context.Background(), session); err != nil { t.Fatalf("retry: %v", err) }
			if got := events[before:]; !reflect.DeepEqual(got, test.wantRetryEvents) { t.Fatalf("retry events = %v, want %v", got, test.wantRetryEvents) }
		})
	}
}

func TestStrictJailerCoordinatorErrorsAreSanitizedAtRenderTime(t *testing.T) {
	err := &strictJailerCoordinatorError{kind: errors.New("/host/secret token=abc"), operation: "https://secret.invalid"}
	if got := err.Error(); strings.Contains(got, "secret") || strings.Contains(got, "host") || strings.Contains(got, "http") {
		t.Fatalf("unsafe error: %q", got)
	}
}

func coordinatorForStateTest(events *[]string, root *coordinatorFakeRoot, lifecycle *coordinatorFakeLifecycle) *strictJailerCoordinator {
	return newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
		inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) { return validCoordinatorInspection(), nil },
		newFilesystem: func(jailerStagingAuthority) (jailerStagingFilesystem, error) { return &coordinatorFakeFS{events: events}, nil },
		stage: func(jailerStagingFilesystem, jailerStagingRequest) (jailerStagingResult, error) { return jailerStagingResult{lease: &jailerStagingLease{root: root}}, nil },
		plan: func(request strictJailerLaunchRequest) (strictJailerLaunchPlan, error) { return strictJailerLaunchPlan{hostPaths: request.HostPaths}, nil },
		lifecycle: lifecycle,
	})
}

func validStrictJailerCoordinatorRequest(t *testing.T) strictJailerCoordinatorRequest {
	t.Helper()
	paths := firecracker.PathPlan{StateDir: "/run", APISocketPath: "/run/api.sock", ConfigPath: "/run/config.json", LogPath: "/run/firecracker.log", MetricsPath: "/run/metrics.fifo", VsockSocketPath: "/run/guest.vsock"}
	resource := func(id, jailPath, content string, mode os.FileMode) jailerStagingResourceInput {
		digest := sha256.Sum256([]byte(content))
		return jailerStagingResourceInput{ID: id, JailPath: jailPath, Source: bytes.NewReader([]byte(content)), SizeBytes: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), Mode: mode}
	}
	config := validCoordinatorConfig()
	return strictJailerCoordinatorRequest{
		runtimeID: "run-1",
		inspection: strictJailerHostInspectionRequest{jailerPath: "/opt/jailer", firecrackerPath: "/opt/firecracker", runtimeUID: 1001, runtimeGID: 1002, chrootBaseDir: "/srv/jailer"},
		jailPaths: paths,
		kernel: resource("kernel", "/boot/vmlinux", "kernel", 0o400),
		rootfs: resource("rootfs", "/images/rootfs.ext4", "rootfs", 0o600),
		config: resource("config", paths.ConfigPath, config, 0o600),
		support: []jailerStagingResourceInput{resource("support-log", paths.LogPath, "", 0o600), resource("support-metrics", paths.MetricsPath, "", 0o600)},
		enablePCI: true,
	}
}

func validCoordinatorConfig() string {
	return `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true,"is_read_only":false}]}`
}

func replaceCoordinatorConfig(t *testing.T, request *strictJailerCoordinatorRequest, content string) {
	t.Helper()
	digest := sha256.Sum256([]byte(content))
	request.config.Source = bytes.NewReader([]byte(content))
	request.config.SizeBytes = int64(len(content))
	request.config.SHA256 = hex.EncodeToString(digest[:])
}

func cloneCoordinatorRequest(request strictJailerCoordinatorRequest) strictJailerCoordinatorRequest {
	request.support = append([]jailerStagingResourceInput(nil), request.support...)
	return request
}

func validCoordinatorInspection() strictJailerHostInspectionResult {
	return strictJailerHostInspectionResult{canonicalJailerPath: "/opt/jailer", canonicalFirecrackerPath: "/opt/firecracker", runtimeUID: 1001, runtimeGID: 1002, canonicalChrootBaseDir: "/srv/jailer"}
}
