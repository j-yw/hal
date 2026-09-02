package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
	closeErr     error
}

func (*coordinatorFakeRoot) createDirectory(string, os.FileMode, uint32, uint32) error { return nil }
func (*coordinatorFakeRoot) createFileExclusive(string) (jailerStagingFile, error) {
	return nil, errors.New("unused")
}
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
func (root *coordinatorFakeRoot) close() error { return root.closeErr }

type coordinatorFakeFS struct{ events *[]string }

type coordinatorRejectingCleanupFS struct{ calls int }

func (filesystem *coordinatorRejectingCleanupFS) Lstat(string) (os.FileInfo, error) {
	filesystem.calls++
	return nil, errors.New("unexpected generic cleanup inspection")
}
func (filesystem *coordinatorRejectingCleanupFS) RemoveAll(string) error {
	filesystem.calls++
	return errors.New("unexpected generic cleanup removal")
}

func (*coordinatorFakeFS) createExclusiveRoot(jailerStagingRootRequest) (jailerStagingRoot, error) {
	return nil, errors.New("unused")
}
func (filesystem *coordinatorFakeFS) close() error {
	*filesystem.events = append(*filesystem.events, "fs-close")
	return nil
}

type coordinatorFakeLifecycle struct {
	events           *[]string
	startErr         error
	stopErrors       []error
	retryStartErrors []error
	forgetErrors     []error
	terminatedValues []bool
	process          strictJailerLifecycleProcess
	lastStart        strictJailerLifecycleStartRequest
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
func (lifecycle *coordinatorFakeLifecycle) terminated(strictJailerLifecycleProcess) bool {
	*lifecycle.events = append(*lifecycle.events, "terminated")
	if len(lifecycle.terminatedValues) == 0 {
		return true
	}
	value := lifecycle.terminatedValues[0]
	lifecycle.terminatedValues = lifecycle.terminatedValues[1:]
	return value
}
func (lifecycle *coordinatorFakeLifecycle) forgetTerminated(strictJailerLifecycleProcess) error {
	*lifecycle.events = append(*lifecycle.events, "forget")
	if len(lifecycle.forgetErrors) == 0 {
		return nil
	}
	err := lifecycle.forgetErrors[0]
	lifecycle.forgetErrors = lifecycle.forgetErrors[1:]
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
			got.Support[0].ID = "mutated"
			return jailerStagingResult{lease: &jailerStagingLease{root: root}}, nil
		},
		plan: func(got strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
			events = append(events, "plan")
			if got.HostPaths.ConfigPath != "/srv/jailer/firecracker/run-1/root/run/fc-run-1/firecracker-config.json" || got.JailPaths != request.jailPaths {
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
	if request.support[0].ID != "support-log" {
		t.Fatalf("caller support mutated: %#v", request.support)
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
	if got, want := events[len(events)-4:], []string{"stop", "terminated", "release", "forget"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stop events = %v", got)
	}
}

func TestStrictJailerCoordinatorRequestHasNoUnsafeAssemblyInputs(t *testing.T) {
	typeOf := reflect.TypeOf(strictJailerCoordinatorRequest{})
	for _, forbidden := range []string{"hostPaths", "args", "argv", "firecracker", "startRequest", "executable"} {
		if _, ok := typeOf.FieldByName(forbidden); ok {
			t.Fatalf("request exposes forbidden assembly input %q", forbidden)
		}
	}
}

func TestStrictJailerLifecycleDefaultStrictStartDoesNotUseGenericStaleRemoval(t *testing.T) {
	filesystem := &coordinatorRejectingCleanupFS{}
	manager := NewProcessLifecycleManager(nil, WithProcessLifecycleCleanupFilesystem(filesystem))
	paths := validStrictJailerCoordinatorRequest(t).jailPaths
	if err := manager.removeStrictJailerStaleAPISocketBeforeStart(paths, privateStateDirIdentity{}, false, 1001); err != nil {
		t.Fatalf("API cleanup: %v", err)
	}
	if err := manager.removeStrictJailerStaleVsockBeforeStart(paths, privateStateDirIdentity{}, false, 1001); err != nil {
		t.Fatalf("vsock cleanup: %v", err)
	}
	if filesystem.calls != 0 {
		t.Fatalf("generic cleanup filesystem calls = %d", filesystem.calls)
	}
}

func TestStrictJailerCoordinatorRejectsInvalidConfigBeforeDependencies(t *testing.T) {
	base := validStrictJailerCoordinatorRequest(t)
	tests := map[string]func(*strictJailerCoordinatorRequest){
		"config path": func(r *strictJailerCoordinatorRequest) { r.config.JailPath = "/run/other.json" },
		"kernel": func(r *strictJailerCoordinatorRequest) {
			replaceCoordinatorConfig(t, r, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/wrong"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true}]}`)
		},
		"two drives": func(r *strictJailerCoordinatorRequest) {
			replaceCoordinatorConfig(t, r, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true},{"drive_id":"other","path_on_host":"/images/other","is_root_device":false}]}`)
		},
		"root drive": func(r *strictJailerCoordinatorRequest) {
			replaceCoordinatorConfig(t, r, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/wrong","is_root_device":true}]}`)
		},
		"vsock": func(r *strictJailerCoordinatorRequest) {
			replaceCoordinatorConfig(t, r, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true}],"vsock":{"guest_cid":3,"uds_path":"/run/wrong.vsock"}}`)
		},
		"missing metrics":     func(r *strictJailerCoordinatorRequest) { r.support = r.support[:1] },
		"reserved api":        func(r *strictJailerCoordinatorRequest) { r.kernel.JailPath = r.jailPaths.APISocketPath },
		"reserved vsock":      func(r *strictJailerCoordinatorRequest) { r.rootfs.JailPath = r.jailPaths.VsockSocketPath },
		"reserved executable": func(r *strictJailerCoordinatorRequest) { r.support[0].JailPath = "/firecracker" },
		"reserved dev":        func(r *strictJailerCoordinatorRequest) { r.support[0].JailPath = "/dev/log" },
		"digest":              func(r *strictJailerCoordinatorRequest) { r.config.SHA256 = strings.Repeat("0", sha256.Size*2) },
		"kernel mode":         func(r *strictJailerCoordinatorRequest) { r.kernel.Mode = 0o600 },
		"config mode":         func(r *strictJailerCoordinatorRequest) { r.config.Mode = 0o600 },
		"metrics mode":        func(r *strictJailerCoordinatorRequest) { r.support[1].Mode = 0o400 },
		"pci config mismatch": func(r *strictJailerCoordinatorRequest) { r.enablePCI = false },
		"duplicate JSON": func(r *strictJailerCoordinatorRequest) {
			replaceCoordinatorConfig(t, r, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"machine-config":{"vcpu_count":2,"mem_size_mib":256},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true}],"vsock":{"guest_cid":3,"uds_path":"/run/fc-run-1/guest.vsock"}}`)
		},
		"trailing JSON": func(r *strictJailerCoordinatorRequest) {
			replaceCoordinatorConfig(t, r, validCoordinatorConfig()+` {}`)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := cloneCoordinatorRequest(base)
			mutate(&request)
			called := false
			coordinator := newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
				inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
					called = true
					return strictJailerHostInspectionResult{}, nil
				},
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

func TestStrictJailerCoordinatorAcceptsCorrelatedOptionalConfigResources(t *testing.T) {
	t.Run("without vsock", func(t *testing.T) {
		request := validStrictJailerCoordinatorRequest(t)
		request.enablePCI = false
		replaceCoordinatorConfig(t, &request, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true}]}`)
		if err := validateStrictJailerCoordinatorConfig(request); err != nil {
			t.Fatalf("validate: %v", err)
		}
	})
	t.Run("with initrd", func(t *testing.T) {
		request := validStrictJailerCoordinatorRequest(t)
		request.support = append(request.support, coordinatorTestResource("support-initrd", "/boot/initrd", "initrd", 0o400))
		replaceCoordinatorConfig(t, &request, `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux","initrd_path":"/boot/initrd"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true}],"vsock":{"guest_cid":3,"uds_path":"/run/fc-run-1/guest.vsock"}}`)
		if err := validateStrictJailerCoordinatorConfig(request); err != nil {
			t.Fatalf("validate: %v", err)
		}
		request.support[2].Mode = 0o600
		if err := validateStrictJailerCoordinatorConfig(request); !errors.Is(err, errStrictJailerCoordinatorInvalid) {
			t.Fatalf("unsafe initrd mode = %v", err)
		}
	})
}

func TestStrictJailerCoordinatorAcceptsExactProductionVsockEntropyConfig(t *testing.T) {
	request := validStrictJailerCoordinatorRequest(t)
	config := productionVsockCoordinatorConfig(t, request)
	replaceCoordinatorConfig(t, &request, string(config))

	if err := validateStrictJailerCoordinatorConfig(request); err != nil {
		t.Fatalf("validate production-vsock config: %v", err)
	}
	staged, err := io.ReadAll(request.config.Source)
	if err != nil {
		t.Fatalf("read reset config source: %v", err)
	}
	if !bytes.Equal(staged, config) {
		t.Fatalf("config source changed during validation:\n got %q\nwant %q", staged, config)
	}
}

func TestStrictJailerCoordinatorRejectsUncorrelatedSupportResources(t *testing.T) {
	tests := map[string]jailerStagingResourceInput{
		"dynamic loader preload": coordinatorTestResource("support-preload", "/etc/ld.so.preload", "preload", 0o400),
		"dynamic loader":         coordinatorTestResource("support-loader", "/lib64/ld-linux-x86-64.so.2", "loader", 0o400),
		"shared library":         coordinatorTestResource("support-library", "/lib64/libc.so.6", "library", 0o400),
		"undeclared initrd":      coordinatorTestResource("support-initrd", "/boot/initrd", "initrd", 0o400),
		"arbitrary support":      coordinatorTestResource("support-extra", "/opt/extra", "extra", 0o400),
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			request := validStrictJailerCoordinatorRequest(t)
			request.support = append(request.support, extra)
			if err := validateStrictJailerCoordinatorConfig(request); !errors.Is(err, errStrictJailerCoordinatorInvalid) {
				t.Fatalf("validate extra support = %v", err)
			}
		})
	}
}

func TestStrictJailerCoordinatorRejectsUnsupportedDeviceConfig(t *testing.T) {
	tests := map[string]string{
		"network interfaces":       coordinatorConfigWith(`"network-interfaces":[{"iface_id":"eth0","host_dev_name":"tap0"}]`),
		"empty network interfaces": coordinatorConfigWith(`"network-interfaces":[]`),
		"null entropy":             coordinatorConfigWith(`"entropy":null`),
		"array entropy":            coordinatorConfigWith(`"entropy":[]`),
		"string entropy":           coordinatorConfigWith(`"entropy":"empty"`),
		"boolean entropy":          coordinatorConfigWith(`"entropy":false`),
		"number entropy":           coordinatorConfigWith(`"entropy":0`),
		"entropy rate limiter":     coordinatorConfigWith(`"entropy":{"rate_limiter":{}}`),
		"entropy unexpected field": coordinatorConfigWith(`"entropy":{"unexpected":true}`),
		"duplicate entropy":        coordinatorConfigWith(`"entropy":{},"entropy":{}`),
		"duplicate entropy field":  coordinatorConfigWith(`"entropy":{"rate_limiter":{},"rate_limiter":{}}`),
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			request := validStrictJailerCoordinatorRequest(t)
			replaceCoordinatorConfig(t, &request, config)
			if err := validateStrictJailerCoordinatorConfig(request); !errors.Is(err, errStrictJailerCoordinatorInvalid) {
				t.Fatalf("validate opaque device config = %v", err)
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
		forgetErrors    []error
		terminated      []bool
		wantStartEvents []string
		wantRetryEvents []string
	}{
		{name: "contained start", startErr: errors.New("sensitive contained failure"), wantStartEvents: []string{"start", "release"}},
		{name: "uncertain start", startErr: errStrictJailerNamespaceCleanupIncomplete, wantStartEvents: []string{"start"}, wantRetryEvents: []string{"retry-process", "release"}},
		{name: "stop retry", stopErrors: []error{errors.New("sensitive stop failure"), nil}, terminated: []bool{false, true}, wantStartEvents: []string{"start", "stop", "terminated"}, wantRetryEvents: []string{"stop", "terminated", "release", "forget"}},
		{name: "stop error but terminal", stopErrors: []error{errors.New("sensitive stop failure")}, terminated: []bool{true}, wantStartEvents: []string{"start", "stop", "terminated", "release", "forget"}},
		{name: "root retry", removeErrors: []error{errors.New("sensitive remove failure"), nil}, terminated: []bool{true}, wantStartEvents: []string{"start", "stop", "terminated", "release"}, wantRetryEvents: []string{"release", "forget"}},
		{name: "forget retry", forgetErrors: []error{errors.New("sensitive forget failure"), nil}, terminated: []bool{true}, wantStartEvents: []string{"start", "stop", "terminated", "release", "forget"}, wantRetryEvents: []string{"forget"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			root := &coordinatorFakeRoot{events: &events, removeErrors: append([]error(nil), test.removeErrors...)}
			lifecycle := &coordinatorFakeLifecycle{events: &events, startErr: test.startErr, stopErrors: append([]error(nil), test.stopErrors...), retryStartErrors: append([]error(nil), test.retryErrors...), forgetErrors: append([]error(nil), test.forgetErrors...), terminatedValues: append([]bool(nil), test.terminated...)}
			coordinator := coordinatorForStateTest(&events, root, lifecycle)
			session, startErr := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
			if test.startErr == nil {
				if startErr != nil {
					t.Fatalf("start: %v", startErr)
				}
				stopErr := coordinator.stop(context.Background(), session)
				if len(test.stopErrors) > 0 || len(test.removeErrors) > 0 || len(test.forgetErrors) > 0 {
					if stopErr == nil {
						t.Fatal("expected stop error")
					}
				}
			} else if startErr == nil {
				t.Fatal("expected start error")
			}
			prefix := events[len(events)-len(test.wantStartEvents):]
			if !reflect.DeepEqual(prefix, test.wantStartEvents) {
				t.Fatalf("initial tail = %v, want %v", prefix, test.wantStartEvents)
			}
			if len(test.wantRetryEvents) == 0 {
				return
			}
			if _, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); !errors.Is(err, errStrictJailerCoordinatorBusy) {
				t.Fatalf("pending start = %v", err)
			}
			before := len(events)
			if err := coordinator.retryCleanup(context.Background(), session); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if got := events[before:]; !reflect.DeepEqual(got, test.wantRetryEvents) {
				t.Fatalf("retry events = %v, want %v", got, test.wantRetryEvents)
			}
		})
	}
}

func TestStrictJailerCoordinatorDoesNotReleaseWithoutPositiveTerminalProof(t *testing.T) {
	events := []string{}
	root := &coordinatorFakeRoot{events: &events}
	lifecycle := &coordinatorFakeLifecycle{events: &events, terminatedValues: []bool{false, true}}
	coordinator := coordinatorForStateTest(&events, root, lifecycle)
	session, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := coordinator.stop(context.Background(), session); !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) {
		t.Fatalf("stop without terminal proof = %v", err)
	}
	if events[len(events)-1] != "terminated" {
		t.Fatalf("root released without proof: %v", events)
	}
	if err := coordinator.retryCleanup(context.Background(), session); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got, want := events[len(events)-4:], []string{"stop", "terminated", "release", "forget"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retry order = %v, want %v", got, want)
	}
}

func TestStrictJailerCoordinatorForgetsOnlyAfterTerminalProcessAndRootProof(t *testing.T) {
	t.Run("process cleanup uncertain", func(t *testing.T) {
		events := []string{}
		root := &coordinatorFakeRoot{events: &events}
		lifecycle := &coordinatorFakeLifecycle{events: &events, terminatedValues: []bool{false}}
		coordinator := coordinatorForStateTest(&events, root, lifecycle)
		session, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := coordinator.stop(context.Background(), session); !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) {
			t.Fatalf("stop() error = %v, want cleanup incomplete", err)
		}
		if slicesContain(events, "forget") {
			t.Fatalf("events = %v, process was forgotten without terminal proof", events)
		}
	})

	t.Run("root cleanup uncertain", func(t *testing.T) {
		events := []string{}
		root := &coordinatorFakeRoot{events: &events, removeErrors: []error{errors.New("private removal failure")}}
		lifecycle := &coordinatorFakeLifecycle{events: &events, terminatedValues: []bool{true}}
		coordinator := coordinatorForStateTest(&events, root, lifecycle)
		session, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := coordinator.stop(context.Background(), session); !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) {
			t.Fatalf("stop() error = %v, want cleanup incomplete", err)
		}
		if slicesContain(events, "forget") {
			t.Fatalf("events = %v, process was forgotten without terminal root release", events)
		}
	})
}

func TestStrictJailerCoordinatorSuccessfulGenerationsDoNotRetainProcessRecords(t *testing.T) {
	events := []string{}
	lifecycle := newCoordinatorRetainedLifecycle(&events)
	coordinator := newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
		inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
			return validCoordinatorInspection(), nil
		},
		newFilesystem: func(jailerStagingAuthority) (jailerStagingFilesystem, error) {
			return &coordinatorFakeFS{events: &events}, nil
		},
		stage: func(jailerStagingFilesystem, jailerStagingRequest) (jailerStagingResult, error) {
			return jailerStagingResult{lease: &jailerStagingLease{root: &coordinatorFakeRoot{events: &events}}}, nil
		},
		plan: func(request strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
			return strictJailerLaunchPlan{hostPaths: request.HostPaths}, nil
		},
		lifecycle: lifecycle,
	})
	request := validStrictJailerCoordinatorRequest(t)
	for generation := 0; generation < 64; generation++ {
		session, err := coordinator.start(context.Background(), request)
		if err != nil {
			t.Fatalf("generation %d start: %v", generation, err)
		}
		if err := coordinator.stop(context.Background(), session); err != nil {
			t.Fatalf("generation %d stop: %v", generation, err)
		}
		if got := lifecycle.recordCount(); got != 0 {
			t.Fatalf("generation %d retained process records = %d, want 0", generation, got)
		}
	}
}

type coordinatorRetainedLifecycle struct {
	manager *ProcessLifecycleManager
	events  *[]string
}

func newCoordinatorRetainedLifecycle(events *[]string) *coordinatorRetainedLifecycle {
	return &coordinatorRetainedLifecycle{manager: NewProcessLifecycleManager(nil), events: events}
}

func (lifecycle *coordinatorRetainedLifecycle) start(_ context.Context, request strictJailerLifecycleStartRequest) (strictJailerLifecycleProcess, error) {
	*lifecycle.events = append(*lifecycle.events, "start")
	process := newAtomicJailerTestProcess()
	handle := lifecycle.manager.storeStrictJailerProcess(process, request.hostPaths, privateStateDirIdentity{}, false, 1001)
	return strictJailerLifecycleProcess{handle: handle, hostPaths: request.hostPaths, runtimeUID: 1001}, nil
}

func (lifecycle *coordinatorRetainedLifecycle) stop(ctx context.Context, process strictJailerLifecycleProcess) error {
	*lifecycle.events = append(*lifecycle.events, "stop")
	return lifecycle.manager.StopLiveProcess(ctx, firecracker.LiveProcessRequest{Handle: process.handle, Paths: process.hostPaths})
}

func (lifecycle *coordinatorRetainedLifecycle) terminated(process strictJailerLifecycleProcess) bool {
	*lifecycle.events = append(*lifecycle.events, "terminated")
	return lifecycle.manager.LiveProcessTerminated(firecracker.LiveProcessRequest{Handle: process.handle, Paths: process.hostPaths})
}

func (lifecycle *coordinatorRetainedLifecycle) forgetTerminated(process strictJailerLifecycleProcess) error {
	*lifecycle.events = append(*lifecycle.events, "forget")
	return lifecycle.manager.forgetTerminatedStrictJailerProcess(process.handle, process.hostPaths, process.runtimeUID)
}

func (*coordinatorRetainedLifecycle) retryUncertainStartCleanup(context.Context) error { return nil }

func (lifecycle *coordinatorRetainedLifecycle) recordCount() int {
	lifecycle.manager.mu.Lock()
	defer lifecycle.manager.mu.Unlock()
	return len(lifecycle.manager.processes)
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestStrictJailerCoordinatorDoesNotRetainTerminalRootCloseFailure(t *testing.T) {
	events := []string{}
	root := &coordinatorFakeRoot{events: &events, closeErr: errors.New("sensitive close failure")}
	lifecycle := &coordinatorFakeLifecycle{events: &events}
	coordinator := coordinatorForStateTest(&events, root, lifecycle)
	session, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := coordinator.stop(context.Background(), session); !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) {
		t.Fatalf("stop close failure = %v", err)
	}
	if _, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); errors.Is(err, errStrictJailerCoordinatorBusy) {
		t.Fatalf("terminal removal remained busy: %v", err)
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
		inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
			return validCoordinatorInspection(), nil
		},
		newFilesystem: func(jailerStagingAuthority) (jailerStagingFilesystem, error) {
			return &coordinatorFakeFS{events: events}, nil
		},
		stage: func(jailerStagingFilesystem, jailerStagingRequest) (jailerStagingResult, error) {
			return jailerStagingResult{lease: &jailerStagingLease{root: root}}, nil
		},
		plan: func(request strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
			return strictJailerLaunchPlan{hostPaths: request.HostPaths}, nil
		},
		lifecycle: lifecycle,
	})
}

func validStrictJailerCoordinatorRequest(t *testing.T) strictJailerCoordinatorRequest {
	t.Helper()
	paths := firecracker.PathPlan{StateDir: "/run/fc-run-1", APISocketPath: "/run/fc-run-1/firecracker.sock", ConfigPath: "/run/fc-run-1/firecracker-config.json", LogPath: "/run/fc-run-1/firecracker.log", MetricsPath: "/run/fc-run-1/firecracker.metrics", VsockSocketPath: "/run/fc-run-1/guest.vsock"}
	config := validCoordinatorConfig()
	return strictJailerCoordinatorRequest{
		runtimeID:  "run-1",
		inspection: strictJailerHostInspectionRequest{jailerPath: "/opt/jailer", firecrackerPath: "/opt/firecracker", runtimeUID: 1001, runtimeGID: 1002, chrootBaseDir: "/srv/jailer"},
		jailPaths:  paths,
		kernel:     coordinatorTestResource("kernel", "/boot/vmlinux", "kernel", 0o400),
		rootfs:     coordinatorTestResource("rootfs", "/images/rootfs.ext4", "rootfs", 0o600),
		config:     coordinatorTestResource("config", paths.ConfigPath, config, 0o400),
		support:    []jailerStagingResourceInput{coordinatorTestResource("support-log", paths.LogPath, "", 0o600), coordinatorTestResource("support-metrics", paths.MetricsPath, "", 0o600)},
		enablePCI:  true,
	}
}

func coordinatorTestResource(id, jailPath, content string, mode os.FileMode) jailerStagingResourceInput {
	digest := sha256.Sum256([]byte(content))
	return jailerStagingResourceInput{ID: id, JailPath: jailPath, Source: bytes.NewReader([]byte(content)), SizeBytes: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), Mode: mode}
}

func validCoordinatorConfig() string {
	return `{"machine-config":{"vcpu_count":1,"mem_size_mib":128},"boot-source":{"kernel_image_path":"/boot/vmlinux"},"drives":[{"drive_id":"rootfs","path_on_host":"/images/rootfs.ext4","is_root_device":true,"is_read_only":false}],"vsock":{"guest_cid":3,"uds_path":"/run/fc-run-1/guest.vsock"}}`
}

func productionVsockCoordinatorConfig(t *testing.T, request strictJailerCoordinatorRequest) []byte {
	t.Helper()
	config := firecracker.BackendConfig{
		CPUCount:        1,
		MemoryMiB:       128,
		KernelImagePath: request.kernel.JailPath,
		RootfsPath:      request.rootfs.JailPath,
		Paths:           request.jailPaths,
		ProductionVsock: true,
	}
	machineConfig, err := firecracker.RenderMachineConfigPayload(config)
	if err != nil {
		t.Fatalf("render production machine config: %v", err)
	}
	bootSource, err := firecracker.RenderBootSourcePayload(config)
	if err != nil {
		t.Fatalf("render production boot source: %v", err)
	}
	rootDrive, err := firecracker.RenderRootDrivePayload(config)
	if err != nil {
		t.Fatalf("render production root drive: %v", err)
	}
	rendered := struct {
		MachineConfig firecracker.MachineConfigPayload `json:"machine-config"`
		BootSource    firecracker.BootSourcePayload    `json:"boot-source"`
		Drives        []firecracker.RootDrivePayload   `json:"drives"`
		Vsock         struct {
			GuestCID uint32 `json:"guest_cid"`
			UDSPath  string `json:"uds_path"`
		} `json:"vsock"`
		Entropy struct{} `json:"entropy"`
	}{
		MachineConfig: machineConfig,
		BootSource:    bootSource,
		Drives:        []firecracker.RootDrivePayload{rootDrive},
	}
	rendered.Vsock.GuestCID = 3
	rendered.Vsock.UDSPath = request.jailPaths.VsockSocketPath
	encoded, err := json.Marshal(rendered)
	if err != nil {
		t.Fatalf("marshal production-vsock config: %v", err)
	}
	return append(encoded, '\n')
}

func coordinatorConfigWith(fields string) string {
	return strings.TrimSuffix(validCoordinatorConfig(), "}") + "," + fields + "}"
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
