package firecrackerhost

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestPlanStrictJailerLaunchBuildsHostOwnedCommand(t *testing.T) {
	request := validStrictJailerLaunchRequest()

	plan, err := planStrictJailerLaunch(request)
	if err != nil {
		t.Fatalf("PlanStrictJailerLaunch() error = %v, want nil", err)
	}
	process := plan.processRequest()
	if process.Executable != request.JailerPath {
		t.Fatalf("executable = %q, want configured Jailer", process.Executable)
	}
	wantArgs := []string{
		"--id", "run-alpha",
		"--exec-file", request.CanonicalFirecrackerPath,
		"--uid", "1001",
		"--gid", "1002",
		"--chroot-base-dir", request.ChrootBaseDir,
		"--",
		"--api-sock", request.JailPaths.APISocketPath,
		"--config-file", request.JailPaths.ConfigPath,
		"--log-path", request.JailPaths.LogPath,
		"--metrics-path", request.JailPaths.MetricsPath,
	}
	if !reflect.DeepEqual(process.Args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", process.Args, wantArgs)
	}
	if len(process.Environment) != 0 || len(process.InheritedFiles) != 0 {
		t.Fatalf("process environment/files = %#v/%#v, want explicit empty values", process.Environment, process.InheritedFiles)
	}
	for _, arg := range process.Args {
		if arg == "--daemonize" || arg == "--new-pid-ns" {
			t.Fatalf("strict launch detached from the exact supervised process with %q", arg)
		}
	}
	if plan.hostPathPlan() != request.HostPaths {
		t.Fatalf("host paths = %#v, want lifecycle-owned paths", plan.hostPathPlan())
	}
	if plan.jailPathPlan() != request.JailPaths {
		t.Fatalf("jail paths = %#v, want Firecracker-visible paths", plan.jailPathPlan())
	}
	if plan.runtimeID != request.RuntimeID || plan.runtimeUID != request.UID || plan.runtimeGID != request.GID ||
		plan.chrootBaseDir != request.ChrootBaseDir || plan.firecrackerPath != request.CanonicalFirecrackerPath {
		t.Fatalf("structured authority = %#v, want runtime/uid/gid/chroot/executable retained outside argv", plan)
	}
}

func TestPlanStrictJailerLaunchFailsClosedAtEveryMissingBoundary(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*strictJailerLaunchRequest)
	}{
		{name: "runtime identity", field: "runtimeId", edit: func(req *strictJailerLaunchRequest) { req.RuntimeID = "bad/runtime" }},
		{name: "runtime short option", field: "runtimeId", edit: func(req *strictJailerLaunchRequest) { req.RuntimeID = "-h" }},
		{name: "runtime help option", field: "runtimeId", edit: func(req *strictJailerLaunchRequest) { req.RuntimeID = "--help" }},
		{name: "runtime version option", field: "runtimeId", edit: func(req *strictJailerLaunchRequest) { req.RuntimeID = "--version" }},
		{name: "runtime separator", field: "runtimeId", edit: func(req *strictJailerLaunchRequest) { req.RuntimeID = "--" }},
		{name: "jailer", field: "jailerPath", edit: func(req *strictJailerLaunchRequest) { req.JailerPath = "" }},
		{name: "jailer root", field: "jailerPath", edit: func(req *strictJailerLaunchRequest) { req.JailerPath = "/" }},
		{name: "Firecracker", field: "firecrackerPath", edit: func(req *strictJailerLaunchRequest) { req.CanonicalFirecrackerPath = "" }},
		{name: "Firecracker root", field: "firecrackerPath", edit: func(req *strictJailerLaunchRequest) {
			req.CanonicalFirecrackerPath = "/"
			req.Firecracker.Executable = "/"
		}},
		{name: "root uid", field: "uid", edit: func(req *strictJailerLaunchRequest) { req.UID = 0 }},
		{name: "root gid", field: "gid", edit: func(req *strictJailerLaunchRequest) { req.GID = 0 }},
		{name: "chroot", field: "chrootBaseDir", edit: func(req *strictJailerLaunchRequest) { req.ChrootBaseDir = "/" }},
		{name: "host paths", field: "hostPaths", edit: func(req *strictJailerLaunchRequest) { req.HostPaths.ConfigPath += "-other" }},
		{name: "jail paths", field: "jailPaths", edit: func(req *strictJailerLaunchRequest) { req.JailPaths.APISocketPath = req.HostPaths.APISocketPath }},
		{name: "environment", field: "environment", edit: func(req *strictJailerLaunchRequest) { req.Firecracker.Environment = []string{"SECRET=value"} }},
		{name: "inherited assets", field: "inheritedFiles", edit: func(req *strictJailerLaunchRequest) { req.Firecracker.InheritedFiles = []*os.File{nil} }},
		{name: "direct substitution", field: "firecrackerPath", edit: func(req *strictJailerLaunchRequest) { req.JailerPath = req.CanonicalFirecrackerPath }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := validStrictJailerLaunchRequest()
			tt.edit(&request)

			_, err := planStrictJailerLaunch(request)
			assertStrictJailerLaunchError(t, err, tt.field)
			for _, unsafe := range []string{"bad/runtime", "SECRET=value", "/opt/hal/private", "/srv/hal/private"} {
				if strings.Contains(err.Error(), unsafe) {
					t.Fatalf("error leaked %q in %q", unsafe, err)
				}
			}
		})
	}
}

func TestPlanStrictJailerLaunchRejectsFirecrackerArgumentDrift(t *testing.T) {
	request := validStrictJailerLaunchRequest()
	request.Firecracker.Args[1] = "/srv/hal/private/attacker.sock"

	_, err := planStrictJailerLaunch(request)

	assertStrictJailerLaunchError(t, err, "hostPaths")
	if strings.Contains(err.Error(), "attacker.sock") {
		t.Fatalf("error leaked drifted path in %q", err)
	}
}

func TestPlanStrictJailerLaunchRejectsNoncanonicalExecutableRequest(t *testing.T) {
	request := validStrictJailerLaunchRequest()
	request.CanonicalFirecrackerPath = "/opt/hal/private/releases/firecracker"
	request.Firecracker.Executable = "/opt/hal/private/bin/firecracker-symlink"

	_, err := planStrictJailerLaunch(request)

	assertStrictJailerLaunchError(t, err, "firecrackerPath")
	for _, unsafe := range []string{"releases/firecracker", "firecracker-symlink", "/opt/hal/private"} {
		if strings.Contains(err.Error(), unsafe) {
			t.Fatalf("error leaked %q in %q", unsafe, err)
		}
	}
}

func TestPlanStrictJailerLaunchPreservesPCIInsideJailerBoundary(t *testing.T) {
	request := validStrictJailerLaunchRequest()
	request.Firecracker.Args = append([]string{"--enable-pci"}, request.Firecracker.Args...)

	plan, err := planStrictJailerLaunch(request)
	if err != nil {
		t.Fatalf("PlanStrictJailerLaunch() error = %v, want nil", err)
	}
	args := plan.processRequest().Args
	separator := -1
	for index, arg := range args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(args) || args[separator+1] != "--enable-pci" {
		t.Fatalf("Jailer args = %#v, want --enable-pci as first Firecracker argument", args)
	}
}

func TestPlanStrictJailerLaunchRejectsPCIArgumentDrift(t *testing.T) {
	for _, args := range [][]string{
		append(validStrictJailerLaunchRequest().Firecracker.Args, "--enable-pci"),
		append([]string{"--enable-pci", "--enable-pci"}, validStrictJailerLaunchRequest().Firecracker.Args...),
	} {
		request := validStrictJailerLaunchRequest()
		request.Firecracker.Args = args

		_, err := planStrictJailerLaunch(request)
		assertStrictJailerLaunchError(t, err, "hostPaths")
	}
}

func TestStrictJailerLaunchProcessRequestReturnsDefensiveCopies(t *testing.T) {
	plan, err := planStrictJailerLaunch(validStrictJailerLaunchRequest())
	if err != nil {
		t.Fatalf("PlanStrictJailerLaunch() error = %v, want nil", err)
	}
	first := plan.processRequest()
	first.Args[0] = "--daemonize"
	first.Environment = append(first.Environment, "SECRET=value")
	first.InheritedFiles = append(first.InheritedFiles, nil)

	second := plan.processRequest()
	if second.Args[0] == "--daemonize" || len(second.Environment) != 0 || len(second.InheritedFiles) != 0 {
		t.Fatalf("second process request was mutated through first copy: %#v", second)
	}
}

func TestStrictJailerLaunchHasNoPublicDurableShape(t *testing.T) {
	plan, err := planStrictJailerLaunch(validStrictJailerLaunchRequest())
	if err != nil {
		t.Fatalf("PlanStrictJailerLaunch() error = %v, want nil", err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("json.Marshal(plan) error = %v", err)
	}
	if got := string(encoded); got != "{}" {
		t.Fatalf("json.Marshal(plan) = %s, want no durable shape", got)
	}
}

func TestStrictJailerLaunchErrorRejectsUnallowlistedFieldText(t *testing.T) {
	err := &strictJailerLaunchError{field: "/Users/alice/private/jailer-secret"}
	if got := err.Error(); got != errStrictJailerLaunchInvalid.Error() {
		t.Fatalf("error = %q, want sanitized sentinel", got)
	}
}

func validStrictJailerLaunchRequest() strictJailerLaunchRequest {
	jailRoot := "/srv/hal/private/jailer/firecracker/run-alpha/root"
	hostPaths := firecracker.PathPlan{
		StateDir:        jailRoot + "/run/fc-run-alpha",
		APISocketPath:   jailRoot + "/run/fc-run-alpha/firecracker.sock",
		ConfigPath:      jailRoot + "/run/fc-run-alpha/firecracker-config.json",
		LogPath:         jailRoot + "/run/fc-run-alpha/firecracker.log",
		MetricsPath:     jailRoot + "/run/fc-run-alpha/firecracker.metrics",
		VsockSocketPath: jailRoot + "/run/fc-run-alpha/guest.vsock",
	}
	jailPaths := firecracker.PathPlan{
		StateDir:        "/run/fc-run-alpha",
		APISocketPath:   "/run/fc-run-alpha/firecracker.sock",
		ConfigPath:      "/run/fc-run-alpha/firecracker-config.json",
		LogPath:         "/run/fc-run-alpha/firecracker.log",
		MetricsPath:     "/run/fc-run-alpha/firecracker.metrics",
		VsockSocketPath: "/run/fc-run-alpha/guest.vsock",
	}
	return strictJailerLaunchRequest{
		RuntimeID:                "run-alpha",
		JailerPath:               "/opt/hal/private/bin/jailer",
		CanonicalFirecrackerPath: "/opt/hal/private/bin/firecracker",
		UID:                      1001,
		GID:                      1002,
		ChrootBaseDir:            "/srv/hal/private/jailer",
		HostPaths:                hostPaths,
		JailPaths:                jailPaths,
		Firecracker: firecracker.ProcessRunnerStartRequest{
			Executable:  "/opt/hal/private/bin/firecracker",
			Args:        strictFirecrackerArgs(hostPaths),
			Environment: []string{},
		},
	}
}

func strictFirecrackerArgs(paths firecracker.PathPlan) []string {
	return []string{
		"--api-sock", paths.APISocketPath,
		"--config-file", paths.ConfigPath,
		"--log-path", paths.LogPath,
		"--metrics-path", paths.MetricsPath,
	}
}

func assertStrictJailerLaunchError(t *testing.T, err error, field string) {
	t.Helper()
	if !errors.Is(err, errStrictJailerLaunchInvalid) {
		t.Fatalf("error = %v, want ErrStrictJailerLaunchInvalid", err)
	}
	var launchErr *strictJailerLaunchError
	if !errors.As(err, &launchErr) || launchErr.field != field {
		t.Fatalf("error = %#v, want field %q", err, field)
	}
}
