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

	plan, err := PlanStrictJailerLaunch(request)
	if err != nil {
		t.Fatalf("PlanStrictJailerLaunch() error = %v, want nil", err)
	}
	process := plan.ProcessRequest()
	if process.Executable != request.JailerPath {
		t.Fatalf("executable = %q, want configured Jailer", process.Executable)
	}
	wantArgs := []string{
		"--id", "run-alpha",
		"--exec-file", request.FirecrackerPath,
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
	if plan.HostPaths() != request.HostPaths {
		t.Fatalf("host paths = %#v, want lifecycle-owned paths", plan.HostPaths())
	}
}

func TestPlanStrictJailerLaunchFailsClosedAtEveryMissingBoundary(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*StrictJailerLaunchRequest)
	}{
		{name: "runtime identity", field: "runtimeId", edit: func(req *StrictJailerLaunchRequest) { req.RuntimeID = "bad/runtime" }},
		{name: "jailer", field: "jailerPath", edit: func(req *StrictJailerLaunchRequest) { req.JailerPath = "" }},
		{name: "Firecracker", field: "firecrackerPath", edit: func(req *StrictJailerLaunchRequest) { req.FirecrackerPath = "" }},
		{name: "root uid", field: "uid", edit: func(req *StrictJailerLaunchRequest) { req.UID = 0 }},
		{name: "root gid", field: "gid", edit: func(req *StrictJailerLaunchRequest) { req.GID = 0 }},
		{name: "chroot", field: "chrootBaseDir", edit: func(req *StrictJailerLaunchRequest) { req.ChrootBaseDir = "/" }},
		{name: "host paths", field: "hostPaths", edit: func(req *StrictJailerLaunchRequest) { req.HostPaths.ConfigPath += "-other" }},
		{name: "jail paths", field: "jailPaths", edit: func(req *StrictJailerLaunchRequest) { req.JailPaths.APISocketPath = req.HostPaths.APISocketPath }},
		{name: "environment", field: "environment", edit: func(req *StrictJailerLaunchRequest) { req.Firecracker.Environment = []string{"SECRET=value"} }},
		{name: "inherited assets", field: "inheritedFiles", edit: func(req *StrictJailerLaunchRequest) { req.Firecracker.InheritedFiles = []*os.File{nil} }},
		{name: "direct substitution", field: "firecrackerPath", edit: func(req *StrictJailerLaunchRequest) { req.JailerPath = req.FirecrackerPath }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := validStrictJailerLaunchRequest()
			tt.edit(&request)

			_, err := PlanStrictJailerLaunch(request)
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

	_, err := PlanStrictJailerLaunch(request)

	assertStrictJailerLaunchError(t, err, "hostPaths")
	if strings.Contains(err.Error(), "attacker.sock") {
		t.Fatalf("error leaked drifted path in %q", err)
	}
}

func TestStrictJailerLaunchPublicShapeOmitsPathsAndArguments(t *testing.T) {
	plan, err := PlanStrictJailerLaunch(validStrictJailerLaunchRequest())
	if err != nil {
		t.Fatalf("PlanStrictJailerLaunch() error = %v, want nil", err)
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("json.Marshal(plan) error = %v", err)
	}
	text := string(encoded)
	for _, unsafe := range []string{"/opt/hal/private", "/srv/hal/private", "/run/hal", "--exec-file", "1001", "1002"} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("public plan leaked %q in %s", unsafe, text)
		}
	}
	for _, required := range []string{`"mode":"jailer"`, `"runtimeId":"run-alpha"`} {
		if !strings.Contains(text, required) {
			t.Fatalf("public plan = %s, want %s", text, required)
		}
	}
}

func validStrictJailerLaunchRequest() StrictJailerLaunchRequest {
	hostPaths := firecracker.PathPlan{
		StateDir:        "/srv/hal/private/state/run-alpha",
		APISocketPath:   "/srv/hal/private/state/run-alpha/firecracker.sock",
		ConfigPath:      "/srv/hal/private/state/run-alpha/firecracker-config.json",
		LogPath:         "/srv/hal/private/state/run-alpha/firecracker.log",
		MetricsPath:     "/srv/hal/private/state/run-alpha/firecracker.metrics",
		VsockSocketPath: "/srv/hal/private/state/run-alpha/guest.vsock",
	}
	jailPaths := firecracker.PathPlan{
		StateDir:        "/run/hal",
		APISocketPath:   "/run/hal/firecracker.sock",
		ConfigPath:      "/run/hal/firecracker-config.json",
		LogPath:         "/run/hal/firecracker.log",
		MetricsPath:     "/run/hal/firecracker.metrics",
		VsockSocketPath: "/run/hal/guest.vsock",
	}
	return StrictJailerLaunchRequest{
		RuntimeID:       "run-alpha",
		JailerPath:      "/opt/hal/private/bin/jailer",
		FirecrackerPath: "/opt/hal/private/bin/firecracker",
		UID:             1001,
		GID:             1002,
		ChrootBaseDir:   "/srv/hal/private/jailer",
		HostPaths:       hostPaths,
		JailPaths:       jailPaths,
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
	if !errors.Is(err, ErrStrictJailerLaunchInvalid) {
		t.Fatalf("error = %v, want ErrStrictJailerLaunchInvalid", err)
	}
	var launchErr *StrictJailerLaunchError
	if !errors.As(err, &launchErr) || launchErr.Field != field {
		t.Fatalf("error = %#v, want field %q", err, field)
	}
}
