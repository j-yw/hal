package firecracker

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPlanPathsReturnsDeterministicTargetPaths(t *testing.T) {
	baseStateDir := firecrackerPathTestBase("state")
	request := PathPlanRequest{
		RuntimeID:    "runtime-alpha",
		BaseStateDir: baseStateDir + string(filepath.Separator),
	}

	first, err := PlanPaths(request)
	if err != nil {
		t.Fatalf("PlanPaths() error = %v, want nil", err)
	}
	second, err := PlanPaths(request)
	if err != nil {
		t.Fatalf("PlanPaths() second error = %v, want nil", err)
	}
	if first != second {
		t.Fatalf("PlanPaths() is not deterministic:\nfirst:  %#v\nsecond: %#v", first, second)
	}

	expectedStateDir := filepath.Join(baseStateDir, "runtime-alpha")
	want := PathPlan{
		StateDir:        expectedStateDir,
		APISocketPath:   filepath.Join(expectedStateDir, DefaultAPISocketPath),
		LogPath:         filepath.Join(expectedStateDir, DefaultLogPath),
		MetricsPath:     filepath.Join(expectedStateDir, DefaultMetricsPath),
		ConfigPath:      filepath.Join(expectedStateDir, DefaultConfigPath),
		VsockSocketPath: filepath.Join(expectedStateDir, defaultVsockPath),
	}
	if first != want {
		t.Fatalf("PlanPaths() = %#v, want %#v", first, want)
	}
}

func TestPlanPathsIsTargetSpecific(t *testing.T) {
	baseStateDir := firecrackerPathTestBase("targets")
	alpha, err := PlanPaths(PathPlanRequest{
		RuntimeID:    "runtime-alpha",
		BaseStateDir: baseStateDir,
	})
	if err != nil {
		t.Fatalf("PlanPaths(alpha) error = %v, want nil", err)
	}
	beta, err := PlanPaths(PathPlanRequest{
		RuntimeID:    "runtime-beta",
		BaseStateDir: baseStateDir,
	})
	if err != nil {
		t.Fatalf("PlanPaths(beta) error = %v, want nil", err)
	}

	if alpha.StateDir == beta.StateDir {
		t.Fatalf("StateDir = %q for both targets, want target-specific paths", alpha.StateDir)
	}
	for _, pair := range []struct {
		role  string
		alpha string
		beta  string
	}{
		{role: "apiSocketPath", alpha: alpha.APISocketPath, beta: beta.APISocketPath},
		{role: "logPath", alpha: alpha.LogPath, beta: beta.LogPath},
		{role: "metricsPath", alpha: alpha.MetricsPath, beta: beta.MetricsPath},
		{role: "configPath", alpha: alpha.ConfigPath, beta: beta.ConfigPath},
	} {
		if pair.alpha == pair.beta {
			t.Fatalf("%s = %q for both targets, want target-specific paths", pair.role, pair.alpha)
		}
		if !strings.HasPrefix(pair.alpha, alpha.StateDir+string(filepath.Separator)) {
			t.Fatalf("%s for alpha = %q, want under alpha state dir %q", pair.role, pair.alpha, alpha.StateDir)
		}
		if !strings.HasPrefix(pair.beta, beta.StateDir+string(filepath.Separator)) {
			t.Fatalf("%s for beta = %q, want under beta state dir %q", pair.role, pair.beta, beta.StateDir)
		}
	}
}

func TestPlanPathsEnforcesUnixSocketPathLimit(t *testing.T) {
	const runtimeID = "runtime-alpha"

	acceptedBase := firecrackerPathTestBaseForAPISocketLength(t, runtimeID, maxFirecrackerUnixSocketPathBytes)
	accepted, err := PlanPaths(PathPlanRequest{
		RuntimeID:    runtimeID,
		BaseStateDir: acceptedBase,
	})
	if err != nil {
		t.Fatalf("PlanPaths(accepted boundary) error = %v, want nil", err)
	}
	if got := len(accepted.APISocketPath); got != maxFirecrackerUnixSocketPathBytes {
		t.Fatalf("API socket path length = %d, want %d", got, maxFirecrackerUnixSocketPathBytes)
	}

	rejectedBase := firecrackerPathTestBaseForAPISocketLength(t, runtimeID, maxFirecrackerUnixSocketPathBytes+1)
	_, err = PlanPaths(PathPlanRequest{
		RuntimeID:    runtimeID,
		BaseStateDir: rejectedBase,
	})
	assertFirecrackerPathPlanningError(t, err, "apiSocketPath")
	assertFirecrackerErrorDoesNotLeak(t, err, rejectedBase, filepath.Base(rejectedBase), DefaultAPISocketPath)
}

func TestValidateLiveBootRenderPathsRejectsOverlongAPISocketPath(t *testing.T) {
	const runtimeID = "runtime-alpha"
	baseStateDir := firecrackerPathTestBaseForAPISocketLength(t, runtimeID, maxFirecrackerUnixSocketPathBytes+1)
	stateDir := filepath.Join(baseStateDir, runtimeID)
	paths := PathPlan{
		StateDir:      stateDir,
		APISocketPath: filepath.Join(stateDir, DefaultAPISocketPath),
		LogPath:       filepath.Join(stateDir, DefaultLogPath),
		MetricsPath:   filepath.Join(stateDir, DefaultMetricsPath),
		ConfigPath:    filepath.Join(stateDir, DefaultConfigPath),
	}

	_, err := validateLiveBootRenderPaths(paths)
	if err == nil {
		t.Fatal("validateLiveBootRenderPaths() error = nil, want invalid config error")
	}
	if !errors.Is(err, microvm.ErrInvalidConfig) {
		t.Fatalf("errors.Is(err, microvm.ErrInvalidConfig) = false for %v", err)
	}
	var opErr *microvm.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *microvm.OperationError", err)
	}
	if opErr.Operation != liveBootRenderOperation || opErr.Field != "apiSocketPath" {
		t.Fatalf("render error operation/field = %q/%q, want %q/apiSocketPath", opErr.Operation, opErr.Field, liveBootRenderOperation)
	}
	assertFirecrackerErrorDoesNotLeak(t, err, baseStateDir, filepath.Base(baseStateDir), DefaultAPISocketPath)
}

func TestPlanPathsRejectsInvalidInputsWithoutLeakingRawPaths(t *testing.T) {
	privateBaseDir := firecrackerPathTestBase("alice", "private", "firecracker-state")
	tests := []struct {
		name            string
		request         PathPlanRequest
		field           string
		unsafeFragments []string
	}{
		{
			name: "missing runtime ID",
			request: PathPlanRequest{
				RuntimeID:    " \t ",
				BaseStateDir: privateBaseDir,
			},
			field: "runtimeId",
			unsafeFragments: []string{
				privateBaseDir,
				"alice",
				"private",
			},
		},
		{
			name: "unsafe runtime ID",
			request: PathPlanRequest{
				RuntimeID:    "/Users/alice/private/runtime-alpha",
				BaseStateDir: privateBaseDir,
			},
			field: "runtimeId",
			unsafeFragments: []string{
				"/Users/alice",
				"runtime-alpha",
				privateBaseDir,
			},
		},
		{
			name: "missing base state dir",
			request: PathPlanRequest{
				RuntimeID:    "runtime-alpha",
				BaseStateDir: " \t ",
			},
			field: "baseStateDir",
			unsafeFragments: []string{
				privateBaseDir,
				"alice",
				"private",
			},
		},
		{
			name: "relative base state dir",
			request: PathPlanRequest{
				RuntimeID:    "runtime-alpha",
				BaseStateDir: "alice/private/firecracker-state",
			},
			field: "baseStateDir",
			unsafeFragments: []string{
				"alice/private",
				"firecracker-state",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PlanPaths(tt.request)
			assertFirecrackerPathPlanningError(t, err, tt.field)
			assertFirecrackerErrorDoesNotLeak(t, err, tt.unsafeFragments...)
		})
	}
}

func firecrackerPathTestBase(elements ...string) string {
	parts := append([]string{string(filepath.Separator), "var", "lib", "hal", "firecracker"}, elements...)
	return filepath.Join(parts...)
}

func firecrackerPathTestBaseForAPISocketLength(t *testing.T, runtimeID string, pathLength int) string {
	t.Helper()
	suffix := string(filepath.Separator) + filepath.Join(runtimeID, DefaultAPISocketPath)
	baseLength := pathLength - len(suffix)
	if baseLength < 2 {
		t.Fatalf("requested API socket path length %d is too short for test suffix", pathLength)
	}
	base := string(filepath.Separator) + strings.Repeat("a", baseLength-1)
	if got := len(filepath.Join(base, runtimeID, DefaultAPISocketPath)); got != pathLength {
		t.Fatalf("constructed API socket path length = %d, want %d", got, pathLength)
	}
	return base
}

func assertFirecrackerPathPlanningError(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatal("PlanPaths() error = nil, want invalid config error")
	}
	if !errors.Is(err, microvm.ErrInvalidConfig) {
		t.Fatalf("errors.Is(err, microvm.ErrInvalidConfig) = false for %v", err)
	}
	var opErr *microvm.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *microvm.OperationError", err)
	}
	if opErr.Code != microvm.ErrorCodeInvalidConfig {
		t.Fatalf("OperationError.Code = %q, want %q", opErr.Code, microvm.ErrorCodeInvalidConfig)
	}
	if opErr.Operation != PathPlanningOperation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, PathPlanningOperation)
	}
	if opErr.Field != field {
		t.Fatalf("OperationError.Field = %q, want %q", opErr.Field, field)
	}
}
