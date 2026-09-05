package firecracker

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestRenderStartOperationPlanConstructsDeterministicProcessDescriptor(t *testing.T) {
	config := validFirecrackerOperationConfig(t)

	first, err := RenderStartOperationPlan(config)
	if err != nil {
		t.Fatalf("RenderStartOperationPlan() error = %v, want nil", err)
	}
	second, err := RenderStartOperationPlan(config)
	if err != nil {
		t.Fatalf("RenderStartOperationPlan() second error = %v, want nil", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("RenderStartOperationPlan() is not deterministic:\nfirst:  %#v\nsecond: %#v", first, second)
	}

	if first.Action != OperationActionStart {
		t.Fatalf("Action = %q, want %q", first.Action, OperationActionStart)
	}
	assertOperationPathReference(t, first.Executable, OperationPathRoleExecutable, config.ExecutablePath)
	assertOperationPathReference(t, first.APISocket, OperationPathRoleAPISocket, config.Paths.APISocketPath)
	assertOperationPathReference(t, first.Config, OperationPathRoleConfig, config.Paths.ConfigPath)
	assertOperationPathReference(t, first.Log, OperationPathRoleLog, config.Paths.LogPath)
	assertOperationPathReference(t, first.Metrics, OperationPathRoleMetrics, config.Paths.MetricsPath)

	wantArgv := []string{
		config.ExecutablePath,
		"--api-sock", config.Paths.APISocketPath,
		"--config-file", config.Paths.ConfigPath,
		"--log-path", config.Paths.LogPath,
		"--metrics-path", config.Paths.MetricsPath,
	}
	if !reflect.DeepEqual(first.Argv, wantArgv) {
		t.Fatalf("Argv = %#v, want %#v", first.Argv, wantArgv)
	}
	if first.Environment == nil {
		t.Fatal("Environment = nil, want explicit empty metadata list")
	}
	if len(first.Environment) != 0 {
		t.Fatalf("Environment length = %d, want 0", len(first.Environment))
	}

	wantPayloads := []OperationPayloadReference{
		{Role: OperationPayloadRoleMachineConfig, APIPath: "/machine-config"},
		{Role: OperationPayloadRoleBootSource, APIPath: "/boot-source"},
		{Role: OperationPayloadRoleRootDrive, APIPath: "/drives/rootfs"},
	}
	if !reflect.DeepEqual(first.Payloads, wantPayloads) {
		t.Fatalf("Payloads = %#v, want %#v", first.Payloads, wantPayloads)
	}
}

func TestRenderStartOperationPlanRejectsInvalidPayloadInput(t *testing.T) {
	config := validFirecrackerOperationConfig(t)
	config.CPUCount = 0
	config.KernelImagePath = "/Users/alice/private/images/secret-vmlinux"
	config.RootfsPath = "/var/folders/private/rootfs-secret.ext4"

	_, err := RenderStartOperationPlan(config)

	assertFirecrackerOperationPlanError(t, err, "cpuCount")
	assertFirecrackerErrorDoesNotLeak(t, err,
		"/Users/alice",
		"/var/folders",
		"secret-vmlinux",
		"rootfs-secret.ext4",
	)
}

func TestRenderStopInspectDeleteOperationPlansDescribeLifecycleActions(t *testing.T) {
	config := validFirecrackerOperationConfig(t)

	stopPlan, err := RenderStopOperationPlan(config.Paths)
	if err != nil {
		t.Fatalf("RenderStopOperationPlan() error = %v, want nil", err)
	}
	secondStopPlan, err := RenderStopOperationPlan(config.Paths)
	if err != nil {
		t.Fatalf("RenderStopOperationPlan() second error = %v, want nil", err)
	}
	if !reflect.DeepEqual(stopPlan, secondStopPlan) {
		t.Fatalf("RenderStopOperationPlan() is not deterministic:\nfirst:  %#v\nsecond: %#v", stopPlan, secondStopPlan)
	}
	if stopPlan.Action != OperationActionStop {
		t.Fatalf("stop Action = %q, want %q", stopPlan.Action, OperationActionStop)
	}
	assertOperationPathReference(t, stopPlan.APISocket, OperationPathRoleAPISocket, config.Paths.APISocketPath)

	inspectPlan, err := RenderInspectOperationPlan(config.Paths)
	if err != nil {
		t.Fatalf("RenderInspectOperationPlan() error = %v, want nil", err)
	}
	secondInspectPlan, err := RenderInspectOperationPlan(config.Paths)
	if err != nil {
		t.Fatalf("RenderInspectOperationPlan() second error = %v, want nil", err)
	}
	if !reflect.DeepEqual(inspectPlan, secondInspectPlan) {
		t.Fatalf("RenderInspectOperationPlan() is not deterministic:\nfirst:  %#v\nsecond: %#v", inspectPlan, secondInspectPlan)
	}
	if inspectPlan.Action != OperationActionInspect {
		t.Fatalf("inspect Action = %q, want %q", inspectPlan.Action, OperationActionInspect)
	}
	assertOperationPathReference(t, inspectPlan.APISocket, OperationPathRoleAPISocket, config.Paths.APISocketPath)

	deletePlan, err := RenderDeleteOperationPlan(config.Paths)
	if err != nil {
		t.Fatalf("RenderDeleteOperationPlan() error = %v, want nil", err)
	}
	secondDeletePlan, err := RenderDeleteOperationPlan(config.Paths)
	if err != nil {
		t.Fatalf("RenderDeleteOperationPlan() second error = %v, want nil", err)
	}
	if !reflect.DeepEqual(deletePlan, secondDeletePlan) {
		t.Fatalf("RenderDeleteOperationPlan() is not deterministic:\nfirst:  %#v\nsecond: %#v", deletePlan, secondDeletePlan)
	}
	if deletePlan.Action != OperationActionDelete {
		t.Fatalf("delete Action = %q, want %q", deletePlan.Action, OperationActionDelete)
	}
	assertOperationPathReference(t, deletePlan.StateDir, OperationPathRoleStateDir, config.Paths.StateDir)
	assertOperationPathReference(t, deletePlan.APISocket, OperationPathRoleAPISocket, config.Paths.APISocketPath)
	assertOperationPathReference(t, deletePlan.Config, OperationPathRoleConfig, config.Paths.ConfigPath)
	assertOperationPathReference(t, deletePlan.Log, OperationPathRoleLog, config.Paths.LogPath)
	assertOperationPathReference(t, deletePlan.Metrics, OperationPathRoleMetrics, config.Paths.MetricsPath)
}

func TestOperationPlanSummariesOmitRawHostPaths(t *testing.T) {
	config := validFirecrackerOperationConfig(t)
	config.ExecutablePath = "/Users/alice/private/bin/firecracker"
	config.KernelImagePath = "/Users/alice/private/images/vmlinux-secret"
	config.RootfsPath = "/Users/alice/private/images/rootfs-secret.ext4"
	initrd := "/Users/alice/private/images/initrd-secret.img"
	config.InitrdPath = &initrd
	paths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    "runtime-alpha",
		BaseStateDir: "/Users/alice/private/firecracker-state",
	})
	if err != nil {
		t.Fatalf("PlanPaths() error = %v, want nil", err)
	}
	config.Paths = paths

	startPlan, err := RenderStartOperationPlan(config)
	if err != nil {
		t.Fatalf("RenderStartOperationPlan() error = %v, want nil", err)
	}
	stopPlan, err := RenderStopOperationPlan(config.Paths)
	if err != nil {
		t.Fatalf("RenderStopOperationPlan() error = %v, want nil", err)
	}
	inspectPlan, err := RenderInspectOperationPlan(config.Paths)
	if err != nil {
		t.Fatalf("RenderInspectOperationPlan() error = %v, want nil", err)
	}
	deletePlan, err := RenderDeleteOperationPlan(config.Paths)
	if err != nil {
		t.Fatalf("RenderDeleteOperationPlan() error = %v, want nil", err)
	}

	for _, tt := range []struct {
		name    string
		summary OperationPlanSummary
	}{
		{name: "start", summary: startPlan.Summary()},
		{name: "stop", summary: stopPlan.Summary()},
		{name: "inspect", summary: inspectPlan.Summary()},
		{name: "delete", summary: deletePlan.Summary()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			encoded, marshalErr := json.Marshal(tt.summary)
			if marshalErr != nil {
				t.Fatalf("Marshal(%T) error = %v", tt.summary, marshalErr)
			}
			publicText := string(encoded)
			for _, unsafe := range []string{
				"/Users/alice",
				"private",
				"firecracker.sock",
				"firecracker-config.json",
				"firecracker.log",
				"firecracker.metrics",
				"vmlinux-secret",
				"rootfs-secret.ext4",
				"initrd-secret.img",
			} {
				if strings.Contains(publicText, unsafe) {
					t.Fatalf("%s summary leaked unsafe fragment %q in %s", tt.name, unsafe, publicText)
				}
			}
		})
	}
}

func TestStartOperationPlanSummaryPreservesReviewableShapeWithoutPaths(t *testing.T) {
	config := validFirecrackerOperationConfig(t)
	plan, err := RenderStartOperationPlan(config)
	if err != nil {
		t.Fatalf("RenderStartOperationPlan() error = %v, want nil", err)
	}

	summary := plan.Summary()
	if summary.Action != OperationActionStart {
		t.Fatalf("summary Action = %q, want %q", summary.Action, OperationActionStart)
	}
	if summary.ExecutableRole != OperationPathRoleExecutable {
		t.Fatalf("summary ExecutableRole = %q, want %q", summary.ExecutableRole, OperationPathRoleExecutable)
	}
	if summary.Environment == nil {
		t.Fatal("summary Environment = nil, want explicit empty metadata list")
	}
	wantArgv := []OperationArgumentSummary{
		{PathRole: OperationPathRoleExecutable},
		{Value: "--api-sock"},
		{PathRole: OperationPathRoleAPISocket},
		{Value: "--config-file"},
		{PathRole: OperationPathRoleConfig},
		{Value: "--log-path"},
		{PathRole: OperationPathRoleLog},
		{Value: "--metrics-path"},
		{PathRole: OperationPathRoleMetrics},
	}
	if !reflect.DeepEqual(summary.Argv, wantArgv) {
		t.Fatalf("summary Argv = %#v, want %#v", summary.Argv, wantArgv)
	}
	wantPathRoles := []OperationPathRole{
		OperationPathRoleAPISocket,
		OperationPathRoleConfig,
		OperationPathRoleLog,
		OperationPathRoleMetrics,
	}
	if !reflect.DeepEqual(summary.PathRoles, wantPathRoles) {
		t.Fatalf("summary PathRoles = %#v, want %#v", summary.PathRoles, wantPathRoles)
	}
	if !reflect.DeepEqual(summary.Payloads, plan.Payloads) {
		t.Fatalf("summary Payloads = %#v, want %#v", summary.Payloads, plan.Payloads)
	}
}

func validFirecrackerOperationConfig(t *testing.T) BackendConfig {
	t.Helper()

	config := validFirecrackerPayloadConfig(t)
	paths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    "runtime-alpha",
		BaseStateDir: firecrackerPathTestBase("operation-state"),
	})
	if err != nil {
		t.Fatalf("PlanPaths() error = %v, want nil", err)
	}
	config.Paths = paths
	return config
}

func assertOperationPathReference(t *testing.T, got OperationPathReference, role OperationPathRole, path string) {
	t.Helper()
	if got.Role != role {
		t.Fatalf("path reference role = %q, want %q", got.Role, role)
	}
	if got.Path != path {
		t.Fatalf("path reference path = %q, want %q", got.Path, path)
	}
}

func assertFirecrackerOperationPlanError(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatal("operation plan error = nil, want invalid config error")
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
	if opErr.Operation != OperationPlanningOperation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, OperationPlanningOperation)
	}
	if opErr.Field != field {
		t.Fatalf("OperationError.Field = %q, want %q", opErr.Field, field)
	}
}
