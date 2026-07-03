package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestPhase40MicroVMDefaultCapabilitiesStayLifecycleOnlyWithoutGuestTransport(t *testing.T) {
	registry, err := sandboxworker.NewDriverRegistry(fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverMicroVM})
	if err != nil {
		t.Fatalf("NewDriverRegistry(microvm) error = %v", err)
	}
	service, err := sandboxworker.NewService(sandboxworker.ServiceOptions{
		WorkerID: "worker-phase40-microvm",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService(microvm) error = %v", err)
	}
	capabilities := service.Capabilities()
	assertPhase40MicroVMCabilitiesOmitExecCopy(t, "default worker microVM capabilities", capabilities.SupportedOperations)
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtimeDrivers = %#v, want one microVM descriptor", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != sandboxruntime.DriverMicroVM {
		t.Fatalf("runtime driver ID = %q, want %q", driver.ID, sandboxruntime.DriverMicroVM)
	}
	assertPhase40MicroVMCabilitiesOmitExecCopy(t, "default worker microVM driver operations", driver.Operations)
	assertPhase40JSONOmitsImplicitExecCopyClaims(t, "default worker microVM capabilities", capabilities)

	descriptors := sandboxdRuntimeDriverDescriptors(sandboxdRequest{
		Drivers: []string{sandboxruntime.DriverMicroVM},
		MicroVM: sandboxdMicroVMConfig{},
	})
	if descriptors != nil {
		t.Fatalf("sandboxd microVM descriptors without guest endpoint = %#v, want nil default descriptors", descriptors)
	}

	descriptors = sandboxdRuntimeDriverDescriptors(sandboxdRequest{
		Drivers: []string{sandboxruntime.DriverMicroVM},
		MicroVM: sandboxdMicroVMConfig{GuestAgentEndpoint: "unix:///tmp/hal-guest-agent.sock"},
	})
	configured := descriptors[sandboxruntime.DriverMicroVM]
	for _, operation := range []string{sandboxworker.OperationExec, sandboxworker.OperationCopyIn, sandboxworker.OperationCopyOut} {
		if !phase40StringSliceContains(configured.Operations, operation) {
			t.Fatalf("configured guest-agent microVM operations = %#v, want %q", configured.Operations, operation)
		}
	}
}

func TestPhase40MicroVMGuestTransportCodeAvoidsHostDockerSocketUse(t *testing.T) {
	for _, path := range phase40GuestTransportProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		for _, forbidden := range []struct {
			needle string
			reason string
		}{
			{needle: "/var/run/docker.sock", reason: "host Docker socket"},
			{needle: "/run/docker.sock", reason: "host Docker socket"},
			{needle: "docker.sock", reason: "host Docker socket"},
			{needle: "DOCKER_HOST", reason: "host Docker endpoint environment"},
			{needle: "github.com/docker/docker", reason: "Docker API package"},
			{needle: "github.com/containers/podman", reason: "Podman API package"},
		} {
			if strings.Contains(string(source), forbidden.needle) {
				t.Fatalf("%s contains %q (%s); Phase 40 guest transport code paths must not use host Docker socket plumbing", phase34FirecrackerDisplayPath(t, path), forbidden.needle, forbidden.reason)
			}
		}
	}
}

func TestPhase40MicroVMGuestProtocolPackagesDoNotImportCommandFactoryOrWorker(t *testing.T) {
	for _, path := range phase40GuestProtocolProductionFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("Unquote(%s in %s) error = %v", spec.Path.Value, path, err)
			}
			for _, forbidden := range []string{
				"github.com/jywlabs/hal/cmd",
				"github.com/jywlabs/hal/internal/factory",
				"github.com/jywlabs/hal/internal/sandboxworker",
			} {
				if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
					t.Fatalf("%s imports %q; Phase 40 guest protocol packages must not import command, factory, or worker packages", phase34FirecrackerDisplayPath(t, path), importPath)
				}
			}
		}
	}
}

func TestPhase40MicroVMGuestTransportPublicErrorsAndJSONAreRedactionSafe(t *testing.T) {
	rawErr := errors.New(`dial unix /Users/alice/private/agent.sock to https://guest.internal:9443/status Authorization: Bearer ghp_secret token=ghp_secret password=hunter2 body={"token":"secret"} socket /var/run/docker.sock 127.0.0.1:8080`)
	protocolErr := guestagent.NewProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationExec, "transport", rawErr)
	encoded, err := json.Marshal(protocolErr)
	if err != nil {
		t.Fatalf("Marshal(ProtocolError) error = %v", err)
	}

	endpointErr := firecrackerhost.ValidateGuestAgentEndpoint("tcp://guest.internal:8080/path?token=ghp_secret")
	if endpointErr == nil {
		t.Fatal("ValidateGuestAgentEndpoint() error = nil, want validation error")
	}

	combined := strings.ToLower(protocolErr.Error() + " " + string(encoded) + " " + endpointErr.Error())
	for _, forbidden := range []string{
		"/users/alice",
		"agent.sock",
		"guest.internal",
		"9443",
		"authorization",
		"bearer",
		"ghp_secret",
		"hunter2",
		`"token":"secret"`,
		"/var/run/docker.sock",
		"127.0.0.1",
		"8080",
		"tcp://",
		"token=",
	} {
		if strings.Contains(combined, strings.ToLower(forbidden)) {
			t.Fatalf("Phase 40 public error or JSON leaked %q in %q", forbidden, combined)
		}
	}
	for _, want := range []string{"transport_failure", "exec", "field", "endpoint"} {
		if !strings.Contains(combined, want) {
			t.Fatalf("Phase 40 public error or JSON = %q, want safe marker %q", combined, want)
		}
	}
}

func assertPhase40MicroVMCabilitiesOmitExecCopy(t *testing.T, label string, operations []string) {
	t.Helper()
	for _, unsupported := range []string{sandboxworker.OperationExec, sandboxworker.OperationCopyIn, sandboxworker.OperationCopyOut} {
		if phase40StringSliceContains(operations, unsupported) {
			t.Fatalf("%s claim unsupported %q operation: %#v", label, unsupported, operations)
		}
	}
}

func assertPhase40JSONOmitsImplicitExecCopyClaims(t *testing.T, label string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", label, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal(%s JSON) error = %v", label, err)
	}
	text := strings.ToLower(string(encoded))
	for _, forbidden := range []string{`"exec"`, `"copy_in"`, `"copy_out"`, "guesttransport", "guest_transport", "guest agent endpoint", "docker.sock"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("%s JSON claims implicit guest exec/copy transport marker %q in %s", label, forbidden, text)
		}
	}
}

func phase40GuestTransportProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "client.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "contracts.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "errors.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "validation.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_agent_readiness.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_agent_unix_transport.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_endpoint.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport.go"),
		"sandboxd_firecracker_live_driver.go",
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Stat(%s) error = %v", path, err)
		}
	}
	sort.Strings(paths)
	return paths
}

func phase40GuestProtocolProductionFiles(t *testing.T) []string {
	t.Helper()
	pattern := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "*.go")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("Glob(%s) error = %v", pattern, err)
	}
	var paths []string
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("no Phase 40 guest protocol production files matched")
	}
	return paths
}

func phase40StringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestPhase40MicroVMGuestTransportGuardRejectsFixtures(t *testing.T) {
	leakyError := guestagent.NewProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationExec, "transport", fmt.Errorf("token=ghp_secret /var/run/docker.sock"))
	if strings.Contains(strings.ToLower(leakyError.Error()), "ghp_secret") || strings.Contains(strings.ToLower(leakyError.Error()), "/var/run/docker.sock") {
		t.Fatalf("fixture protocol error leaked sensitive details: %v", leakyError)
	}

	fixture := []string{
		sandboxworker.OperationCreate,
		sandboxworker.OperationExec,
	}
	if !phase40StringSliceContains(fixture, sandboxworker.OperationExec) {
		t.Fatal("fixture should include exec so capability guard can detect implicit exec claims")
	}
}
