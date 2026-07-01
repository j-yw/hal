package cmd

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestSandboxdSafetyWiringUsesFakeableDepsAndHonestCapabilities(t *testing.T) {
	req := sandboxdRequest{
		SocketPath:    "/tmp/hal-sandboxd-safety.sock",
		WorkerID:      "worker-safety",
		Drivers:       []string{sandboxruntime.DriverRootlessPodman},
		PodmanPath:    "fake-podman",
		MaxConcurrent: 2,
	}
	var driverConstructed bool
	var serviceChecked bool
	var serverStarted bool

	err := runSandboxdWithDeps(context.Background(), req, io.Discard, sandboxdDeps{
		rootlessPodmanAvailable: func(context.Context, string) error {
			return nil
		},
		newRootlessPodmanDriver: func(podmanPath string) sandboxruntime.Driver {
			driverConstructed = true
			if podmanPath != "fake-podman" {
				t.Fatalf("podman path = %q, want fake-podman", podmanPath)
			}
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			service, err := sandboxworker.NewService(options)
			if err != nil {
				return nil, err
			}
			capabilities := service.Capabilities()
			assertSandboxdSafetyIncludesWorkerIOSupport(t, capabilities.SupportedOperations)
			assertSandboxdSafetyHonestPolicy(t, capabilities.Security)
			if len(capabilities.RuntimeDrivers) != 1 {
				t.Fatalf("runtime driver count = %d, want 1", len(capabilities.RuntimeDrivers))
			}
			driver := capabilities.RuntimeDrivers[0]
			if driver.ID != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("runtime driver ID = %q, want %q", driver.ID, sandboxruntime.DriverRootlessPodman)
			}
			if driver.IsolationLevel != sandboxworker.IsolationLevelContainer {
				t.Fatalf("runtime driver isolationLevel = %q, want %q", driver.IsolationLevel, sandboxworker.IsolationLevelContainer)
			}
			assertSandboxdSafetyIncludesWorkerIOSupport(t, driver.Operations)
			assertSandboxdSafetyHonestPolicy(t, driver.Security)
			serviceChecked = true
			return service, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			if options.SocketPath != req.SocketPath {
				t.Fatalf("server socket path = %q, want %q", options.SocketPath, req.SocketPath)
			}
			if options.Handler == nil {
				t.Fatal("server handler is nil")
			}
			return sandboxdServerFunc(func(context.Context) error {
				serverStarted = true
				return nil
			}), nil
		},
	})
	if err != nil {
		t.Fatalf("runSandboxdWithDeps() error: %v", err)
	}
	if !driverConstructed || !serviceChecked || !serverStarted {
		t.Fatalf("driverConstructed=%v serviceChecked=%v serverStarted=%v, want all true", driverConstructed, serviceChecked, serverStarted)
	}
}

func TestSandboxdProductionCodeAvoidsUnsafeHostDependencies(t *testing.T) {
	data, err := os.ReadFile("sandboxd.go")
	if err != nil {
		t.Fatalf("ReadFile(sandboxd.go) error: %v", err)
	}
	content := string(data)
	for _, forbidden := range []struct {
		needle string
		reason string
	}{
		{needle: "/var/run/docker.sock", reason: "host Docker socket mount"},
		{needle: "docker.sock", reason: "host Docker socket dependency"},
		{needle: "--privileged", reason: "privileged container flag"},
		{needle: "privileged=true", reason: "privileged container option"},
	} {
		if strings.Contains(content, forbidden.needle) {
			t.Fatalf("sandboxd.go contains %q (%s); daemon command must not require unsafe host dependencies", forbidden.needle, forbidden.reason)
		}
	}
}

func assertSandboxdSafetyIncludesWorkerIOSupport(t *testing.T, operations []string) {
	t.Helper()

	for _, operation := range []string{sandboxworker.OperationExec, sandboxworker.OperationCopyIn, sandboxworker.OperationCopyOut} {
		if !containsSandboxdSafetyString(operations, operation) {
			t.Fatalf("operations omit %q after worker handler support exists: %#v", operation, operations)
		}
	}
}

func assertSandboxdSafetyHonestPolicy(t *testing.T, policy sandboxworker.SecurityPolicy) {
	t.Helper()

	if err := policy.Validate(); err != nil {
		t.Fatalf("security policy Validate() error: %v", err)
	}
	if policy.Enforced.NetworkPolicy == sandboxworker.NetworkPolicyDenyByDefault {
		t.Fatalf("security policy overclaims deny-by-default network enforcement: %#v", policy)
	}
	if policy.Enforced.CredentialProxyMode || containsSandboxdSafetyString(policy.Enforced.CredentialModes, "credential_proxy") {
		t.Fatalf("security policy overclaims credential proxy support: %#v", policy)
	}
	if policy.Enforced.IsolationLevel == "microvm" {
		t.Fatalf("security policy overclaims microVM isolation: %#v", policy)
	}
}

func containsSandboxdSafetyString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
