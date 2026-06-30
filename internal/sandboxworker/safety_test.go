package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestWorkerSafetyCapabilitiesDoNotOverstateLocalSecurity(t *testing.T) {
	registry, err := NewDriverRegistry(&recordingLifecycleDriver{id: RuntimeDriverRootlessPodman})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-safety",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	status := service.Status()
	assertWorkerSafetyHonestSecurityPolicy(t, "status", status.Security)

	capabilities := service.Capabilities()
	assertWorkerSafetyExposesWorkerIOHandlers(t, "worker capabilities", capabilities.SupportedOperations)
	assertWorkerSafetyHonestSecurityPolicy(t, "capabilities", capabilities.Security)
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime driver count = %d, want 1", len(capabilities.RuntimeDrivers))
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != RuntimeDriverRootlessPodman {
		t.Fatalf("runtime driver ID = %q, want %q", driver.ID, RuntimeDriverRootlessPodman)
	}
	if driver.IsolationLevel != IsolationLevelContainer {
		t.Fatalf("rootless driver isolationLevel = %q, want %q", driver.IsolationLevel, IsolationLevelContainer)
	}
	assertWorkerSafetyExposesWorkerIOHandlers(t, "runtime driver capabilities", driver.Operations)
	assertWorkerSafetyHonestSecurityPolicy(t, "runtime driver", driver.Security)
}

func TestWorkerSafetyMalformedCopyRequestsAreStructuredAndDoNotReachDrivers(t *testing.T) {
	driver := &recordingLifecycleDriver{id: "fake_runtime"}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-safety",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	for _, operation := range []string{OperationCopyIn, OperationCopyOut} {
		resp := service.HandleRequest(context.Background(), Request{
			RequestID: "req-" + operation,
			Operation: operation,
			DriverID:  "fake_runtime",
		})
		if err := resp.Validate(); err != nil {
			t.Fatalf("%s response Validate() error: %v", operation, err)
		}
		if resp.OK || resp.Operation != operation || resp.Error == nil {
			t.Fatalf("%s response = %#v, want structured malformed-request error", operation, resp)
		}
		if resp.Error.Code != ErrorCodeMalformedRequest {
			t.Fatalf("%s error code = %q, want %q", operation, resp.Error.Code, ErrorCodeMalformedRequest)
		}
	}
	if len(driver.calls) != 0 {
		t.Fatalf("driver calls = %#v, want malformed copy requests to stop before driver dispatch", driver.calls)
	}
}

func TestWorkerSafetyRedactsSecretsInProtocolErrorSurfaces(t *testing.T) {
	driver := &recordingLifecycleDriver{
		id: "fake_runtime",
		errByOperation: map[string]error{
			OperationStart: errors.New("provider failed token=raw-secret password=hunter2 api_key=ghp_worker_secret under /Users/alice/worktree"),
		},
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-safety",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	driverResp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-driver-error",
		Operation: OperationStart,
		DriverID:  "fake_runtime",
		Lifecycle: &LifecycleRequest{Target: lifecycleWorkerTarget("fake_runtime", "dev", "created")},
	})
	if driverResp.OK || driverResp.Error == nil || driverResp.Error.Code != ErrorCodeDriverFailed {
		t.Fatalf("driver response = %#v, want driver_error", driverResp)
	}
	assertWorkerSafetyRedactedDetail(t, "driver error", driverResp.Error.Message)

	server, err := NewServer(ServerOptions{
		SocketPath: "/tmp/unused-worker-safety.sock",
		Handler: RequestHandlerFunc(func(context.Context, Request) Response {
			t.Fatal("handler should not receive malformed requests")
			return Response{}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	_, malformedResp := server.readRequest(strings.NewReader(`{"protocolVersion":"sandboxworker-v1","requestId":"bad","operation":"bogus token=raw-secret /Users/alice/worktree"}`))
	if malformedResp == nil || malformedResp.Error == nil {
		t.Fatalf("malformed response = %#v, want structured protocol error", malformedResp)
	}
	assertWorkerSafetyRedactedDetail(t, "malformed request", malformedResp.Error.Message)

	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
			return Response{
				RequestID: req.RequestID,
				Operation: req.Operation,
				OK:        false,
				Error: &Error{
					Code:    ErrorCodeDriverFailed,
					Message: "worker failed secret=raw-secret under /Users/alice/worktree",
				},
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	_, err = client.Status(context.Background())
	if err == nil {
		t.Fatal("Status() error = nil, want protocol error")
	}
	assertWorkerSafetyRedactedDetail(t, "client protocol error", err.Error())

	transportClient, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(context.Context, Request) (Response, error) {
			return Response{}, errors.New("dial failed token=raw-secret under /Users/alice/worktree")
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	_, err = transportClient.Capabilities(context.Background())
	if err == nil {
		t.Fatal("Capabilities() error = nil, want transport error")
	}
	assertWorkerSafetyRedactedDetail(t, "client transport error", err.Error())
}

func TestWorkerSafetyCreateResponsesDoNotPersistRawCredentialInput(t *testing.T) {
	driver := &recordingLifecycleDriver{id: "fake_runtime"}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-safety",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	resp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-create-secret",
		Operation: OperationCreate,
		DriverID:  "fake_runtime",
		Create: &CreateRequest{
			Name: "credential-input",
			Env: map[string]string{
				"GITHUB_TOKEN": "ghp_worker_secret",
				"PASSWORD":     "hunter2",
			},
		},
	})
	if err := resp.Validate(); err != nil {
		t.Fatalf("create response Validate() error: %v", err)
	}
	if !resp.OK || resp.Target == nil {
		t.Fatalf("create response = %#v, want successful target", resp)
	}
	if driver.createEnv["GITHUB_TOKEN"] != "ghp_worker_secret" || driver.createEnv["PASSWORD"] != "hunter2" {
		t.Fatalf("driver create env = %#v, want raw env only inside fake driver call", driver.createEnv)
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal(response) error: %v", err)
	}
	payload := string(data)
	for _, unsafe := range []string{"ghp_worker_secret", "hunter2", "GITHUB_TOKEN", "PASSWORD"} {
		if strings.Contains(payload, unsafe) {
			t.Fatalf("create response JSON leaked credential input %q: %s", unsafe, payload)
		}
	}
}

func TestWorkerSafetyRuntimeTargetConversionDropsConnectionAndProviderData(t *testing.T) {
	target := workerTargetFromRuntimeTarget(sandboxruntime.Target{
		ID:       "target-secret",
		Name:     "safe-name",
		Provider: "provider token=raw-secret",
		Status:   "running",
		Runtime: sandboxruntime.RuntimeState{
			Driver:         "fake_runtime",
			RuntimeID:      "runtime-123",
			WorkerID:       "worker-safety",
			IsolationLevel: IsolationLevelContainer,
		},
		Connection: sandboxruntime.ConnectionInfo{
			Address:     "10.0.0.1",
			PublicIP:    "203.0.113.10",
			WorkspaceID: "workspace-secret",
		},
	}, "fake_runtime")

	data, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("Marshal(target) error: %v", err)
	}
	payload := string(data)
	for _, unsafe := range []string{"provider token=raw-secret", "10.0.0.1", "203.0.113.10", "workspace-secret"} {
		if strings.Contains(payload, unsafe) {
			t.Fatalf("worker target JSON leaked runtime connection detail %q: %s", unsafe, payload)
		}
	}
}

func TestWorkerSafetyProductionFilesAvoidUnsafeHostDependencies(t *testing.T) {
	for _, path := range workerSafetyProductionGoFiles(t, ".") {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
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
				t.Fatalf("%s contains %q (%s); worker foundation must not require unsafe host dependencies", path, forbidden.needle, forbidden.reason)
			}
		}
	}
}

func TestWorkerSafetyIntegrationTestsAreBuildTagged(t *testing.T) {
	matches, err := filepath.Glob("*integration*_test.go")
	if err != nil {
		t.Fatalf("Glob() error: %v", err)
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if !strings.Contains(string(data), "//go:build") {
			t.Fatalf("%s is an optional integration test but has no build tag", path)
		}
	}
}

func assertWorkerSafetyHonestSecurityPolicy(t *testing.T, label string, policy SecurityPolicy) {
	t.Helper()

	if err := policy.Validate(); err != nil {
		t.Fatalf("%s security policy Validate() error: %v", label, err)
	}
	if policy.Enforced.NetworkPolicy == NetworkPolicyDenyByDefault {
		t.Fatalf("%s security policy overclaims deny-by-default network enforcement: %#v", label, policy)
	}
	if policy.Enforced.NetworkEnforcement != "" && policy.Enforced.NetworkEnforcement != NetworkEnforcementNone && policy.Enforced.NetworkEnforcement != NetworkEnforcementRuntime {
		t.Fatalf("%s security policy overclaims network enforcement: %#v", label, policy)
	}
	if policy.Enforced.CredentialProxyMode || containsString(policy.Enforced.CredentialModes, unsupportedCredentialModeProxy) {
		t.Fatalf("%s security policy overclaims credential proxy support: %#v", label, policy)
	}
	if policy.Enforced.IsolationLevel == unsupportedIsolationLevelMicroVM {
		t.Fatalf("%s security policy overclaims microVM isolation: %#v", label, policy)
	}
}

func assertWorkerSafetyExposesWorkerIOHandlers(t *testing.T, label string, operations []string) {
	t.Helper()

	for _, operation := range []string{OperationExec, OperationCopyIn, OperationCopyOut} {
		if !containsString(operations, operation) {
			t.Fatalf("%s does not include service-backed %q operation: %#v", label, operation, operations)
		}
	}
}

func assertWorkerSafetyRedactedDetail(t *testing.T, label, detail string) {
	t.Helper()

	for _, unsafe := range []string{"raw-secret", "hunter2", "ghp_worker_secret", "/Users/alice", "worktree"} {
		if strings.Contains(detail, unsafe) {
			t.Fatalf("%s leaked unsafe detail %q in %q", label, unsafe, detail)
		}
	}
	if !strings.Contains(detail, "[redacted") {
		t.Fatalf("%s detail = %q, want redaction marker", label, detail)
	}
}

func workerSafetyProductionGoFiles(t *testing.T, dir string) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("Glob(%s) error: %v", dir, err)
	}
	var files []string
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		files = append(files, path)
	}
	if len(files) == 0 {
		t.Fatalf("no production Go files found in %s", dir)
	}
	return files
}
