package cmd

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/spf13/cobra"
)

func TestSandboxHostCommandScaffoldRegistered(t *testing.T) {
	host, err := commandAtPath(Root(), "sandbox", "host")
	if err != nil {
		t.Fatalf("sandbox host command missing: %v", err)
	}
	if missing := missingCommandMetadataFields(host); len(missing) > 0 {
		t.Fatalf("sandbox host missing metadata fields: %v", missing)
	}

	for _, path := range [][]string{
		{"sandbox", "host", "register"},
		{"sandbox", "host", "register", "worker"},
		{"sandbox", "host", "list"},
		{"sandbox", "host", "status"},
		{"sandbox", "host", "delete"},
	} {
		cmd, err := commandAtPath(Root(), path...)
		if err != nil {
			t.Fatalf("command path %q missing: %v", strings.Join(path, " "), err)
		}
		if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
			t.Fatalf("command %q missing metadata fields: %v", strings.Join(path, " "), missing)
		}
	}

	if _, err := commandAtPath(Root(), "sandboxd"); err != nil {
		t.Fatalf("sandboxd command missing or moved: %v", err)
	}
	if sandbox, err := commandAtPath(Root(), "sandbox"); err != nil {
		t.Fatalf("sandbox command missing: %v", err)
	} else if child := findDirectSubcommandByName(sandbox, "sandboxd"); child != nil {
		t.Fatal("sandboxd should remain a top-level command, not a hal sandbox subcommand")
	}

	for _, subcommand := range []string{"setup", "auth", "create", "start", "stop", "status", "delete", "ssh", "host"} {
		if _, err := commandAtPath(Root(), "sandbox", subcommand); err != nil {
			t.Fatalf("sandbox subcommand %q disrupted: %v", subcommand, err)
		}
	}
}

func TestSandboxHostHelpListsScaffoldSubcommands(t *testing.T) {
	cmd := newSandboxHostCommand(sandboxHostDeps{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandbox host --help error: %v", err)
	}

	help := stdout.String()
	for _, want := range []string{"register", "list", "status", "delete"} {
		if !strings.Contains(help, want) {
			t.Fatalf("sandbox host help = %q, want subcommand %q", help, want)
		}
	}
}

func TestSandboxHostRegisterWorkerOfflinePersistsConservativeHost(t *testing.T) {
	setSandboxHostRegistryHome(t)
	cmd, stdout, stderr := newTestSandboxHostCommand(defaultSandboxHostDeps())
	cmd.SetArgs([]string{"register", "worker", "local-worker", "--socket", "/tmp/hal-sandboxd.sock"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	loaded, err := sandbox.LoadHost("local-worker")
	if err != nil {
		t.Fatalf("LoadHost() error = %v", err)
	}
	if loaded.ID != "local-worker" || loaded.Name != "local-worker" || loaded.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("loaded host identity = %#v, want worker host using CLI id", loaded)
	}
	if loaded.Endpoint != "unix:///tmp/hal-sandboxd.sock" {
		t.Fatalf("loaded endpoint = %q, want unix socket endpoint", loaded.Endpoint)
	}
	if loaded.Health == nil || loaded.Health.Status != sandboxworker.HealthStatusUnknown {
		t.Fatalf("loaded health = %#v, want unknown cached health", loaded.Health)
	}
	if len(loaded.SupportedRuntimes) != 0 {
		t.Fatalf("supported runtimes = %#v, want none for offline registration", loaded.SupportedRuntimes)
	}
	if loaded.Capacity != nil {
		t.Fatalf("capacity = %#v, want nil for offline registration", loaded.Capacity)
	}
	if loaded.Security != nil {
		t.Fatalf("security = %#v, want nil for offline registration", loaded.Security)
	}

	output := stdout.String()
	if !strings.Contains(output, "Registered worker host local-worker") {
		t.Fatalf("stdout = %q, want registration confirmation", output)
	}
	if !strings.Contains(output, "local Unix socket") {
		t.Fatalf("stdout = %q, want safe endpoint summary", output)
	}
	if strings.Contains(output, "/tmp/hal-sandboxd.sock") {
		t.Fatalf("stdout should not expose raw socket path: %q", output)
	}
}

func TestSandboxHostRegisterWorkerOfflineRequiresIDAndSocket(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantDetail string
	}{
		{
			name:       "missing id",
			args:       []string{"register", "worker", "--socket", "/tmp/hal-sandboxd.sock"},
			wantDetail: "accepts 1 arg(s), received 0",
		},
		{
			name:       "blank id",
			args:       []string{"register", "worker", "   ", "--socket", "/tmp/hal-sandboxd.sock"},
			wantDetail: "worker id is required",
		},
		{
			name:       "missing socket",
			args:       []string{"register", "worker", "local-worker"},
			wantDetail: "worker socket path is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setSandboxHostRegistryHome(t)
			cmd, _, stderr := newTestSandboxHostCommand(defaultSandboxHostDeps())
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Execute() error = nil, want validation error")
			}
			detail := err.Error() + "\n" + stderr.String()
			if !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("error/stderr = %q, want %q", detail, tt.wantDetail)
			}
			if _, loadErr := sandbox.LoadHost("local-worker"); loadErr == nil || !errors.Is(loadErr, fs.ErrNotExist) {
				t.Fatalf("LoadHost(local-worker) error = %v, want fs.ErrNotExist", loadErr)
			}
		})
	}
}

func TestSandboxHostRegisterWorkerOfflineDuplicateDoesNotOverwrite(t *testing.T) {
	setSandboxHostRegistryHome(t)
	original := &sandbox.SandboxHost{
		ID:       "local-worker",
		Name:     "existing-worker",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "unix:///tmp/original.sock",
	}
	if err := sandbox.SaveHost(original); err != nil {
		t.Fatalf("SaveHost(seed) error = %v", err)
	}

	cmd, _, stderr := newTestSandboxHostCommand(defaultSandboxHostDeps())
	cmd.SetArgs([]string{"register", "worker", "local-worker", "--socket", "/tmp/replacement.sock"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want duplicate error")
	}
	if !strings.Contains(stderr.String(), `host "local-worker" already exists`) {
		t.Fatalf("stderr = %q, want duplicate host detail", stderr.String())
	}

	loaded, err := sandbox.LoadHost("local-worker")
	if err != nil {
		t.Fatalf("LoadHost() error = %v", err)
	}
	if loaded.Name != original.Name || loaded.Endpoint != original.Endpoint {
		t.Fatalf("duplicate registration overwrote host: %#v", loaded)
	}
}

func TestSandboxHostRegisterWorkerLiveQueriesClientAndPersistsFreshMetadata(t *testing.T) {
	setSandboxHostRegistryHome(t)
	checkedAt := time.Date(2026, 7, 1, 10, 15, 0, 0, time.UTC)
	fakeClient := &fakeSandboxHostWorkerClient{
		status: &sandboxworker.Status{
			WorkerID:   "local-worker",
			HostKind:   sandboxworker.HostKindLocal,
			SocketPath: "/tmp/reported-sandboxd.sock",
			SupportedRuntimeDrivers: []string{
				sandboxworker.RuntimeDriverSSHMachine,
			},
			Health: sandboxworker.WorkerHealth{
				Status:  sandboxworker.HealthStatusHealthy,
				Message: "ready",
			},
			Capacity: sandboxworker.WorkerCapacity{
				MaxConcurrentSandboxes: 3,
				ActiveSandboxes:        1,
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		},
		capabilities: &sandboxworker.Capabilities{
			WorkerID: "local-worker",
			SupportedOperations: []string{
				sandboxworker.OperationStatus,
				sandboxworker.OperationCapabilities,
			},
			RuntimeDrivers: []sandboxworker.RuntimeDriver{
				{
					ID:             sandboxworker.RuntimeDriverRootlessPodman,
					HostKind:       sandboxworker.HostKindLocal,
					IsolationLevel: sandboxworker.IsolationLevelContainer,
					Security:       sandboxworker.DefaultWorkerSecurityPolicy(),
				},
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		},
	}

	var clientSockets []string
	deps := defaultSandboxHostDeps()
	deps.newWorkerClient = func(socketPath string) (sandboxHostWorkerClient, error) {
		clientSockets = append(clientSockets, socketPath)
		return fakeClient, nil
	}
	deps.now = func() time.Time { return checkedAt }

	cmd, stdout, stderr := newTestSandboxHostCommand(deps)
	cmd.SetArgs([]string{"register", "worker", "local-worker", "--socket", "/tmp/live-sandboxd.sock", "--live"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	if len(clientSockets) != 1 || clientSockets[0] != "/tmp/live-sandboxd.sock" {
		t.Fatalf("worker client sockets = %#v, want requested socket path", clientSockets)
	}
	if fakeClient.statusCalls != 1 || fakeClient.capabilitiesCalls != 1 {
		t.Fatalf("worker client calls status=%d capabilities=%d, want one each", fakeClient.statusCalls, fakeClient.capabilitiesCalls)
	}

	loaded, err := sandbox.LoadHost("local-worker")
	if err != nil {
		t.Fatalf("LoadHost() error = %v", err)
	}
	if loaded.Kind != sandbox.SandboxHostKindWorker || loaded.Endpoint != "unix:///tmp/live-sandboxd.sock" {
		t.Fatalf("loaded host = %#v, want worker host with requested socket endpoint", loaded)
	}
	if loaded.Health == nil || loaded.Health.Status != sandboxworker.HealthStatusHealthy || loaded.Health.Message != "ready" || !loaded.Health.CheckedAt.Equal(checkedAt) {
		t.Fatalf("loaded health = %#v, want live checked worker health", loaded.Health)
	}
	if loaded.Capacity == nil || loaded.Capacity.MaxConcurrentSandboxes != 3 {
		t.Fatalf("loaded capacity = %#v, want worker-reported max capacity", loaded.Capacity)
	}
	if len(loaded.SupportedRuntimes) != 1 || loaded.SupportedRuntimes[0] != sandboxworker.RuntimeDriverRootlessPodman {
		t.Fatalf("supported runtimes = %#v, want capability-reported runtime only", loaded.SupportedRuntimes)
	}
	if loaded.Security == nil || loaded.Security.Network == nil || loaded.Security.Secrets == nil {
		t.Fatalf("security = %#v, want live worker security summary", loaded.Security)
	}

	output := stdout.String()
	if !strings.Contains(output, "Registered worker host local-worker") || !strings.Contains(output, "live") {
		t.Fatalf("stdout = %q, want live registration confirmation", output)
	}
	if strings.Contains(output, "/tmp/live-sandboxd.sock") || strings.Contains(output, "/tmp/reported-sandboxd.sock") {
		t.Fatalf("stdout should not expose raw socket paths: %q", output)
	}
}

func TestSandboxHostRegisterWorkerLiveFailureDoesNotPersistAndSanitizesDetail(t *testing.T) {
	setSandboxHostRegistryHome(t)
	fakeClient := &fakeSandboxHostWorkerClient{
		statusErr: errors.New("dial /tmp/private/hal-sandboxd.sock failed token=supersecret"),
	}
	deps := defaultSandboxHostDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		return fakeClient, nil
	}

	cmd, _, stderr := newTestSandboxHostCommand(deps)
	cmd.SetArgs([]string{"register", "worker", "local-worker", "--socket", "/tmp/live-sandboxd.sock", "--live"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want live worker error")
	}

	detail := err.Error() + "\n" + stderr.String()
	for _, leaked := range []string{"/tmp/private/hal-sandboxd.sock", "supersecret"} {
		if strings.Contains(detail, leaked) {
			t.Fatalf("live failure detail leaked %q: %q", leaked, detail)
		}
	}
	for _, want := range []string{"[redacted-path]", "token=[redacted]"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("live failure detail = %q, want sanitized marker %q", detail, want)
		}
	}
	if _, loadErr := sandbox.LoadHost("local-worker"); loadErr == nil || !errors.Is(loadErr, fs.ErrNotExist) {
		t.Fatalf("LoadHost(local-worker) error = %v, want fs.ErrNotExist after failed live registration", loadErr)
	}
	if fakeClient.capabilitiesCalls != 0 {
		t.Fatalf("capabilities calls = %d, want status failure to stop before capabilities", fakeClient.capabilitiesCalls)
	}
}

func TestSandboxHostListEmptyRegistry(t *testing.T) {
	setSandboxHostRegistryHome(t)
	deps := defaultSandboxHostDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("sandbox host list should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxHostCommand(deps)
	cmd.SetArgs([]string{"list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	if got, want := stdout.String(), "No sandbox hosts registered.\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestSandboxHostListHumanOutputStableAndSafe(t *testing.T) {
	setSandboxHostRegistryHome(t)
	checkedAt := time.Date(2026, 7, 1, 12, 30, 0, 0, time.UTC)
	for _, host := range []*sandbox.SandboxHost{
		{
			ID:       "worker-b",
			Name:     "builder",
			Kind:     sandbox.SandboxHostKindWorker,
			Endpoint: "unix:///tmp/private/worker-b.sock",
			Health:   &sandbox.HostHealth{Status: sandboxworker.HealthStatusUnknown},
		},
		{
			ID:                "ssh-1",
			Name:              "zeta",
			Kind:              sandbox.SandboxHostKindSSH,
			Endpoint:          "ssh://deploy:secret@example.com:22/workspace?token=supersecret",
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
			Capacity:          &sandbox.HostCapacity{CPUCores: 4, MemoryMB: 8192, DiskGB: 80},
			Health:            &sandbox.HostHealth{Status: "degraded", CheckedAt: checkedAt},
		},
		{
			ID:                "worker-a",
			Name:              "builder",
			Kind:              sandbox.SandboxHostKindWorker,
			Endpoint:          "unix:///tmp/private/worker-a.sock",
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman, sandbox.SandboxRuntimeDriverSSHMachine},
			Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
			Health:            &sandbox.HostHealth{Status: sandboxworker.HealthStatusHealthy, CheckedAt: checkedAt},
		},
	} {
		if err := sandbox.SaveHost(host); err != nil {
			t.Fatalf("SaveHost(%q) error = %v", host.ID, err)
		}
	}

	deps := defaultSandboxHostDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("sandbox host list should not contact worker daemons")
		return nil, nil
	}
	cmd, stdout, stderr := newTestSandboxHostCommand(deps)
	cmd.SetArgs([]string{"list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	output := stdout.String()
	for _, want := range []string{
		"Sandbox hosts (sorted by name, then id):",
		"NAME", "ID", "KIND", "ENDPOINT", "HEALTH", "RUNTIMES", "CAPACITY",
		"builder", "worker-a", "worker-b", "zeta", "ssh-1",
		sandbox.SandboxHostKindWorker, sandbox.SandboxHostKindSSH,
		"local Unix socket", "ssh endpoint",
		sandboxworker.HealthStatusHealthy, sandboxworker.HealthStatusUnknown, "degraded",
		"rootless_podman,ssh_machine", "max 2 sandboxes", "4 CPU, 8192 MiB, 80 GiB disk",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %q", output, want)
		}
	}

	workerAIndex := strings.Index(output, "worker-a")
	workerBIndex := strings.Index(output, "worker-b")
	sshIndex := strings.Index(output, "ssh-1")
	if workerAIndex == -1 || workerBIndex == -1 || sshIndex == -1 {
		t.Fatalf("stdout = %q, want all host ids", output)
	}
	if !(workerAIndex < workerBIndex && workerBIndex < sshIndex) {
		t.Fatalf("host order in stdout = %q, want name then id order", output)
	}
	for _, leaked := range []string{"/tmp/private", "deploy:secret", "example.com", "token=supersecret"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("stdout leaked endpoint detail %q: %q", leaked, output)
		}
	}
}

func newTestSandboxHostCommand(deps sandboxHostDeps) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	cmd := newSandboxHostCommand(deps)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	return cmd, &stdout, &stderr
}

func setSandboxHostRegistryHome(t *testing.T) {
	t.Helper()
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())
}

type fakeSandboxHostWorkerClient struct {
	status      *sandboxworker.Status
	statusErr   error
	statusCalls int

	capabilities      *sandboxworker.Capabilities
	capabilitiesErr   error
	capabilitiesCalls int
}

func (client *fakeSandboxHostWorkerClient) Status(context.Context) (*sandboxworker.Status, error) {
	client.statusCalls++
	if client.statusErr != nil {
		return nil, client.statusErr
	}
	return client.status, nil
}

func (client *fakeSandboxHostWorkerClient) Capabilities(context.Context) (*sandboxworker.Capabilities, error) {
	client.capabilitiesCalls++
	if client.capabilitiesErr != nil {
		return nil, client.capabilitiesErr
	}
	return client.capabilities, nil
}
