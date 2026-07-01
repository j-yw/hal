package cmd

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"

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
