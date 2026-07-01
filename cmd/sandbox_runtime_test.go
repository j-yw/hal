package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSandboxRuntimeCommandScaffoldRegistered(t *testing.T) {
	runtime, err := commandAtPath(Root(), "sandbox", "runtime")
	if err != nil {
		t.Fatalf("sandbox runtime command missing: %v", err)
	}
	if missing := missingCommandMetadataFields(runtime); len(missing) > 0 {
		t.Fatalf("sandbox runtime missing metadata fields: %v", missing)
	}

	for _, path := range [][]string{
		{"sandbox", "runtime", "list"},
		{"sandbox", "runtime", "status"},
	} {
		cmd, err := commandAtPath(Root(), path...)
		if err != nil {
			t.Fatalf("command path %q missing: %v", strings.Join(path, " "), err)
		}
		if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
			t.Fatalf("command %q missing metadata fields: %v", strings.Join(path, " "), missing)
		}
		if !strings.Contains(cmd.Example, commandPathLabel(cmd)) {
			t.Fatalf("command %q example must include full command path, got %q", commandPathLabel(cmd), cmd.Example)
		}
		for _, flagName := range []string{"json", "live"} {
			if cmd.Flags().Lookup(flagName) == nil {
				t.Fatalf("command %q missing --%s flag", commandPathLabel(cmd), flagName)
			}
		}
	}
}

func TestSandboxRuntimeHelpListsScaffoldSubcommands(t *testing.T) {
	cmd := newSandboxRuntimeCommand(sandboxRuntimeDeps{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandbox runtime --help error: %v", err)
	}

	help := stdout.String()
	for _, want := range []string{"list", "status"} {
		if !strings.Contains(help, want) {
			t.Fatalf("sandbox runtime help = %q, want subcommand %q", help, want)
		}
	}
}

func TestSandboxRuntimeCommandsUseInjectedDependencies(t *testing.T) {
	var gotList sandboxRuntimeListRequest
	var gotStatus sandboxRuntimeStatusRequest
	deps := sandboxRuntimeDeps{
		list: func(_ context.Context, req sandboxRuntimeListRequest, out io.Writer) error {
			gotList = req
			_, err := out.Write([]byte("list ok\n"))
			return err
		},
		status: func(_ context.Context, req sandboxRuntimeStatusRequest, out io.Writer) error {
			gotStatus = req
			_, err := out.Write([]byte("status ok\n"))
			return err
		},
	}

	listCmd, listOut, listErr := newTestSandboxRuntimeCommand(deps)
	listCmd.SetArgs([]string{"list", "local-worker", "--live", "--json"})
	if err := listCmd.Execute(); err != nil {
		t.Fatalf("runtime list Execute() error = %v; stderr=%q", err, listErr.String())
	}
	if gotList.HostID != "local-worker" || !gotList.Live || !gotList.JSON {
		t.Fatalf("runtime list request = %#v, want host id with live/json flags", gotList)
	}
	if got := listOut.String(); got != "list ok\n" {
		t.Fatalf("runtime list stdout = %q", got)
	}

	statusCmd, statusOut, statusErr := newTestSandboxRuntimeCommand(deps)
	statusCmd.SetArgs([]string{"status", "local-worker", "rootless_podman", "--live", "--json"})
	if err := statusCmd.Execute(); err != nil {
		t.Fatalf("runtime status Execute() error = %v; stderr=%q", err, statusErr.String())
	}
	if gotStatus.HostID != "local-worker" || gotStatus.RuntimeID != "rootless_podman" || !gotStatus.Live || !gotStatus.JSON {
		t.Fatalf("runtime status request = %#v, want host/runtime ids with live/json flags", gotStatus)
	}
	if got := statusOut.String(); got != "status ok\n" {
		t.Fatalf("runtime status stdout = %q", got)
	}
}

func TestSandboxRuntimeGeneratedCLIReferenceLinks(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		wantFragments []string
	}{
		{
			name: "sandbox cli reference links runtime command",
			path: filepath.Join("..", "docs", "cli", "hal_sandbox.md"),
			wantFragments: []string{
				"[hal sandbox runtime](hal_sandbox_runtime.md)",
			},
		},
		{
			name: "runtime cli reference links subcommands",
			path: filepath.Join("..", "docs", "cli", "hal_sandbox_runtime.md"),
			wantFragments: []string{
				"hal sandbox runtime list local-worker",
				"[hal sandbox runtime list](hal_sandbox_runtime_list.md)",
				"[hal sandbox runtime status](hal_sandbox_runtime_status.md)",
			},
		},
		{
			name: "runtime list cli reference links parent",
			path: filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_list.md"),
			wantFragments: []string{
				SandboxRuntimeListContractVersion,
				"[hal sandbox runtime](hal_sandbox_runtime.md)",
			},
		},
		{
			name: "runtime status cli reference links parent",
			path: filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_status.md"),
			wantFragments: []string{
				SandboxRuntimeStatusContractVersion,
				"[hal sandbox runtime](hal_sandbox_runtime.md)",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("ReadFile(%q) error: %v", tt.path, err)
			}
			text := string(data)
			for _, fragment := range tt.wantFragments {
				if !strings.Contains(text, fragment) {
					t.Fatalf("%s missing %q", tt.path, fragment)
				}
			}
		})
	}
}

func newTestSandboxRuntimeCommand(deps sandboxRuntimeDeps) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	cmd := newSandboxRuntimeCommand(deps)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	return cmd, &stdout, &stderr
}
