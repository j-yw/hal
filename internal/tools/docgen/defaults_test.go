package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	halcmd "github.com/jywlabs/hal/cmd"
	"github.com/spf13/cobra"
)

func TestRunSandboxdDocumentationDefaultsArePortable(t *testing.T) {
	for _, format := range []string{formatMarkdown, formatMan, formatReST} {
		t.Run(format, func(t *testing.T) {
			var first string
			for _, runtimeDir := range []string{
				"/run/user/1000/hal-sd",
				"/run/user/1001/hal-sd",
				"/custom/xdg-runtime/hal-sd",
				"/home/operator/tmp/hal-sd-2000",
				"/tmp/hal-sd-3000",
			} {
				root, daemon := newSandboxdDocumentationFixture(runtimeDir)
				// An explicit runtime value must not be replaced by a display default.
				if err := daemon.Flags().Set("socket", "/explicit/worker.sock"); err != nil {
					t.Fatal(err)
				}
				checkUnchanged := snapshotSandboxdDocumentationCommand(daemon)
				outDir := t.TempDir()
				if err := run([]string{"-out", outDir, "-format", format}, root); err != nil {
					t.Fatal(err)
				}
				checkUnchanged(t)
				data, err := os.ReadFile(filepath.Join(outDir, sandboxdDocumentationFilename(format)))
				if err != nil {
					t.Fatal(err)
				}
				content := string(data)
				if strings.Contains(content, runtimeDir) {
					t.Errorf("%s docs contain host-specific runtime directory %q", format, runtimeDir)
				}
				for _, want := range []string{"<runtime-dir>", "XDG_RUNTIME_DIR", "hal-sandboxd.sock", "jobs"} {
					if !strings.Contains(content, want) {
						t.Errorf("%s docs omit portable default explanation %q", format, want)
					}
				}
				if first == "" {
					first = content
				} else if content != first {
					t.Errorf("%s docs differ for runtime directory %q", format, runtimeDir)
				}
			}
		})
	}
}

func TestRunSandboxdDocumentationRestoresDefaultsAfterError(t *testing.T) {
	for _, format := range []string{formatMarkdown, formatMan, formatReST} {
		t.Run(format, func(t *testing.T) {
			root, daemon := newSandboxdDocumentationFixture("/run/user/1001/hal-sd")
			checkUnchanged := snapshotSandboxdDocumentationCommand(daemon)
			outDir := t.TempDir()
			if err := os.Mkdir(filepath.Join(outDir, sandboxdDocumentationFilename(format)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := run([]string{"-out", outDir, "-format", format}, root); err == nil {
				t.Fatal("expected generation failure for directory in place of output file")
			}
			checkUnchanged(t)
		})
	}
}

func TestRunPreservesRealSandboxdRuntimeDefaults(t *testing.T) {
	root := halcmd.Root()
	daemon, _, err := root.Find([]string{"sandboxd"})
	if err != nil || daemon == root {
		t.Fatalf("find real sandboxd command: %v", err)
	}
	checkUnchanged := snapshotSandboxdDocumentationCommand(daemon)
	if err := run([]string{"-out", t.TempDir()}, root); err != nil {
		t.Fatal(err)
	}
	checkUnchanged(t)
}

func newSandboxdDocumentationFixture(runtimeDir string) (*cobra.Command, *cobra.Command) {
	root := newTestRootCommand()
	daemon := &cobra.Command{
		Use: "sandboxd", Short: "Start a worker", Long: "Worker documentation fixture.",
		Run: func(*cobra.Command, []string) {},
	}
	daemon.Flags().String("socket", runtimeDir+"/hal-sandboxd.sock", "worker socket")
	daemon.Flags().String("job-state-dir", runtimeDir+"/jobs", "worker state")
	daemon.Flags().String("unrelated", "unchanged", "unrelated default")
	root.AddCommand(daemon)
	return root, daemon
}

func snapshotSandboxdDocumentationCommand(command *cobra.Command) func(*testing.T) {
	type state struct {
		name, defaultValue, value string
		changed                   bool
	}
	var states []state
	for _, name := range []string{"socket", "job-state-dir", "unrelated"} {
		if flag := command.Flags().Lookup(name); flag != nil {
			states = append(states, state{name, flag.DefValue, flag.Value.String(), flag.Changed})
		}
	}
	long := command.Long
	return func(t *testing.T) {
		t.Helper()
		if command.Long != long {
			t.Error("documentation generation changed the runtime command description")
		}
		for _, before := range states {
			flag := command.Flags().Lookup(before.name)
			if flag.DefValue != before.defaultValue || flag.Value.String() != before.value || flag.Changed != before.changed {
				t.Errorf("documentation generation changed runtime flag %q", before.name)
			}
		}
	}
}

func sandboxdDocumentationFilename(format string) string {
	switch format {
	case formatMan:
		return "hal-sandboxd.1"
	case formatReST:
		return "hal_sandboxd.rst"
	default:
		return "hal_sandboxd.md"
	}
}
