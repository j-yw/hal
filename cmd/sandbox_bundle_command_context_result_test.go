package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/template"
)

func TestPrepareSandboxCommandContextRuntimeRequiresCompletedResult(t *testing.T) {
	transportErr := errors.New("command transport unavailable")
	for _, phase := range []string{"install", "reset", "init"} {
		for _, outcome := range []struct {
			name   string
			result *sandboxruntime.ExecResult
			err    error
		}{
			{name: "missing_result"},
			{name: "nonzero", result: &sandboxruntime.ExecResult{ExitCode: 9}},
			{name: "transport_with_zero_result", result: &sandboxruntime.ExecResult{}, err: transportErr},
			{name: "completed", result: &sandboxruntime.ExecResult{}},
		} {
			t.Run(phase+"/"+outcome.name, func(t *testing.T) {
				project := t.TempDir()
				halDir := filepath.Join(project, template.HalDir)
				if err := os.Mkdir(halDir, 0700); err != nil {
					t.Fatal(err)
				}
				const canary = "command-context-private-fixture-value"
				if err := os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\nfixture: "+canary+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				var events []string
				injected := false
				driver := fakeRunSandboxRuntimeDriver{
					copyIn: func(context.Context, sandboxruntime.CopyRequest) error { return nil },
					exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
						if len(req.Args) == 3 && req.Args[0] == "rm" && req.Args[1] == "-f" {
							events = append(events, "cleanup")
							return &sandboxruntime.ExecResult{}, nil
						}
						if len(req.Args) != 3 || req.Args[0] != "sh" || req.Args[1] != "-c" {
							t.Fatal("unexpected command context operation")
						}
						operation := "reset"
						if strings.Contains(req.Args[2], "exec hal init") {
							operation = "init"
						} else if strings.Contains(req.Args[2], "source_tmp=") {
							operation = "install"
						}
						events = append(events, operation)
						if operation == phase && !injected {
							injected = true
							return outcome.result, outcome.err
						}
						return &sandboxruntime.ExecResult{}, nil
					},
				}
				op, err := prepareSandboxCommandContextRuntime(context.Background(), sandboxexecPrepareContext(driver), project, "/workspace/result-fixture", io.Discard)
				if !injected {
					t.Fatal("failure boundary was not exercised")
				}
				if outcome.name == "completed" {
					if err != nil || op.Phase != sandboxworkspace.MaterializationPhaseCommandConfig || len(events) != 7 || events[6] != "init" {
						t.Fatalf("completed preparation failed: %v, events=%v", err, events)
					}
					return
				}
				if err == nil || op.Phase != "" || op.Summary != "" {
					t.Fatalf("incomplete execution accepted: error=%v phase=%q events=%v", err, op.Phase, events)
				}
				if outcome.err != nil && !errors.Is(err, outcome.err) {
					t.Fatal("transport cause was not preserved")
				}
				if strings.Contains(err.Error(), project) || strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "/workspace/result-fixture") {
					t.Fatal("command-context failure exposed fixture path or contents")
				}
				want := []string{"install", "reset", "reset", "reset", "reset", "reset", "init"}
				if phase == "install" {
					want = []string{"install", "cleanup"}
				} else if phase == "reset" {
					want = []string{"install", "reset"}
				}
				if !reflect.DeepEqual(events, want) {
					t.Fatalf("preparation continued after failure: got=%v want=%v", events, want)
				}
			})
		}
	}
}
