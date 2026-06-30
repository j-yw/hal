package rootlesspodman_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

var _ sandboxruntime.FileTransport = (*rootlesspodman.Driver)(nil)

func TestCopyCommandsUseFakeRunnerAndPodmanCPArgs(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{CopyRunner: runner})
	target := sandboxruntime.Target{
		ID:   "container-id",
		Name: "hal-dev",
		Runtime: sandboxruntime.RuntimeState{
			RuntimeID: "runtime-id",
		},
	}
	localSource := filepath.Join(t.TempDir(), "input with spaces.txt")
	containerDestination := "/workspace/project/input with spaces.txt"
	containerSource := "/workspace/project/output.txt"
	localDestination := filepath.Join(t.TempDir(), "nested", "output.txt")

	if err := driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
		Target:          target,
		SourcePath:      localSource,
		DestinationPath: containerDestination,
	}); err != nil {
		t.Fatalf("CopyIn() unexpected error: %v", err)
	}
	if err := driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
		Target:          target,
		SourcePath:      containerSource,
		DestinationPath: localDestination,
	}); err != nil {
		t.Fatalf("CopyOut() unexpected error: %v", err)
	}

	wantOperations := []string{
		rootlesspodman.OperationCopyIn,
		rootlesspodman.OperationCopyOut,
	}
	if got := runner.copyOperations(); !reflect.DeepEqual(got, wantOperations) {
		t.Fatalf("copy operations = %#v, want %#v", got, wantOperations)
	}
	wantArgsByOperation := map[string][]string{
		rootlesspodman.OperationCopyIn:  {"podman", "cp", localSource, "runtime-id:" + containerDestination},
		rootlesspodman.OperationCopyOut: {"podman", "cp", "runtime-id:" + containerSource, localDestination},
	}
	for _, req := range runner.copyRequests {
		if !reflect.DeepEqual(req.Args, wantArgsByOperation[req.Operation]) {
			t.Fatalf("%s args = %#v, want %#v", req.Operation, req.Args, wantArgsByOperation[req.Operation])
		}
	}
}

func TestCopyOutDoesNotMutateUnrelatedHostFiles(t *testing.T) {
	tempDir := t.TempDir()
	unrelatedPath := filepath.Join(tempDir, "unrelated.txt")
	if err := os.WriteFile(unrelatedPath, []byte("keep me"), 0o644); err != nil {
		t.Fatalf("write unrelated file: %v", err)
	}
	destinationPath := filepath.Join(tempDir, "output.txt")
	runner := &fakeCommandRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{CopyRunner: runner})

	err := driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
		Target:          sandboxruntime.Target{Name: "hal-dev"},
		SourcePath:      "/workspace/project/output.txt",
		DestinationPath: destinationPath,
	})
	if err != nil {
		t.Fatalf("CopyOut() unexpected error: %v", err)
	}

	content, err := os.ReadFile(unrelatedPath)
	if err != nil {
		t.Fatalf("read unrelated file: %v", err)
	}
	if string(content) != "keep me" {
		t.Fatalf("unrelated file content = %q, want unchanged", content)
	}
	if _, err := os.Stat(destinationPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination file was mutated by fake CopyOut, stat error = %v", err)
	}
}

func TestCopyFailuresWrapOperationWithSanitizedOutput(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "input.txt")
	runnerErr := errors.New("podman cp failed from " + sourcePath + " token=raw-secret")
	runner := &fakeCommandRunner{
		resultByOperation: map[string]rootlesspodman.CommandResult{
			rootlesspodman.OperationCopyIn: {
				ExitCode: 125,
				Stdout:   "source " + sourcePath + "\n",
				Stderr:   "refusing /var/run/docker.sock token=abcd1234\n",
			},
		},
		errByOperation: map[string]error{
			rootlesspodman.OperationCopyIn: runnerErr,
		},
	}
	driver := rootlesspodman.New(rootlesspodman.Options{CopyRunner: runner})

	err := driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
		Target:          sandboxruntime.Target{Name: "hal-dev"},
		SourcePath:      sourcePath,
		DestinationPath: "/workspace/project/input.txt",
	})
	if err == nil {
		t.Fatal("CopyIn() expected error, got nil")
	}
	if !errors.Is(err, runnerErr) {
		t.Fatalf("errors.Is(%v, runnerErr) = false, want true", err)
	}
	var opErr *rootlesspodman.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("errors.As(%T) = false, want true", opErr)
	}
	if opErr.Driver != sandboxruntime.DriverRootlessPodman || opErr.Operation != rootlesspodman.OperationCopyIn || opErr.ExitCode != 125 {
		t.Fatalf("OperationError = %#v, want rootless copy_in exit 125", opErr)
	}
	message := err.Error()
	for _, unsafe := range []string{sourcePath, "/var/run/docker.sock", "raw-secret", "abcd1234"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("error message %q contains unsafe detail %q", message, unsafe)
		}
	}
	for _, want := range []string{sandboxruntime.DriverRootlessPodman, rootlesspodman.OperationCopyIn, "[redacted-path]", "[redacted-docker-socket]", "token=[redacted]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error message %q does not include sanitized detail %q", message, want)
		}
	}
}

func TestCopyRejectsMissingRunnerAndPaths(t *testing.T) {
	driver := rootlesspodman.New(rootlesspodman.Options{})
	if err := driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
		Target:          sandboxruntime.Target{Name: "hal-dev"},
		SourcePath:      "/tmp/input.txt",
		DestinationPath: "/workspace/input.txt",
	}); !errors.Is(err, rootlesspodman.ErrCopyRunnerRequired) {
		t.Fatalf("CopyIn() error = %v, want ErrCopyRunnerRequired", err)
	}

	driver = rootlesspodman.New(rootlesspodman.Options{CopyRunner: &fakeCommandRunner{}})
	for _, tt := range []struct {
		name string
		req  sandboxruntime.CopyRequest
		want error
	}{
		{
			name: "missing source",
			req: sandboxruntime.CopyRequest{
				Target:          sandboxruntime.Target{Name: "hal-dev"},
				DestinationPath: "/workspace/input.txt",
			},
			want: rootlesspodman.ErrCopySourcePathRequired,
		},
		{
			name: "missing destination",
			req: sandboxruntime.CopyRequest{
				Target:     sandboxruntime.Target{Name: "hal-dev"},
				SourcePath: "/tmp/input.txt",
			},
			want: rootlesspodman.ErrCopyDestinationPathRequired,
		},
		{
			name: "missing target reference",
			req: sandboxruntime.CopyRequest{
				SourcePath:      "/tmp/input.txt",
				DestinationPath: "/workspace/input.txt",
			},
			want: rootlesspodman.ErrTargetRefRequired,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := driver.CopyIn(context.Background(), tt.req); !errors.Is(err, tt.want) {
				t.Fatalf("CopyIn() error = %v, want %v", err, tt.want)
			}
		})
	}
}
