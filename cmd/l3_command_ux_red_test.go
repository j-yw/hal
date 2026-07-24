package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	l3StatusContractVersion = "sandbox-status-v1"
	l3ListContractVersion   = "sandbox-list-v2"
)

func TestL3SandboxCommandSurface(t *testing.T) {
	tests := []struct {
		name             string
		usePrefix        string
		requiredFlags    []string
		forbiddenFlags   []string
		requiredExamples []string
	}{
		{
			name:           "status",
			usePrefix:      "status ",
			requiredFlags:  []string{"live", "json"},
			forbiddenFlags: []string{"run", "follow"},
			requiredExamples: []string{
				"hal sandbox status NAME --live --json",
			},
		},
		{
			name:           "logs",
			usePrefix:      "logs NAME",
			requiredFlags:  []string{"run", "follow"},
			forbiddenFlags: []string{"live", "json"},
			requiredExamples: []string{
				"hal sandbox logs NAME",
				"hal sandbox logs NAME --run RUN_ID",
				"hal sandbox logs NAME --follow",
			},
		},
		{
			name:           "recover",
			usePrefix:      "recover NAME",
			requiredFlags:  []string{"run"},
			forbiddenFlags: []string{"live", "json", "follow"},
			requiredExamples: []string{
				"hal sandbox recover NAME",
				"hal sandbox recover NAME --run RUN_ID",
			},
		},
		{
			name:           "sync-out",
			usePrefix:      "sync-out NAME",
			requiredFlags:  []string{"run"},
			forbiddenFlags: []string{"live", "json", "follow", "apply"},
			requiredExamples: []string{
				"hal sandbox sync-out NAME",
				"hal sandbox sync-out NAME --run RUN_ID",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := l3SandboxLeaf(tt.name)
			if command == nil {
				t.Fatalf("hal sandbox %s is not registered", tt.name)
				return
			}
			if !strings.HasPrefix(command.Use, tt.usePrefix) {
				t.Fatalf("hal sandbox %s Use = %q, want prefix %q", tt.name, command.Use, tt.usePrefix)
			}
			if strings.TrimSpace(command.Short) == "" || strings.TrimSpace(command.Long) == "" || strings.TrimSpace(command.Example) == "" {
				t.Fatalf("hal sandbox %s must define Use, Short, Long, and Example metadata", tt.name)
			}
			for _, flag := range tt.requiredFlags {
				if command.Flags().Lookup(flag) == nil {
					t.Errorf("hal sandbox %s is missing --%s", tt.name, flag)
				}
			}
			for _, flag := range tt.forbiddenFlags {
				if command.Flags().Lookup(flag) != nil {
					t.Errorf("hal sandbox %s unexpectedly exposes --%s", tt.name, flag)
				}
			}
			for _, example := range tt.requiredExamples {
				if !strings.Contains(command.Example, example) {
					t.Errorf("hal sandbox %s Example missing exact command %q:\n%s", tt.name, example, command.Example)
				}
			}
		})
	}

	for _, name := range []string{"status", "logs", "recover", "sync-out"} {
		command := l3SandboxLeaf(name)
		if command == nil {
			continue
		}
		if name == "status" && command.Flags().Lookup("run") != nil {
			t.Errorf("--run belongs only to ambiguity-resolving commands, not status")
		}
	}
}

func TestL3MachineContractDocumentsAndExamples(t *testing.T) {
	tests := []struct {
		version string
		doc     string
		example string
	}{
		{
			version: l3StatusContractVersion,
			doc:     filepath.Join("..", "docs", "contracts", "sandbox-status-v1.md"),
			example: filepath.Join("..", "docs", "contracts", "examples", "sandbox-status-v1-live.json"),
		},
		{
			version: l3ListContractVersion,
			doc:     filepath.Join("..", "docs", "contracts", "sandbox-list-v2.md"),
			example: filepath.Join("..", "docs", "contracts", "examples", "sandbox-list-v2-live.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			document, err := os.ReadFile(tt.doc)
			if err != nil {
				t.Fatalf("read %s contract document: %v", tt.version, err)
			}
			if !bytes.Contains(document, []byte(tt.version)) {
				t.Errorf("%s contract document does not name its contract version", tt.version)
			}

			payload, err := os.ReadFile(tt.example)
			if err != nil {
				t.Fatalf("read %s example: %v", tt.version, err)
			}
			var raw map[string]any
			decoder := json.NewDecoder(bytes.NewReader(payload))
			if err := decoder.Decode(&raw); err != nil {
				t.Fatalf("decode %s example: %v", tt.version, err)
			}
			if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
				t.Fatalf("%s example contains trailing JSON or text: %v", tt.version, err)
			}
			if got := raw["contractVersion"]; got != tt.version {
				t.Errorf("%s example contractVersion = %v", tt.version, got)
			}
			requireL3MachinePayloadSafe(t, raw)
		})
	}
}

func TestL3CachedListStaysV1AndLiveListUsesV2(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	var cached bytes.Buffer
	if err := runSandboxListWithWriters(&cached, io.Discard, true, false); err != nil {
		t.Fatalf("cached sandbox list: %v", err)
	}
	cachedPayload := decodeL3JSONDocument(t, cached.Bytes())
	if got := cachedPayload["contractVersion"]; got != "sandbox-list-v1" {
		t.Fatalf("cached list contractVersion = %v, want sandbox-list-v1", got)
	}

	var live bytes.Buffer
	if err := runSandboxListWithWriters(&live, io.Discard, true, true); err != nil {
		t.Fatalf("live sandbox list: %v", err)
	}
	livePayload := decodeL3JSONDocument(t, live.Bytes())
	if got := livePayload["contractVersion"]; got != l3ListContractVersion {
		t.Fatalf("live list contractVersion = %v, want %s", got, l3ListContractVersion)
	}
	requireL3MachinePayloadSafe(t, livePayload)
}

func TestL3ResolverRejectsZeroMultipleAndMismatchedRuns(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	now := time.Date(2026, 7, 25, 2, 0, 0, 0, time.UTC)
	saveL3Sandbox(t, "alpha", now)
	saveL3Sandbox(t, "beta", now)

	t.Run("zero", func(t *testing.T) {
		_, _, err := runL3SandboxLeaf(context.Background(), "logs", []string{"alpha"})
		requireL3SafeErrorContains(t, err, "alpha", "execution")
	})

	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	saveL3Manifest(t, store, l3Manifest("run-alpha-a", "alpha", now, "job-alpha-a", "running", 0))
	saveL3Manifest(t, store, l3Manifest("run-alpha-b", "alpha", now.Add(time.Second), "job-alpha-b", "running", 0))

	t.Run("multiple", func(t *testing.T) {
		_, _, err := runL3SandboxLeaf(context.Background(), "logs", []string{"alpha"})
		requireL3ErrorCode(t, err, "ambiguous_run")
		if err != nil {
			message := err.Error()
			if !strings.Contains(message, "run-alpha-a") || !strings.Contains(message, "run-alpha-b") {
				t.Errorf("ambiguity error must contain only safe candidate run IDs: %v", err)
			}
		}
	})

	t.Run("explicit run belongs to another sandbox", func(t *testing.T) {
		_, _, err := runL3SandboxLeaf(context.Background(), "recover", []string{"beta", "--run", "run-alpha-a"})
		requireL3SafeErrorContains(t, err, "beta", "run-alpha-a")
	})
}

func TestL3LogsSelectsSingleRunAndDrainsTerminalCursor(t *testing.T) {
	if l3SandboxLeaf("logs") == nil {
		t.Fatal("hal sandbox logs is not registered")
	}
	harness := newL3WorkerHarness(t, &l3WorkerScript{
		jobState:  sandboxworker.JobStateSucceeded,
		logCursor: 4,
		pages: map[uint64]sandboxworker.JobLogsResponse{
			0: {
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           "job-alpha",
				Records: []sandboxworker.JobLogRecord{
					{Cursor: 2, Stream: sandboxworker.JobLogStreamStdout, Data: "hello\n", Timestamp: time.Date(2026, 7, 25, 2, 0, 1, 0, time.UTC)},
					{Cursor: 3, Stream: sandboxworker.JobLogStreamStderr, Data: "TOKEN=red-test-secret\nAuthorization: Bearer opaque-l3-header-secret\n", Timestamp: time.Date(2026, 7, 25, 2, 0, 2, 0, time.UTC)},
				},
				NextCursor:   3,
				OldestCursor: 2,
				Truncated:    true,
			},
			3: {
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           "job-alpha",
				Records: []sandboxworker.JobLogRecord{
					{Cursor: 4, Stream: sandboxworker.JobLogStreamStdout, Data: "done\n", Timestamp: time.Date(2026, 7, 25, 2, 0, 3, 0, time.UTC)},
				},
				NextCursor:   4,
				OldestCursor: 2,
			},
		},
	})
	harness.seed("alpha", "run-alpha", "job-alpha")
	manifestBefore := harness.manifestBytes()

	stdout, stderr, err := runL3SandboxLeaf(context.Background(), "logs", []string{"alpha", "--follow"})
	if err != nil {
		t.Fatalf("follow terminal logs: %v", err)
	}
	if !strings.Contains(stdout, "hello") || !strings.Contains(stdout, "done") {
		t.Errorf("follow output did not drain through terminal cursor:\n%s", stdout)
	}
	combined := stdout + "\n" + stderr
	for _, secret := range []string{"red-test-secret", "opaque-l3-header-secret"} {
		if strings.Contains(combined, secret) {
			t.Errorf("follow output leaked secret canary %q:\n%s", secret, combined)
		}
	}
	if !strings.Contains(stderr, "[redacted]") {
		t.Errorf("stderr log stream did not render a redacted record:\n%s", stderr)
	}
	if !strings.Contains(strings.ToLower(combined), "truncat") {
		t.Errorf("follow output did not render a retention-gap warning:\n%s", combined)
	}

	requests, forbidden := harness.script.snapshot()
	if got, want := l3LogRequestCursors(requests), []uint64{0, 3}; !equalL3Uint64s(got, want) {
		t.Errorf("job log cursors = %v, want terminal drain chain %v", got, want)
	}
	if len(forbidden) != 0 {
		t.Errorf("logs crossed forbidden worker boundaries: %v", forbidden)
	}
	if manifestAfter := harness.manifestBytes(); !bytes.Equal(manifestBefore, manifestAfter) {
		t.Error("viewing logs mutated the durable execution manifest")
	}
	if _, err := os.Stat(harness.hostMutationMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("logs invoked a host mutation command; marker stat error = %v", err)
	}
}

func TestL3FollowCancellationDoesNotCancelOrMutateTheJob(t *testing.T) {
	if l3SandboxLeaf("logs") == nil {
		t.Fatal("hal sandbox logs is not registered")
	}
	firstLogs := make(chan struct{}, 1)
	harness := newL3WorkerHarness(t, &l3WorkerScript{
		jobState:  sandboxworker.JobStateRunning,
		logCursor: 0,
		firstLogs: firstLogs,
		pages: map[uint64]sandboxworker.JobLogsResponse{
			0: {
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           "job-alpha",
				NextCursor:      0,
			},
		},
	})
	harness.seed("alpha", "run-alpha", "job-alpha")
	manifestBefore := harness.manifestBytes()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, _, err := runL3SandboxLeaf(ctx, "logs", []string{"alpha", "--follow"})
		result <- err
	}()

	select {
	case <-firstLogs:
		cancel()
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("follow did not request the first bounded log page")
	}

	select {
	case err := <-result:
		if err != nil && !errors.Is(err, context.Canceled) && !strings.Contains(strings.ToLower(err.Error()), "canceled") {
			t.Fatalf("follow cancellation error = %v, want nil or context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follow did not stop after context cancellation")
	}

	_, forbidden := harness.script.snapshot()
	for _, operation := range forbidden {
		if operation == sandboxworker.OperationJobCancel {
			t.Fatalf("canceling a logs follower called job_cancel")
		}
	}
	if manifestAfter := harness.manifestBytes(); !bytes.Equal(manifestBefore, manifestAfter) {
		t.Error("canceling a logs follower mutated the durable execution manifest")
	}
}

func TestL3RecoveryCommandsStayBehindObservationAndFinalizationBoundaries(t *testing.T) {
	for _, commandName := range []string{"recover", "sync-out"} {
		t.Run(commandName, func(t *testing.T) {
			if l3SandboxLeaf(commandName) == nil {
				t.Fatalf("hal sandbox %s is not registered", commandName)
			}
			harness := newL3WorkerHarness(t, &l3WorkerScript{
				jobState:  sandboxworker.JobStateSucceeded,
				logCursor: 0,
				pages: map[uint64]sandboxworker.JobLogsResponse{
					0: {
						ContractVersion: sandboxworker.JobContractVersion,
						JobID:           "job-alpha",
						NextCursor:      0,
					},
				},
			})
			harness.seed("alpha", "run-alpha", "job-alpha")

			_, _, _ = runL3SandboxLeaf(context.Background(), commandName, []string{"alpha"})
			requests, forbidden := harness.script.snapshot()
			if len(requests) == 0 {
				t.Fatalf("%s did not resolve and observe the selected durable job", commandName)
			}
			if len(forbidden) != 0 {
				t.Fatalf("%s crossed a forbidden worker boundary: %v", commandName, forbidden)
			}
			if _, err := os.Stat(harness.hostMutationMarker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s invoked a host mutation command; marker stat error = %v", commandName, err)
			}
		})
	}
}

func TestL3NamedStatusLiveJSONUsesDedicatedSafeContract(t *testing.T) {
	command := l3SandboxLeaf("status")
	if command == nil {
		t.Fatal("hal sandbox status is not registered")
	}
	if command.Flags().Lookup("live") == nil || command.Flags().Lookup("json") == nil {
		t.Fatal("hal sandbox status is missing --live or --json")
	}

	harness := newL3WorkerHarness(t, &l3WorkerScript{
		jobState:  sandboxworker.JobStateSucceeded,
		logCursor: 0,
		pages: map[uint64]sandboxworker.JobLogsResponse{
			0: {
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           "job-alpha",
				NextCursor:      0,
			},
		},
	})
	harness.seed("alpha", "run-alpha", "job-alpha")

	stdout, _, err := runL3SandboxLeaf(context.Background(), "status", []string{"alpha", "--live", "--json"})
	if err != nil {
		t.Fatalf("named live JSON status: %v", err)
	}
	payload := decodeL3JSONDocument(t, []byte(stdout))
	if got := payload["contractVersion"]; got != l3StatusContractVersion {
		t.Fatalf("status contractVersion = %v, want %s", got, l3StatusContractVersion)
	}
	requireL3MachinePayloadSafe(t, payload)
	encoded := string([]byte(stdout))
	for _, forbidden := range []string{
		"/home/private/l3-project",
		"/workspace/private",
		"/tmp/",
		"TOKEN=red-test-secret",
		"unix://",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Errorf("status JSON leaked manifest/worker marker %q:\n%s", forbidden, encoded)
		}
	}
}

func TestL3CommandFilesExcludeL4AndLaterDependencies(t *testing.T) {
	entries, err := filepath.Glob("sandbox*.go")
	if err != nil {
		t.Fatalf("glob sandbox command files: %v", err)
	}
	var l3Files []string
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		source := string(data)
		if strings.Contains(source, l3StatusContractVersion) ||
			strings.Contains(source, `Use:   "logs `) ||
			strings.Contains(source, `Use:   "recover `) ||
			strings.Contains(source, `Use:   "sync-out `) {
			l3Files = append(l3Files, path)
		}
	}
	if len(l3Files) == 0 {
		t.Fatal("no L3 command implementation files were found")
	}
	sort.Strings(l3Files)

	forbidden := []string{
		"internal/sandboxruntime/microvm/guestagent",
		"internal/sandboxruntime/microvm/firecrackerhost",
		"internal/sandbox/networkenforcement",
		"internal/sandboxtemplate/acquisition",
		"credentialactivation",
		"firecracker",
		"vsock",
	}
	for _, path := range l3Files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, marker := range forbidden {
			if bytes.Contains(data, []byte(marker)) {
				t.Errorf("%s contains L4+ dependency/behavior marker %q", path, marker)
			}
		}
	}
}

func l3SandboxLeaf(name string) *cobra.Command {
	for _, command := range sandboxCmd.Commands() {
		if command.Name() == name {
			return command
		}
	}
	return nil
}

func runL3SandboxLeaf(ctx context.Context, name string, args []string) (string, string, error) {
	command := l3SandboxLeaf(name)
	if command == nil {
		return "", "", fmt.Errorf("required L3 command %q is not registered", name)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var stdout, stderr bytes.Buffer
	originalOut := command.OutOrStdout()
	originalErr := command.ErrOrStderr()
	originalContext := command.Context()
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetContext(ctx)
	defer func() {
		command.SetOut(originalOut)
		command.SetErr(originalErr)
		command.SetContext(originalContext)
		command.Flags().VisitAll(func(flag *pflag.Flag) {
			_ = flag.Value.Set(flag.DefValue)
			flag.Changed = false
		})
	}()

	command.Flags().VisitAll(func(flag *pflag.Flag) {
		_ = flag.Value.Set(flag.DefValue)
		flag.Changed = false
	})
	if err := command.Flags().Parse(args); err != nil {
		return stdout.String(), stderr.String(), err
	}
	positional := command.Flags().Args()
	if command.Args != nil {
		if err := command.Args(command, positional); err != nil {
			return stdout.String(), stderr.String(), err
		}
	}
	if command.RunE == nil {
		return stdout.String(), stderr.String(), fmt.Errorf("required L3 command %q has no RunE", name)
	}
	err := command.RunE(command, positional)
	return stdout.String(), stderr.String(), err
}

func decodeL3JSONDocument(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var raw map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&raw); err != nil {
		t.Fatalf("decode JSON document: %v\n%s", err, payload)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("JSON output contains trailing JSON or text: %v\n%s", err, payload)
	}
	return raw
}

func requireL3MachinePayloadSafe(t *testing.T, payload any) {
	t.Helper()
	forbiddenKeys := map[string]bool{
		"credentials": true,
		"endpoint":    true,
		"env":         true,
		"ip":          true,
		"projectdir":  true,
		"socketpath":  true,
		"workdir":     true,
	}
	forbiddenValues := []string{
		"/home/private/l3-project",
		"/tmp/private/l3-worker.sock",
		"https://worker.invalid/private",
		"red-test-secret",
		"TOKEN=",
	}
	var visit func(any, string)
	visit = func(value any, path string) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				lower := strings.ToLower(key)
				if forbiddenKeys[lower] {
					t.Errorf("machine payload exposes forbidden key %s", l3JSONPath(path, key))
				}
				visit(child, l3JSONPath(path, key))
			}
		case []any:
			for index, child := range typed {
				visit(child, fmt.Sprintf("%s[%d]", path, index))
			}
		case string:
			for _, forbidden := range forbiddenValues {
				if strings.Contains(typed, forbidden) {
					t.Errorf("machine payload value at %s exposes forbidden marker %q", path, forbidden)
				}
			}
		}
	}
	visit(payload, "$")
}

func l3JSONPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

func requireL3ErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want safe error code %q", code)
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(code)) {
		t.Fatalf("error = %v, want safe error code %q", err, code)
	}
	for _, forbidden := range []string{"/home/", "/tmp/", "TOKEN=", "https://"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("error leaked forbidden marker %q: %v", forbidden, err)
		}
	}
}

func requireL3SafeErrorContains(t *testing.T, err error, fragments ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want an L3 selection error containing %q", fragments)
	}
	message := strings.ToLower(err.Error())
	for _, fragment := range fragments {
		if !strings.Contains(message, strings.ToLower(fragment)) {
			t.Errorf("error = %v, want fragment %q", err, fragment)
		}
	}
	for _, forbidden := range []string{"/home/", "/tmp/", "TOKEN=", "https://"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("error leaked forbidden marker %q: %v", forbidden, err)
		}
	}
}

func saveL3Sandbox(t *testing.T, name string, now time.Time) {
	t.Helper()
	err := sandbox.ForceWriteInstance(&sandbox.SandboxState{
		ID:        "sandbox-" + name,
		Name:      name,
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("save sandbox %s: %v", name, err)
	}
}

func l3Manifest(id, sandboxName string, startedAt time.Time, jobID, jobState string, logCursor uint64) *sandboxexecution.Manifest {
	manifest := &sandboxexecution.Manifest{
		ID:          id,
		Purpose:     sandboxexecution.PurposeRun,
		SandboxName: sandboxName,
		SandboxID:   "sandbox-" + sandboxName,
		ProjectDir:  "/home/private/l3-project",
		Command:     []string{"hal", "run", "TOKEN=red-test-secret"},
		WorkDir:     "/workspace/private",
		Status:      sandboxexecution.StatusRunning,
		StartedAt:   startedAt,
		Host: &sandbox.SandboxHost{
			ID:   "worker-l3",
			Name: "worker-l3",
			Kind: sandbox.SandboxHostKindWorker,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-l3",
			WorkerID:       "worker-l3",
		},
		WorkerRouting: &sandbox.WorkerRoutingMetadata{
			SelectedWorkerHostID:   "worker-l3",
			SelectedWorkerHostName: "worker-l3",
			RuntimeDriverID:        sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel:         sandbox.SandboxIsolationLevelContainer,
			EndpointSummary:        "local Unix socket",
		},
	}
	if jobID != "" {
		job := &sandboxexecution.WorkerJobReference{
			ContractVersion: sandboxexecution.WorkerJobContractVersion,
			JobID:           jobID,
			WorkerID:        "worker-l3",
			HostID:          "worker-l3",
			RuntimeDriver:   sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:       "runtime-l3",
			State:           jobState,
			SubmittedAt:     startedAt,
			LogCursor:       logCursor,
		}
		if jobState != sandboxworker.JobStateQueued {
			started := startedAt.Add(time.Second)
			job.StartedAt = &started
			job.HeartbeatAt = &started
		}
		if jobState != sandboxworker.JobStateQueued && jobState != sandboxworker.JobStateRunning {
			finished := startedAt.Add(2 * time.Second)
			job.FinishedAt = &finished
			manifest.FinishedAt = &finished
		}
		manifest.WorkerJob = job
	}
	return manifest
}

func saveL3Manifest(t *testing.T, store sandboxexecution.Store, manifest *sandboxexecution.Manifest) {
	t.Helper()
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("save execution manifest %s: %v", manifest.ID, err)
	}
}

type l3WorkerHarness struct {
	t                  *testing.T
	script             *l3WorkerScript
	hostMutationMarker string
	manifestPath       string
}

func newL3WorkerHarness(t *testing.T, script *l3WorkerScript) *l3WorkerHarness {
	t.Helper()
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	if script == nil {
		t.Fatal("L3 worker script is required")
		return nil
	}
	script.socketPath = "/tmp/private/l3-worker.sock"
	originalClientFactory := sandboxL3NewWorkerClient
	sandboxL3NewWorkerClient = func(string) (*sandboxworker.Client, error) {
		return sandboxworker.NewClient(sandboxworker.ClientOptions{
			Transport: sandboxworker.ClientTransportFunc(func(ctx context.Context, req sandboxworker.Request) (sandboxworker.Response, error) {
				return script.RoundTrip(ctx, req)
			}),
		})
	}
	t.Cleanup(func() {
		sandboxL3NewWorkerClient = originalClientFactory
	})

	marker := filepath.Join(t.TempDir(), "host-mutation-marker")
	binDir := t.TempDir()
	for _, executable := range []string{"git", "podman", "ssh", "scp", "rsync"} {
		path := filepath.Join(binDir, executable)
		scriptBody := "#!/bin/sh\n: > " + marker + "\nexit 97\n"
		if err := os.WriteFile(path, []byte(scriptBody), 0o700); err != nil {
			t.Fatalf("write %s mutation sentinel: %v", executable, err)
		}
	}
	t.Setenv("PATH", binDir)

	return &l3WorkerHarness{
		t:                  t,
		script:             script,
		hostMutationMarker: marker,
	}
}

func (harness *l3WorkerHarness) seed(sandboxName, executionID, jobID string) {
	harness.t.Helper()
	now := time.Date(2026, 7, 25, 2, 0, 0, 0, time.UTC)
	if err := sandbox.ForceWriteHost(&sandbox.SandboxHost{
		ID:                "worker-l3",
		Name:              "worker-l3",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix://" + harness.script.socketPath,
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
	}); err != nil {
		harness.t.Fatalf("save L3 worker host: %v", err)
	}
	if err := sandbox.ForceWriteInstance(&sandbox.SandboxState{
		ID:        "sandbox-" + sandboxName,
		Name:      sandboxName,
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now,
		Host: &sandbox.SandboxHost{
			ID:   "worker-l3",
			Name: "worker-l3",
			Kind: sandbox.SandboxHostKindWorker,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-l3",
			WorkerID:       "worker-l3",
		},
	}); err != nil {
		harness.t.Fatalf("save L3 sandbox: %v", err)
	}
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		harness.t.Fatalf("open L3 execution store: %v", err)
	}
	saveL3Manifest(harness.t, store, l3Manifest(
		executionID,
		sandboxName,
		now,
		jobID,
		harness.script.jobState,
		harness.script.logCursor,
	))
	harness.manifestPath, err = store.ManifestPath(executionID)
	if err != nil {
		harness.t.Fatalf("resolve L3 manifest path: %v", err)
	}
}

func (harness *l3WorkerHarness) manifestBytes() []byte {
	harness.t.Helper()
	payload, err := os.ReadFile(harness.manifestPath)
	if err != nil {
		harness.t.Fatalf("read L3 manifest: %v", err)
	}
	return payload
}

type l3WorkerScript struct {
	mu                     sync.Mutex
	socketPath             string
	jobState               string
	logCursor              uint64
	resolveJob             *sandboxworker.Job
	resolveError           *sandboxworker.Error
	beforeJobStatus        func()
	pages                  map[uint64]sandboxworker.JobLogsResponse
	failExecContains       map[string]int
	transportFailures      map[string]int
	protocolFailures       map[string]int
	transportAttempts      map[string]int
	firstLogs              chan struct{}
	panicOnForbidden       bool
	panicUnlessObservation bool
	requests               []l3WorkerRequest
	forbidden              []string
}

type l3WorkerRequest struct {
	operation string
	cursor    uint64
	args      []string
}

func (script *l3WorkerScript) RoundTrip(ctx context.Context, req sandboxworker.Request) (sandboxworker.Response, error) {
	script.mu.Lock()
	if script.transportAttempts == nil {
		script.transportAttempts = make(map[string]int)
	}
	script.transportAttempts[req.Operation]++
	if script.transportFailures[req.Operation] > 0 {
		script.transportFailures[req.Operation]--
		script.mu.Unlock()
		return sandboxworker.Response{}, errors.New("temporary worker daemon transport unavailable")
	}
	if script.protocolFailures[req.Operation] > 0 {
		script.protocolFailures[req.Operation]--
		script.mu.Unlock()
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              false,
			Error: &sandboxworker.Error{
				Code:    sandboxworker.ErrorCodeJobNotFound,
				Message: "selected worker job was not found",
			},
		}, nil
	}
	script.mu.Unlock()
	return script.HandleRequest(ctx, req), nil
}

func (script *l3WorkerScript) HandleRequest(_ context.Context, req sandboxworker.Request) sandboxworker.Response {
	script.mu.Lock()
	record := l3WorkerRequest{operation: req.Operation}
	if req.JobLogs != nil {
		record.cursor = req.JobLogs.Cursor
	}
	if req.Exec != nil {
		record.args = append([]string(nil), req.Exec.Args...)
	}
	script.requests = append(script.requests, record)
	failExec := false
	if req.Exec != nil {
		joined := strings.Join(req.Exec.Args, "\n")
		for marker, remaining := range script.failExecContains {
			if remaining > 0 && strings.Contains(joined, marker) {
				script.failExecContains[marker] = remaining - 1
				failExec = true
				break
			}
		}
	}
	forbidden := false
	switch req.Operation {
	case sandboxworker.OperationStatus,
		sandboxworker.OperationCapabilities,
		sandboxworker.OperationInspect,
		sandboxworker.OperationJobResolve,
		sandboxworker.OperationJobStatus,
		sandboxworker.OperationJobLogs,
		sandboxworker.OperationCopyOut:
	case sandboxworker.OperationExec:
		if req.Exec == nil || l3LooksLikeForbiddenRecoveryExec(req.Exec.Args) {
			script.forbidden = append(script.forbidden, req.Operation)
			forbidden = true
		}
	default:
		script.forbidden = append(script.forbidden, req.Operation)
		forbidden = true
	}
	if script.panicUnlessObservation && req.Operation != sandboxworker.OperationJobStatus {
		forbidden = true
	}
	firstLogs := script.firstLogs
	panicOnForbidden := script.panicOnForbidden
	script.mu.Unlock()
	if forbidden && panicOnForbidden {
		panic("L3 recovery crossed a forbidden worker boundary")
	}
	if failExec {
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              false,
			Error: &sandboxworker.Error{
				Code:    sandboxworker.ErrorCodeDriverFailed,
				Message: "injected safe collection failure",
			},
		}
	}

	now := time.Date(2026, 7, 25, 2, 0, 0, 0, time.UTC)
	started := now.Add(time.Second)
	finished := now.Add(2 * time.Second)
	switch req.Operation {
	case sandboxworker.OperationStatus:
		status := &sandboxworker.Status{
			ProtocolVersion:         sandboxworker.ProtocolVersion,
			WorkerID:                "worker-l3",
			HostKind:                sandboxworker.HostKindLocal,
			SocketPath:              script.socketPath,
			SupportedRuntimeDrivers: []string{sandboxworker.RuntimeDriverRootlessPodman},
			Health: sandboxworker.WorkerHealth{
				Status: sandboxworker.HealthStatusHealthy,
			},
			Capacity: sandboxworker.WorkerCapacity{
				MaxConcurrentSandboxes: 1,
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		}
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              true,
			Status:          status,
		}
	case sandboxworker.OperationCapabilities:
		capabilities := &sandboxworker.Capabilities{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			WorkerID:        "worker-l3",
			SupportedOperations: []string{
				sandboxworker.OperationStatus,
				sandboxworker.OperationCapabilities,
				sandboxworker.OperationInspect,
				sandboxworker.OperationJobStatus,
				sandboxworker.OperationJobLogs,
			},
			RuntimeDrivers: []sandboxworker.RuntimeDriver{
				{
					ID:             sandboxworker.RuntimeDriverRootlessPodman,
					HostKind:       sandboxworker.HostKindLocal,
					IsolationLevel: sandboxworker.IsolationLevelContainer,
					Operations:     []string{sandboxworker.OperationInspect},
					Security:       sandboxworker.DefaultWorkerSecurityPolicy(),
				},
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		}
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              true,
			Capabilities:    capabilities,
		}
	case sandboxworker.OperationInspect:
		target := &sandboxworker.Target{
			ID:     "runtime-l3",
			Name:   "alpha",
			Status: sandbox.StatusRunning,
			Runtime: sandboxworker.RuntimeTarget{
				Driver:         sandboxworker.RuntimeDriverRootlessPodman,
				RuntimeID:      "runtime-l3",
				WorkerID:       "worker-l3",
				IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			},
		}
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              true,
			Target:          target,
		}
	case sandboxworker.OperationJobStatus:
		if script.beforeJobStatus != nil {
			script.beforeJobStatus()
		}
		job := &sandboxworker.Job{
			ContractVersion: sandboxworker.JobContractVersion,
			ID:              req.JobStatus.JobID,
			SubmissionKey:   sandboxWorkerJobSubmissionKey("run-alpha"),
			WorkerID:        "worker-l3",
			HostID:          "worker-l3",
			RuntimeDriver:   sandboxworker.RuntimeDriverRootlessPodman,
			RuntimeID:       "runtime-l3",
			State:           script.jobState,
			SubmittedAt:     now,
			LogCursor:       script.logCursor,
		}
		if script.jobState != sandboxworker.JobStateQueued {
			job.StartedAt = &started
			job.HeartbeatAt = &started
		}
		if script.jobState != sandboxworker.JobStateQueued && script.jobState != sandboxworker.JobStateRunning {
			job.FinishedAt = &finished
		}
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              true,
			Job:             job,
		}
	case sandboxworker.OperationJobResolve:
		if script.resolveError != nil {
			return sandboxworker.Response{
				ProtocolVersion: sandboxworker.ProtocolVersion,
				RequestID:       req.RequestID,
				Operation:       req.Operation,
				OK:              false,
				Error:           script.resolveError,
			}
		}
		job := script.resolveJob
		if job == nil {
			job = &sandboxworker.Job{
				ContractVersion: sandboxworker.JobContractVersion,
				ID:              "job-resolved",
				SubmissionKey:   sandboxWorkerJobSubmissionKey(req.JobResolve.SubmissionID),
				WorkerID:        "worker-l3",
				HostID:          "worker-l3",
				RuntimeDriver:   sandboxworker.RuntimeDriverRootlessPodman,
				RuntimeID:       "runtime-l3",
				State:           script.jobState,
				SubmittedAt:     now,
				LogCursor:       script.logCursor,
			}
			if script.jobState != sandboxworker.JobStateQueued {
				job.StartedAt = &started
				job.HeartbeatAt = &started
			}
			if script.jobState != sandboxworker.JobStateQueued && script.jobState != sandboxworker.JobStateRunning {
				job.FinishedAt = &finished
			}
		}
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              true,
			Job:             job,
		}
	case sandboxworker.OperationJobLogs:
		if firstLogs != nil {
			select {
			case firstLogs <- struct{}{}:
			default:
			}
		}
		page, ok := script.pages[req.JobLogs.Cursor]
		if !ok {
			page = sandboxworker.JobLogsResponse{
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           req.JobLogs.JobID,
				NextCursor:      req.JobLogs.Cursor,
			}
		}
		page.JobID = req.JobLogs.JobID
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              true,
			JobLogs:         &page,
		}
	case sandboxworker.OperationExec:
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              true,
			Exec: &sandboxworker.ExecResponse{
				Stdout: sandboxworker.ExecOutputPayload{LimitBytes: req.Exec.StdoutLimitBytes},
				Stderr: sandboxworker.ExecOutputPayload{LimitBytes: req.Exec.StderrLimitBytes},
			},
		}
	case sandboxworker.OperationCopyOut:
		payload := []byte("durable L3 artifact\n")
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              true,
			CopyOut: &sandboxworker.CopyOutResponse{
				Payload: &sandboxworker.CopyFilePayload{
					Data:       base64.StdEncoding.EncodeToString(payload),
					Encoding:   sandboxworker.CopyPayloadEncodingBase64,
					SizeBytes:  int64(len(payload)),
					LimitBytes: req.CopyOut.MaxPayloadBytes,
				},
			},
		}
	default:
		return sandboxworker.Response{
			ProtocolVersion: sandboxworker.ProtocolVersion,
			RequestID:       req.RequestID,
			Operation:       req.Operation,
			OK:              false,
			Error: &sandboxworker.Error{
				Code:    sandboxworker.ErrorCodeUnsupportedOp,
				Message: "forbidden L3 command boundary",
			},
		}
	}
}

func (script *l3WorkerScript) snapshot() ([]l3WorkerRequest, []string) {
	script.mu.Lock()
	defer script.mu.Unlock()
	return append([]l3WorkerRequest(nil), script.requests...), append([]string(nil), script.forbidden...)
}

func (script *l3WorkerScript) transportAttemptCount(operation string) int {
	script.mu.Lock()
	defer script.mu.Unlock()
	return script.transportAttempts[operation]
}

func l3LogRequestCursors(requests []l3WorkerRequest) []uint64 {
	var cursors []uint64
	for _, request := range requests {
		if request.operation == sandboxworker.OperationJobLogs {
			cursors = append(cursors, request.cursor)
		}
	}
	return cursors
}

func equalL3Uint64s(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func l3LooksLikeAgentLaunch(args []string) bool {
	joined := " " + strings.ToLower(strings.Join(args, " ")) + " "
	for _, marker := range []string{" hal run ", " hal auto ", " hal loop ", " codex ", " claude "} {
		if strings.Contains(joined, marker) {
			return true
		}
	}
	return false
}

func l3LooksLikeForbiddenRecoveryExec(args []string) bool {
	if l3LooksLikeAgentLaunch(args) {
		return true
	}
	joined := " " + strings.ToLower(strings.Join(args, " ")) + " "
	for _, marker := range []string{
		" git clone ",
		" git checkout ",
		" auth ",
		" bootstrap ",
		" tailscale ",
	} {
		if strings.Contains(joined, marker) {
			return true
		}
	}
	return false
}
