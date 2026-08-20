//go:build linux

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestL11RootlessPreparedLinuxHarness(t *testing.T) {
	harness := newL11RootlessPreparedHarness(t)
	baseline, err := harness.CaptureBaseline()
	if err != nil {
		t.Fatalf("capture baseline: %v", err)
	}
	if baseline.OwnedTotal() != 0 {
		t.Fatalf("baseline owned total = %d, want 0", baseline.OwnedTotal())
	}

	t.Run("rootless_advisory_success", func(t *testing.T) {
		result, err := harness.AdmitRootless()
		if err != nil {
			t.Fatalf("admit rootless: %v", err)
		}
		if result.ScenarioID != "rootless_advisory_success" || result.Runtime != "rootless_podman" {
			t.Fatalf("scenario/runtime = %q/%q, want exact rootless row", result.ScenarioID, result.Runtime)
		}
		if !result.Advisory || result.StrictSelected {
			t.Fatalf("advisory/strict = %t/%t, want true/false", result.Advisory, result.StrictSelected)
		}
		if result.PolicyMode != "advisory" || result.NetworkEnforcement != "best_effort" || result.StrictReason != "dependency_unaccepted" {
			t.Fatalf("rootless policy/enforcement/reason = %q/%q/%q", result.PolicyMode, result.NetworkEnforcement, result.StrictReason)
		}
		if result.AdmissionCount != 1 {
			t.Fatalf("admission count = %d, want 1", result.AdmissionCount)
		}
		if !result.Connected {
			t.Fatal("rootless client is not connected after admission")
		}
	})

	t.Run("rootless_client_loss_reconnect", func(t *testing.T) {
		if err := harness.LoseClient(); err != nil {
			t.Fatalf("lose initiating client: %v", err)
		}
		result, err := harness.Reconnect()
		if err != nil {
			t.Fatalf("reconnect after client loss: %v", err)
		}
		if result.ScenarioID != "rootless_client_loss_reconnect" || !result.SameDurableJob {
			t.Fatalf("scenario/same durable job = %q/%t", result.ScenarioID, result.SameDurableJob)
		}
		if result.AdmissionCount != 1 {
			t.Fatalf("admission count after reconnect = %d, want 1", result.AdmissionCount)
		}
		if !result.Connected {
			t.Fatal("rootless client is not connected after recovery")
		}
	})

	t.Run("rootless_daemon_restart_recovery", func(t *testing.T) {
		if err := harness.RestartDaemon(); err != nil {
			t.Fatalf("restart fake prepared daemon: %v", err)
		}
		result, err := harness.RecoverAfterRestart()
		if err != nil {
			t.Fatalf("recover after daemon restart: %v", err)
		}
		if result.ScenarioID != "rootless_daemon_restart_recovery" || !result.SameDurableJob {
			t.Fatalf("scenario/same durable job = %q/%t", result.ScenarioID, result.SameDurableJob)
		}
		if result.AdmissionCount != 1 || result.DaemonGeneration != 2 {
			t.Fatalf("admission/generation = %d/%d, want 1/2", result.AdmissionCount, result.DaemonGeneration)
		}
		if result.FinalizationCount != 1 || !result.LeaseReleased {
			t.Fatalf("finalization/lease released = %d/%t, want 1/true", result.FinalizationCount, result.LeaseReleased)
		}
		repeated, err := harness.RecoverAfterRestart()
		if err != nil {
			t.Fatalf("repeat recovery after daemon restart: %v", err)
		}
		if repeated.AdmissionCount != 1 || repeated.FinalizationCount != 1 {
			t.Fatalf("repeated recovery admission/finalization = %d/%d, want 1/1", repeated.AdmissionCount, repeated.FinalizationCount)
		}
	})

	t.Run("artifact_integrity_and_safe_handoff", func(t *testing.T) {
		evidence, err := harness.FinalizeArtifact([]byte("diff --git a/result.txt b/result.txt\nnew file mode 100644\n"))
		if err != nil {
			t.Fatalf("finalize artifact: %v", err)
		}
		if evidence.ScenarioID != "artifact_integrity_and_safe_handoff" || evidence.ArtifactID != "rootless-result" {
			t.Fatalf("scenario/artifact = %q/%q", evidence.ScenarioID, evidence.ArtifactID)
		}
		if evidence.SizeBytes <= 0 || len(evidence.Digest) != 64 {
			t.Fatalf("artifact size/digest length = %d/%d", evidence.SizeBytes, len(evidence.Digest))
		}
		if err := harness.VerifyArtifact(evidence); err != nil {
			t.Fatalf("verify durable artifact: %v", err)
		}
		corrupted := evidence
		corrupted.Digest = strings.Repeat("0", 64)
		if err := harness.VerifyArtifact(corrupted); !errors.Is(err, errL11ArtifactInvalid) {
			t.Fatalf("corrupt digest error = %v, want artifact_invalid", err)
		}
		if evidence.Handoff.Applied || evidence.Handoff.DryRunPassed || evidence.Handoff.ArtifactID != evidence.ArtifactID {
			t.Fatalf("safe handoff outcome is not disabled and artifact-bound")
		}
		encoded, err := json.Marshal(evidence)
		if err != nil {
			t.Fatalf("marshal safe artifact evidence: %v", err)
		}
		if strings.Contains(string(encoded), harness.PrivateRoot()) || strings.Contains(string(encoded), "storedPath") {
			t.Fatal("public artifact evidence exposed a private or store-relative path")
		}
	})

	if err := harness.Cleanup(); err != nil {
		t.Fatalf("cleanup rootless harness: %v", err)
	}
	final, err := harness.CaptureBaseline()
	if err != nil {
		t.Fatalf("capture final census: %v", err)
	}
	if err := l11RequireExactResourceZero(baseline, final); err != nil {
		t.Fatalf("final resource census: %v", err)
	}
}

func TestL11RootlessPreparedLinuxConcurrentReconnectDoesNotReadmit(t *testing.T) {
	harness := newL11RootlessPreparedHarness(t)
	if _, err := harness.AdmitRootless(); err != nil {
		t.Fatalf("admit rootless: %v", err)
	}
	if err := harness.LoseClient(); err != nil {
		t.Fatalf("lose client: %v", err)
	}

	const callers = 16
	results := make(chan l11RootlessPreparedResult, callers)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := harness.Reconnect()
			results <- result
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent reconnect: %v", err)
		}
	}
	for result := range results {
		if result.AdmissionCount != 1 || !result.SameDurableJob {
			t.Fatalf("concurrent reconnect admission/same job = %d/%t", result.AdmissionCount, result.SameDurableJob)
		}
	}
}

func TestL11StrictRowsRemainDependencyBlocked(t *testing.T) {
	want := map[string]string{
		"strict_firecracker_success":      "dependency_unaccepted",
		"strict_remove_one_proof":         "dependency_unaccepted",
		"strict_runtime_loss_reconnect":   "dependency_unaccepted",
		"strict_credential_loss_recovery": "dependency_unaccepted",
	}
	if got := l11StrictBlockedRows(); !equalL11StringMaps(got, want) {
		t.Fatalf("strict blocked rows = %v, want exact dependency blockers", got)
	}
}

func TestL11SelectedWrapperRequiresExactFutureMatrixAndRejectsMutations(t *testing.T) {
	wrapper := filepath.Join("..", "tools", "microvm", "l11", "verify-selected-live.sh")
	info, err := os.Stat(wrapper)
	if err != nil {
		t.Fatalf("stat L11 selected wrapper: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("L11 selected wrapper is not executable")
	}

	exact := l11ExactFakeWrapperEvents()
	if output, err := runL11SelectedWrapperFake(t, wrapper, "exact", exact); err != nil {
		t.Fatalf("exact fake event shape rejected: %v; output=%q", err, output)
	}
	mutations := []struct {
		name     string
		mode     string
		events   []l11WrapperEvent
		wantCode string
	}{
		{name: "selected test missing", mode: "missing", events: exact, wantCode: "required_test_missing"},
		{name: "selected test duplicated", mode: "duplicate", events: exact, wantCode: "evidence_mismatch"},
		{name: "skip event", mode: "exact", events: append(append([]l11WrapperEvent(nil), exact...), l11WrapperEvent{Action: "skip", Test: l11FinalClosureSelectedTest + "/rootless_advisory_success"}), wantCode: "required_test_skipped"},
		{name: "missing row pass", mode: "exact", events: removeL11WrapperEvent(exact, "pass", l11FinalClosureSelectedTest+"/strict_firecracker_success"), wantCode: "required_test_missing"},
		{name: "duplicate row pass", mode: "exact", events: append(append([]l11WrapperEvent(nil), exact...), l11WrapperEvent{Action: "pass", Test: l11FinalClosureSelectedTest + "/zero_resource_leaks"}), wantCode: "evidence_mismatch"},
		{name: "unexpected row", mode: "exact", events: append(append([]l11WrapperEvent(nil), exact...), l11WrapperEvent{Action: "pass", Test: l11FinalClosureSelectedTest + "/extra_row"}), wantCode: "evidence_mismatch"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			output, err := runL11SelectedWrapperFake(t, wrapper, mutation.mode, mutation.events)
			if err == nil {
				t.Fatalf("mutated wrapper event stream passed; output=%q", output)
			}
			if !strings.Contains(output, mutation.wantCode) {
				t.Fatalf("wrapper output = %q, want code %q", output, mutation.wantCode)
			}
			if strings.Contains(output, t.TempDir()) {
				t.Fatal("wrapper failure exposed a private test path")
			}
		})
	}
}

func TestL11SelectedWrapperIsTruthfullyBlockedToday(t *testing.T) {
	wrapper := filepath.Join("..", "tools", "microvm", "l11", "verify-selected-live.sh")
	output, err := runL11SelectedWrapperFake(t, wrapper, "missing", l11ExactFakeWrapperEvents())
	if err == nil {
		t.Fatal("wrapper passed without the future selected test")
	}
	if !strings.Contains(output, "required_test_missing") {
		t.Fatalf("missing selected-test output = %q, want safe blocked code", output)
	}
	if declarations := l11FinalSelectedTestDeclarationCount(t); declarations != 0 {
		t.Fatalf("future final selected-test declarations = %d, want 0 while dependencies are blocked", declarations)
	}
}

type l11WrapperEvent struct {
	Action string `json:"Action"`
	Test   string `json:"Test"`
}

func l11ExactFakeWrapperEvents() []l11WrapperEvent {
	events := []l11WrapperEvent{{Action: "run", Test: l11FinalClosureSelectedTest}}
	for _, row := range l11ExpectedFinalClosureMatrix() {
		testName := l11FinalClosureSelectedTest + "/" + row.id
		events = append(events,
			l11WrapperEvent{Action: "run", Test: testName},
			l11WrapperEvent{Action: "pass", Test: testName},
		)
	}
	return append(events, l11WrapperEvent{Action: "pass", Test: l11FinalClosureSelectedTest})
}

func removeL11WrapperEvent(events []l11WrapperEvent, action, testName string) []l11WrapperEvent {
	result := make([]l11WrapperEvent, 0, len(events))
	removed := false
	for _, event := range events {
		if !removed && event.Action == action && event.Test == testName {
			removed = true
			continue
		}
		result = append(result, event)
	}
	return result
}

var (
	errL11HarnessState    = errors.New("scenario_failed")
	errL11ArtifactInvalid = errors.New("artifact_invalid")
)

type l11RootlessPreparedHarness struct {
	mu                   sync.Mutex
	privateRoot          string
	store                sandboxexecution.Store
	inventory            *l11ResourceInventory
	owner                l11ResourceOwner
	admitted             bool
	cleaned              bool
	clientConnected      bool
	durableJob           string
	admissionCount       int
	daemonGeneration     int
	finalizationCount    int
	leaseReleased        bool
	restartRecoveryReady bool
}

type l11RootlessPreparedResult struct {
	ScenarioID         string
	Runtime            string
	PolicyMode         string
	NetworkEnforcement string
	StrictReason       string
	Advisory           bool
	StrictSelected     bool
	SameDurableJob     bool
	AdmissionCount     int
	DaemonGeneration   int
	FinalizationCount  int
	LeaseReleased      bool
	Connected          bool
}

type l11ArtifactEvidence struct {
	ScenarioID string                           `json:"scenarioId"`
	ArtifactID string                           `json:"artifactId"`
	SizeBytes  int64                            `json:"sizeBytes"`
	Digest     string                           `json:"digest"`
	Handoff    sandboxworkspace.SafeApplyResult `json:"handoff"`

	store       sandboxexecution.Store
	executionID string
	storedPath  string
}

func newL11RootlessPreparedHarness(t *testing.T) *l11RootlessPreparedHarness {
	t.Helper()
	privateRoot := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(privateRoot, "executions"))
	startedAt := time.Unix(1, 0).UTC()
	if err := store.SaveManifest(&sandboxexecution.Manifest{
		ID:        "l11-rootless-harness",
		Purpose:   sandboxexecution.PurposeRun,
		Status:    sandboxexecution.StatusRunning,
		StartedAt: startedAt,
	}); err != nil {
		t.Fatal("initialize contained L11 artifact store")
	}
	inventory := newL11ResourceInventory()
	historical := l11ResourceOwner{Scope: "rootless-harness", Generation: 1}
	for _, kind := range l11ExactOwnedResourceKinds() {
		inventory.Add(historical, kind)
	}
	return &l11RootlessPreparedHarness{
		privateRoot:      privateRoot,
		store:            store,
		inventory:        inventory,
		owner:            l11ResourceOwner{Scope: "rootless-harness", Generation: 2},
		durableJob:       "rootless-durable-job",
		daemonGeneration: 1,
	}
}

func (harness *l11RootlessPreparedHarness) PrivateRoot() string { return harness.privateRoot }

func (harness *l11RootlessPreparedHarness) CaptureBaseline() (l11ResourceCensus, error) {
	return harness.inventory.Capture(harness.owner)
}

func (harness *l11RootlessPreparedHarness) AdmitRootless() (l11RootlessPreparedResult, error) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	if harness.cleaned {
		return l11RootlessPreparedResult{}, fmt.Errorf("admit L11 rootless harness: %w", errL11HarnessState)
	}
	if !harness.admitted {
		harness.admitted = true
		harness.clientConnected = true
		harness.admissionCount = 1
		for _, kind := range []l11ResourceKind{
			l11ResourceContainer,
			l11ResourceListenerConnection,
			l11ResourceSocket,
			l11ResourceLock,
			l11ResourceLease,
			l11ResourceTemporaryArtifactStaging,
		} {
			harness.inventory.Add(harness.owner, kind)
		}
	}
	return harness.rootlessResult("rootless_advisory_success"), nil
}

func (harness *l11RootlessPreparedHarness) LoseClient() error {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	if !harness.admitted || harness.cleaned {
		return fmt.Errorf("lose L11 initiating client: %w", errL11HarnessState)
	}
	harness.clientConnected = false
	return nil
}

func (harness *l11RootlessPreparedHarness) Reconnect() (l11RootlessPreparedResult, error) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	if !harness.admitted || harness.cleaned {
		return l11RootlessPreparedResult{}, fmt.Errorf("reconnect L11 rootless harness: %w", errL11HarnessState)
	}
	harness.clientConnected = true
	return harness.rootlessResult("rootless_client_loss_reconnect"), nil
}

func (harness *l11RootlessPreparedHarness) RestartDaemon() error {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	if !harness.admitted || harness.cleaned || harness.daemonGeneration != 1 {
		return fmt.Errorf("restart L11 prepared daemon: %w", errL11HarnessState)
	}
	harness.daemonGeneration = 2
	harness.clientConnected = false
	harness.restartRecoveryReady = true
	return nil
}

func (harness *l11RootlessPreparedHarness) RecoverAfterRestart() (l11RootlessPreparedResult, error) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	if !harness.admitted || harness.cleaned || !harness.restartRecoveryReady {
		return l11RootlessPreparedResult{}, fmt.Errorf("recover L11 prepared daemon: %w", errL11HarnessState)
	}
	harness.clientConnected = true
	if harness.finalizationCount == 0 {
		harness.finalizationCount = 1
		harness.leaseReleased = true
		harness.inventory.Release(harness.owner, l11ResourceLease)
	}
	return harness.rootlessResult("rootless_daemon_restart_recovery"), nil
}

func (harness *l11RootlessPreparedHarness) FinalizeArtifact(payload []byte) (l11ArtifactEvidence, error) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	if !harness.admitted || harness.cleaned || harness.finalizationCount != 1 || len(payload) == 0 {
		return l11ArtifactEvidence{}, fmt.Errorf("finalize L11 artifact: %w", errL11HarnessState)
	}
	artifact, err := harness.store.SaveArtifact(
		"l11-rootless-harness",
		sandboxexecution.Artifact{ID: "rootless-result", Name: "Rootless result patch", Type: "patch"},
		"rootless/result.txt",
		payload,
	)
	if err != nil {
		return l11ArtifactEvidence{}, fmt.Errorf("finalize L11 artifact: %w", errL11ArtifactInvalid)
	}
	if artifact.SizeBytes == nil {
		return l11ArtifactEvidence{}, fmt.Errorf("finalize L11 artifact: %w", errL11ArtifactInvalid)
	}
	digest := sha256.Sum256(payload)
	handoff := sandboxworkspace.SafeApplyResult{
		Status:       sandboxworkspace.SafeApplyStatusHandoffRequired,
		Applied:      false,
		DryRunPassed: false,
		Mode:         sandboxworkspace.SyncOutApplyModePatch,
		ArtifactID:   artifact.ID,
		DisplayName:  artifact.Name,
		DisplayPath:  "artifacts/rootless-result",
		Reasons:      []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonApplyDisabled},
	}
	finishedAt := time.Unix(2, 0).UTC()
	if err := harness.store.UpdateManifest("l11-rootless-harness", func(manifest *sandboxexecution.Manifest) error {
		manifest.Status = sandboxexecution.StatusSucceeded
		manifest.FinishedAt = &finishedAt
		manifest.SyncOutApply = &handoff
		return nil
	}); err != nil {
		return l11ArtifactEvidence{}, fmt.Errorf("persist L11 safe handoff: %w", errL11ArtifactInvalid)
	}
	return l11ArtifactEvidence{
		ScenarioID:  "artifact_integrity_and_safe_handoff",
		ArtifactID:  artifact.ID,
		SizeBytes:   *artifact.SizeBytes,
		Digest:      hex.EncodeToString(digest[:]),
		Handoff:     handoff,
		store:       harness.store,
		executionID: "l11-rootless-harness",
		storedPath:  artifact.StoredPath,
	}, nil
}

func (harness *l11RootlessPreparedHarness) VerifyArtifact(evidence l11ArtifactEvidence) error {
	if evidence.ArtifactID != "rootless-result" || evidence.SizeBytes <= 0 || len(evidence.Digest) != 64 ||
		evidence.executionID != "l11-rootless-harness" || evidence.storedPath == "" {
		return fmt.Errorf("verify L11 artifact evidence: %w", errL11ArtifactInvalid)
	}
	file, err := evidence.store.OpenStoredFile(evidence.executionID, evidence.storedPath)
	if err != nil {
		return fmt.Errorf("verify L11 artifact evidence: %w", errL11ArtifactInvalid)
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, evidence.SizeBytes+1))
	if err != nil || int64(len(payload)) != evidence.SizeBytes {
		return fmt.Errorf("verify L11 artifact evidence: %w", errL11ArtifactInvalid)
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != evidence.Digest {
		return fmt.Errorf("verify L11 artifact evidence: %w", errL11ArtifactInvalid)
	}
	return nil
}

func (harness *l11RootlessPreparedHarness) Cleanup() error {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	if harness.cleaned {
		return nil
	}
	harness.inventory.Cleanup(harness.owner)
	if err := harness.store.Remove("l11-rootless-harness"); err != nil {
		return fmt.Errorf("cleanup L11 contained artifact store: %w", errL11HarnessState)
	}
	harness.cleaned = true
	return nil
}

func (harness *l11RootlessPreparedHarness) rootlessResult(scenarioID string) l11RootlessPreparedResult {
	return l11RootlessPreparedResult{
		ScenarioID:         scenarioID,
		Runtime:            "rootless_podman",
		PolicyMode:         "advisory",
		NetworkEnforcement: "best_effort",
		StrictReason:       "dependency_unaccepted",
		Advisory:           true,
		StrictSelected:     false,
		SameDurableJob:     harness.durableJob == "rootless-durable-job",
		AdmissionCount:     harness.admissionCount,
		DaemonGeneration:   harness.daemonGeneration,
		FinalizationCount:  harness.finalizationCount,
		LeaseReleased:      harness.leaseReleased,
		Connected:          harness.clientConnected,
	}
}

func l11StrictBlockedRows() map[string]string {
	return map[string]string{
		"strict_firecracker_success":      "dependency_unaccepted",
		"strict_remove_one_proof":         "dependency_unaccepted",
		"strict_runtime_loss_reconnect":   "dependency_unaccepted",
		"strict_credential_loss_recovery": "dependency_unaccepted",
	}
}

func equalL11StringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func runL11SelectedWrapperFake(t *testing.T, wrapper, listMode string, events []l11WrapperEvent) (string, error) {
	t.Helper()
	privateRoot := t.TempDir()
	eventsPath := filepath.Join(privateRoot, "events.jsonl")
	eventsFile, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("create private fake event stream")
	}
	encoder := json.NewEncoder(eventsFile)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			_ = eventsFile.Close()
			t.Fatal("encode fake wrapper event")
		}
	}
	if err := eventsFile.Close(); err != nil {
		t.Fatal("close fake wrapper event stream")
	}
	fakeGo := filepath.Join(privateRoot, "go")
	fakeSource := `#!/bin/sh
case " $* " in
  *" -list "*)
    case "${L11_FAKE_LIST_MODE:-missing}" in
      exact) printf '%s\n' TestL11PreparedLinuxFinalClosure ;;
      duplicate) printf '%s\n' TestL11PreparedLinuxFinalClosure TestL11PreparedLinuxFinalClosure ;;
      missing) : ;;
      *) exit 64 ;;
    esac
    ;;
  *" -json "*)
    /bin/cat -- "$L11_FAKE_EVENTS"
    ;;
  *) exit 64 ;;
esac
`
	if err := os.WriteFile(fakeGo, []byte(fakeSource), 0o700); err != nil {
		t.Fatal("write fake go command")
	}
	command := exec.Command(wrapper, "matrix")
	command.Env = append(os.Environ(),
		"PATH="+privateRoot+string(os.PathListSeparator)+os.Getenv("PATH"),
		"L11_FAKE_LIST_MODE="+listMode,
		"L11_FAKE_EVENTS="+eventsPath,
	)
	output, runErr := command.CombinedOutput()
	if strings.Contains(string(output), privateRoot) {
		t.Fatal("L11 wrapper exposed a private fixture path")
	}
	return string(output), runErr
}

func l11FinalSelectedTestDeclarationCount(t *testing.T) int {
	t.Helper()
	count := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil && function.Name.Name == l11FinalClosureSelectedTest {
				count++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("inspect future L11 selected-test declarations")
	}
	return count
}
