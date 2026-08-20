//go:build linux

package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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
		if result.AdmissionCount != 1 {
			t.Fatalf("admission count = %d, want 1", result.AdmissionCount)
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
	})

	t.Run("artifact_integrity_and_safe_handoff", func(t *testing.T) {
		evidence, err := harness.FinalizeArtifact([]byte("L11 rootless harness artifact\n"))
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
		name   string
		mode   string
		events []l11WrapperEvent
	}{
		{name: "selected test missing", mode: "missing", events: exact},
		{name: "selected test duplicated", mode: "duplicate", events: exact},
		{name: "skip event", mode: "exact", events: append(append([]l11WrapperEvent(nil), exact...), l11WrapperEvent{Action: "skip", Test: l11FinalClosureSelectedTest + "/rootless_advisory_success"})},
		{name: "missing row pass", mode: "exact", events: removeL11WrapperEvent(exact, "pass", l11FinalClosureSelectedTest+"/strict_firecracker_success")},
		{name: "duplicate row pass", mode: "exact", events: append(append([]l11WrapperEvent(nil), exact...), l11WrapperEvent{Action: "pass", Test: l11FinalClosureSelectedTest + "/zero_resource_leaks"})},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			output, err := runL11SelectedWrapperFake(t, wrapper, mutation.mode, mutation.events)
			if err == nil {
				t.Fatalf("mutated wrapper event stream passed; output=%q", output)
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
	if _, statErr := os.Stat("l11_prepared_linux_final_closure_test.go"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("lookalike final selected test unexpectedly exists: %v", statErr)
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
