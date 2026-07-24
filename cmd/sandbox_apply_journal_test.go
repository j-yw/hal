package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

const sandboxApplyOutcomeUnknownReason = sandboxworkspace.SyncOutApplyEligibilityReason("apply_outcome_unknown")

func TestSandboxApplyPersistsSanitizedIntentBeforeHostMutation(t *testing.T) {
	store, executionID := newSandboxApplyJournalFixture(t, "apply-intent-before-mutation")
	projectDir := filepath.Join(t.TempDir(), "host-token=secret")
	if err := store.UpdateManifest(executionID, func(manifest *sandboxexecution.Manifest) error {
		manifest.Command = []string{"preserve", "concurrent-state"}
		return nil
	}); err != nil {
		t.Fatalf("seed unrelated manifest state: %v", err)
	}

	result, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
		ExecutionID: executionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  projectDir,
		Options:     sandboxSyncOutOptions{Enabled: true, Apply: true},
	}, func(_ context.Context, req sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
		manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
		assertSandboxApplyUnknownOutcomeMarker(t, manifest, "committed-patch")
		encoded, marshalErr := json.Marshal(manifest.SyncOutApply)
		if marshalErr != nil {
			t.Fatalf("Marshal(intent marker) error: %v", marshalErr)
		}
		for _, unsafe := range []string{projectDir, req.PayloadPath, "token=secret"} {
			if unsafe != "" && strings.Contains(string(encoded), unsafe) {
				t.Fatalf("durable apply intent leaked %q: %s", unsafe, encoded)
			}
		}
		return sandboxworkspace.SafeApplyResult{
			Status:     sandboxworkspace.SafeApplyStatusApplied,
			Applied:    true,
			ArtifactID: "committed-patch",
			Mode:       sandboxworkspace.SyncOutApplyModePatch,
		}, nil
	})
	if err != nil {
		t.Fatalf("applySandboxSyncOut() error: %v", err)
	}
	if !result.Applied || result.Status != sandboxworkspace.SafeApplyStatusApplied {
		t.Fatalf("apply result = %#v, want applied", result)
	}
	manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
	if manifest.SyncOutApply == nil || !manifest.SyncOutApply.Applied {
		t.Fatalf("persisted apply result = %#v, want applied", manifest.SyncOutApply)
	}
	if got := strings.Join(manifest.Command, " "); got != "preserve concurrent-state" {
		t.Fatalf("unrelated manifest state = %q, want preserved", got)
	}
}

func TestSandboxApplyErrorLeavesUnknownOutcomeAndRetryFailsClosed(t *testing.T) {
	store, executionID := newSandboxApplyJournalFixture(t, "apply-error-ambiguous")
	applyErr := errors.New("host mutation boundary failed")
	firstCalls := 0

	_, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
		ExecutionID: executionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  t.TempDir(),
		Options:     sandboxSyncOutOptions{Enabled: true, Apply: true},
	}, func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
		firstCalls++
		return sandboxworkspace.SafeApplyResult{
			Status:     sandboxworkspace.SafeApplyStatusApplied,
			Applied:    true,
			ArtifactID: "committed-patch",
			Mode:       sandboxworkspace.SyncOutApplyModePatch,
		}, applyErr
	})
	if !errors.Is(err, applyErr) {
		t.Fatalf("first apply error = %v, want %v", err, applyErr)
	}
	if firstCalls != 1 {
		t.Fatalf("first apply calls = %d, want 1", firstCalls)
	}
	assertSandboxApplyUnknownOutcomeMarker(t, mustLoadSandboxExecutionManifest(t, store, executionID), "committed-patch")

	retryCalls := 0
	_, retryErr := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
		ExecutionID: executionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  t.TempDir(),
		Options:     sandboxSyncOutOptions{Enabled: true, Apply: true},
	}, func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
		retryCalls++
		return sandboxworkspace.SafeApplyResult{Status: sandboxworkspace.SafeApplyStatusApplied, Applied: true}, nil
	})
	if retryErr == nil || !strings.Contains(retryErr.Error(), "manual inspection") {
		t.Fatalf("retry error = %v, want fail-closed manual inspection", retryErr)
	}
	if retryCalls != 0 {
		t.Fatalf("retry invoked host mutation %d times, want 0", retryCalls)
	}
	assertSandboxApplyUnknownOutcomeMarker(t, mustLoadSandboxExecutionManifest(t, store, executionID), "committed-patch")
}

func TestSandboxApplySerializesMutationAndKeepsAppliedResultMonotonic(t *testing.T) {
	store, executionID := newSandboxApplyJournalFixture(t, "apply-concurrent")
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	secondEntered := make(chan struct{}, 1)
	secondDone := make(chan error, 1)

	go func() {
		_, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
			ExecutionID: executionID,
			Purpose:     sandboxexecution.PurposeRun,
			ProjectDir:  t.TempDir(),
			Options:     sandboxSyncOutOptions{Enabled: true, Apply: true},
		}, func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
			close(firstEntered)
			<-releaseFirst
			return sandboxworkspace.SafeApplyResult{
				Status:     sandboxworkspace.SafeApplyStatusApplied,
				Applied:    true,
				ArtifactID: "committed-patch",
				Mode:       sandboxworkspace.SyncOutApplyModePatch,
			}, nil
		})
		firstDone <- err
	}()

	select {
	case <-firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first host mutation did not start")
	}
	go func() {
		_, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
			ExecutionID: executionID,
			Purpose:     sandboxexecution.PurposeRun,
			ProjectDir:  t.TempDir(),
			Options:     sandboxSyncOutOptions{Enabled: true, Apply: true},
		}, func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
			secondEntered <- struct{}{}
			return sandboxworkspace.SafeApplyResult{
				Status:     sandboxworkspace.SafeApplyStatusApplied,
				Applied:    true,
				ArtifactID: "committed-patch",
				Mode:       sandboxworkspace.SyncOutApplyModePatch,
			}, nil
		})
		secondDone <- err
	}()

	mutatedTwice := false
	select {
	case <-secondEntered:
		mutatedTwice = true
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if err := receiveSandboxApplyJournalError(t, firstDone); err != nil {
		t.Fatalf("first apply error: %v", err)
	}
	secondErr := receiveSandboxApplyJournalError(t, secondDone)
	if mutatedTwice {
		t.Fatal("concurrent apply invoked the host mutation boundary twice")
	}
	if secondErr == nil {
		t.Fatal("second apply error = nil, want already-applied rejection")
	}

	handoffCalls := 0
	_, handoffErr := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
		ExecutionID: executionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  t.TempDir(),
		Options:     sandboxSyncOutOptions{Enabled: true, Apply: false},
	}, func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
		handoffCalls++
		return sandboxworkspace.SafeApplyResult{
			Status:  sandboxworkspace.SafeApplyStatusHandoffRequired,
			Applied: false,
			Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{
				sandboxworkspace.SyncOutApplyEligibilityReasonApplyDisabled,
			},
		}, nil
	})
	if handoffErr != nil {
		t.Fatalf("post-success handoff lookup error: %v", handoffErr)
	}
	if handoffCalls != 0 {
		t.Fatalf("post-success handoff invoked applier %d times, want 0", handoffCalls)
	}
	manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
	if manifest.SyncOutApply == nil || !manifest.SyncOutApply.Applied ||
		manifest.SyncOutApply.Status != sandboxworkspace.SafeApplyStatusApplied {
		t.Fatalf("successful apply was overwritten: %#v", manifest.SyncOutApply)
	}
}

func TestSandboxApplyLockCoversMutationAndAtomicManifestUpdates(t *testing.T) {
	store, executionID := newSandboxApplyJournalFixture(t, "apply-lock-update")
	updateEntered := make(chan struct{})
	updateDone := make(chan error, 1)
	enteredDuringMutation := false

	_, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
		ExecutionID: executionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  t.TempDir(),
		Options:     sandboxSyncOutOptions{Enabled: true, Apply: true},
	}, func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
		go func() {
			updateDone <- store.UpdateManifest(executionID, func(manifest *sandboxexecution.Manifest) error {
				close(updateEntered)
				manifest.Command = []string{"unrelated", "concurrent", "update"}
				return nil
			})
		}()
		select {
		case <-updateEntered:
			enteredDuringMutation = true
		case <-time.After(100 * time.Millisecond):
		}
		return sandboxworkspace.SafeApplyResult{
			Status:     sandboxworkspace.SafeApplyStatusApplied,
			Applied:    true,
			ArtifactID: "committed-patch",
			Mode:       sandboxworkspace.SyncOutApplyModePatch,
		}, nil
	})
	if err != nil {
		t.Fatalf("applySandboxSyncOut() error: %v", err)
	}
	if updateErr := receiveSandboxApplyJournalError(t, updateDone); updateErr != nil {
		t.Fatalf("concurrent manifest update error: %v", updateErr)
	}
	if enteredDuringMutation {
		t.Fatal("manifest updater entered while the host mutation boundary was active")
	}
	manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
	if manifest.SyncOutApply == nil || !manifest.SyncOutApply.Applied {
		t.Fatalf("persisted apply result = %#v, want applied", manifest.SyncOutApply)
	}
	if got := strings.Join(manifest.Command, " "); got != "unrelated concurrent update" {
		t.Fatalf("unrelated concurrent state = %q, want preserved", got)
	}
}

func TestSandboxApplySafeHandoffCanLaterApply(t *testing.T) {
	store, executionID := newSandboxApplyJournalFixture(t, "apply-after-handoff")

	handoff, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
		ExecutionID: executionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  t.TempDir(),
		Options:     sandboxSyncOutOptions{Enabled: true, Apply: false},
	}, func(_ context.Context, _ sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
		return sandboxworkspace.SafeApplyResult{
			Status:  sandboxworkspace.SafeApplyStatusHandoffRequired,
			Applied: false,
			Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{
				sandboxworkspace.SyncOutApplyEligibilityReasonApplyDisabled,
			},
		}, nil
	})
	if err != nil {
		t.Fatalf("handoff apply error: %v", err)
	}
	if handoff.Status != sandboxworkspace.SafeApplyStatusHandoffRequired ||
		!sandboxApplyReasonsContain(handoff.Reasons, sandboxworkspace.SyncOutApplyEligibilityReasonApplyDisabled) {
		t.Fatalf("handoff result = %#v, want apply-disabled compatibility result", handoff)
	}

	applyCalls := 0
	applied, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
		ExecutionID: executionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  t.TempDir(),
		Options:     sandboxSyncOutOptions{Enabled: true, Apply: true},
	}, func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
		applyCalls++
		assertSandboxApplyUnknownOutcomeMarker(t, mustLoadSandboxExecutionManifest(t, store, executionID), "committed-patch")
		return sandboxworkspace.SafeApplyResult{
			Status:     sandboxworkspace.SafeApplyStatusApplied,
			Applied:    true,
			ArtifactID: "committed-patch",
			Mode:       sandboxworkspace.SyncOutApplyModePatch,
		}, nil
	})
	if err != nil {
		t.Fatalf("apply after handoff error: %v", err)
	}
	if applyCalls != 1 || !applied.Applied {
		t.Fatalf("apply after handoff calls/result = %d/%#v, want one applied result", applyCalls, applied)
	}
}

func newSandboxApplyJournalFixture(t *testing.T, executionID string) (sandboxexecution.Store, string) {
	t.Helper()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	saveSandboxSyncOutApplyManifest(t, store, executionID, sandboxexecution.PurposeRun, sandboxexecution.ArtifactMetadata{
		Collected: []sandboxexecution.ArtifactMetadataEntry{
			sandboxSyncOutApplyCollected(
				"committed-patch",
				".hal/sync/committed.patch",
				executionID+"/artifacts/sync/committed.patch",
			),
		},
	})
	return store, executionID
}

func assertSandboxApplyUnknownOutcomeMarker(t *testing.T, manifest *sandboxexecution.Manifest, artifactID string) {
	t.Helper()
	if manifest == nil || manifest.SyncOut == nil || manifest.SyncOutApply == nil {
		t.Fatalf("durable apply journal = syncOut %#v / syncOutApply %#v, want intent marker", manifest.SyncOut, manifest.SyncOutApply)
	}
	marker := manifest.SyncOutApply
	if marker.Status != sandboxworkspace.SafeApplyStatusHandoffRequired || marker.Applied || marker.DryRunPassed {
		t.Fatalf("durable apply intent marker = %#v, want non-applied unknown outcome", marker)
	}
	if marker.ArtifactID != artifactID || marker.Mode != sandboxworkspace.SyncOutApplyModePatch {
		t.Fatalf("durable apply intent artifact/mode = %q/%q, want %q/patch", marker.ArtifactID, marker.Mode, artifactID)
	}
	if !sandboxApplyReasonsContain(marker.Reasons, sandboxApplyOutcomeUnknownReason) {
		t.Fatalf("durable apply intent reasons = %#v, want %q", marker.Reasons, sandboxApplyOutcomeUnknownReason)
	}
}

func receiveSandboxApplyJournalError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for apply journal operation")
		return nil
	}
}
