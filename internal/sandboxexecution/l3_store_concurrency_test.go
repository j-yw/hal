package sandboxexecution

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestL3ExecutionLockSerializesProcesses(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-process-lock", time.Now().UTC())); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	signals := t.TempDir()
	releaseFirst := filepath.Join(signals, "release-first")

	first := startL3ExecutionLockHelper(t, store.Root(), "exec-process-lock",
		filepath.Join(signals, "first-ready"),
		filepath.Join(signals, "first-entered"),
		releaseFirst,
	)
	waitForL3ExecutionLockSignal(t, filepath.Join(signals, "first-entered"))

	second := startL3ExecutionLockHelper(t, store.Root(), "exec-process-lock",
		filepath.Join(signals, "second-ready"),
		filepath.Join(signals, "second-entered"),
		"",
	)
	waitForL3ExecutionLockSignal(t, filepath.Join(signals, "second-ready"))
	select {
	case err := <-second:
		t.Fatalf("second lock process exited before first released: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(filepath.Join(signals, "second-entered")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second process entered while first held lock; Stat() error = %v", err)
	}

	if err := os.WriteFile(releaseFirst, []byte("release"), 0o600); err != nil {
		t.Fatalf("WriteFile(release signal) error: %v", err)
	}
	if err := <-first; err != nil {
		t.Fatalf("first lock process error: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second lock process error: %v", err)
	}
	waitForL3ExecutionLockSignal(t, filepath.Join(signals, "second-entered"))
}

func TestL3ExecutionLockHelper(t *testing.T) {
	root := os.Getenv("HAL_L3_TEST_STORE_ROOT")
	if root == "" {
		t.Skip("helper process only")
	}
	executionID := os.Getenv("HAL_L3_TEST_EXECUTION_ID")
	readyPath := os.Getenv("HAL_L3_TEST_READY_PATH")
	enteredPath := os.Getenv("HAL_L3_TEST_ENTERED_PATH")
	releasePath := os.Getenv("HAL_L3_TEST_RELEASE_PATH")
	if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("write ready signal: %v", err)
	}
	err := NewStore(root).WithExecutionLock(executionID, func() error {
		if err := os.WriteFile(enteredPath, []byte("entered"), 0o600); err != nil {
			return err
		}
		if releasePath == "" {
			return nil
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(releasePath); err == nil {
				return nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("timed out waiting for lock release signal")
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	if err != nil {
		t.Fatalf("WithExecutionLock() error: %v", err)
	}
}

func TestL3ExecutionLockSerializesContendersAndReleasesAfterSuccess(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-lock", time.Now().UTC())); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- store.WithExecutionLock("exec-lock", func() error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	<-firstEntered

	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- store.WithExecutionLock("exec-lock", func() error {
			close(secondEntered)
			return nil
		})
	}()

	select {
	case <-secondEntered:
		t.Fatal("second lock callback entered before first callback released")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first WithExecutionLock() error: %v", err)
	}
	select {
	case <-secondEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("second lock callback did not enter after first callback released")
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second WithExecutionLock() error: %v", err)
	}
}

func TestL3LockedExecutionStoreAllowsNestedRetrySafeManifestUpdates(t *testing.T) {
	store := newTestStore(t)
	manifest := testManifest("exec-locked-store", time.Now().UTC())
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}

	var escaped Store
	err := store.WithLockedExecution("exec-locked-store", func(locked Store) error {
		escaped = locked
		return locked.UpdateManifest("exec-locked-store", func(current *Manifest) error {
			current.Status = StatusFailed
			return nil
		})
	})
	if err != nil {
		t.Fatalf("WithLockedExecution() nested update error: %v", err)
	}
	loaded, err := store.LoadManifest("exec-locked-store")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if loaded.Status != StatusFailed {
		t.Fatalf("nested update status = %q, want failed", loaded.Status)
	}

	// A scoped store that escapes its callback must not retain the lock bypass.
	if err := escaped.UpdateManifest("exec-locked-store", func(current *Manifest) error {
		current.Status = StatusCanceled
		return nil
	}); err != nil {
		t.Fatalf("escaped store update error: %v", err)
	}
	loaded, err = store.LoadManifest("exec-locked-store")
	if err != nil {
		t.Fatalf("LoadManifest(after escaped update) error: %v", err)
	}
	if loaded.Status != StatusCanceled {
		t.Fatalf("escaped update status = %q, want canceled", loaded.Status)
	}
}

func startL3ExecutionLockHelper(t *testing.T, root, executionID, readyPath, enteredPath, releasePath string) <-chan error {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestL3ExecutionLockHelper$")
	command.Env = append(os.Environ(),
		"HAL_L3_TEST_STORE_ROOT="+root,
		"HAL_L3_TEST_EXECUTION_ID="+executionID,
		"HAL_L3_TEST_READY_PATH="+readyPath,
		"HAL_L3_TEST_ENTERED_PATH="+enteredPath,
		"HAL_L3_TEST_RELEASE_PATH="+releasePath,
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start lock helper: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
	}()
	return done
}

func waitForL3ExecutionLockSignal(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat lock helper signal: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for lock helper signal %q", filepath.Base(path))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestL3ExecutionLockReleasesAfterCallbackError(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-lock-error", time.Now().UTC())); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	sentinel := errors.New("checkpoint failed")
	if err := store.WithExecutionLock("exec-lock-error", func() error {
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("WithExecutionLock() error = %v, want sentinel", err)
	}

	entered := false
	if err := store.WithExecutionLock("exec-lock-error", func() error {
		entered = true
		return nil
	}); err != nil {
		t.Fatalf("second WithExecutionLock() error: %v", err)
	}
	if !entered {
		t.Fatal("second lock callback did not run after callback error")
	}
}

func TestL3UpdateManifestPreventsConcurrentLostUpdates(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-update", time.Now().UTC())); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}

	const updates = 24
	errs := make(chan error, updates)
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < updates; i++ {
		i := i
		go func() {
			start.Wait()
			errs <- store.UpdateManifest("exec-update", func(manifest *Manifest) error {
				manifest.Artifacts = append(manifest.Artifacts, Artifact{
					ID:   fmt.Sprintf("artifact-%02d", i),
					Name: fmt.Sprintf("Artifact %02d", i),
					Type: "text",
				})
				return nil
			})
		}()
	}
	start.Done()
	for i := 0; i < updates; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("UpdateManifest() error: %v", err)
		}
	}

	manifest, err := store.LoadManifest("exec-update")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if len(manifest.Artifacts) != updates {
		t.Fatalf("artifact count = %d, want %d; concurrent update was lost", len(manifest.Artifacts), updates)
	}
	seen := make(map[string]bool, updates)
	for _, artifact := range manifest.Artifacts {
		seen[artifact.ID] = true
	}
	for i := 0; i < updates; i++ {
		id := fmt.Sprintf("artifact-%02d", i)
		if !seen[id] {
			t.Errorf("manifest missing concurrent update %q", id)
		}
	}
}

func TestL3UpdateManifestCallbackErrorDoesNotPersistMutation(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-update-error", time.Now().UTC())); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	sentinel := errors.New("do not commit")
	err := store.UpdateManifest("exec-update-error", func(manifest *Manifest) error {
		manifest.Status = StatusSucceeded
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("UpdateManifest() error = %v, want sentinel", err)
	}
	manifest, loadErr := store.LoadManifest("exec-update-error")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != StatusRunning {
		t.Fatalf("status after rejected update = %q, want %q", manifest.Status, StatusRunning)
	}
}

func TestL3UpsertArtifactMetadataDeduplicatesRetriesAndPreservesUnrelatedEntries(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-artifacts", time.Now().UTC())); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}

	sizeOne := int64(1)
	first := ArtifactMetadata{
		Collected: []ArtifactMetadataEntry{
			{
				ID:         "core-prd",
				Name:       "PRD",
				Type:       "json",
				Path:       ".hal/prd.json",
				StoredPath: "exec-artifacts/artifacts/core/prd.json",
				SizeBytes:  &sizeOne,
			},
			{
				ID:         "unrelated",
				Name:       "Progress",
				Type:       "text",
				Path:       ".hal/progress.txt",
				StoredPath: "exec-artifacts/artifacts/core/progress.txt",
			},
		},
		Partial: []ArtifactMetadataEntry{{
			ID:   "reports",
			Name: "Reports",
			Path: ".hal/reports.tar",
		}},
		Warnings: []ArtifactWarning{{
			Phase:   "copy_out",
			Message: "sandbox reports artifact is unavailable",
			Artifact: ArtifactMetadataEntry{
				ID:   "reports",
				Name: "Reports",
				Path: ".hal/reports.tar",
			},
		}},
	}
	if err := store.UpsertArtifactMetadata("exec-artifacts", first); err != nil {
		t.Fatalf("first UpsertArtifactMetadata() error: %v", err)
	}

	sizeTwo := int64(2)
	retry := ArtifactMetadata{
		Collected: []ArtifactMetadataEntry{{
			ID:         "core-prd",
			Name:       "PRD",
			Type:       "json",
			Path:       ".hal/prd.json",
			StoredPath: "exec-artifacts/artifacts/core/prd.json",
			SizeBytes:  &sizeTwo,
		}},
		Partial:  append([]ArtifactMetadataEntry(nil), first.Partial...),
		Warnings: append([]ArtifactWarning(nil), first.Warnings...),
	}
	if err := store.UpsertArtifactMetadata("exec-artifacts", retry); err != nil {
		t.Fatalf("retry UpsertArtifactMetadata() error: %v", err)
	}

	manifest, err := store.LoadManifest("exec-artifacts")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil")
	}
	if got := len(manifest.ArtifactMetadata.Collected); got != 2 {
		t.Fatalf("collected count = %d, want 2", got)
	}
	if got := len(manifest.ArtifactMetadata.Partial); got != 1 {
		t.Fatalf("partial count = %d, want 1", got)
	}
	if got := len(manifest.ArtifactMetadata.Warnings); got != 1 {
		t.Fatalf("warning count = %d, want 1", got)
	}

	var retried, unrelated *ArtifactMetadataEntry
	for i := range manifest.ArtifactMetadata.Collected {
		entry := &manifest.ArtifactMetadata.Collected[i]
		switch entry.ID {
		case "core-prd":
			retried = entry
		case "unrelated":
			unrelated = entry
		}
	}
	if retried == nil || retried.SizeBytes == nil || *retried.SizeBytes != sizeTwo {
		t.Fatalf("retried entry = %#v, want latest metadata", retried)
	}
	if unrelated == nil {
		t.Fatal("unrelated collected metadata was discarded")
	}
}

func TestL3UpsertArtifactMetadataPromotesPathStablePartialToCollected(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-artifact-promotion", time.Now().UTC())); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	partial := ArtifactMetadata{Partial: []ArtifactMetadataEntry{{
		Name: "Reports",
		Path: ".hal/reports.tar",
	}}}
	if err := store.UpsertArtifactMetadata("exec-artifact-promotion", partial); err != nil {
		t.Fatalf("partial UpsertArtifactMetadata() error: %v", err)
	}
	collected := ArtifactMetadata{Collected: []ArtifactMetadataEntry{{
		Name:       "Reports",
		Type:       "archive",
		Path:       ".hal/reports.tar",
		StoredPath: "exec-artifact-promotion/artifacts/reports.tar",
	}}}
	if err := store.UpsertArtifactMetadata("exec-artifact-promotion", collected); err != nil {
		t.Fatalf("collected UpsertArtifactMetadata() error: %v", err)
	}

	manifest, err := store.LoadManifest("exec-artifact-promotion")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil")
	}
	if got := len(manifest.ArtifactMetadata.Collected); got != 1 {
		t.Fatalf("collected count = %d, want 1", got)
	}
	if got := len(manifest.ArtifactMetadata.Partial); got != 0 {
		t.Fatalf("partial count = %d, want 0 after collection", got)
	}
}
