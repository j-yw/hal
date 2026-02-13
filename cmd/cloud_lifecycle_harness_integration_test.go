//go:build integration
// +build integration

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	cloudconfig "github.com/jywlabs/hal/internal/cloud/config"
	"github.com/jywlabs/hal/internal/template"
)

const (
	cloudLifecycleHarnessDefaultProfileName = "default"
	cloudLifecycleHarnessDefaultAuthProfile = "profile-lifecycle"
	cloudLifecycleHarnessPollInterval       = 5 * time.Millisecond
)

// cloudLifecycleHarnessFactorySnapshot captures mutable package-level wiring so
// the harness can restore it after each integration test.
type cloudLifecycleHarnessFactorySnapshot struct {
	runStoreFactory    func() (cloud.Store, error)
	autoStoreFactory   func() (cloud.Store, error)
	reviewStoreFactory func() (cloud.Store, error)
	listStoreFactory   func() (cloud.Store, error)
	statusStoreFactory func() (cloud.Store, error)
	logsStoreFactory   func() (cloud.Store, error)
	cancelStoreFactory func() (cloud.Store, error)
	pullStoreFactory   func() (cloud.Store, error)

	runConfigFactory    func() cloud.SubmitConfig
	autoConfigFactory   func() cloud.SubmitConfig
	reviewConfigFactory func() cloud.SubmitConfig

	runPollInterval    time.Duration
	autoPollInterval   time.Duration
	reviewPollInterval time.Duration
}

// cloudLifecycleIntegrationHarness provisions isolated workspace, store, and
// factory wiring for lifecycle integration scenarios.
type cloudLifecycleIntegrationHarness struct {
	WorkspaceDir string
	HalDir       string
	Store        *cloudLifecycleHarnessStore

	defaultProfile string
	defaultAuthID  string

	origFactories cloudLifecycleHarnessFactorySnapshot
	idCounter     int64
	tornDown      bool
}

// setupCloudLifecycleIntegrationHarness creates a fully isolated integration
// harness and registers teardown via t.Cleanup.
func setupCloudLifecycleIntegrationHarness(t *testing.T) *cloudLifecycleIntegrationHarness {
	t.Helper()

	workspaceDir := t.TempDir()
	h := &cloudLifecycleIntegrationHarness{
		WorkspaceDir:   workspaceDir,
		HalDir:         filepath.Join(workspaceDir, template.HalDir),
		Store:          newCloudLifecycleHarnessStore(),
		defaultProfile: cloudLifecycleHarnessDefaultProfileName,
		defaultAuthID:  cloudLifecycleHarnessDefaultAuthProfile,
	}

	h.setupWorkspace(t)
	h.setupCloudConfig(t)
	h.seedLinkedAuthProfile(h.defaultAuthID, "anthropic")
	h.installFactoryOverrides()

	t.Cleanup(h.Teardown)
	return h
}

// Teardown restores all package-level cloud wiring. It is safe to call more
// than once.
func (h *cloudLifecycleIntegrationHarness) Teardown() {
	if h.tornDown {
		return
	}
	h.tornDown = true

	runCloudStoreFactory = h.origFactories.runStoreFactory
	autoCloudStoreFactory = h.origFactories.autoStoreFactory
	reviewCloudStoreFactory = h.origFactories.reviewStoreFactory
	cloudListStoreFactory = h.origFactories.listStoreFactory
	cloudStatusStoreFactory = h.origFactories.statusStoreFactory
	cloudLogsStoreFactory = h.origFactories.logsStoreFactory
	cloudCancelStoreFactory = h.origFactories.cancelStoreFactory
	cloudPullStoreFactory = h.origFactories.pullStoreFactory

	runCloudConfigFactory = h.origFactories.runConfigFactory
	autoCloudConfigFactory = h.origFactories.autoConfigFactory
	reviewCloudConfigFactory = h.origFactories.reviewConfigFactory

	runCloudPollInterval = h.origFactories.runPollInterval
	autoCloudPollInterval = h.origFactories.autoPollInterval
	reviewCloudPollInterval = h.origFactories.reviewPollInterval
}

func (h *cloudLifecycleIntegrationHarness) setupWorkspace(t *testing.T) {
	t.Helper()

	setupHalDir(t, h.WorkspaceDir, map[string]string{
		template.PRDFile:      `{"project":"hal","description":"integration harness"}`,
		template.ProgressFile: "## cloud lifecycle integration harness\n",
		template.PromptFile:   "Follow the integration test prompt.\n",
		template.ConfigFile:   "model: claude\n",
	})

	reportsDir := filepath.Join(h.HalDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("failed to create reports directory: %v", err)
	}
}

func (h *cloudLifecycleIntegrationHarness) setupCloudConfig(t *testing.T) {
	t.Helper()

	wait := true
	cfg := &cloudconfig.CloudConfig{
		DefaultProfile: h.defaultProfile,
		Profiles: map[string]*cloudconfig.Profile{
			h.defaultProfile: {
				Endpoint:    "https://example.invalid/cloud",
				Mode:        cloudconfig.ModeUntilComplete,
				Repo:        "acme/hal",
				Base:        "main",
				Engine:      "claude",
				AuthProfile: h.defaultAuthID,
				Scope:       "lifecycle-integration",
				Wait:        &wait,
				PullPolicy:  cloudconfig.PullPolicyAll,
			},
		},
	}

	yamlData, err := marshalCloudConfig(cfg)
	if err != nil {
		t.Fatalf("failed to marshal cloud config: %v", err)
	}

	configPath := filepath.Join(h.HalDir, template.CloudConfigFile)
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		t.Fatalf("failed to write cloud config: %v", err)
	}
}

func (h *cloudLifecycleIntegrationHarness) seedLinkedAuthProfile(profileID, provider string) {
	if provider == "" {
		provider = "anthropic"
	}
	h.Store.profiles[profileID] = linkedCloudProfile(profileID, provider)
}

func (h *cloudLifecycleIntegrationHarness) installFactoryOverrides() {
	h.origFactories = cloudLifecycleHarnessFactorySnapshot{
		runStoreFactory:    runCloudStoreFactory,
		autoStoreFactory:   autoCloudStoreFactory,
		reviewStoreFactory: reviewCloudStoreFactory,
		listStoreFactory:   cloudListStoreFactory,
		statusStoreFactory: cloudStatusStoreFactory,
		logsStoreFactory:   cloudLogsStoreFactory,
		cancelStoreFactory: cloudCancelStoreFactory,
		pullStoreFactory:   cloudPullStoreFactory,

		runConfigFactory:    runCloudConfigFactory,
		autoConfigFactory:   autoCloudConfigFactory,
		reviewConfigFactory: reviewCloudConfigFactory,

		runPollInterval:    runCloudPollInterval,
		autoPollInterval:   autoCloudPollInterval,
		reviewPollInterval: reviewCloudPollInterval,
	}

	storeFactory := func() (cloud.Store, error) {
		return h.Store, nil
	}

	runCloudStoreFactory = storeFactory
	autoCloudStoreFactory = storeFactory
	reviewCloudStoreFactory = storeFactory
	cloudListStoreFactory = storeFactory
	cloudStatusStoreFactory = storeFactory
	cloudLogsStoreFactory = storeFactory
	cloudCancelStoreFactory = storeFactory
	cloudPullStoreFactory = storeFactory

	runCloudConfigFactory = func() cloud.SubmitConfig {
		return cloud.SubmitConfig{IDFunc: func() string { return h.nextID("run") }}
	}
	autoCloudConfigFactory = func() cloud.SubmitConfig {
		return cloud.SubmitConfig{IDFunc: func() string { return h.nextID("auto") }}
	}
	reviewCloudConfigFactory = func() cloud.SubmitConfig {
		return cloud.SubmitConfig{IDFunc: func() string { return h.nextID("review") }}
	}

	runCloudPollInterval = cloudLifecycleHarnessPollInterval
	autoCloudPollInterval = cloudLifecycleHarnessPollInterval
	reviewCloudPollInterval = cloudLifecycleHarnessPollInterval
}

func (h *cloudLifecycleIntegrationHarness) nextID(prefix string) string {
	n := atomic.AddInt64(&h.idCounter, 1)
	return fmt.Sprintf("%s-%03d", prefix, n)
}

// cloudLifecycleRunTransition tracks one run status transition for assertions.
type cloudLifecycleRunTransition struct {
	From      cloud.RunStatus
	To        cloud.RunStatus
	UpdatedAt time.Time
}

// cloudLifecycleAttemptTerminalization tracks one terminal attempt transition.
type cloudLifecycleAttemptTerminalization struct {
	AttemptID    string
	Status       cloud.AttemptStatus
	EndedAt      time.Time
	ErrorCode    *string
	ErrorMessage *string
}

// cloudLifecycleSnapshotRefs captures persisted run snapshot references.
type cloudLifecycleSnapshotRefs struct {
	InputSnapshotID       *string
	LatestSnapshotID      *string
	LatestSnapshotVersion int
}

// cloudLifecycleHarnessStore extends cloudMockStore with lifecycle-focused
// persistence behavior needed by integration scenarios.
type cloudLifecycleHarnessStore struct {
	*cloudMockStore

	attemptsByID            map[string]*cloud.Attempt
	runTransitions          map[string][]cloudLifecycleRunTransition
	attemptTerminalizations map[string][]cloudLifecycleAttemptTerminalization
	snapshotRefsByRun       map[string]cloudLifecycleSnapshotRefs
}

func newCloudLifecycleHarnessStore() *cloudLifecycleHarnessStore {
	return &cloudLifecycleHarnessStore{
		cloudMockStore:          newCloudMockStore(),
		attemptsByID:            make(map[string]*cloud.Attempt),
		runTransitions:          make(map[string][]cloudLifecycleRunTransition),
		attemptTerminalizations: make(map[string][]cloudLifecycleAttemptTerminalization),
		snapshotRefsByRun:       make(map[string]cloudLifecycleSnapshotRefs),
	}
}

func (s *cloudLifecycleHarnessStore) RunTransitions(runID string) []cloudLifecycleRunTransition {
	transitions := s.runTransitions[runID]
	copied := make([]cloudLifecycleRunTransition, len(transitions))
	copy(copied, transitions)
	return copied
}

func (s *cloudLifecycleHarnessStore) AttemptTerminalizationCount(runID string) int {
	return len(s.attemptTerminalizations[runID])
}

func (s *cloudLifecycleHarnessStore) AttemptTerminalizations(runID string) []cloudLifecycleAttemptTerminalization {
	records := s.attemptTerminalizations[runID]
	copied := make([]cloudLifecycleAttemptTerminalization, len(records))
	for i, record := range records {
		copied[i] = cloudLifecycleAttemptTerminalization{
			AttemptID:    record.AttemptID,
			Status:       record.Status,
			EndedAt:      record.EndedAt,
			ErrorCode:    cloneStringPointer(record.ErrorCode),
			ErrorMessage: cloneStringPointer(record.ErrorMessage),
		}
	}
	return copied
}

func (s *cloudLifecycleHarnessStore) SnapshotRefs(runID string) (cloudLifecycleSnapshotRefs, bool) {
	refs, ok := s.snapshotRefsByRun[runID]
	if !ok {
		return cloudLifecycleSnapshotRefs{}, false
	}
	return cloudLifecycleSnapshotRefs{
		InputSnapshotID:       cloneStringPointer(refs.InputSnapshotID),
		LatestSnapshotID:      cloneStringPointer(refs.LatestSnapshotID),
		LatestSnapshotVersion: refs.LatestSnapshotVersion,
	}, true
}

func (s *cloudLifecycleHarnessStore) EnqueueRun(ctx context.Context, run *cloud.Run) error {
	if err := s.cloudMockStore.EnqueueRun(ctx, run); err != nil {
		return err
	}
	s.runsByID[run.ID] = run
	return nil
}

func (s *cloudLifecycleHarnessStore) TransitionRun(_ context.Context, runID string, fromStatus, toStatus cloud.RunStatus) error {
	run, ok := s.runsByID[runID]
	if !ok {
		return cloud.ErrNotFound
	}
	if run.Status != fromStatus {
		return cloud.ErrConflict
	}

	now := time.Now().UTC()
	run.Status = toStatus
	run.UpdatedAt = now
	s.recordRunTransition(runID, fromStatus, toStatus, now)
	return nil
}

func (s *cloudLifecycleHarnessStore) CreateAttempt(_ context.Context, attempt *cloud.Attempt) error {
	if attempt == nil {
		return nil
	}
	s.attemptsByID[attempt.ID] = attempt
	s.activeAttempts[attempt.RunID] = attempt
	return nil
}

func (s *cloudLifecycleHarnessStore) GetAttempt(_ context.Context, attemptID string) (*cloud.Attempt, error) {
	attempt := s.findAttemptByID(attemptID)
	if attempt == nil {
		return nil, cloud.ErrNotFound
	}
	return attempt, nil
}

func (s *cloudLifecycleHarnessStore) TransitionAttempt(_ context.Context, attemptID string, status cloud.AttemptStatus, endedAt time.Time, errorCode, errorMessage *string) error {
	attempt := s.findAttemptByID(attemptID)
	if attempt == nil {
		return cloud.ErrNotFound
	}

	endedAtCopy := endedAt
	attempt.Status = status
	attempt.EndedAt = &endedAtCopy
	attempt.ErrorCode = cloneStringPointer(errorCode)
	attempt.ErrorMessage = cloneStringPointer(errorMessage)

	if status.IsTerminal() {
		if active, ok := s.activeAttempts[attempt.RunID]; ok && active != nil && active.ID == attemptID {
			delete(s.activeAttempts, attempt.RunID)
		}
	}

	s.attemptTerminalizations[attempt.RunID] = append(s.attemptTerminalizations[attempt.RunID], cloudLifecycleAttemptTerminalization{
		AttemptID:    attemptID,
		Status:       status,
		EndedAt:      endedAt,
		ErrorCode:    cloneStringPointer(errorCode),
		ErrorMessage: cloneStringPointer(errorMessage),
	})

	return nil
}

func (s *cloudLifecycleHarnessStore) SetCancelIntent(ctx context.Context, runID string) error {
	if err := s.cloudMockStore.SetCancelIntent(ctx, runID); err != nil {
		return err
	}

	run, ok := s.runsByID[runID]
	if !ok {
		return cloud.ErrNotFound
	}

	if !run.Status.IsTerminal() {
		fromStatus := run.Status
		now := time.Now().UTC()
		run.Status = cloud.RunStatusCanceled
		run.UpdatedAt = now
		s.recordRunTransition(runID, fromStatus, cloud.RunStatusCanceled, now)
	}

	return nil
}

func (s *cloudLifecycleHarnessStore) findAttemptByID(attemptID string) *cloud.Attempt {
	if attempt, ok := s.attemptsByID[attemptID]; ok {
		return attempt
	}

	for _, attempt := range s.activeAttempts {
		if attempt != nil && attempt.ID == attemptID {
			s.attemptsByID[attemptID] = attempt
			return attempt
		}
	}

	return nil
}

func (s *cloudLifecycleHarnessStore) recordRunTransition(runID string, fromStatus, toStatus cloud.RunStatus, updatedAt time.Time) {
	s.runTransitions[runID] = append(s.runTransitions[runID], cloudLifecycleRunTransition{
		From:      fromStatus,
		To:        toStatus,
		UpdatedAt: updatedAt,
	})
}

func (s *cloudLifecycleHarnessStore) InsertEvent(_ context.Context, event *cloud.Event) error {
	if event == nil {
		return nil
	}
	s.events[event.RunID] = append(s.events[event.RunID], event)
	return nil
}

func (s *cloudLifecycleHarnessStore) PutSnapshot(_ context.Context, snapshot *cloud.RunStateSnapshot) error {
	if snapshot == nil {
		return nil
	}
	current, ok := s.snapshots[snapshot.RunID]
	if !ok || snapshot.Version >= current.Version {
		s.snapshots[snapshot.RunID] = snapshot
	}
	return nil
}

func (s *cloudLifecycleHarnessStore) UpdateRunSnapshotRefs(_ context.Context, runID string, inputSnapshotID, latestSnapshotID *string, latestSnapshotVersion int) error {
	run, ok := s.runsByID[runID]
	if !ok {
		return cloud.ErrNotFound
	}

	refs := cloudLifecycleSnapshotRefs{
		InputSnapshotID:       cloneStringPointer(inputSnapshotID),
		LatestSnapshotID:      cloneStringPointer(latestSnapshotID),
		LatestSnapshotVersion: latestSnapshotVersion,
	}
	s.snapshotRefsByRun[runID] = refs

	run.InputSnapshotID = cloneStringPointer(refs.InputSnapshotID)
	run.LatestSnapshotID = cloneStringPointer(refs.LatestSnapshotID)
	run.LatestSnapshotVersion = refs.LatestSnapshotVersion
	run.UpdatedAt = time.Now().UTC()
	return nil
}

func cloneStringPointer(v *string) *string {
	if v == nil {
		return nil
	}
	copyValue := *v
	return &copyValue
}

func newHarnessTestRun(runID string, status cloud.RunStatus) *cloud.Run {
	now := time.Now().UTC().Truncate(time.Second)
	return &cloud.Run{
		ID:            runID,
		Repo:          "acme/hal",
		BaseBranch:    "main",
		WorkflowKind:  cloud.WorkflowKindRun,
		Engine:        "claude",
		AuthProfileID: cloudLifecycleHarnessDefaultAuthProfile,
		ScopeRef:      "scope",
		Status:        status,
		AttemptCount:  1,
		MaxAttempts:   3,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestCloudLifecycleHarnessStore_RecordsRunTransitions(t *testing.T) {
	store := newCloudLifecycleHarnessStore()
	run := newHarnessTestRun("run-transition-001", cloud.RunStatusQueued)
	if err := store.EnqueueRun(context.Background(), run); err != nil {
		t.Fatalf("enqueue run failed: %v", err)
	}

	transitions := []struct {
		from cloud.RunStatus
		to   cloud.RunStatus
	}{
		{from: cloud.RunStatusQueued, to: cloud.RunStatusClaimed},
		{from: cloud.RunStatusClaimed, to: cloud.RunStatusRunning},
		{from: cloud.RunStatusRunning, to: cloud.RunStatusSucceeded},
	}

	for _, transition := range transitions {
		if err := store.TransitionRun(context.Background(), run.ID, transition.from, transition.to); err != nil {
			t.Fatalf("transition %s->%s failed: %v", transition.from, transition.to, err)
		}
	}

	recorded := store.RunTransitions(run.ID)
	if len(recorded) != len(transitions) {
		t.Fatalf("recorded transitions = %d, want %d", len(recorded), len(transitions))
	}
	for i, want := range transitions {
		got := recorded[i]
		if got.From != want.from || got.To != want.to {
			t.Fatalf("transition[%d] = %s->%s, want %s->%s", i, got.From, got.To, want.from, want.to)
		}
		if got.UpdatedAt.IsZero() {
			t.Fatalf("transition[%d] has zero UpdatedAt", i)
		}
	}

	persisted, err := store.GetRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("GetRun failed: %v", err)
	}
	if persisted.Status != cloud.RunStatusSucceeded {
		t.Fatalf("persisted run status = %q, want %q", persisted.Status, cloud.RunStatusSucceeded)
	}
}

func TestCloudLifecycleHarnessStore_RecordsAttemptTerminalizations(t *testing.T) {
	store := newCloudLifecycleHarnessStore()
	run := newHarnessTestRun("run-attempt-001", cloud.RunStatusRunning)
	if err := store.EnqueueRun(context.Background(), run); err != nil {
		t.Fatalf("enqueue run failed: %v", err)
	}

	now := time.Now().UTC()
	attempt := &cloud.Attempt{
		ID:             "att-001",
		RunID:          run.ID,
		AttemptNumber:  1,
		WorkerID:       "worker-1",
		Status:         cloud.AttemptStatusActive,
		StartedAt:      now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(30 * time.Second),
	}
	if err := store.CreateAttempt(context.Background(), attempt); err != nil {
		t.Fatalf("CreateAttempt failed: %v", err)
	}

	errorCode := "lease_lost"
	errorMessage := "lease expired"
	endedAt := now.Add(15 * time.Second)
	if err := store.TransitionAttempt(context.Background(), attempt.ID, cloud.AttemptStatusFailed, endedAt, &errorCode, &errorMessage); err != nil {
		t.Fatalf("TransitionAttempt failed: %v", err)
	}

	if got := store.AttemptTerminalizationCount(run.ID); got != 1 {
		t.Fatalf("AttemptTerminalizationCount = %d, want 1", got)
	}
	terminalizations := store.AttemptTerminalizations(run.ID)
	if len(terminalizations) != 1 {
		t.Fatalf("terminalization records = %d, want 1", len(terminalizations))
	}
	record := terminalizations[0]
	if record.AttemptID != attempt.ID {
		t.Fatalf("record.AttemptID = %q, want %q", record.AttemptID, attempt.ID)
	}
	if record.Status != cloud.AttemptStatusFailed {
		t.Fatalf("record.Status = %q, want %q", record.Status, cloud.AttemptStatusFailed)
	}
	if record.ErrorCode == nil || *record.ErrorCode != "lease_lost" {
		t.Fatalf("record.ErrorCode = %v, want %q", record.ErrorCode, "lease_lost")
	}
	if record.ErrorMessage == nil || *record.ErrorMessage != "lease expired" {
		t.Fatalf("record.ErrorMessage = %v, want %q", record.ErrorMessage, "lease expired")
	}

	errorCode = "mutated"
	errorMessage = "mutated"
	if record.ErrorCode == nil || *record.ErrorCode != "lease_lost" {
		t.Fatalf("record.ErrorCode mutated unexpectedly: %v", record.ErrorCode)
	}
	if record.ErrorMessage == nil || *record.ErrorMessage != "lease expired" {
		t.Fatalf("record.ErrorMessage mutated unexpectedly: %v", record.ErrorMessage)
	}

	persistedAttempt, err := store.GetAttempt(context.Background(), attempt.ID)
	if err != nil {
		t.Fatalf("GetAttempt failed: %v", err)
	}
	if persistedAttempt.Status != cloud.AttemptStatusFailed {
		t.Fatalf("persisted attempt status = %q, want %q", persistedAttempt.Status, cloud.AttemptStatusFailed)
	}
	if _, err := store.GetActiveAttemptByRun(context.Background(), run.ID); !cloud.IsNotFound(err) {
		t.Fatalf("expected active attempt to be cleared, got err = %v", err)
	}
}

func TestCloudLifecycleHarnessStore_ExposesSnapshotRefs(t *testing.T) {
	store := newCloudLifecycleHarnessStore()
	run := newHarnessTestRun("run-snapshot-001", cloud.RunStatusQueued)
	if err := store.EnqueueRun(context.Background(), run); err != nil {
		t.Fatalf("enqueue run failed: %v", err)
	}

	inputSnapshotID := "snapshot-input-001"
	latestSnapshotID := "snapshot-latest-002"
	if err := store.UpdateRunSnapshotRefs(context.Background(), run.ID, &inputSnapshotID, &latestSnapshotID, 2); err != nil {
		t.Fatalf("UpdateRunSnapshotRefs failed: %v", err)
	}

	refs, ok := store.SnapshotRefs(run.ID)
	if !ok {
		t.Fatalf("SnapshotRefs(%q) not found", run.ID)
	}
	if refs.InputSnapshotID == nil || *refs.InputSnapshotID != "snapshot-input-001" {
		t.Fatalf("InputSnapshotID = %v, want %q", refs.InputSnapshotID, "snapshot-input-001")
	}
	if refs.LatestSnapshotID == nil || *refs.LatestSnapshotID != "snapshot-latest-002" {
		t.Fatalf("LatestSnapshotID = %v, want %q", refs.LatestSnapshotID, "snapshot-latest-002")
	}
	if refs.LatestSnapshotVersion != 2 {
		t.Fatalf("LatestSnapshotVersion = %d, want 2", refs.LatestSnapshotVersion)
	}

	inputSnapshotID = "mutated-input"
	latestSnapshotID = "mutated-latest"
	if refs.InputSnapshotID == nil || *refs.InputSnapshotID != "snapshot-input-001" {
		t.Fatalf("InputSnapshotID mutated unexpectedly: %v", refs.InputSnapshotID)
	}
	if refs.LatestSnapshotID == nil || *refs.LatestSnapshotID != "snapshot-latest-002" {
		t.Fatalf("LatestSnapshotID mutated unexpectedly: %v", refs.LatestSnapshotID)
	}

	if refs.InputSnapshotID != nil {
		*refs.InputSnapshotID = "local-mutation"
	}
	freshRefs, ok := store.SnapshotRefs(run.ID)
	if !ok {
		t.Fatalf("SnapshotRefs(%q) missing on second read", run.ID)
	}
	if freshRefs.InputSnapshotID == nil || *freshRefs.InputSnapshotID != "snapshot-input-001" {
		t.Fatalf("stored InputSnapshotID mutated unexpectedly: %v", freshRefs.InputSnapshotID)
	}

	persistedRun, err := store.GetRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("GetRun failed: %v", err)
	}
	if persistedRun.InputSnapshotID == nil || *persistedRun.InputSnapshotID != "snapshot-input-001" {
		t.Fatalf("persisted run InputSnapshotID = %v, want %q", persistedRun.InputSnapshotID, "snapshot-input-001")
	}
	if persistedRun.LatestSnapshotID == nil || *persistedRun.LatestSnapshotID != "snapshot-latest-002" {
		t.Fatalf("persisted run LatestSnapshotID = %v, want %q", persistedRun.LatestSnapshotID, "snapshot-latest-002")
	}
	if persistedRun.LatestSnapshotVersion != 2 {
		t.Fatalf("persisted run LatestSnapshotVersion = %d, want 2", persistedRun.LatestSnapshotVersion)
	}
}

func TestCloudLifecycleIntegrationHarness_IsolatedStatePerInvocation(t *testing.T) {
	h1 := setupCloudLifecycleIntegrationHarness(t)
	h2 := setupCloudLifecycleIntegrationHarness(t)

	if h1.WorkspaceDir == h2.WorkspaceDir {
		t.Fatalf("workspace directories must differ: %s", h1.WorkspaceDir)
	}
	if h1.HalDir == h2.HalDir {
		t.Fatalf("hal directories must differ: %s", h1.HalDir)
	}
	if h1.Store == h2.Store {
		t.Fatal("harness stores must be isolated per invocation")
	}

	markerPath := filepath.Join(h1.HalDir, "reports", "h1-only.txt")
	if err := os.WriteFile(markerPath, []byte("h1"), 0644); err != nil {
		t.Fatalf("failed to write marker file: %v", err)
	}

	if _, err := os.Stat(filepath.Join(h2.HalDir, "reports", "h1-only.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected h2 workspace isolation; stat err = %v", err)
	}
}

func TestCloudLifecycleIntegrationHarness_WiresEphemeralDependencies(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)

	storeFactories := []struct {
		name    string
		factory func() (cloud.Store, error)
	}{
		{name: "run", factory: runCloudStoreFactory},
		{name: "auto", factory: autoCloudStoreFactory},
		{name: "review", factory: reviewCloudStoreFactory},
		{name: "list", factory: cloudListStoreFactory},
		{name: "status", factory: cloudStatusStoreFactory},
		{name: "logs", factory: cloudLogsStoreFactory},
		{name: "cancel", factory: cloudCancelStoreFactory},
		{name: "pull", factory: cloudPullStoreFactory},
	}

	for _, tt := range storeFactories {
		t.Run("store_factory_"+tt.name, func(t *testing.T) {
			store, err := tt.factory()
			if err != nil {
				t.Fatalf("factory returned unexpected error: %v", err)
			}
			if store != h.Store {
				t.Fatalf("factory returned unexpected store instance: got %T", store)
			}
		})
	}

	configFactories := []struct {
		name   string
		prefix string
		build  func() cloud.SubmitConfig
	}{
		{name: "run", prefix: "run", build: runCloudConfigFactory},
		{name: "auto", prefix: "auto", build: autoCloudConfigFactory},
		{name: "review", prefix: "review", build: reviewCloudConfigFactory},
	}

	for _, tt := range configFactories {
		t.Run("config_factory_"+tt.name, func(t *testing.T) {
			cfg := tt.build()
			if cfg.IDFunc == nil {
				t.Fatalf("%s config factory must provide IDFunc", tt.name)
			}
			id1 := cfg.IDFunc()
			id2 := cfg.IDFunc()
			if id1 == id2 {
				t.Fatalf("%s IDFunc must generate unique IDs, got %q", tt.name, id1)
			}
			if !strings.HasPrefix(id1, tt.prefix+"-") {
				t.Fatalf("%s ID %q must start with prefix %q", tt.name, id1, tt.prefix+"-")
			}
		})
	}

	run := &cloud.Run{ID: "run-store-check", Status: cloud.RunStatusQueued}
	if err := h.Store.EnqueueRun(context.Background(), run); err != nil {
		t.Fatalf("enqueue run failed: %v", err)
	}
	persisted, err := h.Store.GetRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("get run failed: %v", err)
	}
	if persisted.ID != run.ID {
		t.Fatalf("persisted run ID = %q, want %q", persisted.ID, run.ID)
	}
}

func TestCloudLifecycleIntegrationHarness_SetupAndTeardownHelpers(t *testing.T) {
	origRunStoreFactory := functionPointer(runCloudStoreFactory)
	origAutoStoreFactory := functionPointer(autoCloudStoreFactory)
	origRunConfigFactory := functionPointer(runCloudConfigFactory)
	origRunPoll := runCloudPollInterval

	h := setupCloudLifecycleIntegrationHarness(t)

	for _, relPath := range []string{template.PRDFile, template.ProgressFile, template.CloudConfigFile} {
		absPath := filepath.Join(h.HalDir, relPath)
		if _, err := os.Stat(absPath); err != nil {
			t.Fatalf("expected setup helper to create %s: %v", absPath, err)
		}
	}

	cfg, err := cloudconfig.Load(filepath.Join(h.HalDir, template.CloudConfigFile))
	if err != nil {
		t.Fatalf("failed to load generated cloud config: %v", err)
	}
	profile := cfg.GetProfile("")
	if profile == nil {
		t.Fatal("default cloud profile must be present")
	}
	if profile.AuthProfile != cloudLifecycleHarnessDefaultAuthProfile {
		t.Fatalf("authProfile = %q, want %q", profile.AuthProfile, cloudLifecycleHarnessDefaultAuthProfile)
	}
	if profile.Mode != cloudconfig.ModeUntilComplete {
		t.Fatalf("mode = %q, want %q", profile.Mode, cloudconfig.ModeUntilComplete)
	}
	if profile.PullPolicy != cloudconfig.PullPolicyAll {
		t.Fatalf("pullPolicy = %q, want %q", profile.PullPolicy, cloudconfig.PullPolicyAll)
	}
	if profile.Wait == nil || !*profile.Wait {
		t.Fatalf("wait = %v, want true", profile.Wait)
	}

	if runCloudPollInterval != cloudLifecycleHarnessPollInterval {
		t.Fatalf("runCloudPollInterval = %s, want %s", runCloudPollInterval, cloudLifecycleHarnessPollInterval)
	}

	h.Teardown()
	h.Teardown() // idempotency

	if got := functionPointer(runCloudStoreFactory); got != origRunStoreFactory {
		t.Fatalf("runCloudStoreFactory was not restored")
	}
	if got := functionPointer(autoCloudStoreFactory); got != origAutoStoreFactory {
		t.Fatalf("autoCloudStoreFactory was not restored")
	}
	if got := functionPointer(runCloudConfigFactory); got != origRunConfigFactory {
		t.Fatalf("runCloudConfigFactory was not restored")
	}
	if runCloudPollInterval != origRunPoll {
		t.Fatalf("runCloudPollInterval = %s, want %s", runCloudPollInterval, origRunPoll)
	}
}

func functionPointer(fn interface{}) uintptr {
	v := reflect.ValueOf(fn)
	if !v.IsValid() || v.IsNil() {
		return 0
	}
	return v.Pointer()
}
