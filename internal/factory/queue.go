package factory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

const (
	queueFileName           = "queue.json"
	queueLockDirName        = "queue.lock"
	queueLockOwnerFileName  = "owner.json"
	queueLockOwnerPrefix    = "owner-"
	queueLockOwnerSuffix    = ".json"
	queueLockWaitTimeout    = 5 * time.Second
	queueLockRetryDelay     = 10 * time.Millisecond
	queueLockStaleAfter     = 10 * time.Minute
	queueClaimLeaseDuration = 24 * time.Hour
)

var saveQueueFile = saveStoreFile

// queueState is the durable on-disk representation of the local factory queue.
type queueState struct {
	Entries []QueueEntry `json:"entries"`
}

type queueLockMetadata struct {
	PID        int       `json:"pid,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	AcquiredAt time.Time `json:"acquiredAt"`
	Token      string    `json:"token,omitempty"`
}

type queueLockSnapshot struct {
	acquiredAt time.Time
	ownerData  []byte
	ownerName  string
	hasOwner   bool
	modTime    time.Time
}

// QueueUpdateFunc applies a read-modify-write mutation to queue entries.
type QueueUpdateFunc func([]QueueEntry) ([]QueueEntry, error)

// QueueOperationOptions injects non-deterministic queue operation sources.
type QueueOperationOptions struct {
	Now                  func() time.Time
	NewQueueID           func() (string, error)
	Claim                *QueueClaim
	ClaimLeaseDuration   time.Duration
	ExpectedClaimedAt    *time.Time
	ExpectedAttemptCount int
}

// QueuePath returns the committed queue state file path.
func (s Store) QueuePath() string {
	if s.root == "" {
		return ""
	}
	return filepath.Join(s.root, queueFileName)
}

// LoadQueue loads the committed queue state. A missing queue file is empty
// state and does not create global config directories.
func (s Store) LoadQueue() ([]QueueEntry, error) {
	return s.loadQueue()
}

// SaveQueue persists the queue state under Hal's global factory store.
func (s Store) SaveQueue(entries []QueueEntry) error {
	return s.withQueueLock(func() error {
		if _, err := s.loadQueue(); err != nil {
			return err
		}
		return s.saveQueue(entries)
	})
}

// UpdateQueue serializes a queue read-modify-write mutation under the local
// queue lock. Future queue commands should use this instead of separate
// LoadQueue and SaveQueue calls.
func (s Store) UpdateQueue(update QueueUpdateFunc) ([]QueueEntry, error) {
	if update == nil {
		return nil, fmt.Errorf("factory queue update function is required")
	}

	var updated []QueueEntry
	if err := s.withQueueLock(func() error {
		entries, err := s.loadQueue()
		if err != nil {
			return err
		}

		next, err := update(copyQueueEntries(entries))
		if err != nil {
			return err
		}
		if err := s.saveQueue(next); err != nil {
			return err
		}

		updated = copyQueueEntries(next)
		return nil
	}); err != nil {
		return nil, err
	}

	if updated == nil {
		return []QueueEntry{}, nil
	}
	return updated, nil
}

// EnqueueQueueEntry appends one queued factory run entry using the store's
// atomic queue mutation path.
func (s Store) EnqueueQueueEntry(runID, executorMode string, opts QueueOperationOptions) (QueueEntry, error) {
	return s.EnqueueQueueEntryWithLockedPostSave(runID, executorMode, opts, nil)
}

// EnqueueQueueEntryWithLockedPostSave appends one queued factory run entry,
// saves it, then runs afterSave before releasing the queue lock. The callback
// observes the committed queue entry while workers remain blocked from claiming
// it. If the callback fails, the queue entry is rolled back before unlock.
func (s Store) EnqueueQueueEntryWithLockedPostSave(runID, executorMode string, opts QueueOperationOptions, afterSave func(QueueEntry) error) (QueueEntry, error) {
	runID, err := validateRunID(runID)
	if err != nil {
		return QueueEntry{}, err
	}
	executorMode, err = validateQueueExecutorMode(executorMode)
	if err != nil {
		return QueueEntry{}, err
	}

	opts = normalizeQueueOperationOptions(opts)
	queueID, err := opts.NewQueueID()
	if err != nil {
		return QueueEntry{}, fmt.Errorf("create factory queue ID: %w", err)
	}
	queueID, err = validateQueueID(queueID)
	if err != nil {
		return QueueEntry{}, err
	}

	entry := QueueEntry{
		QueueID:      queueID,
		RunID:        runID,
		ExecutorMode: executorMode,
		Status:       QueueStatusQueued,
		CreatedAt:    opts.Now().UTC(),
		AttemptCount: 0,
	}

	if err := s.withQueueLock(func() error {
		entries, err := s.loadQueue()
		if err != nil {
			return err
		}
		if existing := activeQueueEntryForRun(entries, runID); existing != nil {
			return fmt.Errorf("factory run %q already has active queue entry %q", runID, existing.QueueID)
		}

		next := append(copyQueueEntries(entries), entry)
		if err := s.saveQueue(next); err != nil {
			return err
		}
		if afterSave == nil {
			return nil
		}
		if err := afterSave(entry); err != nil {
			if rollbackErr := s.saveQueue(entries); rollbackErr != nil {
				return errors.Join(err, fmt.Errorf("rollback factory queue entry %q: %w", entry.QueueID, rollbackErr))
			}
			return err
		}
		return nil
	}); err != nil {
		return QueueEntry{}, err
	}

	return entry, nil
}

// ListQueue returns queue entries in FIFO order by creation time.
func (s Store) ListQueue() ([]QueueEntry, error) {
	entries, err := s.LoadQueue()
	if err != nil {
		return nil, err
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return queueEntryFIFOBefore(entries[i], entries[j])
	})
	return entries, nil
}

// ClaimNextQueueEntry claims the oldest queued entry. It returns nil when no
// queued entries are available.
func (s Store) ClaimNextQueueEntry(opts QueueOperationOptions) (*QueueEntry, error) {
	opts = normalizeQueueOperationOptions(opts)
	now := opts.Now().UTC()
	entries, err := s.loadQueue()
	if err != nil {
		return nil, err
	}
	if !hasClaimableQueueEntry(entries, now, opts.ClaimLeaseDuration) {
		return nil, nil
	}

	claim := opts.queueClaim()

	var claimed *QueueEntry
	if err := s.withQueueLock(func() error {
		entries, err := s.loadQueue()
		if err != nil {
			return err
		}
		now := opts.Now().UTC()
		requeueExpiredQueueClaims(entries, now, opts.ClaimLeaseDuration)

		idx := oldestQueuedEntryIndex(entries)
		if idx < 0 {
			return nil
		}

		entries[idx].Status = QueueStatusClaimed
		entries[idx].ClaimedAt = &now
		entries[idx].CompletedAt = nil
		entries[idx].Claim = &claim
		entries[idx].AttemptCount++
		entries[idx].LastError = ""

		entry := entries[idx]
		claimed = &entry
		return s.saveQueue(entries)
	}); err != nil {
		return nil, err
	}

	return claimed, nil
}

// MarkQueueEntrySucceeded records successful completion while retaining the
// terminal queue entry for history and JSON inspection.
func (s Store) MarkQueueEntrySucceeded(queueID string, opts QueueOperationOptions) (QueueEntry, error) {
	queueID, err := validateQueueID(queueID)
	if err != nil {
		return QueueEntry{}, err
	}
	opts = normalizeQueueOperationOptions(opts)

	var updated QueueEntry
	if _, err := s.UpdateQueue(func(entries []QueueEntry) ([]QueueEntry, error) {
		idx := queueEntryIndex(entries, queueID)
		if idx < 0 {
			return nil, fmt.Errorf("factory queue entry %q does not exist", queueID)
		}
		if entries[idx].Status != QueueStatusClaimed {
			return nil, fmt.Errorf("factory queue entry %q is %q, want %q", queueID, entries[idx].Status, QueueStatusClaimed)
		}
		if err := validateQueueClaimFence(queueID, entries[idx], opts); err != nil {
			return nil, err
		}

		completedAt := opts.Now().UTC()
		entries[idx].Status = QueueStatusSucceeded
		entries[idx].CompletedAt = &completedAt
		if entries[idx].AttemptCount == 0 {
			entries[idx].AttemptCount = 1
		}
		entries[idx].LastError = ""

		updated = entries[idx]
		return entries, nil
	}); err != nil {
		return QueueEntry{}, err
	}

	return updated, nil
}

// MarkQueueEntryFailed records failed completion and leaves the entry
// inspectable through queue JSON output.
func (s Store) MarkQueueEntryFailed(queueID, errorMessage string, opts QueueOperationOptions) (QueueEntry, error) {
	queueID, err := validateQueueID(queueID)
	if err != nil {
		return QueueEntry{}, err
	}
	errorMessage = strings.TrimSpace(errorMessage)
	if errorMessage == "" {
		return QueueEntry{}, fmt.Errorf("factory queue failure message is required")
	}
	opts = normalizeQueueOperationOptions(opts)

	var updated QueueEntry
	if _, err := s.UpdateQueue(func(entries []QueueEntry) ([]QueueEntry, error) {
		idx := queueEntryIndex(entries, queueID)
		if idx < 0 {
			return nil, fmt.Errorf("factory queue entry %q does not exist", queueID)
		}
		if entries[idx].Status != QueueStatusClaimed {
			return nil, fmt.Errorf("factory queue entry %q is %q, want %q", queueID, entries[idx].Status, QueueStatusClaimed)
		}
		if err := validateQueueClaimFence(queueID, entries[idx], opts); err != nil {
			return nil, err
		}

		completedAt := opts.Now().UTC()
		entries[idx].Status = QueueStatusFailed
		entries[idx].CompletedAt = &completedAt
		if entries[idx].AttemptCount == 0 {
			entries[idx].AttemptCount = 1
		}
		entries[idx].LastError = errorMessage

		updated = entries[idx]
		return entries, nil
	}); err != nil {
		return QueueEntry{}, err
	}

	return updated, nil
}

// RequeueClaimedQueueEntry releases a claimed entry back to queued state while
// preserving attempt history for a later worker retry.
func (s Store) RequeueClaimedQueueEntry(queueID, errorMessage string, opts QueueOperationOptions) (QueueEntry, error) {
	queueID, err := validateQueueID(queueID)
	if err != nil {
		return QueueEntry{}, err
	}
	errorMessage = strings.TrimSpace(errorMessage)
	if errorMessage == "" {
		return QueueEntry{}, fmt.Errorf("factory queue requeue message is required")
	}
	opts = normalizeQueueOperationOptions(opts)

	var updated QueueEntry
	if _, err := s.UpdateQueue(func(entries []QueueEntry) ([]QueueEntry, error) {
		idx := queueEntryIndex(entries, queueID)
		if idx < 0 {
			return nil, fmt.Errorf("factory queue entry %q does not exist", queueID)
		}
		if entries[idx].Status != QueueStatusClaimed {
			return nil, fmt.Errorf("factory queue entry %q is %q, want %q", queueID, entries[idx].Status, QueueStatusClaimed)
		}
		if err := validateQueueClaimFence(queueID, entries[idx], opts); err != nil {
			return nil, err
		}

		entries[idx].Status = QueueStatusQueued
		entries[idx].ClaimedAt = nil
		entries[idx].CompletedAt = nil
		entries[idx].Claim = nil
		entries[idx].LastError = errorMessage

		updated = entries[idx]
		return entries, nil
	}); err != nil {
		return QueueEntry{}, err
	}

	return updated, nil
}

func validateQueueClaimFence(queueID string, entry QueueEntry, opts QueueOperationOptions) error {
	if opts.ExpectedClaimedAt == nil || opts.ExpectedAttemptCount <= 0 {
		return fmt.Errorf("factory queue entry %q claim fence is required", queueID)
	}
	if entry.ClaimedAt == nil {
		return fmt.Errorf("stale factory queue claim for entry %q", queueID)
	}
	expectedClaimedAt := opts.ExpectedClaimedAt.UTC()
	if !entry.ClaimedAt.Equal(expectedClaimedAt) || entry.AttemptCount != opts.ExpectedAttemptCount {
		return fmt.Errorf("stale factory queue claim for entry %q", queueID)
	}
	return nil
}

func (s Store) loadQueue() ([]QueueEntry, error) {
	path := s.QueuePath()
	if path == "" {
		return nil, errStoreDirUnavailable
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []QueueEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read factory queue: %w", err)
	}

	var state queueState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse factory queue: %w", err)
	}
	if state.Entries == nil {
		return []QueueEntry{}, nil
	}

	return copyQueueEntries(state.Entries), nil
}

func (s Store) saveQueue(entries []QueueEntry) error {
	path := s.QueuePath()
	if path == "" {
		return errStoreDirUnavailable
	}

	state := queueState{Entries: copyQueueEntries(entries)}
	if state.Entries == nil {
		state.Entries = []QueueEntry{}
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory queue: %w", err)
	}
	data = append(data, '\n')

	tmpPath := path + storeTempFileExt
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write factory queue: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod factory queue: %w", err)
	}
	if err := saveQueueFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save factory queue: %w", err)
	}

	return nil
}

func (s Store) queueLockPath() string {
	if s.root == "" {
		return ""
	}
	return filepath.Join(s.root, queueLockDirName)
}

func (s Store) withQueueLock(fn func() error) error {
	if fn == nil {
		return fmt.Errorf("factory queue lock function is required")
	}
	if err := s.Ensure(); err != nil {
		return err
	}

	release, err := acquireQueueLock(s.queueLockPath())
	if err != nil {
		return err
	}
	defer release()

	return fn()
}

func acquireQueueLock(path string) (func(), error) {
	if path == "" {
		return nil, errStoreDirUnavailable
	}

	deadline := time.Now().Add(queueLockWaitTimeout)
	for {
		err := os.Mkdir(path, 0o700)
		if err == nil {
			release, err := writeQueueLockMetadata(path, time.Now())
			if err != nil {
				_ = os.RemoveAll(path)
				return nil, err
			}
			return release, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("acquire factory queue lock: %w", err)
		}
		removed, staleErr := removeStaleQueueLock(path, time.Now())
		if staleErr != nil {
			return nil, staleErr
		}
		if removed {
			continue
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("acquire factory queue lock %q: existing lock is not stale; remove it only if no factory worker is running: %w", path, err)
		}
		time.Sleep(queueLockRetryDelay)
	}
}

func writeQueueLockMetadata(path string, now time.Time) (func(), error) {
	hostname, _ := os.Hostname()
	token, err := sandbox.NewV7()
	if err != nil {
		return nil, fmt.Errorf("create factory queue lock token: %w", err)
	}
	metadata := queueLockMetadata{
		PID:        os.Getpid(),
		Hostname:   hostname,
		AcquiredAt: now.UTC(),
		Token:      token,
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal factory queue lock metadata: %w", err)
	}
	data = append(data, '\n')

	ownerName := queueLockOwnerPrefix + token + queueLockOwnerSuffix
	ownerPath := filepath.Join(path, ownerName)
	if err := os.WriteFile(ownerPath, data, 0o600); err != nil {
		return nil, fmt.Errorf("write factory queue lock metadata: %w", err)
	}

	return func() {
		releaseQueueLock(path, ownerName)
	}, nil
}

func releaseQueueLock(path, ownerName string) {
	if ownerName == "" {
		return
	}
	ownerPath := filepath.Join(path, ownerName)
	if err := os.Remove(ownerPath); err != nil {
		return
	}
	_ = os.Remove(path)
}

func removeStaleQueueLock(path string, now time.Time) (bool, error) {
	snapshot, err := readQueueLockSnapshot(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	if !queueLockSnapshotIsStale(snapshot, now) {
		return false, nil
	}
	return removeStaleQueueLockSnapshot(path, now, snapshot)
}

func removeStaleQueueLockSnapshot(path string, now time.Time, snapshot queueLockSnapshot) (bool, error) {
	latest, err := readQueueLockSnapshot(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	if !sameQueueLockSnapshot(snapshot, latest) || !queueLockSnapshotIsStale(latest, now) {
		return false, nil
	}

	if latest.hasOwner {
		ownerPath := filepath.Join(path, latest.ownerName)
		if err := os.Remove(ownerPath); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false, nil
			}
			return false, fmt.Errorf("remove stale factory queue lock metadata %q: %w", ownerPath, err)
		}
	}
	return removeQueueLockDir(path)
}

func removeQueueLockDir(path string) (bool, error) {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		hasEntries, readErr := queueLockDirHasEntries(path)
		if readErr != nil {
			return false, readErr
		}
		if hasEntries {
			return false, nil
		}
		return false, fmt.Errorf("remove stale factory queue lock %q: %w", path, err)
	}
	return true, nil
}

func queueLockDirHasEntries(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read factory queue lock directory %q: %w", path, err)
	}
	return len(entries) > 0, nil
}

func queueLockIsStale(path string, now time.Time) (bool, error) {
	snapshot, err := readQueueLockSnapshot(path)
	if err != nil {
		return false, err
	}
	return queueLockSnapshotIsStale(snapshot, now), nil
}

func queueLockAcquiredAt(path string) (time.Time, error) {
	snapshot, err := readQueueLockSnapshot(path)
	if err != nil {
		return time.Time{}, err
	}
	return snapshot.acquiredAt, nil
}

func readQueueLockSnapshot(path string) (queueLockSnapshot, error) {
	ownerName, err := queueLockOwnerName(path)
	if err != nil {
		return queueLockSnapshot{}, err
	}
	ownerPath := filepath.Join(path, ownerName)
	data, err := os.ReadFile(ownerPath)
	snapshot := queueLockSnapshot{
		ownerData: append([]byte(nil), data...),
		ownerName: ownerName,
		hasOwner:  err == nil,
	}
	if err == nil {
		var metadata queueLockMetadata
		if err := json.Unmarshal(data, &metadata); err == nil && !metadata.AcquiredAt.IsZero() {
			snapshot.acquiredAt = metadata.AcquiredAt
		}
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return queueLockSnapshot{}, fmt.Errorf("read factory queue lock metadata: %w", err)
	}

	info, statErr := os.Stat(path)
	if statErr != nil {
		return queueLockSnapshot{}, fmt.Errorf("stat factory queue lock: %w", statErr)
	}
	snapshot.modTime = info.ModTime()
	if snapshot.acquiredAt.IsZero() {
		snapshot.acquiredAt = snapshot.modTime
	}
	return snapshot, nil
}

func queueLockOwnerName(path string) (string, error) {
	if _, err := os.Stat(filepath.Join(path, queueLockOwnerFileName)); err == nil {
		return queueLockOwnerFileName, nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("stat factory queue lock metadata: %w", err)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return queueLockOwnerFileName, nil
		}
		return "", fmt.Errorf("read factory queue lock directory: %w", err)
	}
	var ownerNames []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, queueLockOwnerPrefix) || !strings.HasSuffix(name, queueLockOwnerSuffix) {
			continue
		}
		ownerNames = append(ownerNames, name)
	}
	if len(ownerNames) == 0 {
		return queueLockOwnerFileName, nil
	}
	sort.Strings(ownerNames)
	return ownerNames[0], nil
}

func queueLockSnapshotIsStale(snapshot queueLockSnapshot, now time.Time) bool {
	return now.Sub(snapshot.acquiredAt) >= queueLockStaleAfter
}

func sameQueueLockSnapshot(left, right queueLockSnapshot) bool {
	return left.hasOwner == right.hasOwner &&
		left.acquiredAt.Equal(right.acquiredAt) &&
		left.modTime.Equal(right.modTime) &&
		left.ownerName == right.ownerName &&
		bytes.Equal(left.ownerData, right.ownerData)
}

func copyQueueEntries(entries []QueueEntry) []QueueEntry {
	if entries == nil {
		return nil
	}

	out := make([]QueueEntry, len(entries))
	copy(out, entries)
	for i := range out {
		if out[i].ClaimedAt != nil {
			claimedAt := *out[i].ClaimedAt
			out[i].ClaimedAt = &claimedAt
		}
		if out[i].CompletedAt != nil {
			completedAt := *out[i].CompletedAt
			out[i].CompletedAt = &completedAt
		}
		if out[i].Claim != nil {
			claim := *out[i].Claim
			out[i].Claim = &claim
		}
	}
	return out
}

func normalizeQueueOperationOptions(opts QueueOperationOptions) QueueOperationOptions {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewQueueID == nil {
		opts.NewQueueID = newQueueID
	}
	if opts.ClaimLeaseDuration <= 0 {
		opts.ClaimLeaseDuration = queueClaimLeaseDuration
	}
	return opts
}

func (opts QueueOperationOptions) queueClaim() QueueClaim {
	if opts.Claim != nil {
		return *opts.Claim
	}

	hostname, _ := os.Hostname()
	return QueueClaim{
		PID:      os.Getpid(),
		Hostname: hostname,
	}
}

func newQueueID() (string, error) {
	id, err := sandbox.NewV7()
	if err != nil {
		return "", err
	}
	return "queue-" + id, nil
}

func validateQueueID(queueID string) (string, error) {
	trimmedQueueID := strings.TrimSpace(queueID)
	if trimmedQueueID == "" {
		return "", fmt.Errorf("factory queue ID is required")
	}
	if queueID != trimmedQueueID {
		return "", fmt.Errorf("factory queue ID %q is invalid", queueID)
	}
	return trimmedQueueID, nil
}

func validateQueueExecutorMode(executorMode string) (string, error) {
	return ValidateExecutorMode(executorMode)
}

func oldestQueuedEntryIndex(entries []QueueEntry) int {
	oldest := -1
	for i, entry := range entries {
		if entry.Status != QueueStatusQueued {
			continue
		}
		if oldest < 0 || queueEntryFIFOBefore(entry, entries[oldest]) {
			oldest = i
		}
	}
	return oldest
}

func hasClaimableQueueEntry(entries []QueueEntry, now time.Time, leaseDuration time.Duration) bool {
	if oldestQueuedEntryIndex(entries) >= 0 {
		return true
	}
	for _, entry := range entries {
		if entry.Status != QueueStatusClaimed {
			continue
		}
		if queueClaimExpired(entry, now, leaseDuration) {
			return true
		}
	}
	return false
}

func activeQueueEntryForRun(entries []QueueEntry, runID string) *QueueEntry {
	for i := range entries {
		if entries[i].RunID == runID && isActiveQueueStatus(entries[i].Status) {
			return &entries[i]
		}
	}
	return nil
}

func isActiveQueueStatus(status string) bool {
	return status == QueueStatusQueued || status == QueueStatusClaimed
}

func requeueExpiredQueueClaims(entries []QueueEntry, now time.Time, leaseDuration time.Duration) {
	if leaseDuration <= 0 {
		return
	}
	for i := range entries {
		if entries[i].Status != QueueStatusClaimed {
			continue
		}
		if !queueClaimExpired(entries[i], now, leaseDuration) {
			continue
		}

		entries[i].Status = QueueStatusQueued
		entries[i].ClaimedAt = nil
		entries[i].CompletedAt = nil
		entries[i].Claim = nil
		entries[i].LastError = fmt.Sprintf("claim expired after %s", leaseDuration)
	}
}

func queueClaimExpired(entry QueueEntry, now time.Time, leaseDuration time.Duration) bool {
	if entry.ClaimedAt == nil {
		return true
	}
	if entry.ClaimedAt.After(now) {
		return false
	}
	return now.Sub(*entry.ClaimedAt) >= leaseDuration
}

func queueEntryIndex(entries []QueueEntry, queueID string) int {
	for i, entry := range entries {
		if entry.QueueID == queueID {
			return i
		}
	}
	return -1
}

func queueEntryFIFOBefore(left, right QueueEntry) bool {
	if !left.CreatedAt.Equal(right.CreatedAt) {
		return left.CreatedAt.Before(right.CreatedAt)
	}
	if left.QueueID != right.QueueID {
		return left.QueueID < right.QueueID
	}
	return left.RunID < right.RunID
}
