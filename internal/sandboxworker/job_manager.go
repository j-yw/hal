package sandboxworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const defaultJobHeartbeatInterval = time.Second

var (
	errJobNotFound         = errors.New("worker job was not found")
	errJobCapacityExceeded = errors.New("worker job capacity is exhausted")
)

type jobManagerOptions struct {
	Context           context.Context
	WorkerID          string
	StateDir          string
	Now               func() time.Time
	NewID             func() (string, error)
	HeartbeatInterval time.Duration
	LogRetentionBytes int64
	LogRecordBytes    int64
	MaxConcurrentJobs int
}

type jobManager struct {
	mu                sync.Mutex
	ctx               context.Context
	cancelContext     context.CancelFunc
	workerID          string
	store             *jobStore
	stateLock         *jobStateLock
	now               func() time.Time
	newID             func() (string, error)
	heartbeatInterval time.Duration
	logRetentionBytes int64
	logRecordBytes    int64
	maxConcurrentJobs int
	activeJobs        int
	// Terminal state remains durable in L2. Store-wide retention and pruning
	// are explicitly deferred to a later phase.
	jobs         map[string]*jobEntry
	submissions  map[string]string
	jobWG        sync.WaitGroup
	shutdownOnce sync.Once
	closing      bool
}

type jobEntry struct {
	job           Job
	records       []JobLogRecord
	retainedBytes int64
	cancel        context.CancelFunc
	admitted      bool
}

func newJobManager(options jobManagerOptions) (*jobManager, error) {
	store, err := newJobStore(options.StateDir)
	if err != nil {
		return nil, err
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancelContext := context.WithCancel(ctx)
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	newID := options.NewID
	if newID == nil {
		newID = newOpaqueJobID
	}
	heartbeat := options.HeartbeatInterval
	if heartbeat <= 0 {
		heartbeat = defaultJobHeartbeatInterval
	}
	retention := options.LogRetentionBytes
	if retention <= 0 {
		retention = DefaultJobLogRetentionBytes
	}
	recordBytes := options.LogRecordBytes
	if recordBytes < minJobLogRecordBytes || recordBytes > DefaultJobLogRecordBytes {
		recordBytes = DefaultJobLogRecordBytes
	}
	maxConcurrentJobs := options.MaxConcurrentJobs
	if maxConcurrentJobs <= 0 {
		maxConcurrentJobs = 1
	}
	manager := &jobManager{
		ctx:               ctx,
		cancelContext:     cancelContext,
		workerID:          strings.TrimSpace(options.WorkerID),
		store:             store,
		now:               now,
		newID:             newID,
		heartbeatInterval: heartbeat,
		logRetentionBytes: retention,
		logRecordBytes:    recordBytes,
		maxConcurrentJobs: maxConcurrentJobs,
		jobs:              map[string]*jobEntry{},
		submissions:       map[string]string{},
	}
	if !validJobSafeID(manager.workerID) {
		cancelContext()
		return nil, fmt.Errorf("worker job manager workerId is invalid")
	}
	stateLock, err := acquireJobStateLock(store.root)
	if err != nil {
		cancelContext()
		return nil, err
	}
	manager.stateLock = stateLock
	if err := manager.loadAndReconcile(); err != nil {
		cancelContext()
		_ = stateLock.Close()
		return nil, err
	}
	if manager.ctx.Done() != nil {
		go func() {
			<-manager.ctx.Done()
			manager.shutdown()
		}()
	}
	return manager, nil
}

func (manager *jobManager) close() {
	if manager == nil {
		return
	}
	if manager.cancelContext != nil {
		manager.cancelContext()
	}
	manager.shutdown()
}

func (manager *jobManager) shutdown() {
	if manager == nil {
		return
	}
	manager.shutdownOnce.Do(func() {
		manager.mu.Lock()
		manager.closing = true
		manager.mu.Unlock()
		manager.jobWG.Wait()
		if manager.stateLock != nil {
			_ = manager.stateLock.Close()
		}
	})
}

func (manager *jobManager) loadAndReconcile() error {
	loaded, err := manager.store.loadAll()
	if err != nil {
		return err
	}
	for _, stored := range loaded {
		entry := &jobEntry{
			job:           cloneJob(stored.Job),
			records:       cloneJobLogRecords(stored.Records),
			retainedBytes: jobLogRecordsSize(stored.Records),
		}
		if len(entry.records) > 0 {
			lastCursor := entry.records[len(entry.records)-1].Cursor
			if entry.job.LogCursor < lastCursor {
				entry.job.LogCursor = lastCursor
			}
			if entry.job.LogCursor > lastCursor {
				entry.job.LogTruncated = true
			}
		} else if entry.job.LogCursor > 0 {
			entry.job.LogTruncated = true
		}
		switch {
		case entry.job.State == JobStateQueued && entry.job.CancelRequested:
			entry.job.CancelRequested = false
			manager.markRecoveredJob(entry, JobStateCanceled, "cancel_requested")
		case entry.job.State == JobStateQueued:
			manager.markRecoveredJob(entry, JobStateInterrupted, "daemon_restarted_before_start")
		case entry.job.State == JobStateRunning && entry.job.CancelRequested:
			manager.markRecoveredJob(entry, JobStateUnknown, "daemon_restarted_cancel_state_unknown")
		case entry.job.State == JobStateRunning:
			manager.markRecoveredJob(entry, JobStateUnknown, "daemon_restarted_running_state_unknown")
		}
		if entry.job.SubmissionKey != "" {
			if existingID, exists := manager.submissions[entry.job.SubmissionKey]; exists && existingID != entry.job.ID {
				return fmt.Errorf("worker job submission identity is duplicated")
			}
			manager.submissions[entry.job.SubmissionKey] = entry.job.ID
		}
		manager.jobs[entry.job.ID] = entry
		if err := manager.store.save(entry.job, entry.records); err != nil {
			return err
		}
	}
	return nil
}

func (manager *jobManager) markRecoveredJob(entry *jobEntry, state, failureCode string) {
	now := manager.now().UTC()
	entry.job.State = state
	entry.job.FailureCode = failureCode
	entry.job.FinishedAt = timePointer(now)
	entry.job.HeartbeatAt = timePointer(now)
}

func (manager *jobManager) start(ctx context.Context, driverID string, driver sandboxruntime.Driver, req JobStartRequest) (Job, error) {
	if manager == nil || manager.store == nil {
		return Job{}, fmt.Errorf("worker job manager is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Job{}, err
	}
	if driver == nil {
		return Job{}, ErrDriverRequired
	}
	if err := req.Validate(); err != nil {
		return Job{}, err
	}

	submissionKey := jobSubmissionKey(req.SubmissionID)
	manager.mu.Lock()
	if existingID, exists := manager.submissions[submissionKey]; exists {
		entry, ok := manager.jobs[existingID]
		if !ok {
			manager.mu.Unlock()
			return Job{}, fmt.Errorf("worker job submission identity is unavailable")
		}
		snapshot := cloneJob(entry.job)
		manager.mu.Unlock()
		return snapshot, nil
	}
	if manager.closing || manager.ctx.Err() != nil {
		manager.mu.Unlock()
		return Job{}, fmt.Errorf("worker job manager is unavailable")
	}
	if err := ctx.Err(); err != nil {
		manager.mu.Unlock()
		return Job{}, err
	}
	if manager.activeJobs >= manager.maxConcurrentJobs {
		manager.mu.Unlock()
		return Job{}, errJobCapacityExceeded
	}
	jobID, err := manager.newID()
	if err != nil || validateJobID(jobID) != nil {
		manager.mu.Unlock()
		return Job{}, fmt.Errorf("allocate worker job identity")
	}
	if _, exists := manager.jobs[jobID]; exists {
		manager.mu.Unlock()
		return Job{}, fmt.Errorf("allocate worker job identity")
	}
	now := manager.now().UTC()
	job := Job{
		ContractVersion: JobContractVersion,
		ID:              jobID,
		SubmissionKey:   submissionKey,
		WorkerID:        manager.workerID,
		HostID:          manager.workerID,
		RuntimeDriver:   strings.TrimSpace(driverID),
		RuntimeID:       strings.TrimSpace(req.Exec.Target.Runtime.RuntimeID),
		State:           JobStateQueued,
		SubmittedAt:     now,
	}
	if err := job.Validate(); err != nil {
		manager.mu.Unlock()
		return Job{}, err
	}
	jobCtx, cancel := context.WithCancel(manager.ctx)
	entry := &jobEntry{job: job, cancel: cancel}

	if err := manager.store.save(entry.job, nil); err != nil {
		manager.mu.Unlock()
		cancel()
		return Job{}, err
	}
	manager.jobs[jobID] = entry
	manager.submissions[submissionKey] = jobID
	entry.admitted = true
	manager.activeJobs++
	snapshot := cloneJob(entry.job)
	manager.jobWG.Add(1)
	manager.mu.Unlock()

	execReq := cloneJobExecRequest(req.Exec)
	go manager.run(jobCtx, entry, driver, execReq)
	return snapshot, nil
}

func (manager *jobManager) run(ctx context.Context, entry *jobEntry, driver sandboxruntime.Driver, req ExecRequest) {
	defer func() {
		manager.mu.Lock()
		manager.releaseAdmissionLocked(entry)
		manager.mu.Unlock()
		manager.jobWG.Done()
	}()
	manager.mu.Lock()
	if jobStateTerminal(entry.job.State) {
		manager.mu.Unlock()
		return
	}
	if err := ctx.Err(); err != nil {
		manager.finishLocked(entry, JobStateInterrupted, nil, "daemon_stopped")
		manager.mu.Unlock()
		return
	}
	now := manager.now().UTC()
	entry.job.State = JobStateRunning
	entry.job.StartedAt = timePointer(now)
	entry.job.HeartbeatAt = timePointer(now)
	if err := manager.store.save(entry.job, entry.records); err != nil {
		entry.job.State = JobStateUnknown
		entry.job.FailureCode = "state_write_failed"
		entry.job.FinishedAt = timePointer(now)
		manager.mu.Unlock()
		entry.cancel()
		return
	}
	manager.mu.Unlock()

	stdout := newJobLogWriter(manager, entry, JobLogStreamStdout, req.StdoutLimitBytes, newJobLiteralRedactor(req))
	stderr := newJobLogWriter(manager, entry, JobLogStreamStderr, req.StderrLimitBytes, newJobLiteralRedactor(req))
	runtimeReq := sandboxruntime.ExecRequest{
		Target:                               runtimeTargetFromWorkerTarget(req.Target),
		Args:                                 cloneStringSlice(req.Args),
		Stdout:                               stdout,
		Stderr:                               stderr,
		Stdin:                                execStdinReader(req.Stdin),
		Env:                                  cloneStringMap(req.Env),
		WorkDir:                              strings.TrimSpace(req.WorkDir),
		RequireProcessGroupCancellationProof: true,
	}

	heartbeatDone := make(chan struct{})
	go manager.heartbeat(ctx, entry, heartbeatDone)
	result, runErr := driver.Exec(ctx, runtimeReq)
	stdout.Flush()
	stderr.Flush()
	if runErr == nil {
		runErr = errors.Join(stdout.Err(), stderr.Err())
	}
	close(heartbeatDone)

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if jobStateTerminal(entry.job.State) {
		return
	}
	switch {
	case entry.job.CancelRequested &&
		result != nil &&
		result.Cancellation != nil &&
		result.Cancellation.ProcessGroupTerminated:
		manager.finishLocked(entry, JobStateCanceled, result, "cancel_requested")
	case entry.job.CancelRequested:
		manager.finishLocked(entry, JobStateUnknown, result, "cancel_termination_unconfirmed")
	case errors.Is(ctx.Err(), context.Canceled):
		manager.finishLocked(entry, JobStateInterrupted, result, "daemon_stopped")
	case runErr != nil:
		manager.finishLocked(entry, JobStateFailed, result, "driver_error")
	case result == nil:
		manager.finishLocked(entry, JobStateUnknown, nil, "missing_exec_result")
	case result.ExitCode != 0:
		manager.finishLocked(entry, JobStateFailed, result, "nonzero_exit")
	default:
		manager.finishLocked(entry, JobStateSucceeded, result, "")
	}
}

func (manager *jobManager) heartbeat(ctx context.Context, entry *jobEntry, done <-chan struct{}) {
	ticker := time.NewTicker(manager.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			manager.mu.Lock()
			if entry.job.State != JobStateRunning {
				manager.mu.Unlock()
				return
			}
			now := manager.now().UTC()
			entry.job.HeartbeatAt = timePointer(now)
			if err := manager.store.save(entry.job, entry.records); err != nil {
				entry.job.State = JobStateUnknown
				entry.job.FailureCode = "state_write_failed"
				entry.job.FinishedAt = timePointer(now)
				if entry.cancel != nil {
					entry.cancel()
				}
			}
			manager.mu.Unlock()
		}
	}
}

func (manager *jobManager) finishLocked(entry *jobEntry, state string, result *sandboxruntime.ExecResult, failureCode string) {
	if jobStateTerminal(entry.job.State) {
		return
	}
	now := manager.now().UTC()
	entry.job.State = state
	entry.job.HeartbeatAt = timePointer(now)
	entry.job.FinishedAt = timePointer(now)
	entry.job.FailureCode = failureCode
	if result != nil {
		exitCode := result.ExitCode
		entry.job.ExitCode = &exitCode
	}
	cancelRequested := entry.job.CancelRequested
	entry.job.CancelRequested = false
	if err := manager.store.save(entry.job, entry.records); err != nil {
		entry.job.State = JobStateUnknown
		entry.job.FailureCode = "state_write_failed"
		entry.job.CancelRequested = cancelRequested
	}
	if entry.cancel != nil {
		entry.cancel()
	}
	entry.cancel = nil
	manager.releaseAdmissionLocked(entry)
}

func (manager *jobManager) releaseAdmissionLocked(entry *jobEntry) {
	if entry == nil || !entry.admitted {
		return
	}
	entry.admitted = false
	if manager.activeJobs > 0 {
		manager.activeJobs--
	}
}

func (manager *jobManager) status(jobID string) (Job, error) {
	if err := validateJobID(jobID); err != nil {
		return Job{}, err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry, ok := manager.jobs[jobID]
	if !ok {
		return Job{}, errJobNotFound
	}
	return cloneJob(entry.job), nil
}

func (manager *jobManager) cancelJob(jobID string) (Job, error) {
	if err := validateJobID(jobID); err != nil {
		return Job{}, err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry, ok := manager.jobs[jobID]
	if !ok {
		return Job{}, errJobNotFound
	}
	if jobStateTerminal(entry.job.State) {
		return cloneJob(entry.job), nil
	}
	if !entry.job.CancelRequested {
		entry.job.CancelRequested = true
		if err := manager.store.save(entry.job, entry.records); err != nil {
			entry.job.CancelRequested = false
			return Job{}, err
		}
	}
	if entry.job.State == JobStateQueued {
		manager.finishLocked(entry, JobStateCanceled, nil, "cancel_requested")
	}
	if entry.cancel != nil {
		entry.cancel()
	}
	return cloneJob(entry.job), nil
}

func (manager *jobManager) logs(req JobLogsRequest) (JobLogsResponse, error) {
	if err := req.Validate(); err != nil {
		return JobLogsResponse{}, err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry, ok := manager.jobs[req.JobID]
	if !ok {
		return JobLogsResponse{}, errJobNotFound
	}
	response := JobLogsResponse{
		ContractVersion: JobContractVersion,
		JobID:           req.JobID,
		NextCursor:      req.Cursor,
	}
	if len(entry.records) > 0 {
		response.OldestCursor = entry.records[0].Cursor
		if req.Cursor+1 < response.OldestCursor {
			response.Truncated = true
		}
	}
	var used int64
	expectedCursor := req.Cursor + 1
	moreRetained := false
	for _, record := range entry.records {
		if record.Cursor <= req.Cursor {
			continue
		}
		if record.Cursor > expectedCursor {
			response.Truncated = true
		}
		recordBytes := int64(len([]byte(record.Data)))
		if used+recordBytes > req.LimitBytes {
			moreRetained = true
			break
		}
		response.Records = append(response.Records, record)
		used += recordBytes
		response.NextCursor = record.Cursor
		expectedCursor = record.Cursor + 1
	}
	if entry.job.LogTruncated && response.NextCursor < entry.job.LogCursor {
		response.Truncated = true
		if !moreRetained {
			response.NextCursor = entry.job.LogCursor
		}
	}
	return response, nil
}
