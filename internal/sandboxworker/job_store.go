package sandboxworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	jobStateFileName        = "job.json"
	jobLogsFileName         = "logs.json"
	jobStateMarkerFileName  = ".hal-job-state"
	jobStateMarkerContents  = "hal-sandboxworker-job-state-v1\n"
	jobStateWorkerPrefix    = jobStateMarkerContents + "workerId="
	maxJobStateMarkerBytes  = len(jobStateWorkerPrefix) + 192 + 1
	jobTransactionDirPrefix = ".job-state-txn-"
	maxJobLogsFileBytes     = DefaultJobLogRetentionBytes*6 + (256 << 10)
)

type jobStore struct {
	root string
}

type storedJobLogs struct {
	Records         []JobLogRecord `json:"records,omitempty"`
	LogCursor       uint64         `json:"logCursor,omitempty"`
	LogTruncated    bool           `json:"logTruncated,omitempty"`
	StdoutTruncated bool           `json:"stdoutTruncated,omitempty"`
	StderrTruncated bool           `json:"stderrTruncated,omitempty"`
}

type storedJob struct {
	Job     Job
	Records []JobLogRecord
}

type storedJobState struct {
	Job
	RequestKey string `json:"requestKey,omitempty"`
}

func newJobStore(root string) (*jobStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("job state root is required")
	}
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) || root == string(filepath.Separator) {
		return nil, fmt.Errorf("job state root is invalid")
	}
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("job state root is invalid")
		}
		resolvedRoot, err := resolveJobStateRoot(root)
		if err != nil {
			return nil, err
		}
		if err := validateExistingJobStateRoot(resolvedRoot); err != nil {
			return nil, err
		}
		return &jobStore{root: resolvedRoot}, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect job state root: %w", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, fmt.Errorf("create job state root: %w", err)
	}
	initialized := false
	defer func() {
		if initialized {
			return
		}
		_ = os.Remove(filepath.Join(root, jobStateMarkerFileName))
		_ = os.Remove(root)
	}()
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("secure job state root: %w", err)
	}
	resolvedRoot, err := resolveJobStateRoot(root)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateJobStateRoot(resolvedRoot); err != nil {
		return nil, err
	}
	if err := writePrivateFileAtomic(resolvedRoot, jobStateMarkerFileName, []byte(jobStateMarkerContents)); err != nil {
		return nil, fmt.Errorf("initialize job state root: %w", err)
	}
	initialized = true
	return &jobStore{root: resolvedRoot}, nil
}

func resolveJobStateRoot(root string) (string, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(resolvedRoot) || resolvedRoot == string(filepath.Separator) {
		return "", fmt.Errorf("job state root is invalid")
	}
	return resolvedRoot, nil
}

func validateExistingJobStateRoot(root string) error {
	if err := validatePrivateJobStateRoot(root); err != nil {
		return err
	}
	markerPath := filepath.Join(root, jobStateMarkerFileName)
	info, err := os.Lstat(markerPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > int64(maxJobStateMarkerBytes) {
		return fmt.Errorf("job state root ownership marker is invalid")
	}
	file, err := os.Open(markerPath)
	if err != nil {
		return fmt.Errorf("job state root ownership marker is invalid")
	}
	marker, readErr := io.ReadAll(io.LimitReader(file, int64(maxJobStateMarkerBytes)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !validJobStateMarker(string(marker)) {
		return fmt.Errorf("job state root ownership marker is invalid")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("read job state root: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() == jobStateMarkerFileName {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("job state root contents are invalid")
		}
		switch {
		case entry.Name() == jobStateLockFileName:
			if !info.Mode().IsRegular() {
				return fmt.Errorf("job state root contents are invalid")
			}
		case strings.HasPrefix(entry.Name(), jobTransactionDirPrefix), validJobSafeID(entry.Name()):
			if !info.IsDir() {
				return fmt.Errorf("job state root contents are invalid")
			}
		default:
			return fmt.Errorf("job state root contents are invalid")
		}
	}
	return nil
}

func validJobStateMarker(marker string) bool {
	if marker == jobStateMarkerContents {
		return true
	}
	if !strings.HasPrefix(marker, jobStateWorkerPrefix) || !strings.HasSuffix(marker, "\n") {
		return false
	}
	workerID := strings.TrimSuffix(strings.TrimPrefix(marker, jobStateWorkerPrefix), "\n")
	return validJobSafeID(workerID) && marker == jobStateWorkerPrefix+workerID+"\n"
}

func (store *jobStore) bindWorkerID(workerID string) error {
	if store == nil || !validJobSafeID(workerID) {
		return fmt.Errorf("job state root worker identity is invalid")
	}
	markerPath := filepath.Join(store.root, jobStateMarkerFileName)
	marker, err := os.ReadFile(markerPath)
	if err != nil || !validJobStateMarker(string(marker)) {
		return fmt.Errorf("job state root ownership marker is invalid")
	}
	boundMarker := jobStateWorkerPrefix + workerID + "\n"
	switch string(marker) {
	case jobStateMarkerContents:
		if err := writePrivateFileAtomic(store.root, jobStateMarkerFileName, []byte(boundMarker)); err != nil {
			return fmt.Errorf("bind job state root worker identity: %w", err)
		}
		return nil
	case boundMarker:
		return nil
	default:
		return fmt.Errorf("job state root worker identity does not match")
	}
}

func validatePrivateJobStateRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("job state root is invalid")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("job state root permissions are invalid")
	}
	return validateJobStateRootOwner(info)
}

func (store *jobStore) loadAll() ([]storedJob, error) {
	if store == nil {
		return nil, fmt.Errorf("job store is unavailable")
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, fmt.Errorf("read job state root: %w", err)
	}
	cleanedTransactions := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), jobTransactionDirPrefix) {
			continue
		}
		transactionDir := filepath.Join(store.root, entry.Name())
		info, err := os.Lstat(transactionDir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("incomplete job state transaction is invalid")
		}
		if err := os.RemoveAll(transactionDir); err != nil {
			return nil, fmt.Errorf("remove incomplete job state transaction: %w", err)
		}
		cleanedTransactions = true
	}
	if cleanedTransactions {
		if err := syncPrivateDirectory(store.root); err != nil {
			return nil, fmt.Errorf("sync job state root: %w", err)
		}
	}
	jobs := make([]storedJob, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !validJobSafeID(entry.Name()) {
			continue
		}
		jobDir := filepath.Join(store.root, entry.Name())
		info, err := os.Lstat(jobDir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("job state directory is invalid")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("job state directory permissions are too broad")
		}
		job, err := loadJobStateFile(filepath.Join(jobDir, jobStateFileName))
		if err != nil {
			return nil, err
		}
		if job.ID != entry.Name() {
			return nil, fmt.Errorf("job state identity does not match its directory")
		}
		logs, err := loadJobLogsFile(filepath.Join(jobDir, jobLogsFileName))
		if err != nil {
			return nil, err
		}
		reconcileJobLogSnapshot(&job, logs)
		jobs = append(jobs, storedJob{Job: job, Records: logs.Records})
	}
	return jobs, nil
}

func (store *jobStore) save(job Job, records []JobLogRecord) error {
	if store == nil {
		return fmt.Errorf("job store is unavailable")
	}
	if err := job.Validate(); err != nil {
		return fmt.Errorf("persist job state: %w", err)
	}
	jobDir, err := store.jobDir(job.ID)
	if err != nil {
		return err
	}
	stateData, err := json.Marshal(storedJobState{
		Job:        job,
		RequestKey: job.requestKey,
	})
	if err != nil {
		return fmt.Errorf("encode job state: %w", err)
	}
	logData, err := encodeStoredJobLogs(job, records)
	if err != nil {
		return fmt.Errorf("encode job logs: %w", err)
	}
	if int64(len(logData)) > maxJobLogsFileBytes {
		return fmt.Errorf("persist job logs: encoded logs exceed size limit")
	}
	if _, err := os.Lstat(jobDir); errors.Is(err, fs.ErrNotExist) {
		return store.create(jobDir, append(stateData, '\n'), logData)
	} else if err != nil {
		return fmt.Errorf("inspect job state directory: %w", err)
	}
	if err := ensurePrivateJobDir(jobDir); err != nil {
		return err
	}
	if err := writePrivateFileAtomic(jobDir, jobLogsFileName, logData); err != nil {
		return fmt.Errorf("persist job logs: %w", err)
	}
	if err := writePrivateFileAtomic(jobDir, jobStateFileName, append(stateData, '\n')); err != nil {
		return fmt.Errorf("persist job state: %w", err)
	}
	return nil
}

func (store *jobStore) create(jobDir string, stateData, logData []byte) error {
	transactionDir, err := os.MkdirTemp(store.root, jobTransactionDirPrefix)
	if err != nil {
		return fmt.Errorf("create job state transaction: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(transactionDir)
		}
	}()
	if err := os.Chmod(transactionDir, 0o700); err != nil {
		return fmt.Errorf("secure job state transaction: %w", err)
	}
	if err := writePrivateFileAtomic(transactionDir, jobLogsFileName, logData); err != nil {
		return fmt.Errorf("persist job logs: %w", err)
	}
	if err := writePrivateFileAtomic(transactionDir, jobStateFileName, stateData); err != nil {
		return fmt.Errorf("persist job state: %w", err)
	}
	if _, err := os.Lstat(jobDir); err == nil {
		return fmt.Errorf("job state directory already exists")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect job state directory: %w", err)
	}
	if err := os.Rename(transactionDir, jobDir); err != nil {
		return fmt.Errorf("publish job state: %w", err)
	}
	published = true
	if err := syncPrivateDirectory(store.root); err != nil {
		return fmt.Errorf("sync job state root: %w", err)
	}
	return nil
}

func (store *jobStore) jobDir(jobID string) (string, error) {
	if err := validateJobID(jobID); err != nil {
		return "", err
	}
	return filepath.Join(store.root, jobID), nil
}

func ensurePrivateJobDir(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("job state directory is invalid")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect job state directory: %w", err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create job state directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure job state directory: %w", err)
	}
	return nil
}

func loadJobStateFile(path string) (Job, error) {
	var state storedJobState
	if err := decodePrivateJSONFile(path, &state, 64<<10); err != nil {
		return Job{}, fmt.Errorf("load job state: %w", err)
	}
	job := state.Job
	job.requestKey = state.RequestKey
	if err := job.Validate(); err != nil {
		return Job{}, fmt.Errorf("load job state: %w", err)
	}
	return job, nil
}

func loadJobLogsFile(path string) (storedJobLogs, error) {
	var logs storedJobLogs
	if err := decodePrivateJSONFile(path, &logs, maxJobLogsFileBytes); err != nil {
		return storedJobLogs{}, fmt.Errorf("load job logs: %w", err)
	}
	response := JobLogsResponse{
		ContractVersion: JobContractVersion,
		JobID:           "validation",
		Records:         logs.Records,
	}
	if len(logs.Records) > 0 {
		response.NextCursor = logs.Records[len(logs.Records)-1].Cursor
	}
	if err := response.Validate(); err != nil {
		return storedJobLogs{}, fmt.Errorf("load job logs: %w", err)
	}
	if logs.LogCursor == 0 {
		logs.LogCursor = response.NextCursor
	} else if logs.LogCursor < response.NextCursor {
		return storedJobLogs{}, fmt.Errorf("load job logs: persisted cursor precedes retained records")
	}
	logs.LogTruncated = logs.LogTruncated || logs.StdoutTruncated || logs.StderrTruncated
	if logs.LogCursor > response.NextCursor && !logs.LogTruncated {
		return storedJobLogs{}, fmt.Errorf("load job logs: persisted cursor has no truncation proof")
	}
	logs.Records = cloneJobLogRecords(logs.Records)
	return logs, nil
}

func encodeStoredJobLogs(job Job, records []JobLogRecord) ([]byte, error) {
	data, err := json.Marshal(storedJobLogs{
		Records:         records,
		LogCursor:       job.LogCursor,
		LogTruncated:    job.LogTruncated,
		StdoutTruncated: job.StdoutTruncated,
		StderrTruncated: job.StderrTruncated,
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func reconcileJobLogSnapshot(job *Job, logs storedJobLogs) {
	if job == nil {
		return
	}
	if logs.LogCursor > job.LogCursor {
		job.LogCursor = logs.LogCursor
	}
	job.LogTruncated = job.LogTruncated || logs.LogTruncated
	job.StdoutTruncated = job.StdoutTruncated || logs.StdoutTruncated
	job.StderrTruncated = job.StderrTruncated || logs.StderrTruncated
}

func decodePrivateJSONFile(path string, target any, maxBytes int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private state file is invalid")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private state file permissions are too broad")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("private state file exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("private state file is corrupt")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("private state file is corrupt")
	}
	return nil
}

func writePrivateFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".job-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	target := filepath.Join(dir, name)
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private state file target is invalid")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	if err := os.Chmod(target, 0o600); err != nil {
		return err
	}
	return syncPrivateDirectory(dir)
}

func syncPrivateDirectory(dir string) error {
	dirHandle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirHandle.Close()
	return dirHandle.Sync()
}

func cloneJobLogRecords(records []JobLogRecord) []JobLogRecord {
	if records == nil {
		return nil
	}
	return append([]JobLogRecord(nil), records...)
}
