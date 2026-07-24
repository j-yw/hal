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
	jobStateFileName    = "job.json"
	jobLogsFileName     = "logs.json"
	maxJobLogsFileBytes = DefaultJobLogRetentionBytes*6 + (256 << 10)
)

type jobStore struct {
	root string
}

type storedJobLogs struct {
	Records []JobLogRecord `json:"records,omitempty"`
}

type storedJob struct {
	Job     Job
	Records []JobLogRecord
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
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect job state root: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create job state root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("secure job state root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || resolvedRoot != root {
		return nil, fmt.Errorf("job state root is invalid")
	}
	return &jobStore{root: root}, nil
}

func (store *jobStore) loadAll() ([]storedJob, error) {
	if store == nil {
		return nil, fmt.Errorf("job store is unavailable")
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, fmt.Errorf("read job state root: %w", err)
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
		records, err := loadJobLogsFile(filepath.Join(jobDir, jobLogsFileName))
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, storedJob{Job: job, Records: records})
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
	if err := ensurePrivateJobDir(jobDir); err != nil {
		return err
	}
	stateData, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("encode job state: %w", err)
	}
	logData, err := encodeStoredJobLogs(records)
	if err != nil {
		return fmt.Errorf("encode job logs: %w", err)
	}
	if int64(len(logData)) > maxJobLogsFileBytes {
		return fmt.Errorf("persist job logs: encoded logs exceed size limit")
	}
	if err := writePrivateFileAtomic(jobDir, jobLogsFileName, logData); err != nil {
		return fmt.Errorf("persist job logs: %w", err)
	}
	if err := writePrivateFileAtomic(jobDir, jobStateFileName, append(stateData, '\n')); err != nil {
		return fmt.Errorf("persist job state: %w", err)
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
	var job Job
	if err := decodePrivateJSONFile(path, &job, 64<<10); err != nil {
		return Job{}, fmt.Errorf("load job state: %w", err)
	}
	if err := job.Validate(); err != nil {
		return Job{}, fmt.Errorf("load job state: %w", err)
	}
	return job, nil
}

func loadJobLogsFile(path string) ([]JobLogRecord, error) {
	var logs storedJobLogs
	if err := decodePrivateJSONFile(path, &logs, maxJobLogsFileBytes); err != nil {
		return nil, fmt.Errorf("load job logs: %w", err)
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
		return nil, fmt.Errorf("load job logs: %w", err)
	}
	return cloneJobLogRecords(logs.Records), nil
}

func encodeStoredJobLogs(records []JobLogRecord) ([]byte, error) {
	data, err := json.Marshal(storedJobLogs{Records: records})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
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
