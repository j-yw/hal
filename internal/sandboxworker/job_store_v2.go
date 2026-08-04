package sandboxworker

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const maxStoredJobStateV2Bytes int64 = 64 << 10

type storedJobStateV2 struct {
	JobV2            JobV2
	RequestKey       string `json:"requestKey"`
	PrincipalID      string `json:"principalId"`
	DaemonGeneration string `json:"daemonGeneration"`
}

type jobStoreV2 struct {
	root string
}

type storedJobReaderV2 interface {
	io.Reader
	Close() error
}

func newJobStoreV2(root string) (*jobStoreV2, error) {
	cleaned := filepath.Clean(root)
	if !filepath.IsAbs(cleaned) || cleaned == string(filepath.Separator) {
		return nil, errors.New("job v2 state root is invalid")
	}
	if err := os.MkdirAll(cleaned, 0o700); err != nil {
		return nil, errors.New("job v2 state root could not be created")
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil || !filepath.IsAbs(resolved) || resolved == string(filepath.Separator) {
		return nil, errors.New("job v2 state root is invalid")
	}
	cleaned = resolved
	info, err := os.Lstat(cleaned)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("job v2 state root is invalid")
	}
	if err := os.Chmod(cleaned, 0o700); err != nil {
		return nil, errors.New("job v2 state root could not be secured")
	}
	return &jobStoreV2{root: cleaned}, nil
}

func (state storedJobStateV2) Validate() error {
	if err := state.JobV2.Validate(); err != nil {
		return err
	}
	if !validWorkerV2OpaqueKey(state.RequestKey, "request-v2-") {
		return errors.New("stored worker job request identity is invalid")
	}
	if !validWorkerV2SafeID(state.PrincipalID) || !validWorkerV2SafeID(state.DaemonGeneration) {
		return errors.New("stored worker job private identity is invalid")
	}
	return nil
}

func encodeStoredJobStateV2(state storedJobStateV2) ([]byte, error) {
	return json.Marshal(state)
}

func (store *jobStoreV2) save(state storedJobStateV2) error {
	if store == nil {
		return errors.New("job v2 store is unavailable")
	}
	if err := state.Validate(); err != nil {
		return err
	}
	payload, err := encodeStoredJobStateV2(state)
	if err != nil {
		return errors.New("job v2 state could not be encoded")
	}
	if int64(len(payload)) > maxStoredJobStateV2Bytes {
		return errors.New("job v2 state exceeds limit")
	}
	path := filepath.Join(store.root, state.JobV2.ID+".json")
	temporary := path + ".tmp"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("job v2 state transaction could not be opened")
	}
	if _, err = file.Write(payload); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(temporary)
		return errors.New("job v2 state could not be written")
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return errors.New("job v2 state could not be committed")
	}
	directory, err := os.Open(store.root)
	if err != nil {
		return errors.New("job v2 state root could not be synchronized")
	}
	if err = directory.Sync(); err == nil {
		err = directory.Close()
	} else {
		_ = directory.Close()
	}
	if err != nil {
		return errors.New("job v2 state root could not be synchronized")
	}
	return nil
}

func (store *jobStoreV2) openStoredJobStateV2(jobID string) (storedJobReaderV2, error) {
	if store == nil || !validJobSafeID(jobID) {
		return nil, errors.New("stored job state is unavailable")
	}
	path := filepath.Join(store.root, jobID+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxStoredJobStateV2Bytes {
		return nil, errors.New("stored job state is unavailable")
	}
	return os.Open(path)
}

func (store *jobStoreV2) load(jobID string) (storedJobStateV2, error) {
	reader, err := store.openStoredJobStateV2(jobID)
	if err != nil {
		return storedJobStateV2{}, errors.New("stored job state could not be opened")
	}
	defer reader.Close()
	var state storedJobStateV2
	if err := decodeStoredJobStateV2Into(reader, maxStoredJobStateV2Bytes, &state); err != nil {
		return storedJobStateV2{}, errors.New("stored job state is malformed")
	}
	if err := state.Validate(); err != nil {
		return storedJobStateV2{}, errors.New("stored job state is malformed")
	}
	if state.JobV2.ID != jobID {
		return storedJobStateV2{}, errors.New("stored job state is malformed")
	}
	return state, nil
}

func (store *jobStoreV2) list() ([]storedJobStateV2, error) {
	if store == nil {
		return nil, errors.New("job v2 store is unavailable")
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return nil, errors.New("job v2 state root could not be read")
	}
	states := make([]storedJobStateV2, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		jobID := entry.Name()[:len(entry.Name())-len(".json")]
		state, err := store.load(jobID)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	for index := 1; index < len(states); index++ {
		for current := index; current > 0 && states[current].JobV2.ID < states[current-1].JobV2.ID; current-- {
			states[current], states[current-1] = states[current-1], states[current]
		}
	}
	return states, nil
}

func reconcileJobStoreV2AtStartup(store *jobStoreV2, restartAt time.Time) ([]storedJobStateV2, error) {
	states, err := store.list()
	if err != nil {
		return nil, err
	}
	for index := range states {
		if states[index].JobV2.State != JobStateQueued {
			continue
		}
		finishedAt := restartAt
		states[index].JobV2.State = JobStateInterrupted
		states[index].JobV2.FailureCode = "daemon_restarted_before_start"
		states[index].JobV2.FinishedAt = &finishedAt
		if err := store.save(states[index]); err != nil {
			return nil, err
		}
	}
	return states, nil
}
