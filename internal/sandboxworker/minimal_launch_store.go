package sandboxworker

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const minimalLaunchPrivateVersion = "sandboxjob-minimal-launch-private-v1"

type storedMinimalLaunchV1 struct {
	ContractVersion      string    `json:"contractVersion"`
	Revision             uint64    `json:"revision"`
	Phase                string    `json:"phase"`
	JobGeneration        string    `json:"jobGeneration"`
	SandboxID            string    `json:"sandboxId"`
	ExecutionID          string    `json:"executionId"`
	SubmissionID         string    `json:"submissionId"`
	RuntimeGeneration    string    `json:"runtimeGeneration"`
	LaunchGrantID        string    `json:"launchGrantId"`
	LaunchPolicyID       string    `json:"launchPolicyId"`
	LaunchPolicyRevision uint64    `json:"launchPolicyRevision"`
	NetworkPolicyID      string    `json:"networkPolicyId"`
	PreparationStartedAt time.Time `json:"preparationStartedAt"`
	PreparationDeadline  time.Time `json:"preparationDeadline"`
}

func validateStoredMinimalLaunchV1(state storedJobStateV2) error {
	m := state.MinimalLaunch
	if m == nil || m.ContractVersion != minimalLaunchPrivateVersion || state.CredentialState != nil || state.CredentialRecoveryReceipt != nil || !state.JobV2.CredentialIntent.ProductionCredentialsRequested || state.JobV2.RuntimeDriver != RuntimeDriverMicroVM || state.JobV2.State != JobStateQueued {
		return errMinimalLaunchState
	}
	if !(m.Phase == "reserved" && m.Revision == 1 || m.Phase == "dispatching" && m.Revision == 2) || m.LaunchPolicyRevision == 0 || m.JobGeneration == state.JobV2.ID || m.LaunchGrantID == state.JobV2.CredentialIntent.AdmissionGrantID ||
		!m.PreparationStartedAt.Equal(state.JobV2.SubmittedAt) || m.PreparationStartedAt.IsZero() || !m.PreparationDeadline.After(m.PreparationStartedAt) || m.PreparationDeadline.Sub(m.PreparationStartedAt) > maxMinimalLaunchPreparationTimeout {
		return errMinimalLaunchState
	}
	for _, id := range []string{state.JobV2.ID, state.JobV2.WorkerID, state.JobV2.HostID, state.JobV2.RuntimeID, state.PrincipalID,
		state.JobV2.CredentialIntent.PlanID, state.JobV2.CredentialIntent.TemplatePolicyID, state.JobV2.CredentialIntent.WorkspacePolicyID,
		m.JobGeneration, m.SandboxID, m.ExecutionID, m.SubmissionID, m.RuntimeGeneration, m.LaunchGrantID, m.LaunchPolicyID, m.NetworkPolicyID} {
		if len(id) > 64 || !validWorkerV2SafeID(id) {
			return errMinimalLaunchState
		}
	}
	return nil
}

var errMinimalLaunchState = errors.New("worker minimal launch state is unavailable")

// The initial selected consumer does not recover records yet. Only the exact
// held lock may exist: an unknown entry is not evidence of an empty job store.
func (store *jobStoreV2) requireMinimalLaunchEmpty(lock *jobStateLock) error {
	if store == nil || lock == nil {
		return ErrL8RecoveryDependency
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.file == nil {
		return ErrL8RecoveryDependency
	}
	directory, err := openMinimalLaunchNoFollow(store.root, true)
	if err != nil {
		return ErrL8RecoveryDependency
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !minimalLaunchFileOwned(info) {
		return ErrL8RecoveryDependency
	}
	names, err := directory.Readdirnames(2)
	if err != nil && err != io.EOF || len(names) != 1 || names[0] != jobStateLockFileName {
		return ErrL8RecoveryDependency
	}
	held, heldErr := lock.file.Stat()
	current, currentErr := os.Lstat(filepath.Join(store.root, jobStateLockFileName))
	root, rootErr := os.Lstat(store.root)
	if heldErr != nil || currentErr != nil || rootErr != nil || !os.SameFile(held, current) || !held.Mode().IsRegular() || held.Mode().Perm() != 0o600 || !minimalLaunchFileOwned(held) || !os.SameFile(info, root) || directory.Close() != nil {
		return ErrL8RecoveryDependency
	}
	return nil
}

// saveMinimalLaunch keeps the transaction's exact inode open through commit
// and independently reopens/readbacks the published bytes without following a
// final symlink. Any error is uncertain; the manager must poison admission.
// This selected path never calls the legacy write/rename rollback path.
func (store *jobStoreV2) saveMinimalLaunch(state storedJobStateV2) error {
	if store == nil || validateStoredMinimalLaunchV1(state) != nil {
		return errMinimalLaunchState
	}
	payload, err := encodeStoredJobStateV2(state)
	if err != nil || len(payload) == 0 || int64(len(payload)) > maxStoredJobStateV2Bytes {
		return errMinimalLaunchState
	}
	directory, err := openMinimalLaunchNoFollow(store.root, true)
	if err != nil {
		return errMinimalLaunchState
	}
	defer directory.Close()
	dirInfo, err := directory.Stat()
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0o700 || !minimalLaunchFileOwned(dirInfo) {
		return errMinimalLaunchState
	}
	file, err := os.CreateTemp(store.root, ".minimal-"+state.JobV2.ID+"-")
	if err != nil {
		return errMinimalLaunchState
	}
	defer file.Close()
	defer os.Remove(file.Name())
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !minimalLaunchFileOwned(info) {
		return errMinimalLaunchState
	}
	if n, err := file.Write(payload); err != nil || n != len(payload) {
		return errMinimalLaunchState
	}
	if file.Sync() != nil {
		return errMinimalLaunchState
	}
	path := filepath.Join(store.root, state.JobV2.ID+".json")
	if state.MinimalLaunch.Phase == "reserved" {
		// Link is an exclusive initial publication, never an overwrite. The
		// private temporary name is removed only after successful readback.
		if os.Link(file.Name(), path) != nil {
			return errMinimalLaunchState
		}
	} else {
		prior, err := store.readMinimalLaunchFile(path)
		if err != nil || prior.MinimalLaunch == nil || prior.MinimalLaunch.Phase != "reserved" {
			return errMinimalLaunchState
		}
		expected := cloneStoredJobStateV2(state)
		expected.MinimalLaunch.Phase, expected.MinimalLaunch.Revision = "reserved", 1
		previous, err := encodeStoredJobStateV2(prior)
		want, wantErr := encodeStoredJobStateV2(expected)
		if err != nil || wantErr != nil || !bytes.Equal(previous, want) || os.Rename(file.Name(), path) != nil {
			return errMinimalLaunchState
		}
	}
	if directory.Sync() != nil {
		return errMinimalLaunchState
	}
	currentDir, err := os.Lstat(store.root)
	if err != nil || !os.SameFile(dirInfo, currentDir) {
		return errMinimalLaunchState
	}
	current, err := openMinimalLaunchNoFollow(path, false)
	if err != nil {
		return errMinimalLaunchState
	}
	defer current.Close()
	currentInfo, err := current.Stat()
	writtenInfo, writtenErr := file.Stat()
	if err != nil || writtenErr != nil || !os.SameFile(writtenInfo, currentInfo) || !validMinimalLaunchStoredFile(currentInfo) {
		return errMinimalLaunchState
	}
	readback, err := io.ReadAll(io.LimitReader(current, maxStoredJobStateV2Bytes+1))
	if err != nil || !bytes.Equal(readback, payload) {
		return errMinimalLaunchState
	}
	var decoded storedJobStateV2
	if decodeStoredJobStateV2Into(bytes.NewReader(readback), maxStoredJobStateV2Bytes, &decoded) != nil || decoded.Validate() != nil {
		return errMinimalLaunchState
	}
	finalInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(writtenInfo, finalInfo) || !validMinimalLaunchStoredFile(finalInfo) {
		return errMinimalLaunchState
	}
	if os.Remove(file.Name()) != nil && state.MinimalLaunch.Phase == "reserved" {
		return errMinimalLaunchState
	}
	if directory.Sync() != nil {
		return errMinimalLaunchState
	}
	// Explicit close errors precede admission too; deferred closes are cleanup
	// only and do not turn a failed close into an accepted transaction.
	if current.Close() != nil || file.Close() != nil || directory.Close() != nil {
		return errMinimalLaunchState
	}
	return nil
}

func (store *jobStoreV2) readMinimalLaunchFile(path string) (storedJobStateV2, error) {
	file, err := openMinimalLaunchNoFollow(path, false)
	if err != nil {
		return storedJobStateV2{}, errMinimalLaunchState
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !validMinimalLaunchStoredFile(info) {
		return storedJobStateV2{}, errMinimalLaunchState
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxStoredJobStateV2Bytes+1))
	if err != nil || int64(len(payload)) != info.Size() {
		return storedJobStateV2{}, errMinimalLaunchState
	}
	var state storedJobStateV2
	if decodeStoredJobStateV2Into(bytes.NewReader(payload), maxStoredJobStateV2Bytes, &state) != nil || state.Validate() != nil || state.MinimalLaunch == nil {
		return storedJobStateV2{}, errMinimalLaunchState
	}
	canonical, err := encodeStoredJobStateV2(state)
	if err != nil || !bytes.Equal(canonical, payload) {
		return storedJobStateV2{}, errMinimalLaunchState
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) || !validMinimalLaunchStoredFile(current) || file.Close() != nil {
		return storedJobStateV2{}, errMinimalLaunchState
	}
	return state, nil
}

func validMinimalLaunchStoredFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && minimalLaunchFileOwned(info) && info.Size() > 0 && info.Size() <= maxStoredJobStateV2Bytes
}
