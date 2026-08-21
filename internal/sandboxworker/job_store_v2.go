package sandboxworker

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const maxStoredJobStateV2Bytes int64 = 64 << 10

const storedJobCredentialContractVersionV2 = "sandboxjob-credential-private-v1"

type storedJobCredentialIdentitySeedV1 struct {
	SandboxID                    string    `json:"sandboxId"`
	ExecutionID                  string    `json:"executionId"`
	WorkerID                     string    `json:"workerId"`
	HostID                       string    `json:"hostId"`
	RuntimeDriver                string    `json:"runtimeDriver"`
	RuntimeID                    string    `json:"runtimeId"`
	RuntimeGeneration            string    `json:"runtimeGeneration"`
	FirecrackerProcessGeneration string    `json:"firecrackerProcessGeneration"`
	VsockGeneration              string    `json:"vsockGeneration"`
	WorkerJobID                  string    `json:"workerJobId"`
	SubmissionID                 string    `json:"submissionId"`
	PlanID                       string    `json:"planId"`
	ActivationGeneration         string    `json:"activationGeneration"`
	CredentialGeneration         string    `json:"credentialGeneration"`
	NetworkPlanID                string    `json:"networkPlanId"`
	PolicySnapshotID             string    `json:"policySnapshotId"`
	ProxySessionID               string    `json:"proxySessionId"`
	ProxyGenerationID            string    `json:"proxyGenerationId"`
	TopologyGenerationID         string    `json:"topologyGenerationId"`
	RuleGenerationID             string    `json:"ruleGenerationId"`
	AdmissionGrantID             string    `json:"admissionGrantId"`
	PrincipalID                  string    `json:"principalId"`
	TemplatePolicyID             string    `json:"templatePolicyId"`
	WorkspacePolicyID            string    `json:"workspacePolicyId"`
	ControllerKeyGeneration      string    `json:"controllerKeyGeneration"`
	GuestBootGeneration          string    `json:"guestBootGeneration"`
	GuestImageGeneration         string    `json:"guestImageGeneration"`
	GuestImageDigest             string    `json:"guestImageDigest"`
	AdmissionGrantRevision       uint64    `json:"admissionGrantRevision"`
	BindingIDs                   []string  `json:"bindingIds"`
	DeliveryModes                []string  `json:"deliveryModes"`
	IssuedAt                     time.Time `json:"issuedAt"`
}

type storedJobCredentialIdentityV1 struct {
	SandboxID                    string    `json:"sandboxId"`
	ExecutionID                  string    `json:"executionId"`
	WorkerID                     string    `json:"workerId"`
	HostID                       string    `json:"hostId"`
	RuntimeDriver                string    `json:"runtimeDriver"`
	RuntimeID                    string    `json:"runtimeId"`
	RuntimeGeneration            string    `json:"runtimeGeneration"`
	FirecrackerProcessGeneration string    `json:"firecrackerProcessGeneration"`
	VsockGeneration              string    `json:"vsockGeneration"`
	WorkerJobID                  string    `json:"workerJobId"`
	SubmissionID                 string    `json:"submissionId"`
	PlanID                       string    `json:"planId"`
	ActivationGeneration         string    `json:"activationGeneration"`
	CredentialGeneration         string    `json:"credentialGeneration"`
	NetworkPlanID                string    `json:"networkPlanId"`
	PolicySnapshotID             string    `json:"policySnapshotId"`
	ProxySessionID               string    `json:"proxySessionId"`
	ProxyGenerationID            string    `json:"proxyGenerationId"`
	TopologyGenerationID         string    `json:"topologyGenerationId"`
	RuleGenerationID             string    `json:"ruleGenerationId"`
	AdmissionGrantID             string    `json:"admissionGrantId"`
	PrincipalID                  string    `json:"principalId"`
	TemplatePolicyID             string    `json:"templatePolicyId"`
	WorkspacePolicyID            string    `json:"workspacePolicyId"`
	ControllerKeyGeneration      string    `json:"controllerKeyGeneration"`
	GuestBootGeneration          string    `json:"guestBootGeneration"`
	GuestImageGeneration         string    `json:"guestImageGeneration"`
	GuestImageDigest             string    `json:"guestImageDigest"`
	GuestSessionGeneration       string    `json:"guestSessionGeneration"`
	GuestHelperGeneration        string    `json:"guestHelperGeneration"`
	AdmissionGrantRevision       uint64    `json:"admissionGrantRevision"`
	BindingIDs                   []string  `json:"bindingIds"`
	DeliveryModes                []string  `json:"deliveryModes"`
	IssuedAt                     time.Time `json:"issuedAt"`
}

type storedJobCredentialStateV2 struct {
	ContractVersion string                            `json:"contractVersion"`
	Seed            storedJobCredentialIdentitySeedV1 `json:"seed"`
	Identity        *storedJobCredentialIdentityV1    `json:"identity,omitempty"`
	Revision        uint64                            `json:"revision"`
}

type storedJobStateV2 struct {
	JobV2            JobV2
	RequestKey       string                      `json:"requestKey"`
	PrincipalID      string                      `json:"principalId"`
	DaemonGeneration string                      `json:"daemonGeneration"`
	CredentialState  *storedJobCredentialStateV2 `json:"credentialState,omitempty"`
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
	return validateStoredJobCredentialStateV2(state)
}

func validateStoredJobCredentialStateV2(state storedJobStateV2) error {
	if state.CredentialState == nil {
		if state.JobV2.CredentialIntent.ProductionCredentialsRequested {
			return errors.New("stored worker job credential state is required")
		}
		return nil
	}
	credential := state.CredentialState
	if !state.JobV2.CredentialIntent.ProductionCredentialsRequested || credential.ContractVersion != storedJobCredentialContractVersionV2 ||
		credential.Identity == nil && credential.Revision != 0 {
		return errors.New("stored worker job credential state is invalid")
	}
	seed, err := credential.Seed.runtimeSeed()
	if err != nil || seed.WorkerID != state.JobV2.WorkerID || seed.WorkerJobID != state.JobV2.ID || seed.HostID != state.JobV2.HostID ||
		seed.RuntimeDriver != state.JobV2.RuntimeDriver || seed.RuntimeID != state.JobV2.RuntimeID || seed.PlanID != state.JobV2.CredentialIntent.PlanID ||
		seed.AdmissionGrantID != state.JobV2.CredentialIntent.AdmissionGrantID || seed.AdmissionGrantRevision != state.JobV2.CredentialIntent.AdmissionGrantRevision ||
		seed.PrincipalID != state.PrincipalID || seed.TemplatePolicyID != state.JobV2.CredentialIntent.TemplatePolicyID ||
		seed.WorkspacePolicyID != state.JobV2.CredentialIntent.WorkspacePolicyID || !storedJobCredentialBindingsExactV2(seed, state.JobV2.CredentialIntent) {
		return errors.New("stored worker job credential seed is invalid")
	}
	if credential.Identity != nil {
		identity, identityErr := credential.Identity.runtimeIdentity()
		if identityErr != nil || sandboxruntime.ValidateJobCredentialIdentityCompletion(seed, identity) != nil {
			return errors.New("stored worker job credential identity is invalid")
		}
	}
	return nil
}

func newStoredJobCredentialStateV2(seed sandboxruntime.JobCredentialIdentitySeed) (*storedJobCredentialStateV2, error) {
	cloned, err := sandboxruntime.CloneJobCredentialIdentitySeed(seed)
	if err != nil {
		return nil, errors.New("worker job credential seed is invalid")
	}
	return &storedJobCredentialStateV2{
		ContractVersion: storedJobCredentialContractVersionV2,
		Seed:            storedJobCredentialSeedV1(cloned),
	}, nil
}

func (state *storedJobCredentialStateV2) withIdentity(identity sandboxruntime.JobCredentialIdentity) (*storedJobCredentialStateV2, error) {
	if state == nil {
		return nil, errors.New("worker job credential state is invalid")
	}
	seed, err := state.Seed.runtimeSeed()
	if err != nil || sandboxruntime.ValidateJobCredentialIdentityCompletion(seed, identity) != nil {
		return nil, errors.New("worker job credential identity is invalid")
	}
	cloned := cloneStoredJobCredentialStateV2(state)
	stored := storedJobCredentialIdentityV1FromRuntime(identity)
	cloned.Identity = &stored
	return cloned, nil
}

func storedJobCredentialSeedV1(seed sandboxruntime.JobCredentialIdentitySeed) storedJobCredentialIdentitySeedV1 {
	modes := make([]string, len(seed.DeliveryModes))
	for index := range seed.DeliveryModes {
		modes[index] = string(seed.DeliveryModes[index])
	}
	return storedJobCredentialIdentitySeedV1{
		SandboxID: seed.SandboxID, ExecutionID: seed.ExecutionID, WorkerID: seed.WorkerID, HostID: seed.HostID,
		RuntimeDriver: seed.RuntimeDriver, RuntimeID: seed.RuntimeID, RuntimeGeneration: seed.RuntimeGeneration,
		FirecrackerProcessGeneration: seed.FirecrackerProcessGeneration, VsockGeneration: seed.VsockGeneration,
		WorkerJobID: seed.WorkerJobID, SubmissionID: seed.SubmissionID, PlanID: seed.PlanID,
		ActivationGeneration: seed.ActivationGeneration, CredentialGeneration: seed.CredentialGeneration,
		NetworkPlanID: seed.NetworkPlanID, PolicySnapshotID: seed.PolicySnapshotID, ProxySessionID: seed.ProxySessionID,
		ProxyGenerationID: seed.ProxyGenerationID, TopologyGenerationID: seed.TopologyGenerationID, RuleGenerationID: seed.RuleGenerationID,
		AdmissionGrantID: seed.AdmissionGrantID, PrincipalID: seed.PrincipalID, TemplatePolicyID: seed.TemplatePolicyID,
		WorkspacePolicyID: seed.WorkspacePolicyID, ControllerKeyGeneration: seed.ControllerKeyGeneration,
		GuestBootGeneration: seed.GuestBootGeneration, GuestImageGeneration: seed.GuestImageGeneration, GuestImageDigest: seed.GuestImageDigest,
		AdmissionGrantRevision: seed.AdmissionGrantRevision, BindingIDs: append([]string(nil), seed.BindingIDs...), DeliveryModes: modes, IssuedAt: seed.IssuedAt,
	}
}

func (stored storedJobCredentialIdentitySeedV1) runtimeSeed() (sandboxruntime.JobCredentialIdentitySeed, error) {
	modes := make([]sandboxruntime.JobCredentialDeliveryMode, len(stored.DeliveryModes))
	for index := range stored.DeliveryModes {
		modes[index] = sandboxruntime.JobCredentialDeliveryMode(stored.DeliveryModes[index])
	}
	seed := sandboxruntime.JobCredentialIdentitySeed{
		SandboxID: stored.SandboxID, ExecutionID: stored.ExecutionID, WorkerID: stored.WorkerID, HostID: stored.HostID,
		RuntimeDriver: stored.RuntimeDriver, RuntimeID: stored.RuntimeID, RuntimeGeneration: stored.RuntimeGeneration,
		FirecrackerProcessGeneration: stored.FirecrackerProcessGeneration, VsockGeneration: stored.VsockGeneration,
		WorkerJobID: stored.WorkerJobID, SubmissionID: stored.SubmissionID, PlanID: stored.PlanID,
		ActivationGeneration: stored.ActivationGeneration, CredentialGeneration: stored.CredentialGeneration,
		NetworkPlanID: stored.NetworkPlanID, PolicySnapshotID: stored.PolicySnapshotID, ProxySessionID: stored.ProxySessionID,
		ProxyGenerationID: stored.ProxyGenerationID, TopologyGenerationID: stored.TopologyGenerationID, RuleGenerationID: stored.RuleGenerationID,
		AdmissionGrantID: stored.AdmissionGrantID, PrincipalID: stored.PrincipalID, TemplatePolicyID: stored.TemplatePolicyID,
		WorkspacePolicyID: stored.WorkspacePolicyID, ControllerKeyGeneration: stored.ControllerKeyGeneration,
		GuestBootGeneration: stored.GuestBootGeneration, GuestImageGeneration: stored.GuestImageGeneration, GuestImageDigest: stored.GuestImageDigest,
		AdmissionGrantRevision: stored.AdmissionGrantRevision, BindingIDs: append([]string(nil), stored.BindingIDs...), DeliveryModes: modes, IssuedAt: stored.IssuedAt,
	}
	if err := sandboxruntime.ValidateJobCredentialIdentitySeed(seed); err != nil {
		return sandboxruntime.JobCredentialIdentitySeed{}, err
	}
	return seed, nil
}

func storedJobCredentialIdentityV1FromRuntime(identity sandboxruntime.JobCredentialIdentity) storedJobCredentialIdentityV1 {
	modes := make([]string, len(identity.DeliveryModes))
	for index := range identity.DeliveryModes {
		modes[index] = string(identity.DeliveryModes[index])
	}
	return storedJobCredentialIdentityV1{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID, HostID: identity.HostID,
		RuntimeDriver: identity.RuntimeDriver, RuntimeID: identity.RuntimeID, RuntimeGeneration: identity.RuntimeGeneration,
		FirecrackerProcessGeneration: identity.FirecrackerProcessGeneration, VsockGeneration: identity.VsockGeneration,
		WorkerJobID: identity.WorkerJobID, SubmissionID: identity.SubmissionID, PlanID: identity.PlanID,
		ActivationGeneration: identity.ActivationGeneration, CredentialGeneration: identity.CredentialGeneration,
		NetworkPlanID: identity.NetworkPlanID, PolicySnapshotID: identity.PolicySnapshotID, ProxySessionID: identity.ProxySessionID,
		ProxyGenerationID: identity.ProxyGenerationID, TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
		AdmissionGrantID: identity.AdmissionGrantID, PrincipalID: identity.PrincipalID, TemplatePolicyID: identity.TemplatePolicyID,
		WorkspacePolicyID: identity.WorkspacePolicyID, ControllerKeyGeneration: identity.ControllerKeyGeneration,
		GuestBootGeneration: identity.GuestBootGeneration, GuestImageGeneration: identity.GuestImageGeneration, GuestImageDigest: identity.GuestImageDigest,
		GuestSessionGeneration: identity.GuestSessionGeneration, GuestHelperGeneration: identity.GuestHelperGeneration,
		AdmissionGrantRevision: identity.AdmissionGrantRevision, BindingIDs: append([]string(nil), identity.BindingIDs...), DeliveryModes: modes, IssuedAt: identity.IssuedAt,
	}
}

func (stored storedJobCredentialIdentityV1) runtimeIdentity() (sandboxruntime.JobCredentialIdentity, error) {
	modes := make([]sandboxruntime.JobCredentialDeliveryMode, len(stored.DeliveryModes))
	for index := range stored.DeliveryModes {
		modes[index] = sandboxruntime.JobCredentialDeliveryMode(stored.DeliveryModes[index])
	}
	identity := sandboxruntime.JobCredentialIdentity{
		SandboxID: stored.SandboxID, ExecutionID: stored.ExecutionID, WorkerID: stored.WorkerID, HostID: stored.HostID,
		RuntimeDriver: stored.RuntimeDriver, RuntimeID: stored.RuntimeID, RuntimeGeneration: stored.RuntimeGeneration,
		FirecrackerProcessGeneration: stored.FirecrackerProcessGeneration, VsockGeneration: stored.VsockGeneration,
		WorkerJobID: stored.WorkerJobID, SubmissionID: stored.SubmissionID, PlanID: stored.PlanID,
		ActivationGeneration: stored.ActivationGeneration, CredentialGeneration: stored.CredentialGeneration,
		NetworkPlanID: stored.NetworkPlanID, PolicySnapshotID: stored.PolicySnapshotID, ProxySessionID: stored.ProxySessionID,
		ProxyGenerationID: stored.ProxyGenerationID, TopologyGenerationID: stored.TopologyGenerationID, RuleGenerationID: stored.RuleGenerationID,
		AdmissionGrantID: stored.AdmissionGrantID, PrincipalID: stored.PrincipalID, TemplatePolicyID: stored.TemplatePolicyID,
		WorkspacePolicyID: stored.WorkspacePolicyID, ControllerKeyGeneration: stored.ControllerKeyGeneration,
		GuestBootGeneration: stored.GuestBootGeneration, GuestImageGeneration: stored.GuestImageGeneration, GuestImageDigest: stored.GuestImageDigest,
		GuestSessionGeneration: stored.GuestSessionGeneration, GuestHelperGeneration: stored.GuestHelperGeneration,
		AdmissionGrantRevision: stored.AdmissionGrantRevision, BindingIDs: append([]string(nil), stored.BindingIDs...), DeliveryModes: modes, IssuedAt: stored.IssuedAt,
	}
	if err := sandboxruntime.ValidateJobCredentialIdentity(identity); err != nil {
		return sandboxruntime.JobCredentialIdentity{}, err
	}
	return identity, nil
}

func cloneStoredJobCredentialStateV2(state *storedJobCredentialStateV2) *storedJobCredentialStateV2 {
	if state == nil {
		return nil
	}
	cloned := *state
	cloned.Seed.BindingIDs = append([]string(nil), state.Seed.BindingIDs...)
	cloned.Seed.DeliveryModes = append([]string(nil), state.Seed.DeliveryModes...)
	if state.Identity != nil {
		identity := *state.Identity
		identity.BindingIDs = append([]string(nil), state.Identity.BindingIDs...)
		identity.DeliveryModes = append([]string(nil), state.Identity.DeliveryModes...)
		cloned.Identity = &identity
	}
	return &cloned
}

func cloneStoredJobStateV2(state storedJobStateV2) storedJobStateV2 {
	state.JobV2 = cloneJobV2(state.JobV2)
	state.CredentialState = cloneStoredJobCredentialStateV2(state.CredentialState)
	return state
}

func storedJobCredentialBindingsExactV2(seed sandboxruntime.JobCredentialIdentitySeed, intent JobCredentialIntentV2) bool {
	if len(seed.BindingIDs) != len(intent.Bindings) || len(seed.DeliveryModes) != len(intent.Bindings) {
		return false
	}
	for index, binding := range intent.Bindings {
		if seed.BindingIDs[index] != binding.BindingID || string(seed.DeliveryModes[index]) != binding.Mode {
			return false
		}
	}
	return true
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
	if store == nil || !validWorkerV2JobID(jobID) {
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
	for _, state := range states {
		if state.CredentialState != nil {
			return nil, ErrL8RecoveryDependency
		}
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
