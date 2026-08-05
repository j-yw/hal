// Package v2control owns data-only credential identity contracts for the
// guest-agent v2 control channel. It performs no transport or lifecycle work.
package v2control

import (
	"encoding/base64"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// DeliveryMode is an alias of the root credential delivery-mode authority.
type DeliveryMode = sandboxruntime.JobCredentialDeliveryMode

// JobBinding correlates one ordered root binding ID with its delivery mode.
type JobBinding struct {
	BindingID string       `json:"bindingId"`
	Mode      DeliveryMode `json:"mode"`
}

// JobIdentity is the exact data-only child projection of a complete root job
// credential identity.
type JobIdentity struct {
	SandboxID                    string       `json:"sandboxId"`
	ExecutionID                  string       `json:"executionId"`
	WorkerID                     string       `json:"workerId"`
	HostID                       string       `json:"hostId"`
	RuntimeDriver                string       `json:"runtimeDriver"`
	RuntimeID                    string       `json:"runtimeId"`
	RuntimeGeneration            string       `json:"runtimeGeneration"`
	FirecrackerProcessGeneration string       `json:"firecrackerProcessGeneration"`
	VsockGeneration              string       `json:"vsockGeneration"`
	WorkerJobID                  string       `json:"workerJobId"`
	SubmissionID                 string       `json:"submissionId"`
	PlanID                       string       `json:"planId"`
	ActivationGeneration         string       `json:"activationGeneration"`
	CredentialGeneration         string       `json:"credentialGeneration"`
	NetworkPlanID                string       `json:"networkPlanId"`
	PolicySnapshotID             string       `json:"policySnapshotId"`
	ProxySessionID               string       `json:"proxySessionId"`
	ProxyGenerationID            string       `json:"proxyGenerationId"`
	TopologyGenerationID         string       `json:"topologyGenerationId"`
	RuleGenerationID             string       `json:"ruleGenerationId"`
	AdmissionGrantID             string       `json:"admissionGrantId"`
	PrincipalID                  string       `json:"principalId"`
	TemplatePolicyID             string       `json:"templatePolicyId"`
	WorkspacePolicyID            string       `json:"workspacePolicyId"`
	ControllerKeyGeneration      string       `json:"controllerKeyGeneration"`
	GuestBootGeneration          string       `json:"guestBootGeneration"`
	GuestImageGeneration         string       `json:"guestImageGeneration"`
	GuestImageDigest             string       `json:"guestImageDigest"`
	GuestSessionGeneration       string       `json:"guestSessionGeneration"`
	GuestHelperGeneration        string       `json:"guestHelperGeneration"`
	AdmissionGrantRevision       uint64       `json:"admissionGrantRevision"`
	IssuedAtUnixNano             int64        `json:"issuedAtUnixNano"`
	Bindings                     []JobBinding `json:"bindings"`
}

// JobIdentityFromRoot validates and defensively projects the root identity.
func JobIdentityFromRoot(root sandboxruntime.JobCredentialIdentity) (JobIdentity, error) {
	if err := sandboxruntime.ValidateJobCredentialIdentity(root); err != nil {
		return JobIdentity{}, ErrInvalidJobIdentity
	}
	bindings := make([]JobBinding, len(root.BindingIDs))
	for index := range root.BindingIDs {
		bindings[index] = JobBinding{
			BindingID: root.BindingIDs[index],
			Mode:      root.DeliveryModes[index],
		}
	}
	identity := JobIdentity{
		SandboxID: root.SandboxID, ExecutionID: root.ExecutionID,
		WorkerID: root.WorkerID, HostID: root.HostID,
		RuntimeDriver: root.RuntimeDriver, RuntimeID: root.RuntimeID,
		RuntimeGeneration:            root.RuntimeGeneration,
		FirecrackerProcessGeneration: root.FirecrackerProcessGeneration,
		VsockGeneration:              root.VsockGeneration,
		WorkerJobID:                  root.WorkerJobID, SubmissionID: root.SubmissionID,
		PlanID: root.PlanID, ActivationGeneration: root.ActivationGeneration,
		CredentialGeneration: root.CredentialGeneration,
		NetworkPlanID:        root.NetworkPlanID, PolicySnapshotID: root.PolicySnapshotID,
		ProxySessionID: root.ProxySessionID, ProxyGenerationID: root.ProxyGenerationID,
		TopologyGenerationID: root.TopologyGenerationID, RuleGenerationID: root.RuleGenerationID,
		AdmissionGrantID: root.AdmissionGrantID, PrincipalID: root.PrincipalID,
		TemplatePolicyID: root.TemplatePolicyID, WorkspacePolicyID: root.WorkspacePolicyID,
		ControllerKeyGeneration: root.ControllerKeyGeneration,
		GuestBootGeneration:     root.GuestBootGeneration,
		GuestImageGeneration:    root.GuestImageGeneration,
		GuestImageDigest:        root.GuestImageDigest,
		GuestSessionGeneration:  root.GuestSessionGeneration,
		GuestHelperGeneration:   root.GuestHelperGeneration,
		AdmissionGrantRevision:  root.AdmissionGrantRevision,
		IssuedAtUnixNano:        root.IssuedAt.UnixNano(), Bindings: bindings,
	}
	if err := ValidateJobIdentity(identity); err != nil {
		return JobIdentity{}, err
	}
	return identity, nil
}

// ValidateJobIdentity revalidates every child field through the root identity
// authority, including ordered bindings and mode-dependent network fields.
func ValidateJobIdentity(identity JobIdentity) error {
	root := rootJobIdentity(identity)
	if err := sandboxruntime.ValidateJobCredentialIdentity(root); err != nil {
		return ErrInvalidJobIdentity
	}
	return nil
}

// JobIdentityDigest delegates the canonical digest to the validated root
// authority so the child cannot define a divergent formula.
func JobIdentityDigest(identity JobIdentity) ([32]byte, error) {
	root := rootJobIdentity(identity)
	if err := sandboxruntime.ValidateJobCredentialIdentity(root); err != nil {
		return [32]byte{}, ErrInvalidJobIdentity
	}
	digest, err := sandboxruntime.JobCredentialIdentityDigest(root)
	if err != nil {
		return [32]byte{}, ErrInvalidJobIdentity
	}
	return digest, nil
}

func rootJobIdentity(identity JobIdentity) sandboxruntime.JobCredentialIdentity {
	bindingIDs := make([]string, len(identity.Bindings))
	modes := make([]sandboxruntime.JobCredentialDeliveryMode, len(identity.Bindings))
	for index, binding := range identity.Bindings {
		bindingIDs[index] = binding.BindingID
		modes[index] = binding.Mode
	}
	return sandboxruntime.JobCredentialIdentity{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID,
		WorkerID: identity.WorkerID, HostID: identity.HostID,
		RuntimeDriver: identity.RuntimeDriver, RuntimeID: identity.RuntimeID,
		RuntimeGeneration:            identity.RuntimeGeneration,
		FirecrackerProcessGeneration: identity.FirecrackerProcessGeneration,
		VsockGeneration:              identity.VsockGeneration,
		WorkerJobID:                  identity.WorkerJobID, SubmissionID: identity.SubmissionID,
		PlanID: identity.PlanID, ActivationGeneration: identity.ActivationGeneration,
		CredentialGeneration: identity.CredentialGeneration,
		NetworkPlanID:        identity.NetworkPlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
		AdmissionGrantID: identity.AdmissionGrantID, PrincipalID: identity.PrincipalID,
		TemplatePolicyID: identity.TemplatePolicyID, WorkspacePolicyID: identity.WorkspacePolicyID,
		ControllerKeyGeneration: identity.ControllerKeyGeneration,
		GuestBootGeneration:     identity.GuestBootGeneration,
		GuestImageGeneration:    identity.GuestImageGeneration,
		GuestImageDigest:        identity.GuestImageDigest,
		GuestSessionGeneration:  identity.GuestSessionGeneration,
		GuestHelperGeneration:   identity.GuestHelperGeneration,
		AdmissionGrantRevision:  identity.AdmissionGrantRevision,
		IssuedAt:                time.Unix(0, identity.IssuedAtUnixNano).UTC(),
		BindingIDs:              bindingIDs, DeliveryModes: modes,
	}
}

func cloneJobIdentity(identity JobIdentity) JobIdentity {
	identity.Bindings = append([]JobBinding(nil), identity.Bindings...)
	return identity
}

func generationForSessionID(sessionID [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(sessionID[:])
}
