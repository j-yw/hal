package sandboxruntime

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
)

const maxJobCredentialIdentityBindings = 16

// ValidateJobCredentialIdentitySeed validates the pre-authentication identity
// fields without changing the supplied value.
func ValidateJobCredentialIdentitySeed(seed JobCredentialIdentitySeed) error {
	values := []string{
		seed.SandboxID, seed.ExecutionID, seed.WorkerID, seed.HostID,
		seed.RuntimeDriver, seed.RuntimeID, seed.RuntimeGeneration,
		seed.FirecrackerProcessGeneration, seed.VsockGeneration,
		seed.WorkerJobID, seed.SubmissionID, seed.PlanID,
		seed.ActivationGeneration, seed.CredentialGeneration,
		seed.AdmissionGrantID, seed.PrincipalID,
		seed.TemplatePolicyID, seed.WorkspacePolicyID,
		seed.ControllerKeyGeneration, seed.GuestBootGeneration,
		seed.GuestImageGeneration,
	}
	for _, value := range values {
		if !validJobCredentialSafeID(value) {
			return ErrJobCredentialIdentityMismatch
		}
	}
	if !validJobCredentialGuestImageDigest(seed.GuestImageDigest) || seed.AdmissionGrantRevision == 0 || seed.IssuedAt.IsZero() ||
		len(seed.BindingIDs) == 0 || len(seed.BindingIDs) > maxJobCredentialIdentityBindings || len(seed.BindingIDs) != len(seed.DeliveryModes) {
		return ErrJobCredentialIdentityMismatch
	}
	httpBindings := 0
	for index, bindingID := range seed.BindingIDs {
		if !validJobCredentialSafeID(bindingID) || !validJobCredentialDeliveryMode(seed.DeliveryModes[index]) {
			return ErrJobCredentialIdentityMismatch
		}
		if seed.DeliveryModes[index] == JobCredentialDeliveryModeHTTPProxy {
			httpBindings++
			if httpBindings > 1 {
				return ErrJobCredentialIdentityMismatch
			}
		}
		for previous := 0; previous < index; previous++ {
			if seed.BindingIDs[previous] == bindingID {
				return ErrJobCredentialIdentityMismatch
			}
		}
	}
	if !validJobCredentialNetworkTuple(seed, httpBindings == 1) {
		return ErrJobCredentialIdentityMismatch
	}
	return nil
}

// CloneJobCredentialIdentitySeed validates and defensively copies a seed.
func CloneJobCredentialIdentitySeed(seed JobCredentialIdentitySeed) (JobCredentialIdentitySeed, error) {
	if err := ValidateJobCredentialIdentitySeed(seed); err != nil {
		return JobCredentialIdentitySeed{}, err
	}
	seed.BindingIDs = append([]string(nil), seed.BindingIDs...)
	seed.DeliveryModes = append([]JobCredentialDeliveryMode(nil), seed.DeliveryModes...)
	return seed, nil
}

// CompleteJobCredentialIdentity adds authenticated guest generations to a
// validated defensive copy of seed.
func CompleteJobCredentialIdentity(seed JobCredentialIdentitySeed, guestSessionGeneration, guestHelperGeneration string) (JobCredentialIdentity, error) {
	cloned, err := CloneJobCredentialIdentitySeed(seed)
	if err != nil {
		return JobCredentialIdentity{}, err
	}
	identity := JobCredentialIdentity{
		SandboxID: cloned.SandboxID, ExecutionID: cloned.ExecutionID, WorkerID: cloned.WorkerID, HostID: cloned.HostID,
		RuntimeDriver: cloned.RuntimeDriver, RuntimeID: cloned.RuntimeID, RuntimeGeneration: cloned.RuntimeGeneration,
		FirecrackerProcessGeneration: cloned.FirecrackerProcessGeneration, VsockGeneration: cloned.VsockGeneration,
		WorkerJobID: cloned.WorkerJobID, SubmissionID: cloned.SubmissionID, PlanID: cloned.PlanID,
		ActivationGeneration: cloned.ActivationGeneration, CredentialGeneration: cloned.CredentialGeneration,
		NetworkPlanID: cloned.NetworkPlanID, PolicySnapshotID: cloned.PolicySnapshotID,
		ProxySessionID: cloned.ProxySessionID, ProxyGenerationID: cloned.ProxyGenerationID,
		TopologyGenerationID: cloned.TopologyGenerationID, RuleGenerationID: cloned.RuleGenerationID,
		AdmissionGrantID: cloned.AdmissionGrantID, PrincipalID: cloned.PrincipalID,
		TemplatePolicyID: cloned.TemplatePolicyID, WorkspacePolicyID: cloned.WorkspacePolicyID,
		ControllerKeyGeneration: cloned.ControllerKeyGeneration, GuestBootGeneration: cloned.GuestBootGeneration,
		GuestImageGeneration: cloned.GuestImageGeneration, GuestImageDigest: cloned.GuestImageDigest,
		GuestSessionGeneration: guestSessionGeneration, GuestHelperGeneration: guestHelperGeneration,
		AdmissionGrantRevision: cloned.AdmissionGrantRevision,
		BindingIDs:             cloned.BindingIDs, DeliveryModes: cloned.DeliveryModes, IssuedAt: cloned.IssuedAt,
	}
	if err := ValidateJobCredentialIdentity(identity); err != nil {
		return JobCredentialIdentity{}, err
	}
	return identity, nil
}

// ValidateJobCredentialIdentityCompletion verifies exact seed-to-identity
// correlation and validates both authenticated guest generations.
func ValidateJobCredentialIdentityCompletion(seed JobCredentialIdentitySeed, identity JobCredentialIdentity) error {
	if ValidateJobCredentialIdentitySeed(seed) != nil || ValidateJobCredentialIdentity(identity) != nil ||
		!sameJobCredentialIdentitySeed(seed, jobCredentialIdentitySeedFromIdentity(identity)) {
		return ErrJobCredentialIdentityMismatch
	}
	return nil
}

// ValidateJobCredentialIdentity validates a complete credential identity.
func ValidateJobCredentialIdentity(identity JobCredentialIdentity) error {
	if ValidateJobCredentialIdentitySeed(jobCredentialIdentitySeedFromIdentity(identity)) != nil ||
		!validJobCredentialGuestSessionGeneration(identity.GuestSessionGeneration) ||
		!validJobCredentialSafeID(identity.GuestHelperGeneration) {
		return ErrJobCredentialIdentityMismatch
	}
	return nil
}

// JobCredentialIdentityDigest returns the canonical digest of a validated
// complete credential identity.
func JobCredentialIdentityDigest(identity JobCredentialIdentity) ([32]byte, error) {
	if err := ValidateJobCredentialIdentity(identity); err != nil {
		return [32]byte{}, err
	}
	digest := sha256.New()
	writeString := func(value string) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = io.WriteString(digest, value)
	}
	for _, value := range []string{
		identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.HostID,
		identity.RuntimeDriver, identity.RuntimeID, identity.RuntimeGeneration,
		identity.FirecrackerProcessGeneration, identity.VsockGeneration,
		identity.WorkerJobID, identity.SubmissionID, identity.PlanID,
		identity.ActivationGeneration, identity.CredentialGeneration,
		identity.NetworkPlanID, identity.PolicySnapshotID, identity.ProxySessionID,
		identity.ProxyGenerationID, identity.TopologyGenerationID, identity.RuleGenerationID,
		identity.AdmissionGrantID, identity.PrincipalID,
		identity.TemplatePolicyID, identity.WorkspacePolicyID, identity.ControllerKeyGeneration,
		identity.GuestBootGeneration, identity.GuestImageGeneration, identity.GuestImageDigest,
		identity.GuestSessionGeneration, identity.GuestHelperGeneration,
	} {
		writeString(value)
	}
	var numeric [8]byte
	binary.BigEndian.PutUint64(numeric[:], identity.AdmissionGrantRevision)
	_, _ = digest.Write(numeric[:])
	binary.BigEndian.PutUint64(numeric[:], uint64(identity.IssuedAt.UnixNano()))
	_, _ = digest.Write(numeric[:])
	binary.BigEndian.PutUint64(numeric[:], uint64(len(identity.BindingIDs)))
	_, _ = digest.Write(numeric[:])
	for index := range identity.BindingIDs {
		writeString(identity.BindingIDs[index])
		writeString(string(identity.DeliveryModes[index]))
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func validJobCredentialGuestImageDigest(value string) bool {
	if len(value) != len("sha256-")+64 || !strings.HasPrefix(value, "sha256-") {
		return false
	}
	for _, character := range value[len("sha256-"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validJobCredentialGuestSessionGeneration(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validJobCredentialNetworkTuple(seed JobCredentialIdentitySeed, required bool) bool {
	values := []string{
		seed.NetworkPlanID, seed.PolicySnapshotID, seed.ProxySessionID,
		seed.ProxyGenerationID, seed.TopologyGenerationID, seed.RuleGenerationID,
	}
	for _, value := range values {
		if required {
			if !validJobCredentialSafeID(value) {
				return false
			}
		} else if value != "" {
			return false
		}
	}
	return true
}

func jobCredentialIdentitySeedFromIdentity(identity JobCredentialIdentity) JobCredentialIdentitySeed {
	return JobCredentialIdentitySeed{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID, HostID: identity.HostID,
		RuntimeDriver: identity.RuntimeDriver, RuntimeID: identity.RuntimeID, RuntimeGeneration: identity.RuntimeGeneration,
		FirecrackerProcessGeneration: identity.FirecrackerProcessGeneration, VsockGeneration: identity.VsockGeneration,
		WorkerJobID: identity.WorkerJobID, SubmissionID: identity.SubmissionID, PlanID: identity.PlanID,
		ActivationGeneration: identity.ActivationGeneration, CredentialGeneration: identity.CredentialGeneration,
		NetworkPlanID: identity.NetworkPlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
		AdmissionGrantID: identity.AdmissionGrantID, PrincipalID: identity.PrincipalID,
		TemplatePolicyID: identity.TemplatePolicyID, WorkspacePolicyID: identity.WorkspacePolicyID,
		ControllerKeyGeneration: identity.ControllerKeyGeneration, GuestBootGeneration: identity.GuestBootGeneration,
		GuestImageGeneration: identity.GuestImageGeneration, GuestImageDigest: identity.GuestImageDigest,
		AdmissionGrantRevision: identity.AdmissionGrantRevision,
		BindingIDs:             identity.BindingIDs, DeliveryModes: identity.DeliveryModes, IssuedAt: identity.IssuedAt,
	}
}

func sameJobCredentialIdentitySeed(left, right JobCredentialIdentitySeed) bool {
	if left.SandboxID != right.SandboxID || left.ExecutionID != right.ExecutionID || left.WorkerID != right.WorkerID || left.HostID != right.HostID ||
		left.RuntimeDriver != right.RuntimeDriver || left.RuntimeID != right.RuntimeID || left.RuntimeGeneration != right.RuntimeGeneration ||
		left.FirecrackerProcessGeneration != right.FirecrackerProcessGeneration || left.VsockGeneration != right.VsockGeneration ||
		left.WorkerJobID != right.WorkerJobID || left.SubmissionID != right.SubmissionID || left.PlanID != right.PlanID ||
		left.ActivationGeneration != right.ActivationGeneration || left.CredentialGeneration != right.CredentialGeneration ||
		left.NetworkPlanID != right.NetworkPlanID || left.PolicySnapshotID != right.PolicySnapshotID ||
		left.ProxySessionID != right.ProxySessionID || left.ProxyGenerationID != right.ProxyGenerationID ||
		left.TopologyGenerationID != right.TopologyGenerationID || left.RuleGenerationID != right.RuleGenerationID ||
		left.AdmissionGrantID != right.AdmissionGrantID || left.PrincipalID != right.PrincipalID ||
		left.TemplatePolicyID != right.TemplatePolicyID || left.WorkspacePolicyID != right.WorkspacePolicyID ||
		left.ControllerKeyGeneration != right.ControllerKeyGeneration || left.GuestBootGeneration != right.GuestBootGeneration ||
		left.GuestImageGeneration != right.GuestImageGeneration || left.GuestImageDigest != right.GuestImageDigest ||
		left.AdmissionGrantRevision != right.AdmissionGrantRevision || !left.IssuedAt.Equal(right.IssuedAt) ||
		len(left.BindingIDs) != len(right.BindingIDs) || len(left.DeliveryModes) != len(right.DeliveryModes) {
		return false
	}
	for index := range left.BindingIDs {
		if left.BindingIDs[index] != right.BindingIDs[index] || left.DeliveryModes[index] != right.DeliveryModes[index] {
			return false
		}
	}
	return true
}
