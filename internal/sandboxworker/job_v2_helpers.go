package sandboxworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

type jobRequestIdentityV2 struct {
	DriverID         string            `json:"driverId"`
	PrincipalID      string            `json:"principalId"`
	DaemonGeneration string            `json:"daemonGeneration"`
	Request          JobStartRequestV2 `json:"request"`
}

func jobRequestKeyV2(driverID, principalID, daemonGeneration string, request JobStartRequestV2) (string, error) {
	canonicalDriverID, canonicalPrincipalID, canonicalDaemonGeneration, canonicalRequest := canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration, request)
	identity := jobRequestIdentityV2{DriverID: canonicalDriverID, PrincipalID: canonicalPrincipalID, DaemonGeneration: canonicalDaemonGeneration, Request: canonicalRequest}
	payload, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "request-v2-" + hex.EncodeToString(digest[:]), nil
}

func canonicalJobRequestIdentityInputsV2(driverID, principalID, daemonGeneration string, request JobStartRequestV2) (string, string, string, JobStartRequestV2) {
	canonical := cloneJobStartRequestV2(request)
	canonical.ContractVersion = strings.TrimSpace(canonical.ContractVersion)
	canonical.SubmissionID = strings.TrimSpace(canonical.SubmissionID)
	canonical.PlanID = strings.TrimSpace(canonical.PlanID)
	canonical.AdmissionGrantID = strings.TrimSpace(canonical.AdmissionGrantID)
	canonical.TemplatePolicyID = strings.TrimSpace(canonical.TemplatePolicyID)
	canonical.WorkspacePolicyID = strings.TrimSpace(canonical.WorkspacePolicyID)
	canonical.Exec = canonicalJobExecRequestV2(canonical.Exec)
	for index := range canonical.SourceReferenceIDs {
		canonical.SourceReferenceIDs[index] = strings.TrimSpace(canonical.SourceReferenceIDs[index])
	}
	sort.Strings(canonical.SourceReferenceIDs)
	for index := range canonical.Bindings {
		canonical.Bindings[index].BindingID = strings.TrimSpace(canonical.Bindings[index].BindingID)
		canonical.Bindings[index].SourceReferenceID = strings.TrimSpace(canonical.Bindings[index].SourceReferenceID)
		canonical.Bindings[index].Mode = strings.TrimSpace(canonical.Bindings[index].Mode)
		canonical.Bindings[index].ServiceID = strings.TrimSpace(canonical.Bindings[index].ServiceID)
	}
	sortCredentialBindingsV2(canonical.Bindings)
	return strings.TrimSpace(driverID), strings.TrimSpace(principalID), strings.TrimSpace(daemonGeneration), canonical
}

func canonicalJobExecRequestV2(request ExecRequest) ExecRequest {
	canonical := canonicalJobExecRequest(request)
	canonical.OperationID = strings.TrimSpace(canonical.OperationID)
	if canonical.Target.Runtime.Metadata != nil {
		metadata := *canonical.Target.Runtime.Metadata
		metadata.CapabilityLabels = append([]string(nil), metadata.CapabilityLabels...)
		metadata.PathRoles = append([]string(nil), metadata.PathRoles...)
		sort.Strings(metadata.CapabilityLabels)
		sort.Strings(metadata.PathRoles)
		canonical.Target.Runtime.Metadata = &metadata
	}
	return canonical
}

func cloneJobStartRequestV2(request JobStartRequestV2) JobStartRequestV2 {
	cloned := request
	cloned.Exec = cloneJobExecRequest(request.Exec)
	cloned.SourceReferenceIDs = append([]string(nil), request.SourceReferenceIDs...)
	cloned.Bindings = append([]JobCredentialBindingV2(nil), request.Bindings...)
	return cloned
}

func cloneJobV2(job JobV2) JobV2 {
	cloned := job
	cloned.StartedAt = cloneTimePointer(job.StartedAt)
	cloned.HeartbeatAt = cloneTimePointer(job.HeartbeatAt)
	cloned.FinishedAt = cloneTimePointer(job.FinishedAt)
	if job.ExitCode != nil {
		exitCode := *job.ExitCode
		cloned.ExitCode = &exitCode
	}
	cloned.CredentialIntent.SourceReferenceIDs = append([]string(nil), job.CredentialIntent.SourceReferenceIDs...)
	cloned.CredentialIntent.Bindings = append([]JobCredentialBindingV2(nil), job.CredentialIntent.Bindings...)
	return cloned
}

func jobSubmissionKeyV2(principalID, daemonGeneration string, request JobStartRequestV2) string {
	_, principal, generation, canonical := canonicalJobRequestIdentityInputsV2("", principalID, daemonGeneration, request)
	identity := make([]byte, 0, 512)
	identity = appendWorkerV2Identity(identity, principal)
	identity = appendWorkerV2Identity(identity, generation)
	identity = appendWorkerV2Identity(identity, canonical.ContractVersion)
	identity = appendWorkerV2Identity(identity, canonical.SubmissionID)
	identity = append(identity, strconv.FormatBool(canonical.ProductionCredentialsRequested)...)
	identity = appendWorkerV2Identity(identity, canonical.PlanID)
	identity = appendWorkerV2Identity(identity, canonical.AdmissionGrantID)
	identity = strconv.AppendUint(identity, canonical.AdmissionGrantRevision, 10)
	identity = append(identity, 0)
	identity = appendWorkerV2Identity(identity, canonical.TemplatePolicyID)
	identity = appendWorkerV2Identity(identity, canonical.WorkspacePolicyID)
	identity = appendWorkerV2Identity(identity, "sources")
	identity = strconv.AppendInt(identity, int64(len(canonical.SourceReferenceIDs)), 10)
	identity = append(identity, 0)
	for _, source := range canonical.SourceReferenceIDs {
		identity = appendWorkerV2Identity(identity, source)
	}
	identity = appendWorkerV2Identity(identity, "bindings")
	identity = strconv.AppendInt(identity, int64(len(canonical.Bindings)), 10)
	identity = append(identity, 0)
	for _, binding := range canonical.Bindings {
		identity = appendWorkerV2Identity(identity, binding.BindingID)
		identity = appendWorkerV2Identity(identity, binding.SourceReferenceID)
		identity = appendWorkerV2Identity(identity, binding.Mode)
		identity = appendWorkerV2Identity(identity, binding.ServiceID)
	}
	digest := sha256.Sum256(identity)
	return "submission-v2-" + hex.EncodeToString(digest[:])
}

func sortCredentialBindingsV2(bindings []JobCredentialBindingV2) {
	for index := 1; index < len(bindings); index++ {
		for current := index; current > 0 && credentialBindingV2Less(bindings[current], bindings[current-1]); current-- {
			bindings[current], bindings[current-1] = bindings[current-1], bindings[current]
		}
	}
}

func credentialBindingV2Less(left, right JobCredentialBindingV2) bool {
	if left.BindingID != right.BindingID {
		return left.BindingID < right.BindingID
	}
	if left.SourceReferenceID != right.SourceReferenceID {
		return left.SourceReferenceID < right.SourceReferenceID
	}
	if left.Mode != right.Mode {
		return left.Mode < right.Mode
	}
	return left.ServiceID < right.ServiceID
}

func appendWorkerV2Identity(output []byte, value string) []byte {
	output = strconv.AppendInt(output, int64(len(value)), 10)
	output = append(output, ':')
	output = append(output, value...)
	return append(output, 0)
}
