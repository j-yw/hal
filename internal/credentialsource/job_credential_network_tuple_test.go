package credentialsource

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestJobCredentialAdmissionNetworkTupleMatchesDeliveryModes(t *testing.T) {
	httpRequest := l8AdmissionRequest()
	mixedRequest := l8AdmissionRequest()
	mixedRequest.Bindings = append(mixedRequest.Bindings, sandboxruntime.JobCredentialBindingRequest{
		ID: "binding-file", Mode: sandboxruntime.JobCredentialDeliveryModeFileTmpfs, SourceReferenceID: "source-primary",
	})
	fileRequest := l8AdmissionRequest()
	fileRequest.Bindings[0].Mode = sandboxruntime.JobCredentialDeliveryModeFileTmpfs
	fileRequest.Bindings[0].ServiceID = ""
	clearAdmissionNetworkTuple(&fileRequest)
	sshRequest := fileRequest
	sshRequest.Bindings = append([]sandboxruntime.JobCredentialBindingRequest(nil), fileRequest.Bindings...)
	sshRequest.Bindings[0].Mode = sandboxruntime.JobCredentialDeliveryModeSSHAgent

	for _, request := range []sandboxruntime.JobCredentialAdmissionRequest{httpRequest, mixedRequest, fileRequest, sshRequest} {
		if !validAdmissionRequest(request) {
			t.Fatal("valid mode-dependent admission tuple rejected")
		}
		if !validSealedAdmissionRequest(sealAdmissionRequest(request)) {
			t.Fatal("valid mode-dependent tuple was not preserved by sealing")
		}
	}

	httpMissing := httpRequest
	clearAdmissionNetworkTuple(&httpMissing)
	httpPartial := httpRequest
	httpPartial.Identity.ProxySessionID = ""
	filePopulated := fileRequest
	filePopulated.Identity.NetworkPlanID = "network-plan-1"
	for _, request := range []sandboxruntime.JobCredentialAdmissionRequest{httpMissing, httpPartial, filePopulated} {
		if validAdmissionRequest(request) {
			t.Fatal("invalid mode-dependent admission tuple accepted")
		}
	}
}

func clearAdmissionNetworkTuple(request *sandboxruntime.JobCredentialAdmissionRequest) {
	request.Identity.NetworkPlanID = ""
	request.Identity.PolicySnapshotID = ""
	request.Identity.ProxySessionID = ""
	request.Identity.ProxyGenerationID = ""
	request.Identity.TopologyGenerationID = ""
	request.Identity.RuleGenerationID = ""
}
