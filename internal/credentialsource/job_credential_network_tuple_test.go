package credentialsource

import (
	"errors"
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

func TestJobCredentialAdmissionRejectsMultipleHTTPBindingsAtRegistration(t *testing.T) {
	authority := l8PrincipalAuthority(t, "peercred-owner", "daemon-generation-1")
	principal := l8Principal(t, authority, "principal-owner", 1001, 1002)
	twoHTTP := l8AdmissionRequest()
	twoHTTP.SourceReferenceIDs = append(twoHTTP.SourceReferenceIDs, "source-secondary")
	twoHTTP.Bindings = append(twoHTTP.Bindings, sandboxruntime.JobCredentialBindingRequest{
		ID:                "binding-secondary",
		Mode:              sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
		SourceReferenceID: "source-secondary",
		ServiceID:         "service-secondary",
	})
	if validAdmissionRequest(twoHTTP) {
		t.Fatal("two-HTTP admission request passed internal validation")
	}
	if validSealedAdmissionRequest(sealAdmissionRequest(twoHTTP)) {
		t.Fatal("two-HTTP sealed admission request passed internal validation")
	}
	if _, err := NewAdmissionGrantRegistration(authority, principal, twoHTTP, []string{"source-primary", "source-secondary"}); !errors.Is(err, ErrCredentialSourceRegistration) {
		t.Fatalf("two-HTTP grant registration error = %v, want registration rejected", err)
	}

	mixed := l8AdmissionRequest()
	mixed.SourceReferenceIDs = append(mixed.SourceReferenceIDs, "source-secondary")
	mixed.Bindings = append(mixed.Bindings, sandboxruntime.JobCredentialBindingRequest{
		ID:                "binding-secondary",
		Mode:              sandboxruntime.JobCredentialDeliveryModeFileTmpfs,
		SourceReferenceID: "source-secondary",
	})
	grant, err := NewAdmissionGrantRegistration(authority, principal, mixed, []string{"source-primary", "source-secondary"})
	if err != nil {
		t.Fatalf("one-HTTP mixed grant registration rejected: %v", err)
	}
	if !validSealedAdmissionRequest(grant.request) {
		t.Fatal("one-HTTP mixed sealed grant rejected")
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
