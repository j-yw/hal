package sandboxruntime

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestL8JobCredentialRuntimeBindingProviderIsExactRetainedAuthoritySeam(t *testing.T) {
	providerType := reflect.TypeOf((*JobCredentialRuntimeBindingProvider)(nil)).Elem()
	assertExactInterfaceMethods(t, providerType, map[string]reflect.Type{
		"BindJobCredentialRuntime": reflect.TypeOf((func(context.Context, JobCredentialRuntimeBindingRequest) (JobCredentialRuntimeBinding, error))(nil)),
	})

	requestType := reflect.TypeOf(JobCredentialRuntimeBindingRequest{})
	wantFields := []string{
		"Target", "WorkerID", "WorkerJobID", "SubmissionID", "ExecutionID", "PlanID",
		"AdmissionGrantID", "AdmissionGrantRevision", "PrincipalID", "TemplatePolicyID",
		"WorkspacePolicyID", "BindingIDs", "DeliveryModes", "IssuedAt",
	}
	if requestType.NumField() != len(wantFields) {
		t.Fatalf("binding request has %d fields, want exact %d", requestType.NumField(), len(wantFields))
	}
	for index, name := range wantFields {
		if got := requestType.Field(index).Name; got != name {
			t.Fatalf("binding request field %d = %q, want %q", index, got, name)
		}
	}

	var _ JobCredentialRuntimeBindingProvider = (*l8RuntimeBindingProvider)(nil)
	request := JobCredentialRuntimeBindingRequest{
		Target:                 Target{ID: "sandbox-primary", Runtime: RuntimeState{Driver: DriverMicroVM, RuntimeID: "runtime-primary"}},
		WorkerID:               "worker-primary",
		WorkerJobID:            "job-primary",
		SubmissionID:           "submission-primary",
		ExecutionID:            "exec-primary",
		PlanID:                 "plan-primary",
		AdmissionGrantID:       "grant-primary",
		AdmissionGrantRevision: 1,
		PrincipalID:            "principal-primary",
		TemplatePolicyID:       "template-primary",
		WorkspacePolicyID:      "workspace-primary",
		BindingIDs:             []string{"binding-primary"},
		DeliveryModes:          []JobCredentialDeliveryMode{JobCredentialDeliveryModeHTTPProxy},
		IssuedAt:               time.Date(2026, time.August, 20, 1, 2, 3, 0, time.UTC),
	}
	provider := &l8RuntimeBindingProvider{}
	if _, err := provider.BindJobCredentialRuntime(context.Background(), request); err != nil {
		t.Fatalf("BindJobCredentialRuntime() error: %v", err)
	}
	request.BindingIDs[0] = "caller-mutated"
	request.DeliveryModes[0] = JobCredentialDeliveryModeSSHAgent
	if provider.request.BindingIDs[0] != "binding-primary" || provider.request.DeliveryModes[0] != JobCredentialDeliveryModeHTTPProxy {
		t.Fatal("provider request retained caller-owned identity slices")
	}
}

type l8RuntimeBindingProvider struct {
	request JobCredentialRuntimeBindingRequest
}

func (provider *l8RuntimeBindingProvider) BindJobCredentialRuntime(_ context.Context, request JobCredentialRuntimeBindingRequest) (JobCredentialRuntimeBinding, error) {
	request.BindingIDs = append([]string(nil), request.BindingIDs...)
	request.DeliveryModes = append([]JobCredentialDeliveryMode(nil), request.DeliveryModes...)
	provider.request = request
	return JobCredentialRuntimeBinding{}, nil
}
