package sandboxworker

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8ServiceInterceptsV2WithoutChangingDefaultEarlyUnsupported(t *testing.T) {
	base, err := NewService(ServiceOptions{WorkerID: "worker-primary"})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	defer base.Close()

	request := Request{
		RequestID:   "request-status",
		Operation:   OperationJobStatusV2,
		JobStatusV2: &JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary"},
	}
	defaultResponse := base.HandleRequest(context.Background(), request)
	if defaultResponse.Error == nil || defaultResponse.Error.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("default service response = %#v, want guarded unsupported", defaultResponse)
	}

	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("worker-peer-authority", "daemon-generation-1")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authority.IssueAuthenticatedWorkerPrincipal("principal-primary", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewL8Service(L8ServiceOptions{
		WorkerID:           "worker-primary",
		PrincipalAuthority: authority,
		StateDir:           t.TempDir(),
		DaemonGeneration:   "daemon-generation-1",
	})
	if err != nil {
		t.Fatalf("NewL8Service() error: %v", err)
	}
	defer service.Close()

	unauthenticated := service.HandleRequest(context.Background(), request)
	if unauthenticated.Error == nil || unauthenticated.Error.Code != ErrorCodeInternal {
		t.Fatalf("unauthenticated response = %#v, want fail-closed internal error", unauthenticated)
	}
	authenticated := service.HandleAuthenticatedRequest(context.Background(), principal, request)
	if authenticated.Error == nil || authenticated.Error.Code != ErrorCodeJobNotFound {
		t.Fatalf("authenticated response = %#v, want V2 job-not-found dispatch", authenticated)
	}
	if authenticated.Error.Code == ErrorCodeUnsupportedOp {
		t.Fatal("explicit L8 service fell back to the default unsupported path")
	}

}
