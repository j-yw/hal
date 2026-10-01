package sandboxworker

import (
	"testing"
)

func TestL8D6WorkerProtocolHasNoRenewOrRevokeOperations(t *testing.T) {
	for _, operation := range []string{"job_renew_v2", "job_revoke_v2", "job_recover_v2"} {
		if validOperation(operation) || isWorkerV2Operation(operation) {
			t.Fatalf("worker protocol reserved %s; this slice must not invent unreserved operations", operation)
		}
	}
}
