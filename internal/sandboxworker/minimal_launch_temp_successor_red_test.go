package sandboxworker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMinimalLaunchPreservesConsumedTemporarySuccessor(t *testing.T) {
	fixture := newMinimalLaunchDispatchFixture(t)
	service := fixture.service(t)
	var successor string
	var successorInfo os.FileInfo
	original := service.jobs.store.minimalOps.rename
	service.jobs.store.minimalOps.rename = func(old, new string) error {
		if err := original(old, new); err != nil {
			return err
		}
		// Selected operations now use the retained root's relative names.
		old = filepath.Join(fixture.stateDir, old)
		if _, err := os.Lstat(old); !os.IsNotExist(err) {
			t.Fatalf("rename did not consume temporary name: %v", err)
		}
		successor = old
		if err := os.WriteFile(old, []byte("foreign temporary successor\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		successorInfo, err = os.Lstat(old)
		return err
	}
	response := service.HandleAuthenticatedRequest(context.Background(), fixture.principal, fixture.request)
	if successor == "" {
		t.Fatal("actual dispatching rename seam was not reached")
	}
	data, err := os.ReadFile(successor)
	current, statErr := os.Lstat(successor)
	t.Logf("actual dispatching rename reached; provider starts=%d responseOK=%t successorExists=%t", fixture.provider.startCalls, response.OK, err == nil)
	if err != nil || statErr != nil || !os.SameFile(successorInfo, current) || string(data) != "foreign temporary successor\n" {
		t.Fatalf("consumed temporary successor was deleted/replaced/modified: %v, %v", err, statErr)
	}
}
