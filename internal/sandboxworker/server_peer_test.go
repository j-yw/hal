package sandboxworker

import "testing"

func TestWorkerPeerFilesystemFallbackNeverAuthorizesIdentity(t *testing.T) {
	for _, filesystemBoundaryProven := range []bool{false, true} {
		if err := validateWorkerPeerFilesystemFallback(filesystemBoundaryProven); err == nil {
			t.Fatalf("validateWorkerPeerFilesystemFallback(%t) error = nil", filesystemBoundaryProven)
		}
	}
}
