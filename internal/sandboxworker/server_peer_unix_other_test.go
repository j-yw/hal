//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package sandboxworker

import "testing"

func TestValidateWorkerPeerCredentialsFailsClosedWithoutAdapter(t *testing.T) {
	for _, filesystemBoundaryProven := range []bool{false, true} {
		if err := validateWorkerPeerCredentials(nil, filesystemBoundaryProven); err == nil {
			t.Fatalf("validateWorkerPeerCredentials(nil, %t) error = nil", filesystemBoundaryProven)
		}
	}
}
