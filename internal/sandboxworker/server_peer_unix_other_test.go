//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package sandboxworker

import "testing"

func TestValidateWorkerPeerCredentialsUsesHardenedFilesystemFallback(t *testing.T) {
	if err := validateWorkerPeerCredentials(nil, true); err != nil {
		t.Fatalf("validateWorkerPeerCredentials(hardened boundary) error: %v", err)
	}
	if err := validateWorkerPeerCredentials(nil, false); err == nil {
		t.Fatal("validateWorkerPeerCredentials(unhardened boundary) error = nil")
	}
}
