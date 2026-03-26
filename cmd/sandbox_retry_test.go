package cmd

import (
	"fmt"
	"testing"
)

type retryTestPendingRemoval struct {
	alreadyStaged bool
}

func (r *retryTestPendingRemoval) Commit() error {
	return nil
}

func (r *retryTestPendingRemoval) Rollback() error {
	return nil
}

func (r *retryTestPendingRemoval) AlreadyStaged() bool {
	return r.alreadyStaged
}

func TestFinalizeInterruptedDeleteRetry(t *testing.T) {
	pendingRemoval := &retryTestPendingRemoval{alreadyStaged: true}

	tests := []struct {
		name     string
		provider string
		err      error
		want     bool
	}{
		{
			name:     "digitalocean cli missing does not finalize",
			provider: "digitalocean",
			err:      fmt.Errorf("doctl not found: install from https://docs.digitalocean.com/reference/doctl/how-to/install/ and run 'doctl auth init'"),
			want:     false,
		},
		{
			name:     "digitalocean remote missing finalizes",
			provider: "digitalocean",
			err:      fmt.Errorf("doctl compute droplet delete failed with exit code 1: droplet not found"),
			want:     true,
		},
		{
			name:     "lightsail cli missing does not finalize",
			provider: "lightsail",
			err:      fmt.Errorf("aws CLI not found: install with 'brew install awscli' and run 'aws configure'"),
			want:     false,
		},
		{
			name:     "lightsail remote missing finalizes",
			provider: "lightsail",
			err:      fmt.Errorf("aws lightsail delete-instance failed with exit code 1: instance does not exist"),
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := finalizeInterruptedDeleteRetry(tt.provider, pendingRemoval, tt.err)
			if got != tt.want {
				t.Fatalf("finalizeInterruptedDeleteRetry(%q, %v) = %v, want %v", tt.provider, tt.err, got, tt.want)
			}
		})
	}
}

func TestFinalizeInterruptedStartReplaceRetry(t *testing.T) {
	pendingRemoval := &retryTestPendingRemoval{alreadyStaged: true}

	tests := []struct {
		name     string
		provider string
		err      error
		want     bool
	}{
		{
			name:     "digitalocean cli missing does not finalize",
			provider: "digitalocean",
			err:      fmt.Errorf("doctl not found: install from https://docs.digitalocean.com/reference/doctl/how-to/install/ and run 'doctl auth init'"),
			want:     false,
		},
		{
			name:     "digitalocean remote missing finalizes",
			provider: "digitalocean",
			err:      fmt.Errorf("doctl compute droplet delete failed with exit code 1: droplet not found"),
			want:     true,
		},
		{
			name:     "lightsail cli missing does not finalize",
			provider: "lightsail",
			err:      fmt.Errorf("aws CLI not found: install with 'brew install awscli' and run 'aws configure'"),
			want:     false,
		},
		{
			name:     "lightsail remote missing finalizes",
			provider: "lightsail",
			err:      fmt.Errorf("aws lightsail delete-instance failed with exit code 1: instance does not exist"),
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := finalizeInterruptedStartReplaceRetry(tt.provider, pendingRemoval, tt.err)
			if got != tt.want {
				t.Fatalf("finalizeInterruptedStartReplaceRetry(%q, %v) = %v, want %v", tt.provider, tt.err, got, tt.want)
			}
		})
	}
}
