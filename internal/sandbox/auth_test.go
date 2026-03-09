package sandbox

import (
	"fmt"
	"strings"
	"testing"
)

func TestEnsureAuth(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   string
		setupFn  func() error
		reloadFn func() (string, error)
		wantErr  string
	}{
		{
			name:   "returns nil when API key is present",
			apiKey: "valid-key",
		},
		{
			name:    "error when API key empty and no setupFn",
			apiKey:  "",
			wantErr: "run 'hal sandbox setup' first",
		},
		{
			name:   "calls setupFn when API key is empty",
			apiKey: "",
			setupFn: func() error {
				return nil
			},
			reloadFn: func() (string, error) {
				return "new-key", nil
			},
		},
		{
			name:   "propagates setupFn error",
			apiKey: "",
			setupFn: func() error {
				return fmt.Errorf("user cancelled")
			},
			wantErr: "setup failed: user cancelled",
		},
		{
			name:   "error when reloadFn returns empty key",
			apiKey: "",
			setupFn: func() error {
				return nil
			},
			reloadFn: func() (string, error) {
				return "", nil
			},
			wantErr: "API key still empty after setup",
		},
		{
			name:   "propagates reloadFn error",
			apiKey: "",
			setupFn: func() error {
				return nil
			},
			reloadFn: func() (string, error) {
				return "", fmt.Errorf("config read failed")
			},
			wantErr: "reloading config after setup",
		},
		{
			name:   "succeeds without reloadFn when setupFn succeeds",
			apiKey: "",
			setupFn: func() error {
				return nil
			},
			reloadFn: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EnsureAuth(tt.apiKey, tt.setupFn, tt.reloadFn)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
