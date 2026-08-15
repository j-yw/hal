package cmd

import "testing"

func TestIsMissingSandboxDeleteError_DigitalOcean(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		errText  string
		expected bool
	}{
		{
			name:     "missing droplet is treated as already deleted",
			errText:  "doctl compute droplet delete failed with exit code 1: GET https://api.digitalocean.com/v2/droplets/123: 404 The resource you requested could not be found.: exit status 1",
			expected: true,
		},
		{
			name:     "dns failure is not treated as missing",
			errText:  "doctl compute droplet delete failed with exit code 1: Get https://api.digitalocean.com/v2/droplets/123: dial tcp: lookup api.digitalocean.com: no such host: exit status 1",
			expected: false,
		},
		{
			name:     "auth failure is not treated as missing",
			errText:  "doctl compute droplet delete failed with exit code 1: POST https://api.digitalocean.com/v2/droplets/123/actions: 401 Unable to authenticate you: exit status 1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isMissingSandboxDeleteError("digitalocean", testingError(tt.errText)); got != tt.expected {
				t.Fatalf("isMissingSandboxDeleteError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsMissingWorkerRuntimeOperationError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		driverID  string
		operation string
		errText   string
		expected  bool
	}{
		{
			name:      "direct Podman missing object",
			driverID:  "rootless_podman",
			operation: "inspect",
			errText:   `rootless_podman inspect failed: Error: no such object: "container-id"`,
			expected:  true,
		},
		{
			name:      "worker wrapped missing container",
			driverID:  "rootless_podman",
			operation: "delete",
			errText:   "worker_lifecycle_failed: rootless_podman delete failed: worker protocol delete failed: driver_error: runtime driver request failed: rootless_podman delete failed: no such container",
			expected:  true,
		},
		{
			name:      "wrong operation",
			driverID:  "rootless_podman",
			operation: "delete",
			errText:   "rootless_podman inspect failed: Error: no such object",
			expected:  false,
		},
		{
			name:      "wrong driver",
			driverID:  "microvm",
			operation: "delete",
			errText:   "rootless_podman delete failed: Error: no such object",
			expected:  false,
		},
		{
			name:      "network error containing no such host",
			driverID:  "rootless_podman",
			operation: "delete",
			errText:   "rootless_podman delete failed: no such host",
			expected:  false,
		},
		{
			name:      "generic storage failure",
			driverID:  "rootless_podman",
			operation: "delete",
			errText:   "rootless_podman delete failed: directory not empty",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isMissingWorkerRuntimeOperationError(tt.driverID, tt.operation, testingError(tt.errText)); got != tt.expected {
				t.Fatalf("isMissingWorkerRuntimeOperationError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

type testingError string

func (e testingError) Error() string {
	return string(e)
}
