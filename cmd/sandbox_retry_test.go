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

type testingError string

func (e testingError) Error() string {
	return string(e)
}
