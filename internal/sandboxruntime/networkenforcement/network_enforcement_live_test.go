//go:build network_enforcement_live

package networkenforcement

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	networkEnforcementLiveEnvEnabled  = "HAL_NETWORK_ENFORCEMENT_LIVE"
	networkEnforcementLiveEnvProxy    = "HAL_NETWORK_ENFORCEMENT_LIVE_PROXY"
	networkEnforcementLiveEnvFirewall = "HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL"
)

type networkEnforcementLivePrerequisites struct {
	enabled  bool
	proxy    bool
	firewall bool
}

func TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn(t *testing.T) {
	prereqs, skip := networkEnforcementLivePrerequisitesFromEnv(os.Getenv)
	if skip != "" {
		t.Skip(skip)
	}
	if !prereqs.enabled || !prereqs.proxy || !prereqs.firewall {
		t.Fatal("network enforcement live prerequisites unexpectedly incomplete")
	}

	t.Skip("network enforcement live harness is an opt-in stub; no live listener or firewall adapter is implemented")
}

func TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "global opt-in missing",
			env:  map[string]string{},
			want: networkEnforcementLiveEnvEnabled + "=1",
		},
		{
			name: "proxy adapter opt-in missing",
			env: map[string]string{
				networkEnforcementLiveEnvEnabled: "1",
			},
			want: networkEnforcementLiveEnvProxy + "=1",
		},
		{
			name: "firewall adapter opt-in missing",
			env: map[string]string{
				networkEnforcementLiveEnvEnabled: "1",
				networkEnforcementLiveEnvProxy:   "1",
			},
			want: networkEnforcementLiveEnvFirewall + "=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, skip := networkEnforcementLivePrerequisitesFromEnv(func(name string) string {
				return tt.env[name]
			})
			if !strings.Contains(skip, tt.want) {
				t.Fatalf("skip message = %q, want marker %q", skip, tt.want)
			}
			for _, unsafe := range []string{"127.0.0.1", "localhost", "/tmp/", "token", "secret"} {
				if strings.Contains(strings.ToLower(skip), unsafe) {
					t.Fatalf("skip message %q contains unsafe detail %q", skip, unsafe)
				}
			}
		})
	}
}

func networkEnforcementLivePrerequisitesFromEnv(getenv func(string) string) (networkEnforcementLivePrerequisites, string) {
	prereqs := networkEnforcementLivePrerequisites{
		enabled:  networkEnforcementLiveEnvFlag(getenv, networkEnforcementLiveEnvEnabled),
		proxy:    networkEnforcementLiveEnvFlag(getenv, networkEnforcementLiveEnvProxy),
		firewall: networkEnforcementLiveEnvFlag(getenv, networkEnforcementLiveEnvFirewall),
	}
	switch {
	case !prereqs.enabled:
		return networkEnforcementLivePrerequisites{}, networkEnforcementLiveSkipMessage(networkEnforcementLiveEnvEnabled)
	case !prereqs.proxy:
		return networkEnforcementLivePrerequisites{}, networkEnforcementLiveSkipMessage(networkEnforcementLiveEnvProxy)
	case !prereqs.firewall:
		return networkEnforcementLivePrerequisites{}, networkEnforcementLiveSkipMessage(networkEnforcementLiveEnvFirewall)
	default:
		return prereqs, ""
	}
}

func networkEnforcementLiveEnvFlag(getenv func(string) string, name string) bool {
	return strings.TrimSpace(getenv(name)) == "1"
}

func networkEnforcementLiveSkipMessage(name string) string {
	return fmt.Sprintf("%s=1 is required for network enforcement live tests", name)
}
