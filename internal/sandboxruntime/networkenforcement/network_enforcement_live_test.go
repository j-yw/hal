//go:build network_enforcement_live

package networkenforcement

import (
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/livegate"
)

const (
	networkEnforcementLiveGateID      livegate.GateID = "network-enforcement-live"
	networkEnforcementLiveEnvEnabled                  = string(livegate.EnvVarNetworkEnforcementLive)
	networkEnforcementLiveEnvProxy                    = "HAL_NETWORK_ENFORCEMENT_LIVE_PROXY"
	networkEnforcementLiveEnvFirewall                 = "HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL"
)

type networkEnforcementLivePrerequisites struct {
	enabled  bool
	proxy    bool
	firewall bool
}

func TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn(t *testing.T) {
	requireNetworkEnforcementLiveGate(t, os.Getenv)
	prereqs := networkEnforcementLivePrerequisitesFromEnv(os.Getenv)
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
			want: networkEnforcementLiveEnvEnabled,
		},
		{
			name: "proxy adapter opt-in missing",
			env: map[string]string{
				networkEnforcementLiveEnvEnabled: "1",
			},
			want: networkEnforcementLiveEnvProxy,
		},
		{
			name: "firewall adapter opt-in missing",
			env: map[string]string{
				networkEnforcementLiveEnvEnabled: "1",
				networkEnforcementLiveEnvProxy:   "1",
			},
			want: networkEnforcementLiveEnvFirewall,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skip := networkEnforcementLiveGateSkipMessageFromEnv(func(name string) string {
				return tt.env[name]
			})
			if skip == "" {
				t.Fatal("skip message is empty, want sanitized shared live gate output")
			}
			if !strings.Contains(skip, tt.want) {
				t.Fatalf("skip message = %q, want marker %q", skip, tt.want)
			}
			if !strings.Contains(skip, string(livegate.SkipReasonMissingEnvVar)) {
				t.Fatalf("skip message = %q, want shared live gate reason %q", skip, livegate.SkipReasonMissingEnvVar)
			}
			livegate.AssertLiveGateSkipMessageRedactionSafe(t, skip)
			for _, unsafe := range []string{"127.0.0.1", "localhost", "/tmp/", "token", "secret"} {
				if strings.Contains(strings.ToLower(skip), unsafe) {
					t.Fatalf("skip message %q contains unsafe detail %q", skip, unsafe)
				}
			}
		})
	}
}

func requireNetworkEnforcementLiveGate(t *testing.T, getenv func(string) string) livegate.GatePreflightResult {
	t.Helper()
	return livegate.RequireLiveGate(t, livegate.TestGateInput{
		GateID:                networkEnforcementLiveGateID,
		Gate:                  networkEnforcementLiveGate(),
		ExpectedEnvVars:       networkEnforcementLiveEnvVars(),
		EnabledBuildTags:      []livegate.BuildTagName{livegate.BuildTagNetworkEnforcementLive},
		PresentEnvVars:        networkEnforcementLivePresentEnvVars(getenv),
		AvailableCapabilities: []livegate.CapabilityID{livegate.CapabilityNetworkEnforcement},
	})
}

func networkEnforcementLiveGateSkipMessageFromEnv(getenv func(string) string) string {
	result := livegate.PreflightGate(livegate.GateEvaluationInput{
		Gate:                  networkEnforcementLiveGate(),
		EnabledBuildTags:      []livegate.BuildTagName{livegate.BuildTagNetworkEnforcementLive},
		PresentEnvVars:        networkEnforcementLivePresentEnvVars(getenv),
		AvailableCapabilities: []livegate.CapabilityID{livegate.CapabilityNetworkEnforcement},
	})
	if !result.ShouldSkipLiveAction() {
		return ""
	}
	return livegate.LiveGateSkipMessage(result)
}

func networkEnforcementLiveGate() livegate.Gate {
	return livegate.Gate{
		ID:           networkEnforcementLiveGateID,
		Category:     livegate.GateCategoryNetworkEnforcement,
		BuildTags:    []livegate.BuildTagName{livegate.BuildTagNetworkEnforcementLive},
		EnvVars:      networkEnforcementLiveEnvVars(),
		Capabilities: []livegate.CapabilityID{livegate.CapabilityNetworkEnforcement},
	}
}

func networkEnforcementLiveEnvVars() []livegate.EnvVarName {
	return []livegate.EnvVarName{
		livegate.EnvVarNetworkEnforcementLive,
		livegate.EnvVarName(networkEnforcementLiveEnvProxy),
		livegate.EnvVarName(networkEnforcementLiveEnvFirewall),
	}
}

func networkEnforcementLivePresentEnvVars(getenv func(string) string) []livegate.EnvVarName {
	var present []livegate.EnvVarName
	for _, envVar := range networkEnforcementLiveEnvVars() {
		if networkEnforcementLiveEnvFlag(getenv, string(envVar)) {
			present = append(present, envVar)
		}
	}
	return present
}

func networkEnforcementLivePrerequisitesFromEnv(getenv func(string) string) networkEnforcementLivePrerequisites {
	return networkEnforcementLivePrerequisites{
		enabled:  networkEnforcementLiveEnvFlag(getenv, networkEnforcementLiveEnvEnabled),
		proxy:    networkEnforcementLiveEnvFlag(getenv, networkEnforcementLiveEnvProxy),
		firewall: networkEnforcementLiveEnvFlag(getenv, networkEnforcementLiveEnvFirewall),
	}
}

func networkEnforcementLiveEnvFlag(getenv func(string) string, name string) bool {
	return strings.TrimSpace(getenv(name)) == "1"
}
