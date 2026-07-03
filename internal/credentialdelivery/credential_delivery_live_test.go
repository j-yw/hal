//go:build credential_delivery_live

package credentialdelivery

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	credentialDeliveryLiveEnvEnabled   = "HAL_CREDENTIAL_DELIVERY_LIVE"
	credentialDeliveryLiveEnvHTTPProxy = "HAL_CREDENTIAL_DELIVERY_LIVE_HTTP_PROXY"
	credentialDeliveryLiveEnvFileTmpfs = "HAL_CREDENTIAL_DELIVERY_LIVE_FILE_TMPFS"
	credentialDeliveryLiveEnvSSHAgent  = "HAL_CREDENTIAL_DELIVERY_LIVE_SSH_AGENT"
	credentialDeliveryLiveEnvEnv       = "HAL_CREDENTIAL_DELIVERY_LIVE_ENV"
)

type credentialDeliveryLivePrerequisites struct {
	enabled bool
	modes   []Mode
}

type credentialDeliveryLiveModeGate struct {
	mode    Mode
	envName string
}

func TestCredentialDeliveryLiveHarnessRequiresExplicitOptIn(t *testing.T) {
	prereqs, skip := credentialDeliveryLivePrerequisitesFromEnv(os.Getenv)
	if skip != "" {
		t.Skip(skip)
	}
	if !prereqs.enabled || len(prereqs.modes) == 0 {
		t.Fatal("credential delivery live prerequisites unexpectedly incomplete")
	}

	t.Skip("credential delivery live harness is an opt-in placeholder; no live delivery adapter is implemented")
}

func TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "global opt-in missing",
			env:  map[string]string{},
			want: credentialDeliveryLiveEnvEnabled + "=1",
		},
		{
			name: "mode opt-in missing",
			env: map[string]string{
				credentialDeliveryLiveEnvEnabled:   "1",
				credentialDeliveryLiveEnvHTTPProxy: "http://127.0.0.1:8080",
				credentialDeliveryLiveEnvFileTmpfs: "/tmp/hal-secret",
				credentialDeliveryLiveEnvSSHAgent:  "/tmp/agent.sock",
				credentialDeliveryLiveEnvEnv:       "Authorization: Bearer ghp_secret",
			},
			want: credentialDeliveryLiveEnvHTTPProxy + "=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, skip := credentialDeliveryLivePrerequisitesFromEnv(func(name string) string {
				return tt.env[name]
			})
			if skip == "" {
				t.Fatal("skip message is empty, want sanitized prerequisite guidance")
			}
			if !strings.Contains(skip, tt.want) {
				t.Fatalf("skip message = %q, want marker %q", skip, tt.want)
			}
			assertCredentialDeliveryLiveSkipMessageSanitized(t, skip)
		})
	}
}

func TestCredentialDeliveryLivePrerequisitesAcceptAnyModeGate(t *testing.T) {
	for _, gate := range credentialDeliveryLiveModeEnvGates() {
		t.Run(string(gate.mode), func(t *testing.T) {
			env := map[string]string{
				credentialDeliveryLiveEnvEnabled: "1",
				gate.envName:                     "1",
			}
			prereqs, skip := credentialDeliveryLivePrerequisitesFromEnv(func(name string) string {
				return env[name]
			})
			if skip != "" {
				t.Fatalf("skip message = %q, want mode gate %s accepted", skip, gate.envName)
			}
			if !prereqs.enabled {
				t.Fatal("global credential delivery live opt-in was not recorded")
			}
			if len(prereqs.modes) != 1 || prereqs.modes[0] != gate.mode {
				t.Fatalf("modes = %#v, want only %s", prereqs.modes, gate.mode)
			}
		})
	}
}

func credentialDeliveryLivePrerequisitesFromEnv(getenv func(string) string) (credentialDeliveryLivePrerequisites, string) {
	if !credentialDeliveryLiveEnvFlag(getenv, credentialDeliveryLiveEnvEnabled) {
		return credentialDeliveryLivePrerequisites{}, credentialDeliveryLiveSkipMessage(credentialDeliveryLiveEnvEnabled)
	}

	var modes []Mode
	for _, gate := range credentialDeliveryLiveModeEnvGates() {
		if credentialDeliveryLiveEnvFlag(getenv, gate.envName) {
			modes = append(modes, gate.mode)
		}
	}
	if len(modes) == 0 {
		return credentialDeliveryLivePrerequisites{}, credentialDeliveryLiveModeSkipMessage()
	}
	return credentialDeliveryLivePrerequisites{
		enabled: true,
		modes:   modes,
	}, ""
}

func credentialDeliveryLiveModeEnvGates() []credentialDeliveryLiveModeGate {
	return []credentialDeliveryLiveModeGate{
		{mode: ModeHTTPProxy, envName: credentialDeliveryLiveEnvHTTPProxy},
		{mode: ModeFileTmpfs, envName: credentialDeliveryLiveEnvFileTmpfs},
		{mode: ModeSSHAgent, envName: credentialDeliveryLiveEnvSSHAgent},
		{mode: ModeEnv, envName: credentialDeliveryLiveEnvEnv},
	}
}

func credentialDeliveryLiveEnvFlag(getenv func(string) string, name string) bool {
	return strings.TrimSpace(getenv(name)) == "1"
}

func credentialDeliveryLiveSkipMessage(name string) string {
	return fmt.Sprintf("%s=1 is required for credential delivery live tests", name)
}

func credentialDeliveryLiveModeSkipMessage() string {
	markers := make([]string, 0, len(credentialDeliveryLiveModeEnvGates()))
	for _, gate := range credentialDeliveryLiveModeEnvGates() {
		markers = append(markers, gate.envName+"=1")
	}
	return fmt.Sprintf("one credential delivery mode opt-in is required for credential delivery live tests: %s", strings.Join(markers, ", "))
}

func assertCredentialDeliveryLiveSkipMessageSanitized(t *testing.T, message string) {
	t.Helper()
	lower := strings.ToLower(message)
	for _, unsafe := range []string{
		"127.0.0.1",
		"localhost",
		"http://",
		"https://",
		"/tmp/",
		"/users/",
		".sock",
		"authorization:",
		"bearer ",
		"token=",
		"secret=",
		"ghp_",
	} {
		if strings.Contains(lower, unsafe) {
			t.Fatalf("skip message %q contains unsafe detail %q", message, unsafe)
		}
	}
}
