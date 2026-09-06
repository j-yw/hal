package credentialdelivery

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFakeActivationAdapterSupportsNonHTTPModeStatusesWithoutLiveMutation(t *testing.T) {
	modes := []Mode{ModeFileTmpfs, ModeSSHAgent, ModeEnv}
	statuses := []Status{StatusReady, StatusActive, StatusSkipped, StatusFailed}

	for _, mode := range modes {
		for _, status := range statuses {
			t.Run(string(mode)+"/"+string(status), func(t *testing.T) {
				envKey := "US003_FAKE_ACTIVATION_VALUE"
				t.Setenv(envKey, "unchanged")
				rawRoot := t.TempDir()
				rawFilePath := filepath.Join(rawRoot, "credential-value")
				rawSocketPath := filepath.Join(rawRoot, "ssh-agent.sock")
				rawEnvValue := envKey + "=ghp_raw_secret_value"
				rawSecretValue := "ghp_raw_secret_value"
				rawCommandLine := "ssh-agent -a " + rawSocketPath
				rejected := []string{rawFilePath, rawSocketPath, rawEnvValue, rawSecretValue, rawCommandLine}

				binding := nonHTTPFakeActivationBindingFixture(mode, rawFilePath, rawSocketPath, rawEnvValue, rawCommandLine)
				plan := Plan{
					ID:             "delivery-plan-" + string(mode) + "-" + string(status),
					RequestID:      rawCommandLine,
					RequestedModes: []Mode{mode},
					ActiveModes:    []Mode{Mode(rawEnvValue)},
					Status:         StatusPlanned,
					Warnings: []Warning{{
						Code:       WarningAdapterUnavailable,
						ReasonCode: ReasonActivationUnavailable,
						BindingID:  rawSocketPath,
						Mode:       mode,
					}},
				}
				if mode == ModeSSHAgent {
					plan = sshAgentProofPlanFixture(binding)
					plan.ID = "delivery-plan-" + string(mode) + "-" + string(status)
					plan.RequestID = rawCommandLine
					plan.Warnings = []Warning{{
						Code:       WarningAdapterUnavailable,
						ReasonCode: ReasonActivationUnavailable,
						BindingID:  rawSocketPath,
						Mode:       mode,
					}}
				}
				adapter := NewFakeActivationAdapter(FakeActivationModeResult{
					Mode:   mode,
					Status: status,
				})

				got := ActivateDelivery(ActivationRequest{
					ActivationID: rawCommandLine,
					Plan:         plan,
					Bindings:     []Binding{binding},
				}, adapter)

				calls := adapter.Calls()
				if len(calls) != 1 {
					t.Fatalf("adapter calls = %d, want 1", len(calls))
				}
				call := calls[0]
				if call.ActivationID != plan.ID+"-activation" {
					t.Fatalf("adapter activation ID = %q, want sanitized default", call.ActivationID)
				}
				if len(call.Bindings) != 1 || call.Bindings[0].DeliveryMode != mode || call.Bindings[0].ID != binding.ID {
					t.Fatalf("adapter bindings = %#v, want sanitized %s binding only", call.Bindings, mode)
				}
				if got.Status != status {
					t.Fatalf("activation status = %q, want %q", got.Status, status)
				}
				assertActivationBindingStatus(t, got, binding.ID, mode, status)
				if status == StatusActive {
					assertPlanModes(t, got.ActiveModes, []Mode{mode})
				} else {
					assertPlanModes(t, got.ActiveModes, nil)
				}
				if status == StatusFailed {
					assertActivationReason(t, got, ReasonActivationUnavailable)
				}
				if status == StatusSkipped {
					assertActivationWarning(t, got, WarningActivationSkipped, ReasonActivationUnavailable, mode)
				}
				if value := os.Getenv(envKey); value != "unchanged" {
					t.Fatalf("environment value = %q, want activation to leave it unchanged", value)
				}
				assertPathAbsent(t, rawFilePath)
				assertPathAbsent(t, rawSocketPath)
				assertActivationNoLeak(t, call, rejected...)
				assertActivationNoLeak(t, got, rejected...)
			})
		}
	}
}

func TestFakeActivationAdapterDefaultNonHTTPPathsStayPlanningOnlyWithoutLiveDependencies(t *testing.T) {
	envKey := "US003_DEFAULT_PATH_ENV"
	t.Setenv(envKey, "unchanged")
	rawRoot := t.TempDir()
	rawFilePath := filepath.Join(rawRoot, "tmpfs-secret")
	rawSocketPath := filepath.Join(rawRoot, "agent.sock")
	rawEnvValue := envKey + "=ghp_raw_secret_value"
	rawCommandLine := "install-secret " + rawFilePath + " && ssh-agent -a " + rawSocketPath
	rejected := []string{rawFilePath, rawSocketPath, rawEnvValue, rawCommandLine, "ghp_raw_secret_value"}

	for _, mode := range []Mode{ModeFileTmpfs, ModeSSHAgent, ModeEnv} {
		t.Run(string(mode), func(t *testing.T) {
			binding := nonHTTPFakeActivationBindingFixture(mode, rawFilePath, rawSocketPath, rawEnvValue, rawCommandLine)
			plan := Plan{
				ID:             "delivery-plan-default-" + string(mode),
				RequestID:      rawCommandLine,
				RequestedModes: []Mode{mode},
				ActiveModes:    []Mode{mode},
				Status:         StatusPlanned,
			}

			got := ActivateDelivery(ActivationRequest{
				ActivationID: rawCommandLine,
				Plan:         plan,
				Bindings:     []Binding{binding},
			}, nil)

			if got.Status != StatusSkipped {
				t.Fatalf("activation status = %q, want skipped without adapter", got.Status)
			}
			assertPlanModes(t, got.ActiveModes, nil)
			assertActivationWarning(t, got, WarningAdapterUnavailable, ReasonActivationUnavailable, mode)
			assertActivationBindingStatus(t, got, binding.ID, mode, StatusSkipped)
			if value := os.Getenv(envKey); value != "unchanged" {
				t.Fatalf("environment value = %q, want default activation path to leave it unchanged", value)
			}
			assertPathAbsent(t, rawFilePath)
			assertPathAbsent(t, rawSocketPath)
			assertActivationNoLeak(t, got, rejected...)
		})
	}
}

func nonHTTPFakeActivationBindingFixture(mode Mode, rawFilePath, rawSocketPath, rawEnvValue, rawCommandLine string) Binding {
	binding := planBindingFixture(mode)
	binding.ID = "binding-" + string(mode)
	binding.RequestID = rawCommandLine
	binding.PlanID = rawFilePath
	binding.PolicySnapshotID = rawFilePath
	binding.NetworkProxySessionID = rawSocketPath
	binding.ServiceID = rawSocketPath
	binding.ServiceLabels = []string{"credential-delivery", rawEnvValue}
	binding.DomainLabels = []string{"sandbox", rawCommandLine}
	binding.DestinationCategory = DestinationCategory(rawFilePath)
	return binding
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()

	_, err := os.Stat(path)
	if err == nil {
		t.Fatalf("path %q exists, want activation to avoid filesystem/socket creation", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %q error = %v, want not-exist", path, err)
	}
}
