package sandboxworker

import (
	"context"
	"strings"
	"testing"
)

// Actual selected service reproducer. The unchanged legacy request validator
// accepts these values; selected admission must reject before provider calls.
func TestMinimalLaunchRejectsGuestInvalidRequestIDsBeforeProvider(t *testing.T) {
	for _, fixture := range []struct{ field, value string }{
		{"execution", "_execution"}, {"execution", "-execution"}, {"execution", ".execution"},
		{"credential grant", "_grant"}, {"credential grant", strings.Repeat("g", 65)}, {"credential grant", strings.Repeat("g", 128)},
	} {
		t.Run(fixture.field+"/"+fixture.value[:1]+"/"+stringLengthLabel(fixture.value), func(t *testing.T) {
			f := newMinimalLaunchDispatchFixture(t)
			if fixture.field == "execution" {
				f.request.JobStartV2.Exec.OperationID = fixture.value
			} else {
				f.request.JobStartV2.AdmissionGrantID = fixture.value
			}
			if err := f.request.Validate(); err != nil {
				t.Fatalf("legacy request control rejected selected-only syntax: %v", err)
			}
			s := f.service(t)
			response := s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
			if response.OK || f.provider.resolveCalls != 0 || f.provider.startCalls != 0 || len(minimalLaunchRecordFiles(t, f.stateDir)) != 0 {
				t.Fatalf("guest-invalid %s reached resolve=%d start=%d records=%d; want pre-provider rejection", fixture.field, f.provider.resolveCalls, f.provider.startCalls, len(minimalLaunchRecordFiles(t, f.stateDir)))
			}
		})
	}
}

func TestMinimalLaunchStoredGuestIDValidationIsSelectedOnly(t *testing.T) {
	f := newMinimalLaunchDispatchFixture(t)
	s := f.service(t)
	_ = s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
	var original storedJobStateV2
	for _, state := range s.jobs.states {
		original = cloneStoredJobStateV2(state)
	}
	if err := original.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"worker", "host", "runtime", "principal", "plan", "template", "workspace", "credential grant", "job generation", "sandbox", "execution", "submission", "runtime generation", "launch grant", "launch policy", "network policy"} {
		for _, value := range []string{"_invalid", ".invalid", "-invalid", strings.Repeat("x", 65)} {
			t.Run(field+"/"+value[:1]+"/"+stringLengthLabel(value), func(t *testing.T) {
				candidate := cloneStoredJobStateV2(original)
				switch field {
				case "worker":
					candidate.JobV2.WorkerID = value
				case "host":
					candidate.JobV2.HostID = value
				case "runtime":
					candidate.JobV2.RuntimeID = value
				case "principal":
					candidate.PrincipalID = value
				case "plan":
					candidate.JobV2.CredentialIntent.PlanID = value
				case "template":
					candidate.JobV2.CredentialIntent.TemplatePolicyID = value
				case "workspace":
					candidate.JobV2.CredentialIntent.WorkspacePolicyID = value
				case "credential grant":
					candidate.JobV2.CredentialIntent.AdmissionGrantID = value
				case "job generation":
					candidate.MinimalLaunch.JobGeneration = value
				case "sandbox":
					candidate.MinimalLaunch.SandboxID = value
				case "execution":
					candidate.MinimalLaunch.ExecutionID = value
				case "submission":
					candidate.MinimalLaunch.SubmissionID = value
				case "runtime generation":
					candidate.MinimalLaunch.RuntimeGeneration = value
				case "launch grant":
					candidate.MinimalLaunch.LaunchGrantID = value
				case "launch policy":
					candidate.MinimalLaunch.LaunchPolicyID = value
				case "network policy":
					candidate.MinimalLaunch.NetworkPolicyID = value
				}
				if candidate.Validate() == nil {
					t.Fatalf("selected stored %s accepted guest-invalid ID", field)
				}
			})
		}
	}
}

func TestMinimalLaunchLegacyCredentialVocabularyRemainsUnchanged(t *testing.T) {
	for _, value := range []string{"_legacy", ".legacy", "-legacy", strings.Repeat("g", 65), strings.Repeat("g", 128)} {
		t.Run(value[:1]+"/"+stringLengthLabel(value), func(t *testing.T) {
			request := l8D6WorkerStartRequest(t)
			request.JobStartV2.AdmissionGrantID = value
			if err := request.Validate(); err != nil {
				t.Fatalf("legacy admission vocabulary narrowed: %v", err)
			}
			intent := request.JobStartV2.credentialIntent()
			intent.SourceReferenceIDs = []string{value}
			intent.Bindings = intent.Bindings[:1]
			intent.Bindings[0].BindingID, intent.Bindings[0].SourceReferenceID = value, value
			if intent.Bindings[0].Mode == "http_proxy" {
				intent.Bindings[0].ServiceID = value
			}
			if err := intent.Validate(); err != nil {
				t.Fatalf("unrelated legacy credential vocabulary narrowed: %v", err)
			}
		})
	}
}

func TestMinimalLaunchRequestGuestIDSyntaxPositiveControls(t *testing.T) {
	for _, value := range []string{"A", "0", "a._-", strings.Repeat("a", 64)} {
		t.Run(value[:1]+"/"+stringLengthLabel(value), func(t *testing.T) {
			f := newMinimalLaunchDispatchFixture(t)
			f.request.JobStartV2.Exec.OperationID = value
			f.request.JobStartV2.AdmissionGrantID = value
			s := f.service(t)
			_ = s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
			if f.provider.startCalls != 1 || !f.provider.checkedDispatch {
				t.Fatal("valid guest-bound ID did not reach exactly checked dispatch")
			}
		})
	}
}

func stringLengthLabel(value string) string {
	switch len(value) {
	case 1:
		return "one"
	case 64:
		return "64"
	case 65:
		return "65"
	case 128:
		return "128"
	default:
		return "short"
	}
}
