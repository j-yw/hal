package sandboxworker

import (
	"strings"
	"testing"
)

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

func l8D6WorkerStartRequest(t *testing.T) Request {
	t.Helper()
	request := l8WorkerV2RequestPayloadFixturesForTest(t).v2Requests()[0].req
	request.DriverID = RuntimeDriverMicroVM
	return request
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
