package livegate

import (
	"fmt"
	"strings"
	"testing"
)

func TestRequireLiveGateMissingBuildTagSkipsWithSafeMessage(t *testing.T) {
	tb := &recordingLiveGateTB{}

	result := RequireLiveGate(tb, TestGateInput{
		GateID:                GateID("firecracker-live"),
		Gate:                  firecrackerLiveGateForEvaluation(),
		ExpectedEnvVars:       []EnvVarName{EnvVarFirecrackerLive},
		PresentEnvVars:        []EnvVarName{EnvVarFirecrackerLive},
		AvailableCapabilities: []CapabilityID{CapabilityFirecrackerMicroVM},
	})

	if tb.failed {
		t.Fatalf("RequireLiveGate failed before evaluating gate: %s", tb.fatalMessage)
	}
	if !tb.skipped {
		t.Fatal("RequireLiveGate did not skip when required build tag was missing")
	}
	if result.CanRunLiveAction() {
		t.Fatal("CanRunLiveAction() = true, want false when required build tag is missing")
	}
	requireLiveGateMessageContains(t, tb.skipMessage,
		"firecracker-live",
		string(BuildTagFirecrackerLive),
		string(SkipReasonMissingBuildTag),
		"go test -tags=firecracker_live ./...",
	)
	AssertLiveGateSkipMessageRedactionSafe(t, tb.skipMessage)
}

func TestRequireLiveGateMissingEnvMarkerSkipsWithSafeMessage(t *testing.T) {
	tb := &recordingLiveGateTB{}

	result := RequireLiveGate(tb, TestGateInput{
		GateID:                GateID("firecracker-live"),
		Gate:                  firecrackerLiveGateForEvaluation(),
		ExpectedEnvVars:       []EnvVarName{EnvVarFirecrackerLive},
		EnabledBuildTags:      []BuildTagName{BuildTagFirecrackerLive},
		AvailableCapabilities: []CapabilityID{CapabilityFirecrackerMicroVM},
	})

	if tb.failed {
		t.Fatalf("RequireLiveGate failed before evaluating gate: %s", tb.fatalMessage)
	}
	if !tb.skipped {
		t.Fatal("RequireLiveGate did not skip when expected env marker was absent")
	}
	if result.SkipReason != SkipReasonMissingEnvVar {
		t.Fatalf("SkipReason = %q, want %q", result.SkipReason, SkipReasonMissingEnvVar)
	}
	requireLiveGateMessageContains(t, tb.skipMessage,
		"firecracker-live",
		string(EnvVarFirecrackerLive),
		string(SkipReasonMissingEnvVar),
		"env HAL_FIRECRACKER_LIVE=<set> go test ./...",
	)
	AssertLiveGateSkipMessageRedactionSafe(t, tb.skipMessage, "secret-live-env-value")
}

func TestRequireLiveGateMissingCapabilitySkipsWithSafeMessage(t *testing.T) {
	tb := &recordingLiveGateTB{}

	result := RequireLiveGate(tb, TestGateInput{
		GateID:           GateID("firecracker-live"),
		Gate:             firecrackerLiveGateForEvaluation(),
		ExpectedEnvVars:  []EnvVarName{EnvVarFirecrackerLive},
		EnabledBuildTags: []BuildTagName{BuildTagFirecrackerLive},
		PresentEnvVars:   []EnvVarName{EnvVarFirecrackerLive},
	})

	if tb.failed {
		t.Fatalf("RequireLiveGate failed before evaluating gate: %s", tb.fatalMessage)
	}
	if !tb.skipped {
		t.Fatal("RequireLiveGate did not skip when required capability was unavailable")
	}
	if result.SkipReason != SkipReasonCapabilityUnavailable {
		t.Fatalf("SkipReason = %q, want %q", result.SkipReason, SkipReasonCapabilityUnavailable)
	}
	requireLiveGateMessageContains(t, tb.skipMessage,
		"firecracker-live",
		string(CapabilityFirecrackerMicroVM),
		string(SkipReasonCapabilityUnavailable),
		string(RemediationInstallCapability),
	)
	AssertLiveGateSkipMessageRedactionSafe(t, tb.skipMessage)
}

func TestRequireLiveGateSatisfiedGateDoesNotSkip(t *testing.T) {
	tb := &recordingLiveGateTB{}

	result := RequireLiveGate(tb, TestGateInput{
		GateID:                GateID("firecracker-live"),
		Gate:                  firecrackerLiveGateForEvaluation(),
		ExpectedEnvVars:       []EnvVarName{EnvVarFirecrackerLive},
		EnabledBuildTags:      []BuildTagName{BuildTagFirecrackerLive},
		PresentEnvVars:        []EnvVarName{EnvVarFirecrackerLive},
		AvailableCapabilities: []CapabilityID{CapabilityFirecrackerMicroVM},
	})

	if tb.failed {
		t.Fatalf("RequireLiveGate failed before evaluating gate: %s", tb.fatalMessage)
	}
	if tb.skipped {
		t.Fatalf("RequireLiveGate skipped satisfied gate with message: %s", tb.skipMessage)
	}
	if !result.CanRunLiveAction() {
		t.Fatal("CanRunLiveAction() = false, want true when all explicit prerequisites are present")
	}
}

func TestRequireLiveGateRequiresExplicitGateIDAndEnvMarkers(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input TestGateInput
		want  string
	}{
		{
			name: "missing gate ID",
			input: TestGateInput{
				Gate:            firecrackerLiveGateForEvaluation(),
				ExpectedEnvVars: []EnvVarName{EnvVarFirecrackerLive},
			},
			want: "explicit gate id",
		},
		{
			name: "missing expected env marker",
			input: TestGateInput{
				GateID: GateID("firecracker-live"),
				Gate:   firecrackerLiveGateForEvaluation(),
			},
			want: "explicit expected env markers",
		},
		{
			name: "mismatched expected env marker",
			input: TestGateInput{
				GateID:          GateID("firecracker-live"),
				Gate:            firecrackerLiveGateForEvaluation(),
				ExpectedEnvVars: []EnvVarName{EnvVarNetworkEnforcementLive},
			},
			want: "expected env markers",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tb := &recordingLiveGateTB{}

			RequireLiveGate(tb, tt.input)

			if !tb.failed {
				t.Fatalf("RequireLiveGate did not fail for %s", tt.name)
			}
			if !strings.Contains(tb.fatalMessage, tt.want) {
				t.Fatalf("fatal message = %q, want %q", tb.fatalMessage, tt.want)
			}
			if tb.skipped {
				t.Fatalf("RequireLiveGate skipped after invalid helper input: %s", tb.skipMessage)
			}
			AssertLiveGateSkipMessageRedactionSafe(t, tb.fatalMessage)
		})
	}
}

func TestLiveGateSkipAndRemediationOutputAreRedactionSafe(t *testing.T) {
	tb := &recordingLiveGateTB{}

	result := RequireLiveGate(tb, TestGateInput{
		GateID: GateID("firecracker-live"),
		Gate: Gate{
			ID:           GateID("firecracker-live"),
			Category:     GateCategoryFirecracker,
			BuildTags:    []BuildTagName{BuildTagFirecrackerLive, BuildTagName("-tags=firecracker_live")},
			EnvVars:      []EnvVarName{EnvVarFirecrackerLive, EnvVarName("HAL_FIRECRACKER_LIVE=secret-live-env-value")},
			Capabilities: []CapabilityID{CapabilityFirecrackerMicroVM, CapabilityID("providerConfig=/Users/alice/.hal/provider.json")},
		},
		ExpectedEnvVars: []EnvVarName{EnvVarFirecrackerLive},
		EnabledBuildTags: []BuildTagName{
			BuildTagName("-tags=firecracker_live"),
			BuildTagName("/Users/alice/.hal/tags"),
		},
		PresentEnvVars: []EnvVarName{
			EnvVarName("HAL_FIRECRACKER_LIVE=secret-live-env-value"),
			EnvVarName("HTTP_PROXY=http://proxy.internal:8080"),
		},
		AvailableCapabilities: []CapabilityID{
			CapabilityID("firecracker --api-sock /tmp/fc.sock"),
			CapabilityID("iptables -A OUTPUT -j DROP"),
		},
	})

	if tb.failed {
		t.Fatalf("RequireLiveGate failed before evaluating unsafe inputs: %s", tb.fatalMessage)
	}
	if !tb.skipped {
		t.Fatal("RequireLiveGate did not skip when unsafe inputs failed explicit prerequisites")
	}
	remediationOutput := LiveGateRemediationOutput(result.Remediation)
	requireLiveGateMessageContains(t, tb.skipMessage,
		"firecracker-live",
		string(BuildTagFirecrackerLive),
		string(EnvVarFirecrackerLive),
		string(CapabilityFirecrackerMicroVM),
		string(SkipReasonMissingBuildTag),
		"env HAL_FIRECRACKER_LIVE=<set> go test -tags=firecracker_live ./...",
	)
	requireLiveGateMessageContains(t, remediationOutput,
		string(RemediationEnableBuildTag),
		string(RemediationSetEnvVar),
		string(RemediationInstallCapability),
	)
	for _, unsafe := range []string{
		"secret-live-env-value",
		"HAL_FIRECRACKER_LIVE=secret-live-env-value",
		"HTTP_PROXY=http://proxy.internal:8080",
		"proxy.internal",
		"providerConfig",
		"/Users/alice",
		"/tmp/fc.sock",
		"--api-sock",
		"iptables",
		"http://",
	} {
		AssertLiveGateSkipMessageRedactionSafe(t, tb.skipMessage, unsafe)
		AssertLiveGateRemediationOutputRedactionSafe(t, remediationOutput, unsafe)
	}
}

func TestLiveGateRedactionAssertionsRejectUnsafeOutputWithoutEchoingIt(t *testing.T) {
	tb := &recordingLiveGateTB{}

	AssertLiveGateSkipMessageRedactionSafe(tb, "skip leaked https://api.internal.example.com?token=secret-live-env-value")

	if !tb.failed {
		t.Fatal("AssertLiveGateSkipMessageRedactionSafe did not fail for unsafe output")
	}
	if strings.Contains(tb.fatalMessage, "secret-live-env-value") ||
		strings.Contains(tb.fatalMessage, "api.internal.example.com") {
		t.Fatalf("redaction assertion failure echoed unsafe output: %q", tb.fatalMessage)
	}
}

func requireLiveGateMessageContains(t *testing.T, message string, values ...string) {
	t.Helper()

	for _, value := range values {
		if !strings.Contains(message, value) {
			t.Fatalf("message %q missing %q", message, value)
		}
	}
}

type recordingLiveGateTB struct {
	helperCalls  int
	skipped      bool
	skipMessage  string
	failed       bool
	fatalMessage string
}

func (tb *recordingLiveGateTB) Helper() {
	tb.helperCalls++
}

func (tb *recordingLiveGateTB) Skip(args ...any) {
	tb.skipped = true
	tb.skipMessage = fmt.Sprint(args...)
}

func (tb *recordingLiveGateTB) Fatalf(format string, args ...any) {
	tb.failed = true
	tb.fatalMessage = fmt.Sprintf(format, args...)
}
