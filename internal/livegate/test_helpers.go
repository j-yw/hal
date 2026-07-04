package livegate

import "strings"

// LiveGateTestTB is the narrow test surface required by RequireLiveGate.
type LiveGateTestTB interface {
	Helper()
	Skip(args ...any)
	Fatalf(format string, args ...any)
}

// LiveGateAssertionTB is the narrow test surface required by redaction
// assertion helpers.
type LiveGateAssertionTB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// TestGateInput carries explicit prerequisite facts for a live-gated test.
// ExpectedEnvVars duplicates the gate env contract on purpose so test authors
// must name marker variables directly instead of relying on process state.
type TestGateInput struct {
	GateID                GateID
	Gate                  Gate
	ExpectedEnvVars       []EnvVarName
	EnabledBuildTags      []BuildTagName
	PresentEnvVars        []EnvVarName
	AvailableCapabilities []CapabilityID
}

// RequireLiveGate evaluates a live gate and skips with a redaction-safe message
// before the caller performs an optional live action.
func RequireLiveGate(t LiveGateTestTB, input TestGateInput) GatePreflightResult {
	if t != nil {
		t.Helper()
	}

	evaluation, failure := liveGateTestEvaluationInput(input)
	if failure != "" {
		if t != nil {
			t.Fatalf("%s", failure)
		}
		return GatePreflightResult{}
	}

	result := EvaluateGate(evaluation)
	if !result.ShouldSkipLiveAction() {
		return result
	}

	message := LiveGateSkipMessage(result)
	if rule := liveGateOutputRedactionViolation(message, nil); rule >= 0 {
		if t != nil {
			t.Fatalf("live gate skip message failed redaction check at rule %d", rule)
		}
		return result
	}
	if t != nil {
		t.Skip(message)
	}
	return result
}

// LiveGateSkipMessage formats a sanitized skip message from a preflight result.
func LiveGateSkipMessage(result GatePreflightResult) string {
	sanitized := SanitizeGatePreflightResult(result)
	status := "skipped"
	if sanitized.CanRunLiveAction() {
		status = "satisfied"
	}

	segments := []string{"live gate"}
	if sanitized.GateID != "" {
		segments[0] += " " + string(sanitized.GateID)
	}
	segments[0] += " " + status
	if sanitized.SkipReason != "" {
		segments = append(segments, "reason "+string(sanitized.SkipReason))
	}
	if sanitized.Remediation != nil {
		output := LiveGateRemediationOutput(sanitized.Remediation)
		if output != "" {
			segments = append(segments, "remediation "+output)
		}
	}
	return strings.Join(segments, "; ")
}

// LiveGateRemediationOutput formats safe remediation labels and commands.
func LiveGateRemediationOutput(remediation *RemediationMetadata) string {
	if remediation == nil {
		return ""
	}
	sanitized := SanitizeRemediationMetadata(*remediation)
	var segments []string
	if sanitized.ReasonCode != "" {
		segments = append(segments, "reason "+string(sanitized.ReasonCode))
	}
	if len(sanitized.BuildTags) > 0 {
		segments = append(segments, "buildTags "+joinLiveGateBuildTags(sanitized.BuildTags))
	}
	if len(sanitized.EnvVars) > 0 {
		segments = append(segments, "envVars "+joinLiveGateEnvVars(sanitized.EnvVars))
	}
	if len(sanitized.Capabilities) > 0 {
		segments = append(segments, "capabilities "+joinLiveGateCapabilities(sanitized.Capabilities))
	}
	if len(sanitized.CommandLabels) > 0 {
		segments = append(segments, "labels "+joinLiveGateCommandLabels(sanitized.CommandLabels))
	}
	if commands := LiveGateRemediationCommands(&sanitized); len(commands) > 0 {
		segments = append(segments, "commands "+strings.Join(commands, "; "))
	}
	return strings.Join(segments, "; ")
}

// LiveGateRemediationCommands renders allowlisted remediation command shapes
// with safe metadata only. Environment values are always represented as <set>.
func LiveGateRemediationCommands(remediation *RemediationMetadata) []string {
	if remediation == nil {
		return nil
	}
	sanitized := SanitizeRemediationMetadata(*remediation)
	if len(sanitized.CommandTemplates) == 0 {
		return nil
	}

	buildTags := joinLiveGateBuildTagsForFlag(sanitized.BuildTags)
	envVars := joinLiveGateEnvAssignments(sanitized.EnvVars)
	commands := make([]string, 0, len(sanitized.CommandTemplates))
	for _, template := range sanitized.CommandTemplates {
		var command string
		switch template {
		case RemediationTemplateGoTestBuildTags:
			if buildTags == "" {
				continue
			}
			command = "go test -tags=" + buildTags + " ./..."
		case RemediationTemplateGoTestEnvVars:
			if envVars == "" {
				continue
			}
			command = "env " + envVars + " go test ./..."
		case RemediationTemplateGoTestBuildTagsEnvVars:
			if buildTags == "" || envVars == "" {
				continue
			}
			command = "env " + envVars + " go test -tags=" + buildTags + " ./..."
		}
		if command != "" {
			commands = append(commands, command)
		}
	}
	if len(commands) == 0 {
		return nil
	}
	return commands
}

// AssertLiveGateSkipMessageRedactionSafe fails if a skip message contains a
// known unsafe fragment or any caller-provided sensitive fragment.
func AssertLiveGateSkipMessageRedactionSafe(t LiveGateAssertionTB, message string, forbiddenFragments ...string) {
	if t != nil {
		t.Helper()
	}
	if rule := liveGateOutputRedactionViolation(message, forbiddenFragments); rule >= 0 && t != nil {
		t.Fatalf("live gate skip message failed redaction check at rule %d", rule)
	}
}

// AssertLiveGateRemediationOutputRedactionSafe fails if remediation output
// contains a known unsafe fragment or any caller-provided sensitive fragment.
func AssertLiveGateRemediationOutputRedactionSafe(t LiveGateAssertionTB, output string, forbiddenFragments ...string) {
	if t != nil {
		t.Helper()
	}
	if rule := liveGateOutputRedactionViolation(output, forbiddenFragments); rule >= 0 && t != nil {
		t.Fatalf("live gate remediation output failed redaction check at rule %d", rule)
	}
}

func liveGateTestEvaluationInput(input TestGateInput) (GateEvaluationInput, string) {
	gate := SanitizeGate(input.Gate)
	gateID := sanitizeGateID(input.GateID)
	if gateID == "" {
		return GateEvaluationInput{}, "live gate test helper requires explicit gate id"
	}
	if gate.ID == "" {
		return GateEvaluationInput{}, "live gate test helper requires gate contract id"
	}
	if gate.ID != gateID {
		return GateEvaluationInput{}, "live gate test helper gate id mismatch"
	}

	expectedEnvVars := uniqueEnvVars(sanitizeEnvVarList(input.ExpectedEnvVars))
	gateEnvVars := uniqueEnvVars(gate.EnvVars)
	if len(expectedEnvVars) == 0 {
		return GateEvaluationInput{}, "live gate test helper requires explicit expected env markers"
	}
	if !liveGateEnvVarSetsEqual(expectedEnvVars, gateEnvVars) {
		return GateEvaluationInput{}, "live gate test helper expected env markers mismatch"
	}

	return GateEvaluationInput{
		Gate:                  gate,
		EnabledBuildTags:      input.EnabledBuildTags,
		PresentEnvVars:        input.PresentEnvVars,
		AvailableCapabilities: input.AvailableCapabilities,
	}, ""
}

func liveGateEnvVarSetsEqual(left, right []EnvVarName) bool {
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		if !envVarListContains(right, value) {
			return false
		}
	}
	return true
}

func joinLiveGateBuildTags(values []BuildTagName) string {
	parts := make([]string, 0, len(values))
	for _, value := range sanitizeBuildTagList(values) {
		parts = append(parts, string(value))
	}
	return strings.Join(parts, " ")
}

func joinLiveGateBuildTagsForFlag(values []BuildTagName) string {
	parts := make([]string, 0, len(values))
	for _, value := range sanitizeBuildTagList(values) {
		parts = append(parts, string(value))
	}
	return strings.Join(parts, ",")
}

func joinLiveGateEnvVars(values []EnvVarName) string {
	parts := make([]string, 0, len(values))
	for _, value := range sanitizeEnvVarList(values) {
		parts = append(parts, string(value))
	}
	return strings.Join(parts, " ")
}

func joinLiveGateEnvAssignments(values []EnvVarName) string {
	parts := make([]string, 0, len(values))
	for _, value := range sanitizeEnvVarList(values) {
		parts = append(parts, string(value)+"=<set>")
	}
	return strings.Join(parts, " ")
}

func joinLiveGateCapabilities(values []CapabilityID) string {
	parts := make([]string, 0, len(values))
	for _, value := range sanitizeCapabilityIDList(values) {
		parts = append(parts, string(value))
	}
	return strings.Join(parts, " ")
}

func joinLiveGateCommandLabels(values []RemediationCommandLabel) string {
	parts := make([]string, 0, len(values))
	for _, value := range sanitizeRemediationCommandLabelList(values) {
		parts = append(parts, string(value))
	}
	return strings.Join(parts, " ")
}

func liveGateOutputRedactionViolation(output string, forbiddenFragments []string) int {
	normalized := strings.ToLower(output)
	rule := 0
	for _, fragment := range defaultLiveGateOutputUnsafeFragments {
		if fragment != "" && strings.Contains(normalized, fragment) {
			return rule
		}
		rule++
	}
	for _, fragment := range forbiddenFragments {
		normalizedFragment := strings.ToLower(strings.TrimSpace(fragment))
		if normalizedFragment != "" && strings.Contains(normalized, normalizedFragment) {
			return rule
		}
		rule++
	}
	return -1
}

var defaultLiveGateOutputUnsafeFragments = []string{
	"http://",
	"https://",
	"localhost",
	"127.0.0.1",
	".internal.example.com",
	".sock",
	"/tmp/",
	"/users/",
	"/var/run/",
	"ghp_",
	"github_pat_",
	"xoxb-",
	"xoxp-",
	"sk-",
	"bearer",
	"authorization",
	"token=",
	"password=",
	"secret=",
	"credential-value",
	"credential_value",
	"providerconfig",
	"--api-sock",
	"iptables",
	"pfctl",
	"nft ",
	"firewall-cmd",
	"http_proxy=",
	"https_proxy=",
	"proxy.internal",
	"proxy://",
	"socks5://",
}
