package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/verify"
)

const factoryVerificationOutputLimit = 1 << 20
const factoryVerificationExitMarker = "\nHAL_FACTORY_VERIFY_EXIT="

type factoryVerificationOutput struct {
	buffer    bytes.Buffer
	truncated bool
}

func (out *factoryVerificationOutput) Write(data []byte) (int, error) {
	n := len(data)
	remaining := factoryVerificationOutputLimit - out.buffer.Len()
	if len(data) > remaining {
		data = data[:remaining]
		out.truncated = true
	}
	_, _ = out.buffer.Write(data)
	return n, nil
}

func factoryVerificationExecutionError(cause error) error {
	return factoryRunRedactedError{message: "remote sandbox verification execution failed", cause: cause}
}

func factoryVerificationProviderExitCode(err error) int {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return -1
	}
	// A single wrapped typed process exit is authoritative. A joined error can
	// also contain a transport/write failure, so do not select just its exit arm.
	for current := err; current != nil; current = errors.Unwrap(current) {
		if _, joined := current.(interface{ Unwrap() []error }); joined {
			return -1
		}
	}
	return factorySandboxExecExitCode(err)
}

func factorySandboxWorkerVerifyCompletionScript(script string) string {
	// The subshell retains the original exec/errexit behavior. The outer shell
	// succeeds only after Hal has exited and printf has emitted its exit record.
	// No worker error class is repurposed as proof of a completed check.
	return "set +e\n(\n" + script + "\n)\nhal_factory_verify_exit=$?\nprintf '\\nHAL_FACTORY_VERIFY_EXIT=%d\\n' \"$hal_factory_verify_exit\"\n"
}

func parseFactorySandboxWorkerVerifyCompletion(data []byte) ([]byte, int, error) {
	marker := []byte(factoryVerificationExitMarker)
	if bytes.Count(data, marker) != 1 {
		return nil, 0, factoryVerificationExecutionError(nil)
	}
	index := bytes.Index(data, marker)
	footer := string(data[index+len(marker):])
	switch footer {
	case "0\n":
		return data[:index], 0, nil
	case "4\n":
		return data[:index], ExitCodeExpectedNonZero, nil
	default:
		return nil, 0, factoryVerificationExecutionError(nil)
	}
}

func factoryVerificationObject(data []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		folded := strings.ToLower(name)
		if err != nil || !ok || seen[folded] {
			return nil, false
		}
		seen[folded] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		fields[name] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, false
	}
	return fields, true
}

func validateFactorySandboxVerifyJSON(data []byte) (*verify.Result, error) {
	invalid := errors.New("parse remote sandbox verify JSON: invalid verification result")
	if len(data) == 0 || len(data) > factoryVerificationOutputLimit {
		return nil, invalid
	}
	// Check each proof-bearing object boundary and duplicate/case-alias keys
	// before typed decoding. Unknown additive fields remain compatible.
	fields, ok := factoryVerificationObject(data)
	if !ok {
		return nil, invalid
	}
	for _, field := range []string{"schemaVersion", "status", "summary", "checks"} {
		if _, ok := fields[field]; !ok {
			return nil, invalid
		}
	}
	counts, ok := factoryVerificationObject(fields["summary"])
	if !ok {
		return nil, invalid
	}
	for _, name := range []string{"total", "passed", "failed", "timedOut", "missing", "skipped", "warnings"} {
		var count *int
		if json.Unmarshal(counts[name], &count) != nil || count == nil {
			return nil, invalid
		}
	}
	var checks []json.RawMessage
	if json.Unmarshal(fields["checks"], &checks) != nil || checks == nil {
		return nil, invalid
	}
	for _, check := range checks {
		fields, ok := factoryVerificationObject(check)
		if !ok {
			return nil, invalid
		}
		var required *bool
		var status *string
		if json.Unmarshal(fields["required"], &required) != nil || required == nil || json.Unmarshal(fields["status"], &status) != nil || status == nil {
			return nil, invalid
		}
	}
	var result verify.Result
	if json.Unmarshal(data, &result) != nil || result.SchemaVersion != verify.SchemaVersion {
		return nil, invalid
	}
	summary := verify.Summary{Total: len(result.Checks)}
	status := verify.StatusPass
	if len(result.Warnings) != 0 {
		status = verify.StatusWarn
	}
	for _, check := range result.Checks {
		switch check.Status {
		case verify.CheckStatusPass:
			summary.Passed++
		case verify.CheckStatusFail:
			summary.Failed++
		case verify.CheckStatusTimeout:
			summary.TimedOut++
		case verify.CheckStatusMissing:
			summary.Missing++
		case verify.CheckStatusSkipped:
			summary.Skipped++
		default:
			return nil, invalid
		}
		if !check.Required && check.Status != verify.CheckStatusPass {
			summary.Warnings++
		}
		if check.Required && (check.Status == verify.CheckStatusFail || check.Status == verify.CheckStatusTimeout || check.Status == verify.CheckStatusMissing) {
			status = verify.StatusFail
		}
	}
	if result.Summary != summary || result.Status != status || len(result.Warnings) != summary.Warnings {
		return nil, invalid
	}
	return &result, nil
}
