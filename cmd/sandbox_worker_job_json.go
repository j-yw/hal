package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

const sandboxWorkerJobJSONLimit = int(sandboxworker.DefaultJobLogRetentionBytes)

const (
	sandboxWorkerJobJSONInvalid    = "sandbox worker JSON output is unavailable or invalid; recover with the execution ID"
	sandboxWorkerJobJSONUnfinished = "sandbox worker command or host-side finalization did not complete; recover with the execution ID"
	sandboxWorkerJobJSONDetached   = "sandbox worker job is detached; completion is unconfirmed; recover with the execution ID"
)

type sandboxWorkerJobJSONContextKey struct{}

// The zero value preserves legacy capture behavior. Only the explicit daemon
// job route enables the bound; the context carries it through executor writers.
type sandboxWorkerJobJSONCapture struct {
	buffer    bytes.Buffer
	worker    bool
	truncated bool
}

func (capture *sandboxWorkerJobJSONCapture) Write(data []byte) (int, error) {
	size := len(data)
	if capture.worker && len(data) > sandboxWorkerJobJSONLimit-capture.buffer.Len() {
		data = data[:sandboxWorkerJobJSONLimit-capture.buffer.Len()]
		capture.truncated = true
	}
	_, err := capture.buffer.Write(data)
	return size, err
}

func (capture *sandboxWorkerJobJSONCapture) Bytes() []byte { return capture.buffer.Bytes() }

func sandboxWorkerJobJSONCaptureFromContext(ctx context.Context) *sandboxWorkerJobJSONCapture {
	if ctx == nil {
		return nil
	}
	capture, _ := ctx.Value(sandboxWorkerJobJSONContextKey{}).(*sandboxWorkerJobJSONCapture)
	return capture
}

// Bound forwarded bytes as well as retained bytes: sandboxexec buffers complete
// lines before writing to capture. Discarding excess must not detach/cancel a job.
func (capture *sandboxWorkerJobJSONCapture) workerStream(writer io.Writer) io.Writer {
	capture.worker = true
	if capture.buffer.Len() > sandboxWorkerJobJSONLimit {
		capture.buffer.Truncate(sandboxWorkerJobJSONLimit)
		capture.truncated = true
	}
	if writer == nil {
		writer = io.Discard
	}
	return &sandboxWorkerJobJSONStream{capture: capture, writer: writer}
}

type sandboxWorkerJobJSONStream struct {
	capture   *sandboxWorkerJobJSONCapture
	writer    io.Writer
	forwarded int
}

func (stream *sandboxWorkerJobJSONStream) Write(data []byte) (int, error) {
	size := len(data)
	if len(data) > sandboxWorkerJobJSONLimit-stream.forwarded {
		data = data[:sandboxWorkerJobJSONLimit-stream.forwarded]
		stream.capture.truncated = true
	}
	if len(data) > 0 {
		n, err := stream.writer.Write(data)
		stream.forwarded += n
		if err != nil {
			return n, err
		}
		if n != len(data) {
			return n, io.ErrShortWrite
		}
	}
	return size, nil
}

type sandboxWorkerJobJSONPublication struct {
	purpose       sandboxexecution.Purpose
	executionID   string
	store         sandboxexecution.Store
	capture       *sandboxWorkerJobJSONCapture
	commandErr    error
	autoEntryMode autoEntryMode
}

// Publish once, after durable finalization. Command errors remain available to
// errors.Is/As; public error text never incorporates their potentially raw data.
func outputSandboxWorkerJobJSON(out io.Writer, publication sandboxWorkerJobJSONPublication) error {
	if out == nil {
		out = io.Discard
	}
	manifest, manifestErr := publication.store.LoadManifest(publication.executionID)
	var raw map[string]any
	if publication.capture != nil && !publication.capture.truncated {
		raw = decodeSandboxWorkerJobJSON(publication.capture.Bytes(), publication.purpose)
	}
	detached := isSandboxWorkerJobDetachedError(publication.commandErr)
	message := ""
	switch {
	case detached:
		message = sandboxWorkerJobJSONDetached
		raw = nil
	case raw == nil:
		message = sandboxWorkerJobJSONInvalid
	case manifestErr != nil || manifest == nil || manifest.Purpose != publication.purpose || manifest.Finalization == nil ||
		manifest.Finalization.State != sandboxexecution.FinalizationStateCompleted ||
		validateSandboxL3CompletedPublication(manifest) != nil:
		message = sandboxWorkerJobJSONUnfinished
	case raw["ok"] == true && (publication.commandErr != nil || manifest.Status != sandboxexecution.StatusSucceeded):
		message = sandboxWorkerJobJSONUnfinished
	}
	resultErr := publication.commandErr
	if raw == nil {
		raw = sandboxWorkerJobJSONFailure(publication.purpose, publication.autoEntryMode, message)
	} else if message != "" {
		raw["ok"], raw["error"], raw["summary"] = false, message, message
		// An inner suggestion can assume successful host finalization.
		delete(raw, "nextAction")
	}
	if raw["ok"] == false {
		if resultErr == nil {
			// The failure is already rendered; do not print it again on stderr.
			resultErr = &ExitCodeError{Code: ExitCodeExpectedNonZero}
		}
		if sandboxWorkerJobJSONSafeExecutionID(publication.executionID) {
			raw["sandboxExecutionId"] = publication.executionID
		}
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return errors.Join(resultErr, errors.New("encode sandbox worker JSON result"))
	}
	if manifestErr == nil && !detached && sandboxManifestHasCommandJSONAugmentation(manifest) {
		augmented, ok := sandboxAugmentJSON(data, manifest)
		if !ok {
			return errors.Join(resultErr, errors.New("augment sandbox worker JSON result"))
		}
		data = augmented
	} else if message == "" && raw["ok"] == true {
		// Keep the byte-for-byte success pass-through when no augmentation exists.
		return errors.Join(resultErr, writeSandboxCapturedJSON(out, publication.capture.Bytes()))
	}
	_, err = fmt.Fprintln(out, string(data))
	if err != nil {
		return errors.Join(resultErr, fmt.Errorf("write sandbox worker JSON result: %w", err))
	}
	return resultErr
}

func sandboxWorkerJobJSONFailure(purpose sandboxexecution.Purpose, entryMode autoEntryMode, message string) map[string]any {
	var result any = RunResult{ContractVersion: 1, Error: message, Summary: message}
	if purpose == sandboxexecution.PurposeAuto {
		if entryMode == "" {
			entryMode = autoEntryModeReportDiscovery
		}
		auto := autoFailureResult(entryMode, false, message, message, autoFailurePipeline, false, "", "")
		auto.NextAction = nil
		result = auto
	}
	data, _ := json.Marshal(result)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	return raw
}

func sandboxWorkerJobJSONAutoEntryMode(args []string) autoEntryMode {
	if len(args) > 0 {
		return determineAutoEntryMode(strings.TrimSpace(args[0]))
	}
	return autoEntryModeReportDiscovery
}

// Reject missing/null/wrong-type required fields and duplicate top-level keys,
// while preserving unknown additive fields from a valid command contract.
func decodeSandboxWorkerJobJSON(data []byte, purpose sandboxexecution.Purpose) map[string]any {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil
	}
	raw := make(map[string]any)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil
		}
		name, ok := key.(string)
		if !ok {
			return nil
		}
		if _, duplicate := raw[name]; duplicate {
			return nil
		}
		var value any
		if decoder.Decode(&value) != nil {
			return nil
		}
		raw[name] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil
	}
	if _, ok := raw["ok"].(bool); !ok {
		return nil
	}
	if _, ok := raw["summary"].(string); !ok {
		return nil
	}
	version, ok := sandboxWorkerJobJSONInteger(raw["contractVersion"])
	if !ok {
		return nil
	}
	switch purpose {
	case sandboxexecution.PurposeRun:
		var typed RunResult
		if version != 1 || json.Unmarshal(data, &typed) != nil {
			return nil
		}
		if _, ok := raw["complete"].(bool); !ok {
			return nil
		}
		if iterations, ok := sandboxWorkerJobJSONInteger(raw["iterations"]); !ok || iterations < 0 {
			return nil
		}
	case sandboxexecution.PurposeAuto:
		var typed AutoResult
		if version != 2 || json.Unmarshal(data, &typed) != nil {
			return nil
		}
		if raw["entryMode"] != string(autoEntryModeMarkdownPath) && raw["entryMode"] != string(autoEntryModeReportDiscovery) {
			return nil
		}
		if _, ok := raw["resumed"].(bool); !ok {
			return nil
		}
		steps, ok := raw["steps"].(map[string]any)
		if !ok {
			return nil
		}
		for _, name := range []string{"analyze", "spec", "branch", "convert", "validate", "run", "review", "ci", "report", "archive"} {
			step, ok := steps[name].(map[string]any)
			if !ok {
				return nil
			}
			switch step["status"] {
			case string(autoStepStatusCompleted), string(autoStepStatusSkipped), string(autoStepStatusFailed), string(autoStepStatusPending):
			default:
				return nil
			}
		}
	default:
		return nil
	}
	return raw
}

func sandboxWorkerJobJSONInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	integer, err := number.Int64()
	return integer, err == nil
}

func sandboxWorkerJobJSONSafeExecutionID(id string) bool {
	if len(id) == 0 || len(id) > 192 {
		return false
	}
	for index, char := range id {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			continue
		}
		if index > 0 && (char == '.' || char == '_' || char == ':' || char == '-') {
			continue
		}
		return false
	}
	return true
}
