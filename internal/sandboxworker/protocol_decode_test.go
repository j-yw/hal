package sandboxworker

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

func TestWorkerRequestDecoderIsStrictBeforeDispatch(t *testing.T) {
	canonical := `{"protocolVersion":"sandboxworker-v1","requestId":"request-v1","operation":"job_status","jobStatus":{"contractVersion":"sandboxjob-v1","jobId":"job-primary"}}`
	server := &Server{maxRequestBytes: defaultMaxRequestBytes}
	for name, raw := range map[string]string{
		"unknown outer":    strings.Replace(canonical, `"operation":`, `"unknown":true,"operation":`, 1),
		"duplicate outer":  strings.Replace(canonical, `"operation":"job_status"`, `"operation":"job_status","operation":"job_status"`, 1),
		"unknown nested":   strings.Replace(canonical, `"jobId":"job-primary"`, `"jobId":"job-primary","unknown":true`, 1),
		"duplicate nested": strings.Replace(canonical, `"jobId":"job-primary"`, `"jobId":"job-primary","jobId":"job-primary"`, 1),
		"trailing value":   canonical + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, rejected := server.readRequest(strings.NewReader(raw)); rejected == nil || rejected.Error == nil || rejected.Error.Code != ErrorCodeMalformedRequest {
				t.Fatalf("strict decode response = %#v, want malformed_request", rejected)
			}
		})
	}
	for _, raw := range []string{canonical, canonical + " \n\t"} {
		if _, rejected := server.readRequest(strings.NewReader(raw)); rejected != nil {
			t.Fatalf("canonical single request rejected: %#v", rejected)
		}
	}
	server.maxRequestBytes = int64(len(canonical) - 1)
	if _, rejected := server.readRequest(strings.NewReader(canonical)); rejected == nil || rejected.Error == nil || rejected.Error.Code != ErrorCodeMalformedRequest {
		t.Fatalf("oversized request response = %#v, want malformed_request", rejected)
	}
}

func TestWorkerResponseDecoderRejectsUnknownDuplicateTrailingAndNoncanonicalJSON(t *testing.T) {
	canonical := `{"protocolVersion":"sandboxworker-v1","requestId":"request-v1","operation":"job_logs","ok":true,"jobLogs":{"contractVersion":"sandboxjob-v1","jobId":"job-primary","nextCursor":0}}`
	for _, raw := range []string{
		strings.Replace(canonical, `"operation":`, `"unknown":true,"operation":`, 1),
		strings.Replace(canonical, `"operation":"job_logs"`, `"operation":"job_logs","operation":"job_logs"`, 1),
		strings.Replace(canonical, `"contractVersion":"sandboxjob-v1"`, `"contractVersion":"sandboxjob-v1","contractVersion":"sandboxjob-v1"`, 1),
		strings.Replace(canonical, `"nextCursor":0`, `"nextCursor":0.0`, 1),
		canonical + `{}`,
	} {
		var response Response
		if err := decodeWorkerResponseInto(strings.NewReader(raw), defaultMaxResponseBytes, &response); err == nil {
			t.Fatal("malformed client response was accepted")
		}
	}
	var decoded Response
	if err := decodeWorkerResponseInto(strings.NewReader(canonical), defaultMaxResponseBytes, &decoded); err != nil {
		t.Fatalf("canonical client response: %v", err)
	}
	if decoded.Operation != OperationJobLogs || decoded.JobLogs == nil || decoded.JobLogs.ContractVersion != JobContractVersion || decoded.JobLogs.JobID != "job-primary" || decoded.JobLogs.NextCursor != 0 {
		t.Fatalf("decoded response = %#v", decoded)
	}
}

func TestWorkerBoundedJSONReaderPreservesFullPositiveInt64Range(t *testing.T) {
	raw := []byte(`{"operation":"status"}`)
	got, err := readWorkerJSONBounded(bytes.NewReader(raw), math.MaxInt64)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("MaxInt64 bounded read = %q, %v; want exact small payload", got, err)
	}
	large := bytes.Repeat([]byte{'x'}, (1<<20)+1)
	got, err = readWorkerJSONBounded(bytes.NewReader(large), int64(len(large)))
	if err != nil || !bytes.Equal(got, large) {
		t.Fatalf("configured read above 1 MiB length = %d, %v; want exact %d-byte payload", len(got), err, len(large))
	}
	got, err = readWorkerJSONBounded(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("exact-limit EOF read = %q, %v; want success", got, err)
	}
	if _, err := readWorkerJSONBounded(bytes.NewReader(append(append([]byte(nil), raw...), '!')), int64(len(raw))); err == nil {
		t.Fatal("one byte beyond the exact limit was accepted")
	}
	probeFailure := errors.New("probe failure")
	reader := io.MultiReader(bytes.NewReader(raw), workerProbeErrorReader{err: probeFailure})
	if _, err := readWorkerJSONBounded(reader, int64(len(raw))); !errors.Is(err, probeFailure) {
		t.Fatalf("probe error = %v, want wrapped probe failure", err)
	}
}

func TestWorkerJSONPreflightBoundsNestingBeforeTypedDecode(t *testing.T) {
	const decoderNestingLimit = 10_000
	atLimit := strings.Repeat("[", decoderNestingLimit) + "null" + strings.Repeat("]", decoderNestingLimit)
	if err := validateWorkerJSONPreflight(atLimit); err != nil {
		t.Fatalf("preflight rejected JSON at the typed decoder nesting limit: %v", err)
	}
	overLimit := "[" + atLimit + "]"
	if err := validateWorkerJSONPreflight(overLimit); err == nil {
		t.Fatal("preflight accepted JSON beyond the typed decoder nesting limit")
	}
}

type workerProbeErrorReader struct {
	err error
}

func (reader workerProbeErrorReader) Read([]byte) (int, error) {
	return 0, reader.err
}
