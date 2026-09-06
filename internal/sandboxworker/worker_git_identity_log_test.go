package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestWorkerGitIdentityJobLogsPreservePublicJSON(t *testing.T) {
	for _, name := range []string{"a", "true", "Zoë O'Connor 李", "Ordinary User"} {
		t.Run(name, func(t *testing.T) {
			const email = "public@example.invalid"
			const secret = "independent-private-log-canary"
			payload, err := json.Marshal(struct {
				OK      bool   `json:"ok"`
				Command string `json:"command"`
				Author  string `json:"author"`
				Email   string `json:"email"`
			}{true, "run", name, email})
			if err != nil {
				t.Fatal(err)
			}
			payload = append(payload, '\n')
			req := workerGitIdentityLogRequest(name, email)
			req.Env["ACTUAL_SECRET"] = secret
			stdout, stderr, stateDir := collectWorkerGitIdentityJobLogs(t, req, payload, []byte(secret+"\n"))
			if stdout != string(payload) {
				t.Errorf("public run JSON changed: got %q, want %q", stdout, payload)
			}
			decoder := json.NewDecoder(strings.NewReader(stdout))
			var result struct {
				OK      bool   `json:"ok"`
				Command string `json:"command"`
				Author  string `json:"author"`
				Email   string `json:"email"`
			}
			if err := decoder.Decode(&result); err != nil {
				t.Errorf("worker output is not valid run JSON: %v", err)
			} else if !result.OK || result.Command != "run" || result.Author != name || result.Email != email {
				t.Errorf("run JSON values changed: %#v", result)
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				t.Errorf("worker output is not exactly one JSON document: %v", err)
			}
			if stderr != "[redacted]\n" {
				t.Errorf("independent secret masking changed: %q", stderr)
			}
			assertL2JobStatePrivateAndSanitized(t, stateDir, secret)
		})
	}
}

func TestWorkerGitIdentityJobLogsKeepIndependentMasks(t *testing.T) {
	const shared = "public-and-private-canary"
	tests := []struct {
		name   string
		mutate func(*ExecRequest)
		output string
		want   string
	}{
		{name: "secret env", mutate: func(req *ExecRequest) { req.Env["API_TOKEN"] = shared }},
		{name: "other env", mutate: func(req *ExecRequest) { req.Env["OTHER_VALUE"] = shared }},
		{name: "legacy git key", mutate: func(req *ExecRequest) { req.Env["GIT_USER_NAME"] = shared }},
		{name: "lowercase git key", mutate: func(req *ExecRequest) { req.Env["git_author_name"] = shared }},
		{name: "git key suffix", mutate: func(req *ExecRequest) { req.Env["GIT_AUTHOR_NAME_EXTRA"] = shared }},
		{name: "git config key", mutate: func(req *ExecRequest) { req.Env["GIT_CONFIG_GLOBAL"] = shared }},
		{name: "argument", mutate: func(req *ExecRequest) { req.Args = append(req.Args, shared) }},
		{name: "stdin", mutate: func(req *ExecRequest) { req.Stdin = workerExecStdinPayload(shared+"\n", MaxExecStdinBytes) }},
		{name: "structural assignment", output: "token=" + shared + "\n", want: "token=[redacted]\n"},
		{name: "structural header", output: "Authorization: Bearer " + shared + "\n", want: "Authorization: [redacted]\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Every public key has the same value as the independently
			// sensitive source. Public identity must not remove that mask.
			req := workerGitIdentityLogRequest(shared, shared)
			if test.mutate != nil {
				test.mutate(&req)
			}
			output, want := test.output, test.want
			if output == "" {
				output, want = shared+"\n", "[redacted]\n"
			}
			stdout, stderr, stateDir := collectWorkerGitIdentityJobLogs(t, req, []byte(output), []byte(output))
			if stdout != want || stderr != want {
				t.Fatalf("independent masking changed: stdout=%q stderr=%q, want %q", stdout, stderr, want)
			}
			assertL2JobStatePrivateAndSanitized(t, stateDir, shared)
		})
	}
}

func workerGitIdentityLogRequest(name, email string) ExecRequest {
	req := l2JobExecRequest("")
	req.Args = []string{"emit-worker-run-json"}
	req.Env = map[string]string{
		"GIT_AUTHOR_NAME": name, "GIT_COMMITTER_NAME": name,
		"GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_EMAIL": email,
	}
	return req
}

func collectWorkerGitIdentityJobLogs(t *testing.T, req ExecRequest, stdoutData, stderrData []byte) (string, string, string) {
	t.Helper()
	wantStdout, wantStderr := append([]byte(nil), stdoutData...), append([]byte(nil), stderrData...)
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "job_driver"},
		execFn: func(_ context.Context, runtimeReq sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if !reflect.DeepEqual(runtimeReq.Env, req.Env) || !reflect.DeepEqual(runtimeReq.Args, req.Args) {
				t.Error("log policy changed the runtime environment or arguments")
			}
			if req.Stdin != nil {
				got, err := io.ReadAll(runtimeReq.Stdin)
				want, _ := io.ReadAll(execStdinReader(req.Stdin))
				if err != nil || !bytes.Equal(got, want) {
					t.Error("log policy changed runtime stdin")
				}
			}
			for _, stream := range []struct {
				writer io.Writer
				data   []byte
			}{{runtimeReq.Stdout, stdoutData}, {runtimeReq.Stderr, stderrData}} {
				// Exercise literal and structural masks across every byte
				// boundary, including boundaries inside Unicode names.
				for index := range stream.data {
					if _, err := stream.writer.Write(stream.data[index : index+1]); err != nil {
						return nil, err
					}
				}
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	service, stateDir, cancel := newL2JobTestService(t, driver)
	t.Cleanup(func() { cancel(); service.Close() })
	response := service.JobStartResponse(context.Background(), "identity-start", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "identity-log-submission",
		Exec:            req,
	})
	if !response.OK || response.Job == nil {
		t.Fatalf("job was not admitted: %#v", response.Error)
	}
	waitForL2JobState(t, service, response.Job.ID, JobStateSucceeded)
	logs := service.JobLogsResponse("identity-logs", JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           response.Job.ID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	if !logs.OK || logs.JobLogs == nil || logs.JobLogs.Truncated {
		t.Fatalf("job logs unavailable or truncated: %#v", logs)
	}
	var stdout, stderr strings.Builder
	for _, record := range logs.JobLogs.Records {
		switch record.Stream {
		case JobLogStreamStdout:
			stdout.WriteString(record.Data)
		case JobLogStreamStderr:
			stderr.WriteString(record.Data)
		default:
			t.Fatalf("unexpected log stream %q", record.Stream)
		}
	}
	if !bytes.Equal(stdoutData, wantStdout) || !bytes.Equal(stderrData, wantStderr) {
		t.Fatal("log redaction modified the source output buffers")
	}
	return stdout.String(), stderr.String(), stateDir
}
