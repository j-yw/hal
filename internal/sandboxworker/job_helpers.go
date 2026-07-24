package sandboxworker

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"
)

func newOpaqueJobID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return "job-" + hex.EncodeToString(value[:]), nil
}

func cloneJob(job Job) Job {
	cloned := job
	cloned.StartedAt = cloneTimePointer(job.StartedAt)
	cloned.HeartbeatAt = cloneTimePointer(job.HeartbeatAt)
	cloned.FinishedAt = cloneTimePointer(job.FinishedAt)
	if job.ExitCode != nil {
		exitCode := *job.ExitCode
		cloned.ExitCode = &exitCode
	}
	return cloned
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func timePointer(value time.Time) *time.Time {
	return &value
}

func cloneJobExecRequest(req ExecRequest) ExecRequest {
	cloned := req
	cloned.Args = cloneStringSlice(req.Args)
	cloned.Env = cloneStringMap(req.Env)
	if req.Stdin != nil {
		stdin := *req.Stdin
		cloned.Stdin = &stdin
	}
	return cloned
}
