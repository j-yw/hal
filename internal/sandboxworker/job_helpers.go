package sandboxworker

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
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

func jobRequestKey(driverID string, req ExecRequest) (string, error) {
	canonical := canonicalJobExecRequest(req)
	encoded, err := json.Marshal(struct {
		DriverID string      `json:"driverId"`
		Exec     ExecRequest `json:"exec"`
	}{
		DriverID: strings.TrimSpace(driverID),
		Exec:     canonical,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("hal:sandboxworker:job-request:v1\x00"))
	_, _ = digest.Write(encoded)
	return "request-v1-" + hex.EncodeToString(digest.Sum(nil)), nil
}

func validJobRequestKey(value string) bool {
	const prefix = "request-v1-"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func canonicalJobExecRequest(req ExecRequest) ExecRequest {
	canonical := cloneJobExecRequest(req)
	canonical.WorkDir = strings.TrimSpace(canonical.WorkDir)
	canonical.Target.ID = strings.TrimSpace(canonical.Target.ID)
	canonical.Target.Name = strings.TrimSpace(canonical.Target.Name)
	canonical.Target.Status = strings.TrimSpace(canonical.Target.Status)
	canonical.Target.Labels = cloneStringMap(canonical.Target.Labels)
	canonical.Target.Runtime.Driver = strings.TrimSpace(canonical.Target.Runtime.Driver)
	canonical.Target.Runtime.RuntimeID = strings.TrimSpace(canonical.Target.Runtime.RuntimeID)
	canonical.Target.Runtime.Image = strings.TrimSpace(canonical.Target.Runtime.Image)
	canonical.Target.Runtime.WorkerID = strings.TrimSpace(canonical.Target.Runtime.WorkerID)
	canonical.Target.Runtime.IsolationLevel = strings.TrimSpace(canonical.Target.Runtime.IsolationLevel)
	canonical.Target.Runtime.Metadata = sandboxruntime.SanitizeRuntimeMetadata(canonical.Target.Runtime.Metadata)
	return canonical
}
