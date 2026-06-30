package sandboxworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var (
	ErrWorkerClientRequired       = errors.New("worker client is required")
	ErrWorkerTargetRequired       = errors.New("worker client returned no target")
	ErrWorkerOperationUnsupported = errors.New("worker runtime driver operation unsupported")
	ErrWorkerExecResponseRequired = errors.New("worker client returned no exec response")
	ErrWorkerExecOutputTruncated  = errors.New("worker exec output truncated")
)

const clientDriverExecOperationID = "client-driver-exec"

var _ sandboxruntime.Driver = (*ClientDriver)(nil)

// RuntimeDriverClient is the worker-client subset needed by ClientDriver.
type RuntimeDriverClient interface {
	Create(context.Context, string, CreateRequest) (*Target, error)
	Start(context.Context, string, LifecycleRequest) (*Target, error)
	Stop(context.Context, string, LifecycleRequest) (*Target, error)
	Delete(context.Context, string, LifecycleRequest) error
	Inspect(context.Context, string, InspectRequest) (*Target, error)
	Exec(context.Context, string, ExecRequest) (*ExecResponse, error)
}

// ClientDriverOptions configures a sandboxruntime.Driver backed by a worker
// client.
type ClientDriverOptions struct {
	DriverID string
	Client   RuntimeDriverClient
}

// ClientDriver adapts worker protocol lifecycle and inspect calls to the
// sandboxruntime.Driver contract.
type ClientDriver struct {
	driverID string
	client   RuntimeDriverClient
}

// NewClientDriver returns a runtime driver adapter backed by a worker client.
func NewClientDriver(options ClientDriverOptions) (*ClientDriver, error) {
	driverID := strings.TrimSpace(options.DriverID)
	if driverID == "" {
		return nil, ErrDriverIDRequired
	}
	if options.Client == nil {
		return nil, ErrWorkerClientRequired
	}
	return &ClientDriver{
		driverID: driverID,
		client:   options.Client,
	}, nil
}

// ID returns the runtime driver ID this adapter routes through the worker.
func (driver *ClientDriver) ID() string {
	if driver == nil {
		return ""
	}
	return driver.driverID
}

// Create creates a runtime target through the worker client.
func (driver *ClientDriver) Create(ctx context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	client, driverID, err := driver.clientFor(OperationCreate)
	if err != nil {
		return nil, err
	}
	target, err := client.Create(ctx, driverID, CreateRequest{
		Name: strings.TrimSpace(req.Name),
		Env:  cloneStringMap(req.Env),
	})
	return driver.runtimeTargetFromWorkerResponse(OperationCreate, target, err)
}

// Start starts an existing runtime target through the worker client.
func (driver *ClientDriver) Start(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	client, driverID, err := driver.clientFor(OperationStart)
	if err != nil {
		return nil, err
	}
	target, err := client.Start(ctx, driverID, LifecycleRequest{
		Target: workerTargetFromRuntimeTarget(req.Target, driverID),
	})
	return driver.runtimeTargetFromWorkerResponse(OperationStart, target, err)
}

// Stop stops an existing runtime target through the worker client.
func (driver *ClientDriver) Stop(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	client, driverID, err := driver.clientFor(OperationStop)
	if err != nil {
		return nil, err
	}
	target, err := client.Stop(ctx, driverID, LifecycleRequest{
		Target: workerTargetFromRuntimeTarget(req.Target, driverID),
	})
	return driver.runtimeTargetFromWorkerResponse(OperationStop, target, err)
}

// Delete deletes an existing runtime target through the worker client.
func (driver *ClientDriver) Delete(ctx context.Context, req sandboxruntime.LifecycleRequest) error {
	client, driverID, err := driver.clientFor(OperationDelete)
	if err != nil {
		return err
	}
	if err := client.Delete(ctx, driverID, LifecycleRequest{
		Target: workerTargetFromRuntimeTarget(req.Target, driverID),
	}); err != nil {
		return driver.operationError(OperationDelete, err)
	}
	return nil
}

// Inspect inspects an existing runtime target through the worker client.
func (driver *ClientDriver) Inspect(ctx context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	client, driverID, err := driver.clientFor(OperationInspect)
	if err != nil {
		return nil, err
	}
	target, err := client.Inspect(ctx, driverID, InspectRequest{
		Target: workerTargetFromRuntimeTarget(req.Target, driverID),
	})
	return driver.runtimeTargetFromWorkerResponse(OperationInspect, target, err)
}

// Exec runs a bounded command execution through the worker client.
func (driver *ClientDriver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	client, driverID, err := driver.clientFor(OperationExec)
	if err != nil {
		return nil, err
	}

	stdin, err := clientDriverExecStdinPayload(req.Stdin)
	if err != nil {
		return nil, driver.operationError(OperationExec, err)
	}
	workerReq := ExecRequest{
		OperationID:      clientDriverExecOperationID,
		Target:           workerTargetFromRuntimeTarget(req.Target, driverID),
		Args:             cloneStringSlice(req.Args),
		Env:              cloneStringMap(req.Env),
		WorkDir:          strings.TrimSpace(req.WorkDir),
		Stdin:            stdin,
		StdoutLimitBytes: MaxExecStdoutCaptureBytes,
		StderrLimitBytes: MaxExecStderrCaptureBytes,
	}
	if err := workerReq.Validate(); err != nil {
		return nil, driver.operationError(OperationExec, err)
	}

	resp, err := client.Exec(ctx, driverID, workerReq)
	if err != nil {
		return nil, driver.operationError(OperationExec, err)
	}
	return driver.runtimeExecResultFromWorkerResponse(req, resp)
}

// CopyIn is not implemented by the worker foundation adapter yet.
func (driver *ClientDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return driver.operationError(OperationCopyIn, ErrWorkerOperationUnsupported)
}

// CopyOut is not implemented by the worker foundation adapter yet.
func (driver *ClientDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	return driver.operationError(OperationCopyOut, ErrWorkerOperationUnsupported)
}

func (driver *ClientDriver) clientFor(operation string) (RuntimeDriverClient, string, error) {
	driverID := ""
	if driver != nil {
		driverID = strings.TrimSpace(driver.driverID)
	}
	if driverID == "" {
		return nil, "", (&ClientDriver{driverID: driverID}).operationError(operation, ErrDriverIDRequired)
	}
	if driver == nil || driver.client == nil {
		return nil, "", driver.operationError(operation, ErrWorkerClientRequired)
	}
	return driver.client, driverID, nil
}

func (driver *ClientDriver) runtimeTargetFromWorkerResponse(operation string, target *Target, err error) (*sandboxruntime.Target, error) {
	if err != nil {
		return nil, driver.operationError(operation, err)
	}
	if target == nil {
		return nil, driver.operationError(operation, ErrWorkerTargetRequired)
	}
	runtimeTarget := runtimeTargetFromWorkerTarget(*target)
	if strings.TrimSpace(runtimeTarget.Runtime.Driver) == "" {
		runtimeTarget.Runtime.Driver = driver.ID()
	}
	return &runtimeTarget, nil
}

func (driver *ClientDriver) runtimeExecResultFromWorkerResponse(req sandboxruntime.ExecRequest, resp *ExecResponse) (*sandboxruntime.ExecResult, error) {
	if resp == nil {
		return nil, driver.operationError(OperationExec, ErrWorkerExecResponseRequired)
	}
	execResp := *resp
	if execResp.Error != nil {
		protocolError := *execResp.Error
		sanitizeEmbeddedProtocolError(&protocolError)
		execResp.Error = &protocolError
	}
	if err := execResp.Validate(); err != nil {
		return nil, driver.operationError(OperationExec, err)
	}

	result := &sandboxruntime.ExecResult{ExitCode: execResp.ExitCode}
	if err := writeClientDriverExecOutput(req.Stdout, "stdout", execResp.Stdout.Data); err != nil {
		return result, driver.operationError(OperationExec, err)
	}
	if err := writeClientDriverExecOutput(req.Stderr, "stderr", execResp.Stderr.Data); err != nil {
		return result, driver.operationError(OperationExec, err)
	}
	if execResp.Error != nil {
		return result, driver.operationError(OperationExec, &ProtocolError{
			Operation: OperationExec,
			Code:      strings.TrimSpace(execResp.Error.Code),
			Message:   sanitizeProtocolErrorDetail(execResp.Error.Message),
		})
	}
	if execResp.Stdout.Truncated || execResp.Stderr.Truncated {
		return result, driver.operationError(OperationExec, clientDriverExecTruncationError(execResp))
	}
	return result, nil
}

func clientDriverExecStdinPayload(stdin io.Reader) (*ExecStdinPayload, error) {
	if stdin == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(stdin, MaxExecStdinBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read exec stdin: %w", err)
	}
	if int64(len(data)) > MaxExecStdinBytes {
		return nil, workerIOValidationError("exec stdin sizeBytes exceeds maximum of %d bytes", MaxExecStdinBytes)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return &ExecStdinPayload{
		Data:       string(data),
		SizeBytes:  int64(len(data)),
		LimitBytes: MaxExecStdinBytes,
	}, nil
}

func writeClientDriverExecOutput(writer io.Writer, stream, data string) error {
	if writer == nil || data == "" {
		return nil
	}
	if _, err := io.WriteString(writer, data); err != nil {
		return fmt.Errorf("write exec %s: %w", stream, err)
	}
	return nil
}

func clientDriverExecTruncationError(resp ExecResponse) error {
	streams := make([]string, 0, 2)
	if resp.Stdout.Truncated {
		streams = append(streams, "stdout")
	}
	if resp.Stderr.Truncated {
		streams = append(streams, "stderr")
	}
	if len(streams) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrWorkerExecOutputTruncated, strings.Join(streams, ", "))
}

func (driver *ClientDriver) operationError(operation string, err error) error {
	if err == nil {
		return nil
	}
	driverID := ""
	if driver != nil {
		driverID = strings.TrimSpace(driver.driverID)
	}
	return &ClientDriverError{
		Driver:    driverID,
		Operation: strings.TrimSpace(operation),
		Err:       err,
	}
}

// ClientDriverError wraps worker-client failures with runtime driver context.
type ClientDriverError struct {
	Driver    string
	Operation string
	Err       error
}

func (err *ClientDriverError) Error() string {
	if err == nil {
		return ""
	}
	driverID := strings.TrimSpace(err.Driver)
	if driverID == "" {
		driverID = "worker"
	}
	operation := strings.TrimSpace(err.Operation)
	if operation == "" {
		operation = "request"
	}
	if err.Err == nil {
		return fmt.Sprintf("%s %s failed", driverID, operation)
	}
	return fmt.Sprintf("%s %s failed: %s", driverID, operation, sanitizeProtocolErrorDetail(err.Err.Error()))
}

func (err *ClientDriverError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}
