package sandboxworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var (
	ErrWorkerClientRequired          = errors.New("worker client is required")
	ErrWorkerTargetRequired          = errors.New("worker client returned no target")
	ErrWorkerOperationUnsupported    = errors.New("worker runtime driver operation unsupported")
	ErrWorkerExecResponseRequired    = errors.New("worker client returned no exec response")
	ErrWorkerExecOutputTruncated     = errors.New("worker exec output truncated")
	ErrWorkerCopyInResponseRequired  = errors.New("worker client returned no copy_in response")
	ErrWorkerCopyOutResponseRequired = errors.New("worker client returned no copy_out response")
	ErrWorkerCopyOutPayloadRequired  = errors.New("worker client returned no copy_out payload")
	ErrWorkerCopyOutPayloadTruncated = errors.New("worker copy_out payload truncated")
)

const (
	clientDriverExecOperationID    = "client-driver-exec"
	clientDriverCopyInOperationID  = "client-driver-copy-in"
	clientDriverCopyOutOperationID = "client-driver-copy-out"
)

const (
	FailureWorkerClient       = "worker_client_failed"
	FailureWorkerLifecycle    = "worker_lifecycle_failed"
	FailureRuntimeUnavailable = "runtime_unavailable"
)

var _ sandboxruntime.Driver = (*ClientDriver)(nil)

// RuntimeDriverClient is the worker-client subset needed by ClientDriver.
type RuntimeDriverClient interface {
	Create(context.Context, string, CreateRequest) (*Target, error)
	Start(context.Context, string, LifecycleRequest) (*Target, error)
	Stop(context.Context, string, LifecycleRequest) (*Target, error)
	Delete(context.Context, string, LifecycleRequest) error
	Inspect(context.Context, string, InspectRequest) (*Target, error)
	Exec(context.Context, string, ExecRequest) (*ExecResponse, error)
	CopyIn(context.Context, string, CopyInRequest) (*CopyInResponse, error)
	CopyOut(context.Context, string, CopyOutRequest) (*CopyOutResponse, error)
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

// CopyIn copies a bounded local file payload into a worker target.
func (driver *ClientDriver) CopyIn(ctx context.Context, req sandboxruntime.CopyRequest) error {
	client, driverID, err := driver.clientFor(OperationCopyIn)
	if err != nil {
		return err
	}
	payload, err := clientDriverCopyInPayload(req.SourcePath)
	if err != nil {
		return driver.operationError(OperationCopyIn, err)
	}
	workerReq := CopyInRequest{
		OperationID: clientDriverCopyInOperationID,
		Target:      workerTargetFromRuntimeTarget(req.Target, driverID),
		Source: CopyPathMetadata{
			DisplayPath: clientDriverDisplayPath(req.SourcePath),
		},
		RemoteDestinationPath: strings.TrimSpace(req.DestinationPath),
		Payload:               payload,
	}
	if err := workerReq.Validate(); err != nil {
		return driver.operationError(OperationCopyIn, err)
	}
	resp, err := client.CopyIn(ctx, driverID, workerReq)
	if err != nil {
		return driver.operationError(OperationCopyIn, err)
	}
	return driver.runtimeCopyInResultFromWorkerResponse(resp)
}

// CopyOut copies a bounded worker file payload to a local destination.
func (driver *ClientDriver) CopyOut(ctx context.Context, req sandboxruntime.CopyRequest) error {
	client, driverID, err := driver.clientFor(OperationCopyOut)
	if err != nil {
		return err
	}
	workerReq := CopyOutRequest{
		OperationID:      clientDriverCopyOutOperationID,
		Target:           workerTargetFromRuntimeTarget(req.Target, driverID),
		RemoteSourcePath: strings.TrimSpace(req.SourcePath),
		Destination: CopyPathMetadata{
			DisplayPath: clientDriverDisplayPath(req.DestinationPath),
		},
		MaxPayloadBytes: MaxCopyOutPayloadBytes,
	}
	if err := workerReq.Validate(); err != nil {
		return driver.operationError(OperationCopyOut, err)
	}
	resp, err := client.CopyOut(ctx, driverID, workerReq)
	if err != nil {
		return driver.operationError(OperationCopyOut, err)
	}
	return driver.runtimeCopyOutResultFromWorkerResponse(req, resp)
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

func (driver *ClientDriver) runtimeCopyInResultFromWorkerResponse(resp *CopyInResponse) error {
	if resp == nil {
		return driver.operationError(OperationCopyIn, ErrWorkerCopyInResponseRequired)
	}
	copyResp := *resp
	if copyResp.Error != nil {
		protocolError := *copyResp.Error
		sanitizeEmbeddedProtocolError(&protocolError)
		copyResp.Error = &protocolError
	}
	if err := copyResp.Validate(); err != nil {
		return driver.operationError(OperationCopyIn, err)
	}
	if copyResp.Error != nil {
		return driver.operationError(OperationCopyIn, &ProtocolError{
			Operation: OperationCopyIn,
			Code:      strings.TrimSpace(copyResp.Error.Code),
			Message:   sanitizeProtocolErrorDetail(copyResp.Error.Message),
		})
	}
	return nil
}

func (driver *ClientDriver) runtimeCopyOutResultFromWorkerResponse(req sandboxruntime.CopyRequest, resp *CopyOutResponse) error {
	if resp == nil {
		return driver.operationError(OperationCopyOut, ErrWorkerCopyOutResponseRequired)
	}
	copyResp := *resp
	if copyResp.Error != nil {
		protocolError := *copyResp.Error
		sanitizeEmbeddedProtocolError(&protocolError)
		copyResp.Error = &protocolError
	}
	if err := copyResp.Validate(); err != nil {
		return driver.operationError(OperationCopyOut, err)
	}
	if copyResp.Truncated || copyResp.LimitExceeded {
		return driver.operationError(OperationCopyOut, ErrWorkerCopyOutPayloadTruncated)
	}
	if copyResp.Error != nil {
		return driver.operationError(OperationCopyOut, &ProtocolError{
			Operation: OperationCopyOut,
			Code:      strings.TrimSpace(copyResp.Error.Code),
			Message:   sanitizeProtocolErrorDetail(copyResp.Error.Message),
		})
	}
	if copyResp.Payload == nil {
		return driver.operationError(OperationCopyOut, ErrWorkerCopyOutPayloadRequired)
	}
	data, err := decodeWorkerCopyPayload(*copyResp.Payload)
	if err != nil {
		return driver.operationError(OperationCopyOut, err)
	}
	if err := writeClientDriverCopyOutDestination(req.DestinationPath, data); err != nil {
		return driver.operationError(OperationCopyOut, err)
	}
	return nil
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

func clientDriverCopyInPayload(sourcePath string) (CopyFilePayload, error) {
	file, err := os.Open(strings.TrimSpace(sourcePath))
	if err != nil {
		return CopyFilePayload{}, fmt.Errorf("read copy_in source: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, MaxCopyInPayloadBytes+1))
	if err != nil {
		return CopyFilePayload{}, fmt.Errorf("read copy_in source: %w", err)
	}
	if int64(len(data)) > MaxCopyInPayloadBytes {
		return CopyFilePayload{}, workerIOValidationError("copy_in payload sizeBytes exceeds maximum of %d bytes", MaxCopyInPayloadBytes)
	}
	return copyPayloadFromBytes(data, MaxCopyInPayloadBytes), nil
}

func writeClientDriverCopyOutDestination(destinationPath string, data []byte) error {
	destinationPath = strings.TrimSpace(destinationPath)
	if destinationPath == "" {
		return workerIOValidationError("copy_out destination path is required")
	}
	destinationDir := filepath.Dir(destinationPath)
	if err := os.MkdirAll(destinationDir, 0o700); err != nil {
		return fmt.Errorf("prepare copy_out destination: %w", err)
	}

	tmp, err := os.CreateTemp(destinationDir, "."+filepath.Base(destinationPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("prepare copy_out destination: %w", err)
	}
	tmpPath := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write copy_out destination: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write copy_out destination: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("write copy_out destination: %w", err)
	}
	if err := os.Rename(tmpPath, destinationPath); err != nil {
		return fmt.Errorf("write copy_out destination: %w", err)
	}
	removeTmp = false
	return nil
}

func clientDriverDisplayPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	displayPath := filepath.Base(path)
	if displayPath == "." || displayPath == string(filepath.Separator) {
		return ""
	}
	return displayPath
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
		return classifiedWorkerError(err.Classification(), fmt.Sprintf("%s %s failed", driverID, operation))
	}
	message := fmt.Sprintf("%s %s failed: %s", driverID, operation, clientDriverErrorDetail(err.Err))
	return classifiedWorkerError(err.Classification(), message)
}

func (err *ClientDriverError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func (err *ClientDriverError) Classification() string {
	if err == nil {
		return ""
	}
	operation := strings.TrimSpace(err.Operation)
	var protocolErr *ProtocolError
	if errors.As(err.Err, &protocolErr) {
		protocolClassification := protocolErr.Classification()
		if protocolClassification != "" {
			return protocolClassification
		}
		if protocolErr.Code == ErrorCodeDriverFailed && workerLifecycleOperation(defaultString(protocolErr.Operation, operation)) {
			return FailureWorkerLifecycle
		}
		return ""
	}
	var clientErr *ClientError
	if errors.As(err.Err, &clientErr) || workerLifecycleOperation(operation) {
		return FailureWorkerClient
	}
	return ""
}

func clientDriverErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	var clientErr *ClientError
	if errors.As(err, &clientErr) {
		return clientErr.message()
	}
	var protocolErr *ProtocolError
	if errors.As(err, &protocolErr) {
		return protocolErr.message()
	}
	return sanitizeProtocolErrorDetail(err.Error())
}

func workerLifecycleOperation(operation string) bool {
	switch strings.TrimSpace(operation) {
	case OperationCreate, OperationStart, OperationInspect, OperationStop, OperationDelete:
		return true
	default:
		return false
	}
}

func classifiedWorkerError(classification, message string) string {
	classification = strings.TrimSpace(classification)
	message = strings.TrimSpace(message)
	if classification == "" {
		return message
	}
	if message == "" {
		return classification
	}
	if strings.HasPrefix(message, classification+":") {
		return message
	}
	return classification + ": " + message
}
