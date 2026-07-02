package cmd

import (
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtarget"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

type sandboxWorkerRuntimeRequest struct {
	Target sandboxruntime.Target
	Host   *sandbox.SandboxHost
}

type sandboxWorkerRuntimeDriverFactories struct {
	newWorkerClient         func(string) (sandboxworker.RuntimeDriverClient, error)
	newRuntimeDriver        func(sandboxworker.ClientDriverOptions) (sandboxruntime.Driver, error)
	newMicroVMRuntimeDriver func(sandboxworker.ClientDriverOptions) (sandboxruntime.Driver, error)
}

func sandboxWorkerRuntimeDriverFromTarget(req sandboxWorkerRuntimeRequest, factories sandboxWorkerRuntimeDriverFactories) (sandboxruntime.Driver, error) {
	factories = normalizeSandboxWorkerRuntimeDriverFactories(factories)

	host := req.Host
	if host == nil {
		return nil, fmt.Errorf("selected worker host metadata is required")
	}
	hostID := strings.TrimSpace(host.ID)
	if strings.TrimSpace(host.Kind) != sandbox.SandboxHostKindWorker {
		return nil, fmt.Errorf("selected sandbox host %q is not a worker host", sandboxHostDisplayValue(hostID, host.Name))
	}

	driverID := strings.TrimSpace(req.Target.Runtime.Driver)
	if driverID == "" {
		return nil, fmt.Errorf("selected runtime driver is required for worker-backed execution")
	}
	if !sandboxRuntimeHostSupportsRuntime(host, driverID) {
		return nil, sandboxWorkerRuntimeUnsupportedError(host, driverID, "does not support requested runtime")
	}
	runtimeDriverFactory := factories.newRuntimeDriver
	if driverID == sandboxruntime.DriverMicroVM {
		runtimeDriverFactory = factories.newMicroVMRuntimeDriver
	}
	if !sandboxWorkerRuntimeDriverUsesWorkerBoundary(driverID) || runtimeDriverFactory == nil {
		return nil, sandboxWorkerRuntimeUnsupportedError(host, driverID, "is not supported by worker-backed sandbox execution")
	}

	socketPath, err := validateSandboxWorkerHostEndpoint(host, driverID)
	if err != nil {
		return nil, err
	}
	client, err := factories.newWorkerClient(sandboxHostWorkerClientSocketPath(socketPath))
	if err != nil {
		return nil, sandboxHostWorkerClientError("connect", err)
	}
	if client == nil {
		return nil, sandboxHostWorkerClientError("connect", fmt.Errorf("worker client is not configured"))
	}

	driver, err := runtimeDriverFactory(sandboxworker.ClientDriverOptions{
		DriverID: driverID,
		Client:   client,
	})
	if err != nil {
		return nil, sandboxHostWorkerClientError("construct", fmt.Errorf("construct worker-backed runtime driver %q: %w", driverID, err))
	}
	if driver == nil {
		return nil, sandboxHostWorkerClientError("construct", fmt.Errorf("construct worker-backed runtime driver %q: runtime driver factory returned nil", driverID))
	}
	return driver, nil
}

func sandboxWorkerRuntimeRouteSelected(sandboxHostID, sandboxRuntime string, target sandboxruntime.Target, selectedTarget *sandbox.SandboxState) bool {
	if selectedTarget == nil || selectedTarget.Host == nil {
		return false
	}
	if !sandboxWorkerRoutingRequested(sandboxHostID, sandboxRuntime) {
		return false
	}
	if strings.TrimSpace(selectedTarget.Host.Kind) != sandbox.SandboxHostKindWorker {
		return false
	}
	return sandboxWorkerRuntimeDriverUsesWorkerBoundary(target.Runtime.Driver)
}

func sandboxWorkerRoutingRequested(sandboxHostID, sandboxRuntime string) bool {
	return strings.TrimSpace(sandboxHostID) != "" || strings.TrimSpace(sandboxRuntime) != ""
}

func sandboxWorkerRoutingMetadataFromState(target *sandbox.SandboxState) *sandbox.WorkerRoutingMetadata {
	if target == nil || target.Host == nil || target.Runtime == nil {
		return nil
	}
	host := target.Host
	runtime := target.Runtime
	if strings.TrimSpace(host.Kind) != sandbox.SandboxHostKindWorker {
		return nil
	}
	driver := strings.TrimSpace(runtime.Driver)
	if driver == "" {
		return nil
	}
	isolation := strings.TrimSpace(runtime.IsolationLevel)
	if isolation == "" && driver == sandbox.SandboxRuntimeDriverRootlessPodman {
		isolation = sandbox.SandboxIsolationLevelContainer
	}
	return &sandbox.WorkerRoutingMetadata{
		SelectedWorkerHostID:   strings.TrimSpace(host.ID),
		SelectedWorkerHostName: strings.TrimSpace(host.Name),
		RuntimeDriverID:        driver,
		IsolationLevel:         isolation,
		EndpointSummary:        sandboxHostEndpointSummary(host.Endpoint),
	}
}

func sandboxWorkerRuntimeDriverUsesWorkerBoundary(driverID string) bool {
	switch strings.TrimSpace(driverID) {
	case sandboxruntime.DriverRootlessPodman, sandboxruntime.DriverMicroVM:
		return true
	default:
		return false
	}
}

func validateSandboxWorkerHostEndpoint(host *sandbox.SandboxHost, driverID string) (string, error) {
	if host == nil {
		return "", sandboxWorkerEndpointInvalidError(nil, driverID)
	}
	socketPath, err := sandboxHostLocalWorkerSocketPath(host.Endpoint)
	if err != nil {
		return "", sandboxWorkerEndpointInvalidError(host, driverID)
	}
	return socketPath, nil
}

func normalizeSandboxWorkerRuntimeDriverFactories(factories sandboxWorkerRuntimeDriverFactories) sandboxWorkerRuntimeDriverFactories {
	if factories.newWorkerClient == nil {
		factories.newWorkerClient = newSandboxWorkerRuntimeClient
	}
	if factories.newRuntimeDriver == nil {
		factories.newRuntimeDriver = func(options sandboxworker.ClientDriverOptions) (sandboxruntime.Driver, error) {
			return sandboxworker.NewClientDriver(options)
		}
	}
	return factories
}

func newSandboxWorkerRuntimeClient(socketPath string) (sandboxworker.RuntimeDriverClient, error) {
	return sandboxworker.NewClient(sandboxworker.ClientOptions{SocketPath: strings.TrimSpace(socketPath)})
}

func sandboxWorkerRuntimeUnsupportedError(host *sandbox.SandboxHost, driverID, detail string) error {
	hostID := ""
	hostName := ""
	if host != nil {
		hostID = strings.TrimSpace(host.ID)
		hostName = host.Name
	}
	driverID = strings.TrimSpace(driverID)
	detail = strings.TrimSpace(detail)
	if detail == "" {
		detail = "is not supported"
	}
	displayHost := sandboxHostDisplayValue(hostID, hostName)
	message := fmt.Sprintf("runtime_unsupported: worker host %q requested runtime %q %s", displayHost, driverID, detail)
	if detail == "does not support requested runtime" {
		message = fmt.Sprintf("runtime_unsupported: worker host %q does not support requested runtime %q", displayHost, driverID)
	}
	return &sandboxtarget.Failure{
		Reason:        sandboxtarget.FailureReasonRuntimeUnsupported,
		Message:       message,
		HostID:        hostID,
		RuntimeDriver: driverID,
	}
}

func sandboxWorkerEndpointInvalidError(host *sandbox.SandboxHost, driverID string) error {
	hostID := ""
	hostName := ""
	endpointSummary := sandboxHostEndpointSummary("")
	if host != nil {
		hostID = strings.TrimSpace(host.ID)
		hostName = host.Name
		endpointSummary = sandboxHostEndpointSummary(host.Endpoint)
	}
	driverID = strings.TrimSpace(driverID)
	displayHost := sandboxHostDisplayValue(hostID, hostName)
	if displayHost == "" {
		displayHost = "unknown"
	}
	message := fmt.Sprintf("worker_endpoint_invalid: worker host %q requested runtime %q requires an absolute local Unix socket endpoint; configured endpoint: %s", displayHost, driverID, endpointSummary)
	return &sandboxtarget.Failure{
		Reason:        sandboxtarget.FailureReasonInvalidRequest,
		Message:       message,
		HostID:        hostID,
		RuntimeDriver: driverID,
	}
}
