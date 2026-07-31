package firecracker

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

const (
	// ProcessBoundaryOperation is the sanitized operation label used for
	// Firecracker process-boundary errors.
	ProcessBoundaryOperation = "firecracker_process_boundary"
)

var (
	processBoundaryPIDDetailPattern     = regexp.MustCompile(`(?i)\b(?:pid|process[_ -]?id)\s*[:=]\s*\d+\b`)
	processBoundarySecretEnvPattern     = regexp.MustCompile(`(?i)\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API[_-]?KEY|APIKEY|CREDENTIAL|AUTHORIZATION|BEARER)[A-Z0-9_]*=\[redacted\]`)
	processBoundarySecretEnvNamePattern = regexp.MustCompile(`\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|CREDENTIAL|AUTHORIZATION|BEARER)[A-Z0-9_]*\b`)
)

// ProcessAdapter is the injectable boundary for Firecracker process and
// command operations. Default tests should use fakes; live process start
// behavior belongs only behind implementations of this interface.
type ProcessAdapter interface {
	PrepareStartCommand(context.Context, ProcessStartCommandRequest) (ProcessCommandDescriptor, error)
	StartProcess(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error)
}

// ProcessStartCommandRequest asks an adapter to construct a process descriptor
// from a validated Firecracker start operation plan.
type ProcessStartCommandRequest struct {
	Plan StartOperationPlan `json:"plan"`
}

// ProcessStartRequest asks an adapter to start a process from a prepared
// descriptor. The descriptor carries raw argv only across this injected
// boundary.
type ProcessStartRequest struct {
	Descriptor     ProcessCommandDescriptor `json:"descriptor"`
	InheritedFiles []*os.File               `json:"-"`
}

// ProcessCommandDescriptor is the process-boundary command shape. Argv keeps
// host paths available to the adapter but is intentionally omitted from JSON.
type ProcessCommandDescriptor struct {
	Action      OperationAction                `json:"action"`
	Executable  OperationPathReference         `json:"executable"`
	Argv        []string                       `json:"-"`
	EnablePCI   bool                           `json:"enablePCI,omitempty"`
	Environment []OperationEnvironmentMetadata `json:"environment"`
	Paths       []OperationPathReference       `json:"paths"`
	Payloads    []OperationPayloadReference    `json:"payloads"`
}

// ProcessHandleMetadata is redaction-safe process identity returned by a
// process adapter. Unsafe IDs or sources are cleared before callers see them.
type ProcessHandleMetadata struct {
	ID     string `json:"id,omitempty"`
	Source string `json:"source,omitempty"`
}

// PrepareStartCommand delegates Firecracker start command preparation to an
// injected adapter and validates the returned descriptor without starting a
// process.
func PrepareStartCommand(ctx context.Context, adapter ProcessAdapter, plan StartOperationPlan) (ProcessCommandDescriptor, error) {
	if adapter == nil {
		return ProcessCommandDescriptor{}, newProcessBoundaryError("processAdapter", "process adapter is required")
	}
	descriptor, err := adapter.PrepareStartCommand(processContext(ctx), ProcessStartCommandRequest{Plan: plan})
	if err != nil {
		return ProcessCommandDescriptor{}, newProcessBoundaryAdapterError("processAdapter", "process command preparation failed", err)
	}
	if err := validateProcessCommandDescriptor(descriptor); err != nil {
		return ProcessCommandDescriptor{}, err
	}
	if err := validateProcessCommandDescriptorMatchesPlan(descriptor, plan); err != nil {
		return ProcessCommandDescriptor{}, err
	}
	return descriptor, nil
}

// StartProcess delegates Firecracker process start to an injected adapter.
// This function validates the descriptor before crossing the adapter boundary.
func StartProcess(ctx context.Context, adapter ProcessAdapter, descriptor ProcessCommandDescriptor) (ProcessHandleMetadata, error) {
	return startProcessWithInheritedFiles(ctx, adapter, descriptor, nil)
}

// startProcessWithInheritedFiles delegates process start while keeping the
// supplied private files out of descriptors and durable metadata. Ownership
// remains with the caller; the adapter may only borrow them for process start.
func startProcessWithInheritedFiles(
	ctx context.Context,
	adapter ProcessAdapter,
	descriptor ProcessCommandDescriptor,
	files []*os.File,
) (ProcessHandleMetadata, error) {
	if adapter == nil {
		return ProcessHandleMetadata{}, newProcessBoundaryError("processAdapter", "process adapter is required")
	}
	if err := validateProcessCommandDescriptor(descriptor); err != nil {
		return ProcessHandleMetadata{}, err
	}
	if err := validateProcessInheritedFiles(files); err != nil {
		return ProcessHandleMetadata{}, err
	}
	handle, err := adapter.StartProcess(processContext(ctx), ProcessStartRequest{
		Descriptor:     descriptor,
		InheritedFiles: append([]*os.File(nil), files...),
	})
	if err != nil {
		return ProcessHandleMetadata{}, newProcessBoundaryAdapterError("processAdapter", "process start failed", err)
	}
	return sanitizeProcessHandleMetadata(handle), nil
}

func validateProcessInheritedFiles(files []*os.File) error {
	if len(files) != 0 && len(files) != 2 {
		return newProcessBoundaryError("inheritedFiles", "exactly two inherited process files are required")
	}
	for _, file := range files {
		if file == nil {
			return newProcessBoundaryError("inheritedFiles", "inherited process file is invalid")
		}
	}
	return nil
}

// closeProcessInheritedFiles releases a start-owned file set exactly once at
// its owning call site. A close error is cleanup uncertainty: callers must not
// retry an ambiguous close or accept a started process as successful.
func closeProcessInheritedFiles(files []*os.File) error {
	failed := false
	for _, file := range files {
		if file != nil && file.Close() != nil {
			failed = true
		}
	}
	if failed {
		return newProcessBoundaryError("inheritedFiles", "inherited process file cleanup failed")
	}
	return nil
}

// ProcessCommandDescriptorFromStartPlan converts a pure start operation plan
// into the command descriptor consumed by the injected process adapter.
func ProcessCommandDescriptorFromStartPlan(plan StartOperationPlan) (ProcessCommandDescriptor, error) {
	if plan.Action != OperationActionStart {
		return ProcessCommandDescriptor{}, newProcessBoundaryError("action", "start action is required")
	}
	if err := validateProcessPathReference(plan.Executable, OperationPathRoleExecutable, "executablePath"); err != nil {
		return ProcessCommandDescriptor{}, err
	}
	paths := []OperationPathReference{
		plan.APISocket,
		plan.Config,
		plan.Log,
		plan.Metrics,
	}
	if err := validateProcessPathReferences(paths); err != nil {
		return ProcessCommandDescriptor{}, err
	}
	if err := validateProcessStartArgv(plan.Argv, plan.Executable, paths, plan.EnablePCI); err != nil {
		return ProcessCommandDescriptor{}, err
	}
	if err := validateProcessPayloadReferences(plan.Payloads); err != nil {
		return ProcessCommandDescriptor{}, err
	}

	return ProcessCommandDescriptor{
		Action:      plan.Action,
		Executable:  plan.Executable,
		Argv:        cloneStringSlice(plan.Argv),
		EnablePCI:   plan.EnablePCI,
		Environment: cloneOperationEnvironment(plan.Environment),
		Paths:       cloneOperationPathReferences(paths),
		Payloads:    cloneOperationPayloadReferences(plan.Payloads),
	}, nil
}

// Summary returns a public process descriptor shape without raw argv or host
// paths.
func (descriptor ProcessCommandDescriptor) Summary() OperationPlanSummary {
	return OperationPlanSummary{
		Action:         descriptor.Action,
		ExecutableRole: descriptor.Executable.Role,
		Argv:           processCommandArgumentSummary(descriptor),
		Environment:    []OperationEnvironmentMetadata{},
		PathRoles:      operationPathRolesFromReferences(descriptor.Paths),
		Payloads:       cloneOperationPayloadReferences(descriptor.Payloads),
	}
}

func processContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func validateProcessCommandDescriptor(descriptor ProcessCommandDescriptor) error {
	if descriptor.Action != OperationActionStart {
		return newProcessBoundaryError("action", "start action is required")
	}
	if err := validateProcessPathReference(descriptor.Executable, OperationPathRoleExecutable, "executablePath"); err != nil {
		return err
	}
	if err := validateProcessPathReferences(descriptor.Paths); err != nil {
		return err
	}
	if err := validateProcessStartArgv(descriptor.Argv, descriptor.Executable, descriptor.Paths, descriptor.EnablePCI); err != nil {
		return err
	}
	if len(descriptor.Environment) != 0 {
		return newProcessBoundaryError("environment", "process environment metadata is not supported")
	}
	return validateProcessPayloadReferences(descriptor.Payloads)
}

func validateProcessCommandDescriptorMatchesPlan(descriptor ProcessCommandDescriptor, plan StartOperationPlan) error {
	expected, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		return err
	}
	if descriptor.Action != expected.Action ||
		descriptor.Executable != expected.Executable ||
		!equalStringSlices(descriptor.Argv, expected.Argv) ||
		descriptor.EnablePCI != expected.EnablePCI ||
		!equalOperationEnvironment(descriptor.Environment, expected.Environment) ||
		!equalOperationPathReferences(descriptor.Paths, expected.Paths) ||
		!equalOperationPayloadReferences(descriptor.Payloads, expected.Payloads) {
		return newProcessBoundaryError("descriptor", "process descriptor does not match start plan")
	}
	return nil
}

func validateProcessPathReferences(paths []OperationPathReference) error {
	required := []struct {
		role  OperationPathRole
		field string
	}{
		{role: OperationPathRoleAPISocket, field: "apiSocketPath"},
		{role: OperationPathRoleConfig, field: "configPath"},
		{role: OperationPathRoleLog, field: "logPath"},
		{role: OperationPathRoleMetrics, field: "metricsPath"},
	}
	if len(paths) != len(required) {
		return newProcessBoundaryError("paths", "required process path roles are missing")
	}
	for i, req := range required {
		if err := validateProcessPathReference(paths[i], req.role, req.field); err != nil {
			return err
		}
	}
	return nil
}

func validateProcessPathReference(ref OperationPathReference, role OperationPathRole, field string) error {
	if ref.Role != role {
		return newProcessBoundaryError(field, "path role is invalid")
	}
	if strings.TrimSpace(ref.Path) == "" {
		return newProcessBoundaryError(field, "path role is required")
	}
	if hasUnsafePathControl(ref.Path) {
		return newProcessBoundaryError(field, "path role is invalid")
	}
	return nil
}

func validateProcessStartArgv(argv []string, executable OperationPathReference, paths []OperationPathReference, enablePCI bool) error {
	want, err := processStartArgvWithPCI(executable, paths, enablePCI)
	if err != nil {
		return err
	}
	if !equalStringSlices(argv, want) {
		return newProcessBoundaryError("argv", "start argv does not match process path roles")
	}
	for _, arg := range argv {
		if hasUnsafePathControl(arg) {
			return newProcessBoundaryError("argv", "start argv is invalid")
		}
	}
	return nil
}

func processStartArgv(executable OperationPathReference, paths []OperationPathReference) ([]string, error) {
	return processStartArgvWithPCI(executable, paths, false)
}

func processStartArgvWithPCI(executable OperationPathReference, paths []OperationPathReference, enablePCI bool) ([]string, error) {
	byRole := operationPathReferenceByRole(paths)
	apiSocket, ok := byRole[OperationPathRoleAPISocket]
	if !ok {
		return nil, newProcessBoundaryError("apiSocketPath", "path role is required")
	}
	config, ok := byRole[OperationPathRoleConfig]
	if !ok {
		return nil, newProcessBoundaryError("configPath", "path role is required")
	}
	logPath, ok := byRole[OperationPathRoleLog]
	if !ok {
		return nil, newProcessBoundaryError("logPath", "path role is required")
	}
	metrics, ok := byRole[OperationPathRoleMetrics]
	if !ok {
		return nil, newProcessBoundaryError("metricsPath", "path role is required")
	}
	argv := []string{
		executable.Path,
	}
	if enablePCI {
		argv = append(argv, "--enable-pci")
	}
	argv = append(argv,
		"--api-sock", apiSocket.Path,
		"--config-file", config.Path,
		"--log-path", logPath.Path,
		"--metrics-path", metrics.Path,
	)
	return argv, nil
}

func validateProcessPayloadReferences(payloads []OperationPayloadReference) error {
	want := operationPayloadReferences()
	if len(payloads) != len(want) {
		return newProcessBoundaryError("payloads", "required payload references are missing")
	}
	for i := range want {
		if payloads[i].Role != want[i].Role || payloads[i].APIPath != want[i].APIPath {
			return newProcessBoundaryError("payloads", "payload reference is invalid")
		}
		if err := validateProcessPayloadAssetMetadata(payloads[i].Assets); err != nil {
			return err
		}
	}
	return nil
}

func validateProcessPayloadAssetMetadata(assets []OperationPayloadAssetMetadata) error {
	for _, asset := range assets {
		if strings.TrimSpace(asset.AssetRole) != "" && safeFirecrackerMetadataToken(asset.AssetRole) == "" {
			return newProcessBoundaryError("payloads", "payload asset metadata is invalid")
		}
		if strings.TrimSpace(asset.ID) != "" && safeFirecrackerMetadataToken(asset.ID) == "" {
			return newProcessBoundaryError("payloads", "payload asset metadata is invalid")
		}
		for _, label := range asset.Labels {
			if safeFirecrackerMetadataToken(label) == "" {
				return newProcessBoundaryError("payloads", "payload asset metadata is invalid")
			}
		}
		if asset.Digest != nil && !validProcessPayloadDigestMetadata(*asset.Digest) {
			return newProcessBoundaryError("payloads", "payload asset digest metadata is invalid")
		}
	}
	return nil
}

func validProcessPayloadDigestMetadata(digest OperationPayloadDigestMetadata) bool {
	algorithm := strings.TrimSpace(digest.Algorithm)
	value := strings.TrimSpace(digest.Value)
	if algorithm == "" && value == "" {
		return true
	}
	if safeFirecrackerMetadataToken(algorithm) == "" || value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'f':
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func processCommandArgumentSummary(descriptor ProcessCommandDescriptor) []OperationArgumentSummary {
	if descriptor.Action != OperationActionStart {
		return []OperationArgumentSummary{}
	}
	byRole := operationPathReferenceByRole(descriptor.Paths)
	argv := []OperationArgumentSummary{
		{PathRole: descriptor.Executable.Role},
	}
	if descriptor.EnablePCI {
		argv = append(argv, OperationArgumentSummary{Value: "--enable-pci"})
	}
	return append(argv,
		OperationArgumentSummary{Value: "--api-sock"},
		OperationArgumentSummary{PathRole: byRole[OperationPathRoleAPISocket].Role},
		OperationArgumentSummary{Value: "--config-file"},
		OperationArgumentSummary{PathRole: byRole[OperationPathRoleConfig].Role},
		OperationArgumentSummary{Value: "--log-path"},
		OperationArgumentSummary{PathRole: byRole[OperationPathRoleLog].Role},
		OperationArgumentSummary{Value: "--metrics-path"},
		OperationArgumentSummary{PathRole: byRole[OperationPathRoleMetrics].Role},
	)
}

func operationPathReferenceByRole(paths []OperationPathReference) map[OperationPathRole]OperationPathReference {
	out := make(map[OperationPathRole]OperationPathReference, len(paths))
	for _, path := range paths {
		out[path.Role] = path
	}
	return out
}

func operationPathRolesFromReferences(paths []OperationPathReference) []OperationPathRole {
	if len(paths) == 0 {
		return []OperationPathRole{}
	}
	out := make([]OperationPathRole, 0, len(paths))
	for _, path := range paths {
		out = append(out, path.Role)
	}
	return out
}

func sanitizeProcessHandleMetadata(handle ProcessHandleMetadata) ProcessHandleMetadata {
	handle.ID = sanitizeProcessMetadataToken(handle.ID)
	handle.Source = sanitizeProcessMetadataToken(handle.Source)
	return handle
}

func sanitizeProcessMetadataToken(value string) string {
	value = strings.TrimSpace(value)
	if safeFirecrackerMetadataToken(value) == "" {
		return ""
	}
	if isRawProcessIdentityToken(value) {
		return ""
	}
	return value
}

func isRawProcessIdentityToken(value string) bool {
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "pid-"):
		return true
	case strings.HasPrefix(lower, "pid_"):
		return true
	case strings.HasPrefix(lower, "pid."):
		return true
	case strings.HasPrefix(lower, "process-"):
		return true
	case strings.HasPrefix(lower, "process_"):
		return true
	case strings.HasPrefix(lower, "process."):
		return true
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func cloneOperationPathReferences(in []OperationPathReference) []OperationPathReference {
	if len(in) == 0 {
		return []OperationPathReference{}
	}
	out := make([]OperationPathReference, len(in))
	copy(out, in)
	return out
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalOperationEnvironment(a, b []OperationEnvironmentMetadata) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalOperationPathReferences(a, b []OperationPathReference) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalOperationPayloadReferences(a, b []OperationPayloadReference) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Role != b[i].Role || a[i].APIPath != b[i].APIPath ||
			!equalOperationPayloadAssetMetadata(a[i].Assets, b[i].Assets) {
			return false
		}
	}
	return true
}

func equalOperationPayloadAssetMetadata(a, b []OperationPayloadAssetMetadata) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].AssetRole != b[i].AssetRole ||
			a[i].ID != b[i].ID ||
			!equalStringSlices(a[i].Labels, b[i].Labels) ||
			!equalOperationPayloadDigestMetadata(a[i].Digest, b[i].Digest) {
			return false
		}
	}
	return true
}

func equalOperationPayloadDigestMetadata(a, b *OperationPayloadDigestMetadata) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func newProcessBoundaryError(field, message string) *microvm.OperationError {
	err := microvm.NewInvalidConfigError(ProcessBoundaryOperation, microvm.ErrInvalidConfig)
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}

func newProcessBoundaryAdapterError(field, message string, err error) *microvm.OperationError {
	if err == nil {
		err = errors.New(message)
	}
	operationErr := microvm.NewBackendOperationFailedError(ProcessBoundaryOperation, newSanitizedProcessBoundaryAdapterCause(err))
	operationErr.Field = strings.TrimSpace(field)
	operationErr.Message = strings.TrimSpace(message)
	return operationErr
}

type sanitizedProcessBoundaryAdapterCause struct {
	detail string
	cause  error
}

func newSanitizedProcessBoundaryAdapterCause(err error) sanitizedProcessBoundaryAdapterCause {
	if cause := sanitizedProcessBoundaryNestedCause(err); cause != "" {
		return sanitizedProcessBoundaryAdapterCause{
			detail: cause,
			cause:  err,
		}
	}
	return sanitizedProcessBoundaryAdapterCause{
		detail: sanitizeFirecrackerFailureDetail(ProcessBoundaryOperation, err),
		cause:  err,
	}
}

func sanitizedProcessBoundaryNestedCause(err error) string {
	var operationErr *microvm.OperationError
	if !errors.As(err, &operationErr) {
		return ""
	}
	if operationErr.Code != microvm.ErrorCodeBackendOperationFailed || operationErr.Operation != ProcessBoundaryOperation {
		return ""
	}
	if cause := errors.Unwrap(operationErr); cause != nil {
		return sanitizeFirecrackerFailureDetail(ProcessBoundaryOperation, cause)
	}
	return ""
}

func sanitizeProcessBoundaryAdapterDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	detail = processBoundaryPIDDetailPattern.ReplaceAllString(detail, "pid=[redacted-pid]")
	detail = processBoundarySecretEnvPattern.ReplaceAllString(detail, "[redacted-env]=[redacted]")
	detail = processBoundarySecretEnvNamePattern.ReplaceAllString(detail, "[redacted-env]")
	return detail
}

func (err sanitizedProcessBoundaryAdapterCause) Error() string {
	if detail := strings.TrimSpace(err.detail); detail != "" {
		return detail
	}
	return "firecracker process adapter failed"
}

func (err sanitizedProcessBoundaryAdapterCause) Is(target error) bool {
	return target != nil && errors.Is(err.cause, target)
}
