package sshmachine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var ErrProviderRequired = errors.New("sandbox provider is required")

// Driver adapts the existing SSH-machine sandbox.Provider lifecycle behavior
// to the sandboxruntime boundary.
type Driver struct {
	provider sandbox.Provider
}

// OperationError wraps a failed provider lifecycle operation with runtime
// driver metadata while preserving the provider error for errors.Is/As.
type OperationError struct {
	Driver    string
	Operation string
	Err       error
}

func (e *OperationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("%s %s failed", e.Driver, e.Operation)
	}
	return fmt.Sprintf("%s %s failed: %v", e.Driver, e.Operation, e.Err)
}

func (e *OperationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// New creates an SSH-machine lifecycle adapter around an existing provider.
func New(provider sandbox.Provider) *Driver {
	return &Driver{provider: provider}
}

func (d *Driver) ID() string {
	return sandboxruntime.DriverSSHMachine
}

func (d *Driver) Create(ctx context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	provider, err := d.providerFor("create")
	if err != nil {
		return nil, err
	}

	result, err := provider.Create(ctx, req.Name, req.Env, lifecycleWriter(req.Stdout, req.Stderr))
	if err != nil {
		return nil, operationError("create", err)
	}

	target := targetFromCreateResult(req, result)
	return &target, nil
}

func (d *Driver) Start(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	provider, err := d.providerFor("start")
	if err != nil {
		return nil, err
	}

	info := connectInfoFromTarget(req.Target)
	result, err := provider.Start(ctx, info, lifecycleWriter(req.Stdout, req.Stderr))
	if err != nil {
		return nil, operationError("start", err)
	}

	target := req.Target
	applyResolvedConnectInfo(&target, info)
	target.Status = sandbox.StatusRunning
	if result != nil {
		if status := strings.TrimSpace(result.Status); status != "" {
			target.Status = status
		}
		if ip := strings.TrimSpace(result.IP); ip != "" {
			target.Connection.PublicIP = ip
			normalizeTargetConnection(&target)
		}
	}
	ensureRuntimeMetadata(&target)
	return &target, nil
}

func (d *Driver) Stop(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	provider, err := d.providerFor("stop")
	if err != nil {
		return nil, err
	}

	info := connectInfoFromTarget(req.Target)
	if err := provider.Stop(ctx, info, lifecycleWriter(req.Stdout, req.Stderr)); err != nil {
		return nil, operationError("stop", err)
	}

	target := req.Target
	applyResolvedConnectInfo(&target, info)
	target.Status = sandbox.StatusStopped
	ensureRuntimeMetadata(&target)
	return &target, nil
}

func (d *Driver) Delete(ctx context.Context, req sandboxruntime.LifecycleRequest) error {
	provider, err := d.providerFor("delete")
	if err != nil {
		return err
	}

	info := connectInfoFromTarget(req.Target)
	if err := provider.Delete(ctx, info, lifecycleWriter(req.Stdout, req.Stderr)); err != nil {
		return operationError("delete", err)
	}
	return nil
}

func (d *Driver) Inspect(ctx context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	provider, err := d.providerFor("inspect")
	if err != nil {
		return nil, err
	}

	target := req.Target
	info := connectInfoFromTarget(target)
	var output bytes.Buffer
	if err := provider.Status(ctx, info, &output); err != nil {
		return nil, operationError("inspect", err)
	}

	applyResolvedConnectInfo(&target, info)
	applyStatusOutput(&target, output.String())
	ensureRuntimeMetadata(&target)
	return &target, nil
}

func (d *Driver) providerFor(operation string) (sandbox.Provider, error) {
	if d == nil || d.provider == nil {
		return nil, operationError(operation, ErrProviderRequired)
	}
	return d.provider, nil
}

func operationError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &OperationError{
		Driver:    sandboxruntime.DriverSSHMachine,
		Operation: operation,
		Err:       err,
	}
}

func lifecycleWriter(stdout, stderr io.Writer) io.Writer {
	if stdout != nil {
		return stdout
	}
	if stderr != nil {
		return stderr
	}
	return io.Discard
}

func targetFromCreateResult(req sandboxruntime.CreateRequest, result *sandbox.SandboxResult) sandboxruntime.Target {
	target := sandboxruntime.Target{
		Name:   strings.TrimSpace(req.Name),
		Status: sandbox.StatusRunning,
		Runtime: sandboxruntime.RuntimeState{
			Driver: sandboxruntime.DriverSSHMachine,
		},
	}
	if result == nil {
		return target
	}

	if id := strings.TrimSpace(result.ID); id != "" {
		target.ID = id
		target.Runtime.RuntimeID = id
	}
	if name := strings.TrimSpace(result.Name); name != "" {
		target.Name = name
	}
	target.Connection.PublicIP = strings.TrimSpace(result.IP)
	target.Connection.TailscaleIP = strings.TrimSpace(result.TailscaleIP)
	normalizeTargetConnection(&target)
	return target
}

func connectInfoFromTarget(target sandboxruntime.Target) *sandbox.ConnectInfo {
	state := &sandbox.SandboxState{
		ID:                strings.TrimSpace(target.ID),
		Name:              strings.TrimSpace(target.Name),
		Provider:          strings.TrimSpace(target.Provider),
		IP:                strings.TrimSpace(target.Connection.PublicIP),
		TailscaleIP:       strings.TrimSpace(target.Connection.TailscaleIP),
		TailscaleHostname: strings.TrimSpace(target.Connection.TailscaleHostname),
		TailscaleLockdown: target.Connection.TailscaleLockdown,
		WorkspaceID:       strings.TrimSpace(target.Connection.WorkspaceID),
	}
	if state.IP == "" && state.TailscaleIP == "" {
		state.IP = strings.TrimSpace(target.Connection.Address)
	}

	info := sandbox.ConnectInfoFromState(state)
	if info == nil {
		info = &sandbox.ConnectInfo{}
	}
	if address := strings.TrimSpace(target.Connection.Address); address != "" {
		info.IP = address
	}
	return info
}

func applyResolvedConnectInfo(target *sandboxruntime.Target, info *sandbox.ConnectInfo) {
	if target == nil || info == nil {
		return
	}
	if name := strings.TrimSpace(info.Name); target.Name == "" && name != "" {
		target.Name = name
	}
	target.Connection.Address = strings.TrimSpace(info.IP)
	target.Connection.PublicIP = strings.TrimSpace(info.PublicIP)
	target.Connection.TailscaleIP = strings.TrimSpace(info.TailscaleIP)
	target.Connection.TailscaleHostname = strings.TrimSpace(info.TailscaleHostname)
	target.Connection.TailscaleLockdown = info.TailscaleLockdown
	target.Connection.WorkspaceID = strings.TrimSpace(info.WorkspaceID)
}

func normalizeTargetConnection(target *sandboxruntime.Target) {
	if target == nil {
		return
	}
	state := &sandbox.SandboxState{
		ID:                strings.TrimSpace(target.ID),
		Name:              strings.TrimSpace(target.Name),
		Provider:          strings.TrimSpace(target.Provider),
		IP:                strings.TrimSpace(target.Connection.PublicIP),
		TailscaleIP:       strings.TrimSpace(target.Connection.TailscaleIP),
		TailscaleHostname: strings.TrimSpace(target.Connection.TailscaleHostname),
		TailscaleLockdown: target.Connection.TailscaleLockdown,
		WorkspaceID:       strings.TrimSpace(target.Connection.WorkspaceID),
	}
	info := sandbox.ConnectInfoFromState(state)
	applyResolvedConnectInfo(target, info)
}

func ensureRuntimeMetadata(target *sandboxruntime.Target) {
	if target == nil {
		return
	}
	if strings.TrimSpace(target.Runtime.Driver) == "" {
		target.Runtime.Driver = sandboxruntime.DriverSSHMachine
	}
	if strings.TrimSpace(target.Runtime.RuntimeID) == "" {
		target.Runtime.RuntimeID = strings.TrimSpace(target.ID)
	}
}

func applyStatusOutput(target *sandboxruntime.Target, output string) {
	if target == nil {
		return
	}
	if status := parseStatus(output); status != "" {
		target.Status = status
	}
	if publicIP := parsePublicIP(output); publicIP != "" {
		target.Connection.PublicIP = publicIP
		normalizeTargetConnection(target)
	}
}

func parseStatus(output string) string {
	for _, line := range strings.Split(output, "\n") {
		label, value, ok := splitLabeledLine(line)
		if !ok {
			continue
		}
		switch normalizeLabel(label) {
		case "status", "state":
			return classifyStatus(value)
		}
	}
	return classifyStatus(output)
}

func classifyStatus(value string) string {
	tokens := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	if len(tokens) == 0 {
		return ""
	}

	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i] == "not" && isRunningToken(tokens[i+1]) {
			return sandbox.StatusStopped
		}
	}

	hasRunning := false
	hasStopped := false
	for _, token := range tokens {
		if isRunningToken(token) {
			hasRunning = true
		}
		if isStoppedToken(token) {
			hasStopped = true
		}
	}
	switch {
	case hasRunning && !hasStopped:
		return sandbox.StatusRunning
	case hasStopped && !hasRunning:
		return sandbox.StatusStopped
	default:
		return ""
	}
}

func isRunningToken(token string) bool {
	switch token {
	case "running", "active", "started", "online", "ready":
		return true
	default:
		return false
	}
}

func isStoppedToken(token string) bool {
	switch token {
	case "stopped", "off", "inactive", "halted", "shutdown", "shutoff":
		return true
	default:
		return false
	}
}

func parsePublicIP(output string) string {
	for _, line := range strings.Split(output, "\n") {
		label, value, ok := splitLabeledLine(line)
		if !ok || !isPublicIPLabel(normalizeLabel(label)) {
			continue
		}
		if ip := firstIP(value); ip != "" {
			return ip
		}
	}
	return ""
}

func isPublicIPLabel(label string) bool {
	switch label {
	case "ip", "public ip", "public ipv4", "public ipv6", "ipv4", "ipv6":
		return true
	default:
		return false
	}
}

func splitLabeledLine(line string) (string, string, bool) {
	idx := strings.IndexRune(line, ':')
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

func normalizeLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", " ")
	return strings.Join(strings.Fields(value), " ")
}

func firstIP(value string) string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ',', ';', '|', '[', ']', '(', ')', '{', '}', '<', '>', '"', '\'':
			return true
		default:
			return unicode.IsSpace(r)
		}
	})
	for _, field := range fields {
		if addr, err := netip.ParseAddr(strings.TrimSpace(field)); err == nil {
			return addr.String()
		}
	}
	return ""
}
