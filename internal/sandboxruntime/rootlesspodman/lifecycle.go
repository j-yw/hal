package rootlesspodman

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	labelRuntime     = "dev.jywlabs.hal.runtime"
	labelSandboxName = "dev.jywlabs.hal.sandbox.name"
	maxErrorDetail   = 512
)

var (
	ErrLifecycleRunnerRequired = errors.New("rootless Podman lifecycle runner is required")
	ErrTargetNameRequired      = errors.New("rootless Podman target name is required")
	ErrTargetRefRequired       = errors.New("rootless Podman target runtime ID or name is required")
	ErrInspectOutputRequired   = errors.New("rootless Podman inspect output is required")
)

var (
	hostPathPattern         = regexp.MustCompile(`(?i)(/private)?/(Users|home|tmp|var/folders)/[^\s:'"]+`)
	secretAssignmentPattern = regexp.MustCompile(`(?i)\b(token|secret|password|api[_-]?key)=\S+`)
)

// OperationError wraps a failed Podman operation with rootless runtime context.
// Detail is sanitized for display; Err is preserved for errors.Is/As.
type OperationError struct {
	Driver    string
	Operation string
	ExitCode  int
	Detail    string
	Err       error
}

func (e *OperationError) Error() string {
	if e == nil {
		return ""
	}
	message := fmt.Sprintf("%s %s failed", e.Driver, e.Operation)
	if strings.TrimSpace(e.Detail) != "" {
		return message + ": " + e.Detail
	}
	if e.Err != nil {
		return message + ": " + sanitizeCommandDetail(e.Err.Error())
	}
	return message
}

func (e *OperationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (d *Driver) Create(ctx context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, operationError(OperationCreate, CommandResult{}, ErrTargetNameRequired)
	}
	entry, topologyArgs, err := d.prepareNetworkTopology(ctx, name)
	if err != nil {
		return nil, err
	}
	createArgs := d.createArgs(name)
	if entry != nil {
		createArgs = d.createArgsWithNetworkTopology(name, topologyArgs, &entry.identity)
	}

	result, err := d.runLifecycleCommand(ctx, CommandRequest{
		Operation: OperationCreate,
		Args:      createArgs,
		Env:       cloneStringMap(req.Env),
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
	})
	if err != nil {
		if entry != nil {
			d.cleanupUnregisteredTopology(entry.identity, entry.session, sandboxruntime.Target{})
		}
		return nil, err
	}

	runtimeID := firstOutputField(result.Stdout)
	if runtimeID == "" {
		runtimeID = name
	}
	target := sandboxruntime.Target{
		ID:       runtimeID,
		Name:     name,
		Provider: DriverID,
		Status:   sandbox.StatusStopped,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         DriverID,
			RuntimeID:      runtimeID,
			Image:          d.image,
			IsolationLevel: IsolationLevel,
		},
	}
	ensureRootlessRuntimeMetadata(&target)
	clearNetworkTopologyProof(&target)
	if entry != nil {
		if err := d.registerNetworkTopology(entry, target); err != nil {
			cleanupCtx, cancel := d.networkTopologyCleanupContext()
			defer cancel()
			_, deleteErr := d.runLifecycleCommand(cleanupCtx, CommandRequest{
				Operation: OperationDelete,
				Args:      d.deleteArgs(runtimeID),
			})
			d.cleanupUnregisteredTopology(entry.identity, entry.session, target)
			return nil, errors.Join(err, deleteErr)
		}
	}
	return &target, nil
}

func (d *Driver) Start(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	target := req.Target
	entry, topologyErr := d.topologyEntryForTarget(target)
	if topologyErr != nil {
		return nil, topologyError(OperationStart, ErrNetworkTopologySessionMissing)
	}
	if entry != nil {
		entry.mu.Lock()
		unavailable := entry.cleaned
		entry.mu.Unlock()
		if unavailable {
			return nil, topologyError(OperationStart, ErrNetworkTopologySessionMissing)
		}
	}
	ref, err := containerRef(target)
	if err != nil {
		return nil, operationError(OperationStart, CommandResult{}, err)
	}

	if _, err := d.runLifecycleCommand(ctx, CommandRequest{
		Operation: OperationStart,
		Args:      d.startArgs(ref),
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
	}); err != nil {
		if entry != nil {
			return nil, d.rollbackNetworkTopologyStart(entry, target, err)
		}
		return nil, err
	}

	target.Status = sandbox.StatusRunning
	ensureRootlessRuntimeMetadata(&target)
	if entry != nil {
		if err := d.activateNetworkTopology(ctx, entry, &target); err != nil {
			return nil, d.rollbackNetworkTopologyStart(entry, target, err)
		}
	}
	return &target, nil
}

func (d *Driver) Stop(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	target := req.Target
	ref, err := containerRef(target)
	if err != nil {
		return nil, operationError(OperationStop, CommandResult{}, err)
	}

	entry, _ := d.topologyEntryForTarget(target)
	runtimeStop := func(runCtx context.Context) error {
		_, runErr := d.runLifecycleCommand(runCtx, CommandRequest{
			Operation: OperationStop,
			Args:      d.stopArgs(ref),
			Stdout:    req.Stdout,
			Stderr:    req.Stderr,
		})
		return runErr
	}
	if entry != nil {
		err = d.revokeAndCleanupNetworkTopology(entry, target, OperationStop, false, runtimeStop)
	} else {
		err = runtimeStop(ctx)
	}
	if err != nil {
		return nil, err
	}

	target.Status = sandbox.StatusStopped
	ensureRootlessRuntimeMetadata(&target)
	clearNetworkTopologyProof(&target)
	return &target, nil
}

func (d *Driver) Delete(ctx context.Context, req sandboxruntime.LifecycleRequest) error {
	ref, err := containerRef(req.Target)
	if err != nil {
		return operationError(OperationDelete, CommandResult{}, err)
	}

	entry, _ := d.topologyEntryForTarget(req.Target)
	runtimeDelete := func(runCtx context.Context) error {
		_, runErr := d.runLifecycleCommand(runCtx, CommandRequest{
			Operation: OperationDelete,
			Args:      d.deleteArgs(ref),
			Stdout:    req.Stdout,
			Stderr:    req.Stderr,
		})
		return runErr
	}
	if entry != nil {
		return d.revokeAndCleanupNetworkTopology(entry, req.Target, OperationDelete, false, runtimeDelete)
	}
	return runtimeDelete(ctx)
}

func (d *Driver) Inspect(ctx context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	target := req.Target
	ref, err := containerRef(target)
	if err != nil {
		return nil, operationError(OperationInspect, CommandResult{}, err)
	}

	result, err := d.runLifecycleCommand(ctx, CommandRequest{
		Operation: OperationInspect,
		Args:      d.inspectArgs(ref),
	})
	if err != nil {
		return nil, err
	}
	if err := applyInspectOutput(&target, result.Stdout); err != nil {
		return nil, operationError(OperationInspect, result, err)
	}
	ensureRootlessRuntimeMetadata(&target)
	d.projectCurrentNetworkTopologyProof(&target)
	return &target, nil
}

func (d *Driver) runLifecycleCommand(ctx context.Context, req CommandRequest) (CommandResult, error) {
	runner, err := d.lifecycleRunnerFor(req.Operation)
	if err != nil {
		return CommandResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	result, err := runner.RunLifecycleCommand(ctx, req)
	if err != nil || result.ExitCode != 0 {
		return result, operationError(req.Operation, result, err)
	}
	return result, nil
}

func (d *Driver) lifecycleRunnerFor(operation string) (LifecycleCommandRunner, error) {
	if d == nil || d.lifecycleRunner == nil {
		return nil, operationError(operation, CommandResult{}, ErrLifecycleRunnerRequired)
	}
	return d.lifecycleRunner, nil
}

func (d *Driver) createArgs(name string) []string {
	return d.createArgsWithNetworkTopology(name, nil, nil)
}

func (d *Driver) startArgs(ref string) []string {
	return []string{d.podmanPath, "start", ref}
}

func (d *Driver) stopArgs(ref string) []string {
	return []string{d.podmanPath, "stop", ref}
}

func (d *Driver) deleteArgs(ref string) []string {
	return []string{d.podmanPath, "rm", "--force", ref}
}

func (d *Driver) inspectArgs(ref string) []string {
	return []string{d.podmanPath, "inspect", ref}
}

func operationError(operation string, result CommandResult, err error) error {
	if err == nil && result.ExitCode == 0 {
		return nil
	}
	if err == nil {
		err = fmt.Errorf("podman exited with code %d", result.ExitCode)
	}
	return &OperationError{
		Driver:    DriverID,
		Operation: operation,
		ExitCode:  result.ExitCode,
		Detail:    commandResultDetail(result, err),
		Err:       err,
	}
}

func commandResultDetail(result CommandResult, err error) string {
	parts := []string{result.Stderr, result.Stdout}
	if err != nil {
		parts = append(parts, err.Error())
	}
	return sanitizeCommandDetail(parts...)
}

func sanitizeCommandDetail(parts ...string) string {
	raw := strings.Join(nonEmptyStrings(parts), " ")
	if raw == "" {
		return ""
	}
	normalized := strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, raw)
	normalized = strings.Join(strings.Fields(normalized), " ")
	normalized = strings.ReplaceAll(normalized, "/var/run/docker.sock", "[redacted-docker-socket]")
	normalized = strings.ReplaceAll(normalized, "/run/docker.sock", "[redacted-docker-socket]")
	normalized = strings.ReplaceAll(normalized, "docker.sock", "[redacted-docker-socket]")
	normalized = secretAssignmentPattern.ReplaceAllString(normalized, "$1=[redacted]")
	normalized = hostPathPattern.ReplaceAllString(normalized, "[redacted-path]")
	if len(normalized) > maxErrorDetail {
		normalized = normalized[:maxErrorDetail] + "..."
	}
	return normalized
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func containerRef(target sandboxruntime.Target) (string, error) {
	for _, candidate := range []string{
		target.Runtime.RuntimeID,
		target.ID,
		target.Name,
	} {
		if ref := strings.TrimSpace(candidate); ref != "" {
			return ref, nil
		}
	}
	return "", ErrTargetRefRequired
}

func firstOutputField(output string) string {
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func ensureRootlessRuntimeMetadata(target *sandboxruntime.Target) {
	if target == nil {
		return
	}
	target.Provider = firstNonEmpty(target.Provider, DriverID)
	target.Runtime.Driver = DriverID
	target.Runtime.IsolationLevel = IsolationLevel
	if strings.TrimSpace(target.Runtime.RuntimeID) == "" {
		target.Runtime.RuntimeID = firstNonEmpty(target.ID, target.Name)
	}
	if strings.TrimSpace(target.ID) == "" {
		target.ID = strings.TrimSpace(target.Runtime.RuntimeID)
	}
}

func applyInspectOutput(target *sandboxruntime.Target, output string) error {
	output = strings.TrimSpace(output)
	if output == "" {
		return ErrInspectOutputRequired
	}

	entry, err := parseInspectOutput(output)
	if err != nil {
		return err
	}
	if id := strings.TrimSpace(entry.ID); id != "" {
		target.ID = id
		target.Runtime.RuntimeID = id
	}
	if name := strings.TrimPrefix(strings.TrimSpace(entry.Name), "/"); name != "" {
		target.Name = name
	}
	if image := firstNonEmpty(entry.ImageName, entry.Config.Image, entry.Image, target.Runtime.Image); image != "" {
		target.Runtime.Image = image
	}
	if status := normalizePodmanStatus(entry.State.Status, entry.State.Running); status != "" {
		target.Status = status
	}
	return nil
}

func parseInspectOutput(output string) (podmanInspectEntry, error) {
	var entries []podmanInspectEntry
	if err := json.Unmarshal([]byte(output), &entries); err == nil {
		if len(entries) == 0 {
			return podmanInspectEntry{}, ErrInspectOutputRequired
		}
		return entries[0], nil
	}

	var entry podmanInspectEntry
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		return podmanInspectEntry{}, err
	}
	return entry, nil
}

func normalizePodmanStatus(status string, running bool) string {
	value := strings.ToLower(strings.TrimSpace(status))
	switch value {
	case "running", "up":
		return sandbox.StatusRunning
	case "created", "configured", "exited", "stopped", "paused", "dead":
		return sandbox.StatusStopped
	case "":
		if running {
			return sandbox.StatusRunning
		}
		return ""
	default:
		if running {
			return sandbox.StatusRunning
		}
		return sandbox.StatusUnknown
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

type podmanInspectEntry struct {
	ID        string `json:"Id"`
	Name      string `json:"Name"`
	Image     string `json:"Image"`
	ImageName string `json:"ImageName"`
	Config    struct {
		Image string `json:"Image"`
	} `json:"Config"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
	} `json:"State"`
}
