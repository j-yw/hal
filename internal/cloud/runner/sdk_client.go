package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	daytona "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/options"
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

// Compile-time interface satisfaction assertions.
var (
	_ Runner      = (*SDKClient)(nil)
	_ SessionExec = (*SDKClient)(nil)
	_ GitOps      = (*SDKClient)(nil)
)

// SDKClientConfig holds configuration for the Daytona SDK runner client.
type SDKClientConfig struct {
	// APIKey is the Daytona API key (required).
	APIKey string
	// APIURL is the Daytona API URL (optional; SDK default used when empty).
	APIURL string
	// Target is the Daytona target environment (optional).
	Target string
}

// SDKClient is a Daytona SDK implementation of the Runner interface.
type SDKClient struct {
	client *daytona.Client
	mu     sync.RWMutex
	logRef map[string]sessionCommandRef
}

type sessionCommand struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

type sessionCommandRef struct {
	sessionID string
	commandID string
	logs      string
}

type sandboxCommandRef struct {
	SessionID string
	CommandID string
	Command   string
}

// NewSDKClient creates a new SDK runner client with the given configuration.
// APIKey is required; all other fields are optional.
func NewSDKClient(cfg SDKClientConfig) (*SDKClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("sdk runner client: api_key must not be empty")
	}

	client, err := daytona.NewClientWithConfig(&types.DaytonaConfig{
		APIKey: cfg.APIKey,
		APIUrl: cfg.APIURL,
		Target: cfg.Target,
	})
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: init: %w", err)
	}

	return &SDKClient{
		client: client,
		logRef: make(map[string]sessionCommandRef),
	}, nil
}

// CreateSandbox provisions a new Daytona sandbox via the SDK.
func (s *SDKClient) CreateSandbox(ctx context.Context, req *CreateSandboxRequest) (*Sandbox, error) {
	if req == nil {
		return nil, fmt.Errorf("sdk runner client: create request must not be nil")
	}
	if req.Image == "" {
		return nil, fmt.Errorf("sdk runner client: create: image must not be empty")
	}

	sandbox, err := s.client.Create(ctx, types.ImageParams{
		Image: req.Image,
		SandboxBaseParams: types.SandboxBaseParams{
			EnvVars: req.EnvVars,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: create sandbox: %w", err)
	}

	return &Sandbox{
		ID:        sandbox.ID,
		Status:    string(sandbox.State),
		CreatedAt: time.Now(),
	}, nil
}

// DestroySandbox tears down an existing sandbox by ID via the SDK.
func (s *SDKClient) DestroySandbox(ctx context.Context, sandboxID string) error {
	if sandboxID == "" {
		return fmt.Errorf("sdk runner client: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("sdk runner client: destroy: get sandbox: %w", err)
	}

	if err := sandbox.Delete(ctx); err != nil {
		return fmt.Errorf("sdk runner client: destroy sandbox: %w", err)
	}

	s.clearLogRef(sandboxID)
	return nil
}

// Exec executes a command inside an existing sandbox and returns the result.
func (s *SDKClient) Exec(ctx context.Context, sandboxID string, req *ExecRequest) (*ExecResult, error) {
	if req == nil {
		return nil, fmt.Errorf("sdk runner client: exec request must not be nil")
	}
	if sandboxID == "" {
		return nil, fmt.Errorf("sdk runner client: exec: sandbox_id must not be empty")
	}
	if req.Command == "" {
		return nil, fmt.Errorf("sdk runner client: exec: command must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: exec: get sandbox: %w", err)
	}

	beforeSessions, _ := sandbox.Process.ListSessions(ctx) // best-effort for log correlation
	beforeSnapshot := snapshotSessionCommands(beforeSessions)

	var opts []func(*options.ExecuteCommand)
	if req.WorkDir != "" {
		opts = append(opts, options.WithCwd(req.WorkDir))
	}
	if req.Timeout > 0 {
		opts = append(opts, options.WithExecuteTimeout(req.Timeout))
	}

	resp, err := sandbox.Process.ExecuteCommand(ctx, req.Command, opts...)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: exec: %w", err)
	}

	result := &ExecResult{
		ExitCode: resp.ExitCode,
		Stdout:   resp.Result,
	}
	if resp.Artifacts != nil && resp.Artifacts.Stdout != "" {
		result.Stdout = resp.Artifacts.Stdout
	}

	logs := result.Stdout
	if result.Stderr != "" {
		if logs != "" {
			logs += "\n"
		}
		logs += result.Stderr
	}
	ref := sessionCommandRef{logs: logs}

	if afterSessions, listErr := sandbox.Process.ListSessions(ctx); listErr == nil {
		if sessionID, commandID, ok := resolveSessionCommandRef(beforeSnapshot, afterSessions, req.Command); ok {
			ref.sessionID = sessionID
			ref.commandID = commandID
		}
	}
	s.setLogRef(sandboxID, ref)

	return result, nil
}

// StreamLogs retrieves session command logs from a sandbox via the SDK.
func (s *SDKClient) StreamLogs(ctx context.Context, sandboxID string) (io.ReadCloser, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sdk runner client: stream logs: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: stream logs: get sandbox: %w", err)
	}

	ref, _ := s.getLogRef(sandboxID)
	if ref.sessionID == "" || ref.commandID == "" {
		sessions, listErr := sandbox.Process.ListSessions(ctx)
		if listErr == nil {
			if sessionID, commandID, ok := latestSessionCommandRef(sessions); ok {
				ref.sessionID = sessionID
				ref.commandID = commandID
				s.setLogRef(sandboxID, ref)
			}
		} else if strings.TrimSpace(ref.logs) == "" {
			return nil, fmt.Errorf("sdk runner client: stream logs: discover command: %w", listErr)
		}
	}

	if ref.sessionID == "" || ref.commandID == "" {
		if strings.TrimSpace(ref.logs) != "" {
			return io.NopCloser(strings.NewReader(ref.logs)), nil
		}
		return nil, fmt.Errorf("sdk runner client: stream logs: no command logs found")
	}

	logsMap, err := sandbox.Process.GetSessionCommandLogs(ctx, ref.sessionID, ref.commandID)
	if err != nil {
		if strings.TrimSpace(ref.logs) != "" {
			return io.NopCloser(strings.NewReader(ref.logs)), nil
		}
		return nil, fmt.Errorf("sdk runner client: stream logs: %w", err)
	}

	logs := logsFromMap(logsMap)
	if logs == "" && strings.TrimSpace(ref.logs) != "" {
		logs = ref.logs
	}
	return io.NopCloser(strings.NewReader(logs)), nil
}

// Health probes Daytona reachability by listing sandboxes and returns SDK version info.
func (s *SDKClient) Health(ctx context.Context) (*HealthStatus, error) {
	page := 1
	limit := 1

	// Probe with an effectively unique label filter so List returns zero items.
	// This avoids SDK sandbox hydration/toolbox-proxy calls for listed items and
	// keeps health focused on API/auth reachability.
	labels := map[string]string{
		"hal-health-probe": fmt.Sprintf("probe-%d", time.Now().UnixNano()),
	}

	if _, err := s.client.List(ctx, labels, &page, &limit); err != nil {
		return nil, fmt.Errorf("sdk runner client: health: %w", err)
	}

	return &HealthStatus{
		OK:      true,
		Version: daytona.Version,
	}, nil
}

func (s *SDKClient) setLogRef(sandboxID string, ref sessionCommandRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logRef[sandboxID] = ref
}

func (s *SDKClient) getLogRef(sandboxID string) (sessionCommandRef, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ref, ok := s.logRef[sandboxID]
	return ref, ok
}

func (s *SDKClient) clearLogRef(sandboxID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.logRef, sandboxID)
}

func snapshotSessionCommands(sessions []map[string]any) map[string]map[string]struct{} {
	snapshot := make(map[string]map[string]struct{})
	for _, ref := range flattenSessionCommands(sessions) {
		if _, ok := snapshot[ref.SessionID]; !ok {
			snapshot[ref.SessionID] = make(map[string]struct{})
		}
		snapshot[ref.SessionID][ref.CommandID] = struct{}{}
	}
	return snapshot
}

func resolveSessionCommandRef(before map[string]map[string]struct{}, sessions []map[string]any, command string) (string, string, bool) {
	all := flattenSessionCommands(sessions)
	if len(all) == 0 {
		return "", "", false
	}

	newMatching := make([]sandboxCommandRef, 0, len(all))
	newAny := make([]sandboxCommandRef, 0, len(all))
	matchingAny := make([]sandboxCommandRef, 0, len(all))

	for _, ref := range all {
		seen := commandSeen(before, ref.SessionID, ref.CommandID)
		if !seen {
			newAny = append(newAny, ref)
		}
		if command != "" && ref.Command == command {
			matchingAny = append(matchingAny, ref)
			if !seen {
				newMatching = append(newMatching, ref)
			}
		}
	}

	if len(newMatching) > 0 {
		ref := newMatching[len(newMatching)-1]
		return ref.SessionID, ref.CommandID, true
	}
	if len(newAny) > 0 {
		ref := newAny[len(newAny)-1]
		return ref.SessionID, ref.CommandID, true
	}
	if len(matchingAny) > 0 {
		ref := matchingAny[len(matchingAny)-1]
		return ref.SessionID, ref.CommandID, true
	}

	ref := all[len(all)-1]
	return ref.SessionID, ref.CommandID, true
}

func latestSessionCommandRef(sessions []map[string]any) (string, string, bool) {
	return resolveSessionCommandRef(nil, sessions, "")
}

func flattenSessionCommands(sessions []map[string]any) []sandboxCommandRef {
	refs := make([]sandboxCommandRef, 0)
	for _, session := range sessions {
		sessionID, _ := session["sessionId"].(string)
		if sessionID == "" {
			continue
		}
		for _, cmd := range parseSessionCommands(session["commands"]) {
			if cmd.ID == "" {
				continue
			}
			refs = append(refs, sandboxCommandRef{
				SessionID: sessionID,
				CommandID: cmd.ID,
				Command:   cmd.Command,
			})
		}
	}
	return refs
}

func parseSessionCommands(raw any) []sessionCommand {
	if raw == nil {
		return nil
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}

	var commands []sessionCommand
	if err := json.Unmarshal(data, &commands); err != nil {
		return nil
	}
	return commands
}

func commandSeen(snapshot map[string]map[string]struct{}, sessionID, commandID string) bool {
	if snapshot == nil {
		return false
	}
	sessionCommands, ok := snapshot[sessionID]
	if !ok {
		return false
	}
	_, ok = sessionCommands[commandID]
	return ok
}

// ---------------------------------------------------------------------------
// SessionExec implementation — uses Daytona sessions for long-running commands.
// ---------------------------------------------------------------------------

// CreateSession creates a named session in the sandbox.
func (s *SDKClient) CreateSession(ctx context.Context, sandboxID, sessionID string) error {
	if sandboxID == "" {
		return fmt.Errorf("sdk runner client: create session: sandbox_id must not be empty")
	}
	if sessionID == "" {
		return fmt.Errorf("sdk runner client: create session: session_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("sdk runner client: create session: get sandbox: %w", err)
	}

	if err := sandbox.Process.CreateSession(ctx, sessionID); err != nil {
		return fmt.Errorf("sdk runner client: create session: %w", err)
	}
	return nil
}

// ExecAsync launches a command asynchronously in a session.
func (s *SDKClient) ExecAsync(ctx context.Context, sandboxID, sessionID string, req *ExecRequest) (*SessionCommandStatus, error) {
	if req == nil {
		return nil, fmt.Errorf("sdk runner client: exec async: request must not be nil")
	}
	if sandboxID == "" {
		return nil, fmt.Errorf("sdk runner client: exec async: sandbox_id must not be empty")
	}
	if sessionID == "" {
		return nil, fmt.Errorf("sdk runner client: exec async: session_id must not be empty")
	}
	if req.Command == "" {
		return nil, fmt.Errorf("sdk runner client: exec async: command must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: exec async: get sandbox: %w", err)
	}

	// Build the full command. If WorkDir is set, prepend a cd.
	cmd := req.Command
	if req.WorkDir != "" {
		cmd = fmt.Sprintf("cd %s && %s", req.WorkDir, req.Command)
	}

	result, err := sandbox.Process.ExecuteSessionCommand(ctx, sessionID, cmd, true /* runAsync */)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: exec async: %w", err)
	}

	cmdID, _ := result["id"].(string)
	if cmdID == "" {
		return nil, fmt.Errorf("sdk runner client: exec async: no command id returned")
	}

	status := &SessionCommandStatus{CommandID: cmdID}
	if ec, ok := result["exitCode"]; ok {
		if code, ok := ec.(int32); ok {
			c := int(code)
			status.ExitCode = &c
		}
	}

	// Store log ref for StreamLogs compatibility.
	s.setLogRef(sandboxID, sessionCommandRef{
		sessionID: sessionID,
		commandID: cmdID,
	})

	return status, nil
}

// GetCommandStatus polls the status of a session command.
func (s *SDKClient) GetCommandStatus(ctx context.Context, sandboxID, sessionID, commandID string) (*SessionCommandStatus, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sdk runner client: get command status: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: get command status: get sandbox: %w", err)
	}

	result, err := sandbox.Process.GetSessionCommand(ctx, sessionID, commandID)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: get command status: %w", err)
	}

	status := &SessionCommandStatus{CommandID: commandID}
	if ec, ok := result["exitCode"]; ok {
		switch v := ec.(type) {
		case int32:
			c := int(v)
			status.ExitCode = &c
		case float64:
			c := int(v)
			status.ExitCode = &c
		case int:
			status.ExitCode = &v
		}
	}

	return status, nil
}

// StreamCommandLogs opens a real-time WebSocket log stream for a session command.
func (s *SDKClient) StreamCommandLogs(ctx context.Context, sandboxID, sessionID, commandID string, stdout, stderr chan<- string) error {
	if sandboxID == "" {
		close(stdout)
		close(stderr)
		return fmt.Errorf("sdk runner client: stream command logs: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		close(stdout)
		close(stderr)
		return fmt.Errorf("sdk runner client: stream command logs: get sandbox: %w", err)
	}

	// GetSessionCommandLogsStream closes stdout and stderr channels when done.
	return sandbox.Process.GetSessionCommandLogsStream(ctx, sessionID, commandID, stdout, stderr)
}

// GetCommandLogs retrieves the full accumulated logs for a session command.
func (s *SDKClient) GetCommandLogs(ctx context.Context, sandboxID, sessionID, commandID string) (string, error) {
	if sandboxID == "" {
		return "", fmt.Errorf("sdk runner client: get command logs: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return "", fmt.Errorf("sdk runner client: get command logs: get sandbox: %w", err)
	}

	logsMap, err := sandbox.Process.GetSessionCommandLogs(ctx, sessionID, commandID)
	if err != nil {
		return "", fmt.Errorf("sdk runner client: get command logs: %w", err)
	}

	return logsFromMap(logsMap), nil
}

// DeleteSession removes a session from the sandbox.
func (s *SDKClient) DeleteSession(ctx context.Context, sandboxID, sessionID string) error {
	if sandboxID == "" {
		return fmt.Errorf("sdk runner client: delete session: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("sdk runner client: delete session: get sandbox: %w", err)
	}

	if err := sandbox.Process.DeleteSession(ctx, sessionID); err != nil {
		return fmt.Errorf("sdk runner client: delete session: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// GitOps implementation — uses Daytona's native Git API instead of Exec.
// ---------------------------------------------------------------------------

// GitClone clones a repository into the sandbox via the Daytona Git API.
func (s *SDKClient) GitClone(ctx context.Context, sandboxID string, req *GitCloneRequest) error {
	if req == nil {
		return fmt.Errorf("sdk runner client: git clone request must not be nil")
	}
	if sandboxID == "" {
		return fmt.Errorf("sdk runner client: git clone: sandbox_id must not be empty")
	}
	if req.URL == "" {
		return fmt.Errorf("sdk runner client: git clone: url must not be empty")
	}
	if req.Path == "" {
		return fmt.Errorf("sdk runner client: git clone: path must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("sdk runner client: git clone: get sandbox: %w", err)
	}

	var opts []func(*options.GitClone)
	if req.Branch != "" {
		opts = append(opts, options.WithBranch(req.Branch))
	}
	if req.Username != "" {
		opts = append(opts, options.WithUsername(req.Username))
	}
	if req.Password != "" {
		opts = append(opts, options.WithPassword(req.Password))
	}

	if err := sandbox.Git.Clone(ctx, req.URL, req.Path, opts...); err != nil {
		return fmt.Errorf("sdk runner client: git clone: %w", err)
	}
	return nil
}

// GitAdd stages files via the Daytona Git API.
func (s *SDKClient) GitAdd(ctx context.Context, sandboxID, path string, files []string) error {
	if sandboxID == "" {
		return fmt.Errorf("sdk runner client: git add: sandbox_id must not be empty")
	}
	if path == "" {
		return fmt.Errorf("sdk runner client: git add: path must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("sdk runner client: git add: get sandbox: %w", err)
	}

	if err := sandbox.Git.Add(ctx, path, files); err != nil {
		return fmt.Errorf("sdk runner client: git add: %w", err)
	}
	return nil
}

// GitCommit creates a commit via the Daytona Git API.
func (s *SDKClient) GitCommit(ctx context.Context, sandboxID string, req *GitCommitRequest) (*GitCommitResult, error) {
	if req == nil {
		return nil, fmt.Errorf("sdk runner client: git commit request must not be nil")
	}
	if sandboxID == "" {
		return nil, fmt.Errorf("sdk runner client: git commit: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: git commit: get sandbox: %w", err)
	}

	var opts []func(*options.GitCommit)
	if req.AllowEmpty {
		opts = append(opts, options.WithAllowEmpty(true))
	}

	resp, err := sandbox.Git.Commit(ctx, req.Path, req.Message, req.Author, req.Email, opts...)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: git commit: %w", err)
	}

	return &GitCommitResult{SHA: resp.SHA}, nil
}

// GitPush pushes commits to the remote via the Daytona Git API.
func (s *SDKClient) GitPush(ctx context.Context, sandboxID string, req *GitPushRequest) error {
	if req == nil {
		return fmt.Errorf("sdk runner client: git push request must not be nil")
	}
	if sandboxID == "" {
		return fmt.Errorf("sdk runner client: git push: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("sdk runner client: git push: get sandbox: %w", err)
	}

	var opts []func(*options.GitPush)
	if req.Username != "" {
		opts = append(opts, options.WithPushUsername(req.Username))
	}
	if req.Password != "" {
		opts = append(opts, options.WithPushPassword(req.Password))
	}

	if err := sandbox.Git.Push(ctx, req.Path, opts...); err != nil {
		return fmt.Errorf("sdk runner client: git push: %w", err)
	}
	return nil
}

// GitCreateBranch creates a branch via the Daytona Git API.
func (s *SDKClient) GitCreateBranch(ctx context.Context, sandboxID, path, branch string) error {
	if sandboxID == "" {
		return fmt.Errorf("sdk runner client: git create branch: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("sdk runner client: git create branch: get sandbox: %w", err)
	}

	if err := sandbox.Git.CreateBranch(ctx, path, branch); err != nil {
		return fmt.Errorf("sdk runner client: git create branch: %w", err)
	}
	return nil
}

// GitCheckout switches to a branch via the Daytona Git API.
func (s *SDKClient) GitCheckout(ctx context.Context, sandboxID, path, branch string) error {
	if sandboxID == "" {
		return fmt.Errorf("sdk runner client: git checkout: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("sdk runner client: git checkout: get sandbox: %w", err)
	}

	if err := sandbox.Git.Checkout(ctx, path, branch); err != nil {
		return fmt.Errorf("sdk runner client: git checkout: %w", err)
	}
	return nil
}

// GitListBranches lists branches via the Daytona Git API.
func (s *SDKClient) GitListBranches(ctx context.Context, sandboxID, path string) ([]string, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sdk runner client: git list branches: sandbox_id must not be empty")
	}

	sandbox, err := s.client.Get(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: git list branches: get sandbox: %w", err)
	}

	branches, err := sandbox.Git.Branches(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("sdk runner client: git list branches: %w", err)
	}
	return branches, nil
}

func logsFromMap(logsMap map[string]any) string {
	raw, ok := logsMap["logs"]
	if !ok || raw == nil {
		return ""
	}
	logs, ok := raw.(string)
	if ok {
		return logs
	}
	return fmt.Sprint(raw)
}
