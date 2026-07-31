// Package linuxtopology owns the explicitly enabled Linux namespace and pasta
// lifecycle used by higher-level sandbox runtime topology adapters.
package linuxtopology

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ErrDisabled          = errors.New("linux topology lifecycle disabled")
	ErrUnsupported       = errors.New("linux topology lifecycle unsupported")
	ErrInvalidIdentity   = errors.New("linux topology invalid identity")
	ErrInvalidTools      = errors.New("linux topology invalid tools")
	ErrInvalidMapping    = errors.New("linux topology invalid mapping")
	ErrStartFailed       = errors.New("linux topology start failed")
	ErrInspectionFailed  = errors.New("linux topology inspection failed")
	ErrTopologyCollision = errors.New("linux topology collision")
	ErrStaleGeneration   = errors.New("linux topology stale generation")
	ErrIdentityMismatch  = errors.New("linux topology identity mismatch")
	ErrCleanupIncomplete = errors.New("linux topology cleanup incomplete")
	ErrStopped           = errors.New("linux topology stopped")
)

const (
	defaultCleanupTimeout           = 5 * time.Second
	defaultInspectionTimeout        = 5 * time.Second
	defaultInspectionInterval       = 20 * time.Millisecond
	defaultOutputLimit        int64 = 64 << 10
	maxOutputLimit            int64 = 1 << 20
)

var (
	safeIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
	interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
)

type Status string

const (
	StatusActive            Status = "active"
	StatusLost              Status = "lost"
	StatusStopped           Status = "stopped"
	StatusCleanupIncomplete Status = "cleanup_incomplete"
)

type ProcessRole string

const (
	ProcessRoleKeeper     ProcessRole = "keeper"
	ProcessRoleMapping    ProcessRole = "mapping"
	ProcessRoleInspection ProcessRole = "inspection"
)

type LossReason string

const LossReasonProcessExited LossReason = "process_exited"

// Identity is the immutable, redaction-safe correlation identity for one
// topology generation. Every field is required.
type Identity struct {
	SandboxID            string `json:"sandboxId"`
	ExecutionID          string `json:"executionId"`
	WorkerID             string `json:"workerId"`
	RuntimeID            string `json:"runtimeId"`
	PlanID               string `json:"planId"`
	PolicySnapshotID     string `json:"policySnapshotId"`
	ProxySessionID       string `json:"proxySessionId"`
	TopologyGenerationID string `json:"topologyGenerationId"`
}

// Mapping is live-only input. Its endpoint, address, and interface are never
// serialized by this package.
type Mapping struct {
	ProxyEndpoint      string `json:"-"`
	GuestProxyAddress  string `json:"-"`
	NamespaceInterface string `json:"-"`
}

type StartRequest struct {
	Identity Identity `json:"identity"`
	Mapping  Mapping  `json:"-"`
}

// ToolPaths are live-only absolute executable paths.
type ToolPaths struct {
	Unshare string `json:"-"`
	Pasta   string `json:"-"`
	Nsenter string `json:"-"`
	IP      string `json:"-"`
	Keeper  string `json:"-"`
}

// ProcessSpec is passed only to an injected process boundary. It deliberately
// has no serializable fields.
type ProcessSpec struct {
	Role        ProcessRole `json:"-"`
	Path        string      `json:"-"`
	Args        []string    `json:"-"`
	Env         []string    `json:"-"`
	ExtraFiles  []*os.File  `json:"-"`
	OutputLimit int64       `json:"-"`
}

type ProcessHandle interface {
	PID() int
	Done() <-chan struct{}
	Terminate(context.Context) error
}

type ProcessStarter interface {
	Start(context.Context, ProcessSpec) (ProcessHandle, error)
}

type CommandRunner interface {
	Run(context.Context, ProcessSpec) ([]byte, error)
}

type NamespaceOpener func(int) (*NamespaceHandle, error)

type Config struct {
	Enabled            bool            `json:"enabled"`
	Tools              ToolPaths       `json:"-"`
	Environment        []string        `json:"-"`
	Starter            ProcessStarter  `json:"-"`
	Runner             CommandRunner   `json:"-"`
	OpenNamespaces     NamespaceOpener `json:"-"`
	CleanupTimeout     time.Duration   `json:"-"`
	InspectionTimeout  time.Duration   `json:"-"`
	InspectionInterval time.Duration   `json:"-"`
	OutputLimit        int64           `json:"-"`
}

type Metadata struct {
	Identity  Identity `json:"identity"`
	Status    Status   `json:"status"`
	Inspected bool     `json:"inspected,omitempty"`
}

type Loss struct {
	TopologyGenerationID string      `json:"topologyGenerationId"`
	Component            ProcessRole `json:"component"`
	Reason               LossReason  `json:"reason"`
}

func validIdentity(identity Identity) bool {
	if !(safeIDPattern.MatchString(identity.SandboxID) &&
		safeIDPattern.MatchString(identity.ExecutionID) &&
		safeIDPattern.MatchString(identity.WorkerID) &&
		safeIDPattern.MatchString(identity.RuntimeID) &&
		safeIDPattern.MatchString(identity.PlanID) &&
		safeIDPattern.MatchString(identity.PolicySnapshotID) &&
		safeIDPattern.MatchString(identity.ProxySessionID) &&
		safeIDPattern.MatchString(identity.TopologyGenerationID)) {
		return false
	}
	values := []string{
		identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.RuntimeID,
		identity.PlanID, identity.PolicySnapshotID, identity.ProxySessionID, identity.TopologyGenerationID,
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validMapping(mapping Mapping) bool {
	host, portText, err := net.SplitHostPort(mapping.ProxyEndpoint)
	if err != nil {
		return false
	}
	hostAddress, err := netip.ParseAddr(host)
	if err != nil || !hostAddress.IsLoopback() {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	guestAddress, err := netip.ParseAddr(mapping.GuestProxyAddress)
	if err != nil || !guestAddress.IsValid() || guestAddress.IsUnspecified() ||
		guestAddress.IsLoopback() || guestAddress.IsMulticast() || guestAddress.IsLinkLocalUnicast() {
		return false
	}
	return mapping.NamespaceInterface != "lo" && interfacePattern.MatchString(mapping.NamespaceInterface)
}

func validToolPaths(tools ToolPaths) bool {
	for _, path := range []string{tools.Unshare, tools.Pasta, tools.Nsenter, tools.IP, tools.Keeper} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			strings.ContainsAny(path, "\x00\r\n") {
			return false
		}
	}
	return true
}

func validEnvironment(environment []string) bool {
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || (key != "LANG" && key != "LC_ALL") || value == "" || len(value) > 128 ||
			strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	return true
}

func cloneProcessSpec(spec ProcessSpec) ProcessSpec {
	spec.Args = append([]string(nil), spec.Args...)
	spec.Env = append([]string(nil), spec.Env...)
	spec.ExtraFiles = append([]*os.File(nil), spec.ExtraFiles...)
	return spec
}
