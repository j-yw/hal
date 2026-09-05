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
	ErrDisabled                = errors.New("linux topology lifecycle disabled")
	ErrUnsupported             = errors.New("linux topology lifecycle unsupported")
	ErrInvalidIdentity         = errors.New("linux topology invalid identity")
	ErrInvalidTools            = errors.New("linux topology invalid tools")
	ErrInvalidMapping          = errors.New("linux topology invalid mapping")
	ErrStartFailed             = errors.New("linux topology start failed")
	ErrInspectionFailed        = errors.New("linux topology inspection failed")
	ErrTopologyCollision       = errors.New("linux topology collision")
	ErrStaleGeneration         = errors.New("linux topology stale generation")
	ErrIdentityMismatch        = errors.New("linux topology identity mismatch")
	ErrCleanupIncomplete       = errors.New("linux topology cleanup incomplete")
	ErrStaleTopologyUnverified = errors.New("linux topology stale state unverified")
	ErrStopped                 = errors.New("linux topology stopped")
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
	StatusPrepared          Status = "prepared"
	StatusRecoveryOnly      Status = "recovery_only"
	StatusLost              Status = "lost"
	StatusStopping          Status = "stopping"
	StatusStopped           Status = "stopped"
	StatusCleanupIncomplete Status = "cleanup_incomplete"
)

type ProcessRole string

const (
	ProcessRoleKeeper     ProcessRole = "keeper"
	ProcessRoleMapping    ProcessRole = "mapping"
	ProcessRoleInspection ProcessRole = "inspection"
	ProcessRoleProbe      ProcessRole = "probe"
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
	ProxyGenerationID    string `json:"proxyGenerationId"`
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

// RecoveryRequest carries the exact externally retained namespace authority
// required to reopen one topology for cleanup after daemon restart. Namespace
// remains caller-owned; Recover duplicates it before retaining any authority.
type RecoveryRequest struct {
	Identity  Identity         `json:"identity"`
	Namespace *NamespaceHandle `json:"-"`
}

// ToolPaths are live-only absolute executable paths.
type ToolPaths struct {
	Unshare string `json:"-"`
	Pasta   string `json:"-"`
	Nsenter string `json:"-"`
	IP      string `json:"-"`
	NC      string `json:"-"`
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

// ReachabilityProber proves the exact live guest-address/proxy-port mapping.
// Implementations must not retain or serialize the live Mapping value.
type ReachabilityProber interface {
	Probe(context.Context, *NamespaceHandle, Identity, Mapping) error
}

type OwnershipStore interface {
	Acquire(context.Context, Identity) (OwnershipLease, error)
}

// RecoveryOwnershipStore is implemented only by stores that can claim and
// validate a complete private ownership journal under its exclusive lock.
type RecoveryOwnershipStore interface {
	AcquireRecovery(context.Context, RecoveryRequest) (RecoveredOwnership, error)
}

// RecoveredOwnership contains cleanup authority only. Nil process handles mean
// the exact recorded process was positively absent while the supplied
// namespace capability continued to retain the recorded namespace.
type RecoveredOwnership struct {
	Lease     OwnershipLease
	Keeper    ProcessHandle
	Mapper    ProcessHandle
	Namespace *NamespaceHandle
}

type OwnershipLease interface {
	Reconcile(context.Context) error
	Record(context.Context, ProcessHandle, ProcessHandle, *NamespaceHandle) error
	ArmMapping(context.Context, ProcessHandle, *NamespaceHandle) error
	Retire(Identity) error
	Release() error
}

type NamespaceOpener func(int) (*NamespaceHandle, error)

type Config struct {
	Enabled            bool               `json:"enabled"`
	Tools              ToolPaths          `json:"-"`
	Environment        []string           `json:"-"`
	Starter            ProcessStarter     `json:"-"`
	Runner             CommandRunner      `json:"-"`
	OpenNamespaces     NamespaceOpener    `json:"-"`
	Reachability       ReachabilityProber `json:"-"`
	Ownership          OwnershipStore     `json:"-"`
	StateDir           string             `json:"-"`
	CleanupTimeout     time.Duration      `json:"-"`
	InspectionTimeout  time.Duration      `json:"-"`
	InspectionInterval time.Duration      `json:"-"`
	OutputLimit        int64              `json:"-"`
}

type Metadata struct {
	Identity            Identity `json:"identity"`
	Status              Status   `json:"status"`
	StructuralInspected bool     `json:"structuralInspected,omitempty"`
	MappingReachable    bool     `json:"mappingReachable,omitempty"`
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
		safeIDPattern.MatchString(identity.ProxyGenerationID) &&
		safeIDPattern.MatchString(identity.TopologyGenerationID)) {
		return false
	}
	values := []string{
		identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.RuntimeID,
		identity.PlanID, identity.PolicySnapshotID, identity.ProxySessionID, identity.ProxyGenerationID,
		identity.TopologyGenerationID,
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
	if err != nil || (hostAddress.Is4() && hostAddress != netip.MustParseAddr("127.0.0.1")) ||
		(hostAddress.Is6() && hostAddress != netip.IPv6Loopback()) {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	guestAddress, err := netip.ParseAddr(mapping.GuestProxyAddress)
	if err != nil || !guestAddress.IsValid() || guestAddress.IsUnspecified() ||
		guestAddress.IsLoopback() || guestAddress.IsMulticast() || guestAddress.IsLinkLocalUnicast() ||
		guestAddress.Is4() != hostAddress.Is4() {
		return false
	}
	return mapping.NamespaceInterface != "lo" && interfacePattern.MatchString(mapping.NamespaceInterface)
}

func validToolPaths(tools ToolPaths) bool {
	for _, path := range []string{tools.Unshare, tools.Pasta, tools.Nsenter, tools.IP, tools.NC, tools.Keeper} {
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
