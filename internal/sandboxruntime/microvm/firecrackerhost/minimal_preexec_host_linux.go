//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
	"golang.org/x/sys/unix"
)

// Borrowed deployment capabilities, never request fields or readiness proof.
type minimalPreexecHostInputs struct {
	policy                           jailerRecoveryHostPolicy
	vcpus                            int
	memoryMiB                        int64
	baseBootArguments, jailPathBase  string
	stateRoot, stableKey, executable *os.File
	executableSHA256                 [sha256.Size]byte
	networkPolicyID                  string
	proxy                            policyproxy.Config
	topology                         linuxtopology.Config
	tap                              l7network.TAPOptions
	rules                            linuxrules.ProductionExecutorOptions
	networkStateDirectory            string
	cleanupTimeout                   time.Duration
}

type minimalPreexecHost struct {
	self                             *minimalPreexecHost
	provider                         *minimalLaunchProvider
	association                      minimalTemplateAssociation
	input                            minimalPreexecHostInputs
	uid                              uint32
	context                          context.Context
	cancel                           context.CancelFunc
	mu                               sync.Mutex
	closed, usable                   bool
	borrows                          int
	idle, closeDone                  chan struct{}
	closeErr                         error
	stateRoot, stableKey, executable *os.File
	pins                             [3]l8RuntimeOwnerKeyIdentity
}

func newMinimalPreexecHost(ctx context.Context, provider *minimalLaunchProvider, input minimalPreexecHostInputs) (*minimalPreexecHost, error) {
	if os.Geteuid() != 0 {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return newMinimalPreexecHostForUID(ctx, provider, input, 0)
}

// The ordinary-UID seam never replaces the production root observation. All
// validation and duplication below uses actual retained descriptors.
func newMinimalPreexecHostForUID(ctx context.Context, provider *minimalLaunchProvider, input minimalPreexecHostInputs, uid uint32) (result *minimalPreexecHost, resultErr error) {
	var host *minimalPreexecHost
	defer func() {
		if recover() != nil {
			resultErr = sandboxruntime.ErrMinimalLaunchUnavailable
		}
		if resultErr != nil && host != nil {
			result = nil
			if host.close() != nil {
				result = host // Never discard cleanup uncertainty.
			}
		}
	}()
	resultErr = sandboxruntime.ErrMinimalLaunchUnavailable
	if !minimalTemplateOwnerCurrent(ctx) || uid != uint32(os.Geteuid()) || provider == nil || provider.self != provider ||
		!validMinimalTemplateAssociation(provider.association) || !validMinimalPreexecHostInput(input, provider.association.scope) {
		return nil, resultErr
	}
	// Retain the partial host before any duplicate. Its copied config contains
	// no borrowed File aliases after construction.
	host = &minimalPreexecHost{provider: provider, association: provider.association, input: input, uid: uid}
	host.self = host
	host.context, host.cancel = context.WithCancel(ctx)
	host.input.proxy.Policy = networkenforcement.NewPolicyProxyPolicyInput(input.proxy.Policy.PlanMetadata(), input.proxy.Policy.AllowlistRules)
	host.input.topology.Environment = slices.Clone(input.topology.Environment)
	host.input.stateRoot, host.input.stableKey, host.input.executable = nil, nil, nil
	borrowed := []*os.File{input.stateRoot, input.stableKey, input.executable}
	slots := []**os.File{&host.stateRoot, &host.stableKey, &host.executable}
	for index, file := range borrowed {
		pin, err := minimalPreexecInputPin(ctx, file, index, uid, input.executableSHA256)
		if err != nil {
			return nil, resultErr
		}
		duplicate, err := duplicateJailerRecoveryFile(file)
		captureErr := minimalPreexecCaptureFile(slots[index], duplicate, append(borrowed, host.stateRoot, host.stableKey, host.executable))
		if err != nil || captureErr != nil || !minimalTemplateOwnerCurrent(host.context) {
			return nil, resultErr
		}
		actual, err := minimalPreexecInputPin(ctx, duplicate, index, uid, input.executableSHA256)
		if err != nil || actual != pin {
			return nil, resultErr
		}
		host.pins[index] = pin
	}
	if !host.current() || host.checkFiles(ctx, [3]*os.File{host.stateRoot, host.stableKey, host.executable}) != nil {
		return nil, resultErr
	}
	host.usable = true
	return host, nil
}

func validMinimalPreexecHostInput(input minimalPreexecHostInputs, scope sandboxruntime.MinimalLaunchScope) bool {
	p := input.policy
	for _, path := range []string{p.IdentityDirectory, p.TrustedAnchor, p.ChrootBase, p.JailerPath, p.FirecrackerPath, p.CgroupAnchor,
		input.jailPathBase, input.networkStateDirectory, input.topology.StateDir, input.tap.IPPath, input.tap.SysctlPath, input.tap.NsenterPath,
		input.rules.NSenterPath, input.rules.NFTPath, input.topology.Tools.Unshare, input.topology.Tools.Pasta, input.topology.Tools.Nsenter,
		input.topology.Tools.IP, input.topology.Tools.NC, input.topology.Tools.Keeper} {
		if !filepathIsCleanAbsolute(path) || cleanupFilesystemRoot(path) || strings.TrimSpace(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return false
		}
	}
	for _, path := range []string{p.ChrootBase, p.JailerPath, p.FirecrackerPath} {
		rel, err := filepath.Rel(p.TrustedAnchor, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return false
		}
	}
	if input.vcpus <= 0 || input.memoryMiB <= 0 || input.memoryMiB > int64(^uint(0)>>1) ||
		p.UID == 0 || p.GID == 0 || p.JailerPath == p.FirecrackerPath || !validJailerStagingDigest(p.JailerSHA256) ||
		!validJailerStagingDigest(p.FirecrackerSHA256) || p.JailerSHA256 == p.FirecrackerSHA256 || p.CPUQuota == 0 || p.CPUPeriod == 0 || p.MemoryMax == 0 || p.PidsMax == 0 ||
		input.executableSHA256 == ([32]byte{}) || input.networkPolicyID != scope.NetworkPolicyID || !input.topology.Enabled ||
		input.cleanupTimeout <= 0 || input.cleanupTimeout > time.Minute || input.proxy.ApplicationRoutes != nil {
		return false
	}
	for _, dependency := range []any{input.topology.Starter, input.topology.Runner, input.topology.Reachability, input.topology.Ownership, input.tap.Command} {
		if dependency != nil && interfaceValueIsNil(dependency) {
			return false
		}
	}
	if _, err := policyproxy.New(input.proxy); err != nil { // Inert; never binds.
		return false
	}
	if _, err := l7network.NewLinuxTAP(input.tap); err != nil {
		return false
	}
	return validMinimalPreexecPolicy(input.proxy.Policy)
}

func validMinimalPreexecPolicy(policy networkenforcement.PolicyProxyPolicyInput) bool {
	p := policy.PlanMetadata()
	if !reflect.DeepEqual(p, networkenforcement.SanitizePlan(p)) || !sandboxruntime.ValidMinimalLaunchID(p.ID) ||
		p.PolicySnapshot == nil || !sandboxruntime.ValidMinimalLaunchID(p.PolicySnapshot.ID) ||
		p.PolicySnapshot.Preset != networkenforcement.PolicyPresetDenyByDefault || p.DefaultPosture != networkenforcement.DefaultPostureDenyByDefault ||
		p.Proxy == nil || p.Proxy.Mechanism != networkenforcement.EnforcementMechanismProxy ||
		p.Proxy.HTTP != networkenforcement.ProxyRoutingModeRouteViaProxy || p.Proxy.HTTPS != networkenforcement.ProxyRoutingModeRouteViaProxy ||
		p.Firewall == nil || p.Firewall.Mode != networkenforcement.FirewallIntentModeApply || p.Firewall.Mechanism != networkenforcement.EnforcementMechanismFirewall {
		return false
	}
	// Fixed selected deny-by-default intent cannot carry a contradictory
	// allow/audit override, even when that override is syntactically sanitized.
	var postures []networkenforcement.Posture
	if p.Category != nil {
		postures = append(postures, p.Category.PrivateNetwork, p.Category.MetadataEndpoint)
	}
	if p.RawProtocols != nil {
		postures = append(postures, p.RawProtocols.TCP, p.RawProtocols.UDP, p.RawProtocols.ICMP)
	}
	for _, posture := range postures {
		if posture != "" && posture != networkenforcement.PostureUnspecified && posture != networkenforcement.PostureBlock {
			return false
		}
	}
	rules := networkenforcement.NormalizeAllowlistRules(policy.AllowlistRules)
	if !rules.Valid {
		return false
	}
	seen := make(map[string]bool)
	for _, rule := range policy.AllowlistRules {
		if !sandboxruntime.ValidMinimalLaunchID(rule.ID) || seen[rule.ID] || strings.TrimSpace(rule.Value) != rule.Value {
			return false
		}
		seen[rule.ID] = true
	}
	if len(policy.AllowlistRules) == 0 {
		return p.Allowlist == nil || len(p.Allowlist.RuleIDs) == 0 && len(p.Allowlist.RuleCategories) == 0
	}
	return p.Allowlist != nil && p.Allowlist.Mode == networkenforcement.AllowlistModeEnforce &&
		slices.Equal(p.Allowlist.RuleIDs, rules.RuleIDs) && slices.Equal(p.Allowlist.RuleCategories, rules.RuleCategories) && slices.Equal(p.Allowlist.Operations, rules.Operations)
}

func (host *minimalPreexecHost) current() bool {
	return host != nil && host.self == host && host.provider != nil && host.provider.self == host.provider &&
		host.association == host.provider.association && minimalTemplateOwnerCurrent(host.context)
}

func (host *minimalPreexecHost) checkFiles(ctx context.Context, files [3]*os.File) error {
	for index, file := range files {
		pin, err := minimalPreexecInputPin(ctx, file, index, host.uid, host.input.executableSHA256)
		if err != nil || pin != host.pins[index] {
			return sandboxruntime.ErrMinimalLaunchUnavailable
		}
	}
	return nil
}

func minimalPreexecInputPin(ctx context.Context, file *os.File, role int, uid uint32, digest [32]byte) (l8RuntimeOwnerKeyIdentity, error) {
	invalid := sandboxruntime.ErrMinimalLaunchUnavailable
	if file == nil || !minimalTemplateOwnerCurrent(ctx) {
		return l8RuntimeOwnerKeyIdentity{}, invalid
	}
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	identity, statErr := realL8RuntimeOwnerKeyFDOps().Stat(fd)
	if err != nil || statErr != nil || flags&unix.FD_CLOEXEC == 0 || identity.UID != uid {
		return l8RuntimeOwnerKeyIdentity{}, invalid
	}
	switch role {
	case 0:
		if validateL8RuntimeOwnerDirectoryFD(fd) != nil {
			return l8RuntimeOwnerKeyIdentity{}, invalid
		}
		// Creating owned child directories legitimately changes size/link count.
		// Root authority is its stable device/inode, owner and private mode.
		identity.Size, identity.Links = 0, 0
	case 1:
		if !validL8RuntimeOwnerKeyIdentity(identity, uid) {
			return l8RuntimeOwnerKeyIdentity{}, invalid
		}
	case 2:
		if validateStrictJailerExecutableSnapshot(file) != nil || identity.Links != 0 || identity.Mode != 0o555 ||
			minimalPreexecHash(ctx, file, identity.Size, maxStrictJailerExecutableBytes) != digest {
			return l8RuntimeOwnerKeyIdentity{}, invalid
		}
	default:
		return l8RuntimeOwnerKeyIdentity{}, invalid
	}
	if !minimalTemplateOwnerCurrent(ctx) {
		return l8RuntimeOwnerKeyIdentity{}, invalid
	}
	return identity, nil
}

func minimalPreexecHash(ctx context.Context, file *os.File, size, limit int64) [32]byte {
	if file == nil || size <= 0 || size > limit || !minimalTemplateOwnerCurrent(ctx) {
		return [32]byte{}
	}
	hash := sha256.New()
	reader := io.NewSectionReader(file, 0, size)
	var buffer [64 << 10]byte
	for remaining := size; remaining > 0; {
		if !minimalTemplateOwnerCurrent(ctx) {
			return [32]byte{}
		}
		n, err := io.ReadFull(reader, buffer[:min(int64(len(buffer)), remaining)])
		if err != nil || n == 0 {
			return [32]byte{}
		}
		_, _ = hash.Write(buffer[:n])
		remaining -= int64(n)
	}
	return [32]byte(hash.Sum(nil))
}

func minimalPreexecCaptureFile(slot **os.File, file *os.File, protected []*os.File) error {
	if file == nil || *slot != nil || file.Fd() <= 2 || file.Fd() == ^uintptr(0) {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	for _, old := range protected {
		if old != nil && (file == old || file.Fd() == old.Fd()) {
			return sandboxruntime.ErrMinimalLaunchUnavailable
		}
	}
	*slot = file // Capture unique ownership even if the callback also returned an error.
	return nil
}

// Borrow callbacks execute outside host.mu. Close first cancels the lifetime,
// then waits for admitted borrows; it never closes a borrowed FD underneath IO.
func (host *minimalPreexecHost) beginBorrow() ([3]*os.File, func(), error) {
	if host == nil || host.self != host {
		return [3]*os.File{}, nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.current() || host.closed || !host.usable {
		return [3]*os.File{}, nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	if host.borrows == 0 {
		host.idle = make(chan struct{})
	}
	host.borrows++
	release := func() {
		host.mu.Lock()
		defer host.mu.Unlock()
		host.borrows--
		if host.borrows == 0 {
			close(host.idle)
			host.idle = nil
		}
	}
	return [3]*os.File{host.stateRoot, host.stableKey, host.executable}, release, nil
}

func (host *minimalPreexecHost) close() error {
	if host == nil || host.self != host || host.cancel == nil {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	host.cancel() // Outside the mutex, including context callbacks.
	host.mu.Lock()
	if done := host.closeDone; done != nil {
		host.mu.Unlock()
		<-done
		return host.closeErr
	}
	host.closed, host.closeDone = true, make(chan struct{})
	idle := host.idle
	host.mu.Unlock()
	if idle != nil {
		<-idle
	}
	var err error
	for _, file := range []*os.File{host.stateRoot, host.stableKey, host.executable} {
		if file != nil && file.Close() != nil {
			err = sandboxruntime.ErrMinimalLaunchUnavailable
		}
	}
	host.mu.Lock()
	host.closeErr = err
	close(host.closeDone)
	host.mu.Unlock()
	return err
}
