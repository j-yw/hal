//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/base32"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
	"golang.org/x/sys/unix"
)

// Only the private per-call test sibling substitutes these boundaries. It
// cannot supply a Session, descriptor, claim, context or prepared result.
type minimalPreexecOps struct {
	network   func(minimalPreexecHostInputs, l7network.Identity, networkenforcement.Plan) (*l7network.Coordinator, error)
	seed      func(context.Context) (*minimalControllerSeedOwner, error)
	entropy   func([]byte) (int, error)
	duplicate func(*os.File) (*os.File, error)
	seal      func(context.Context, []byte) (*os.File, error)
}

type minimalPreexecAttempt struct {
	owner                                              *minimalTemplateAssetOwner
	host                                               *minimalPreexecHost
	ctx                                                context.Context
	cancel                                             context.CancelFunc
	setupDone, stop, contextDone, lossDone             chan struct{}
	stopOnce                                           sync.Once
	lost                                               atomic.Bool
	retired                                            atomic.Bool
	prepared                                           bool
	ops                                                minimalPreexecOps
	hostFiles                                          [3]*os.File
	directory                                          *os.File
	directoryPin                                       l8RuntimeOwnerKeyIdentity
	directoryCreated                                   bool
	coordinator                                        *l7network.Coordinator
	session                                            *l7network.Session
	networkIdentity                                    l7network.Identity
	networkPlan                                        networkenforcement.Plan
	namespace                                          [2]*os.File
	namespacePins                                      minimalControlNamespaces
	seed                                               *minimalControllerSeedOwner
	fcFile, configFile                                 *os.File
	config                                             minimalControlSupervisorConfig
	configDigest                                       [32]byte
	expectation                                        minimalControlConfigExpectation
	filesClosed, rollbackComplete                      bool
	closeErr                                           error
	publicGenerations                                  [3]string
	bootNonce                                          [32]byte
	prepareStarted, prepareReturned, successfulPrepare bool
}

// Preparation belongs to the exact claimed asset owner. No production caller
// or exec is enabled, and no replacement context/deadline is accepted.
func (owner *minimalTemplateAssetOwner) prepareMinimalInputs(host *minimalPreexecHost) error {
	if host == nil || host.uid != 0 || os.Geteuid() != 0 {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return owner.prepareMinimalInputsWithOps(host, minimalPreexecOps{
		network: newMinimalPreexecNetwork, seed: newMinimalControllerSeed,
		entropy: minimalControlControllerEntropy{}.Read, duplicate: duplicateJailerRecoveryFile, seal: sealJailerRecoveryBytes,
	})
}

func (owner *minimalTemplateAssetOwner) prepareMinimalInputsWithOps(host *minimalPreexecHost, ops minimalPreexecOps) (resultErr error) {
	resultErr = sandboxruntime.ErrMinimalLaunchUnavailable
	if owner == nil || owner.self != owner || owner.source == nil || host == nil || host.self != host ||
		ops.network == nil || ops.seed == nil || ops.entropy == nil || ops.duplicate == nil || ops.seal == nil {
		return resultErr
	}
	if !owner.preparationCurrent(host) {
		return resultErr
	}
	owner.source.mu.Lock()
	if owner.source.owner != owner || owner.closed || owner.attempt != nil || !owner.preparationCurrent(host) {
		owner.source.mu.Unlock()
		return resultErr
	}
	a := &minimalPreexecAttempt{owner: owner, host: host, ops: ops, setupDone: make(chan struct{}),
		stop: make(chan struct{}), contextDone: make(chan struct{})}
	a.ctx, a.cancel = context.WithCancel(owner.preparation)
	owner.attempt = a // Before observers, borrowing or any allocating callback.
	owner.source.mu.Unlock()
	defer func() {
		if recover() != nil {
			resultErr = sandboxruntime.ErrMinimalLaunchUnavailable
		}
		if resultErr != nil {
			a.cancel()
		}
		close(a.setupDone)
	}()
	go func() {
		defer close(a.contextDone)
		select {
		case <-host.context.Done():
			a.cancel()
		case <-owner.context.Done():
			a.cancel()
		case <-a.ctx.Done():
		case <-a.stop:
		}
	}()
	if !a.current() || a.borrowHostFiles() != nil || !a.current() || a.createDirectory() != nil ||
		!a.current() || a.issuePublicIdentity() != nil || !a.current() {
		return resultErr
	}
	input := host.input
	input.proxy.Policy = networkenforcement.NewPolicyProxyPolicyInput(input.proxy.Policy.PlanMetadata(), input.proxy.Policy.AllowlistRules)
	input.topology.Environment = slices.Clone(input.topology.Environment)
	coordinator, err := ops.network(input, a.networkIdentity, networkenforcement.SanitizePlan(a.networkPlan))
	a.coordinator = coordinator
	if err != nil || coordinator == nil || !a.current() {
		return resultErr
	}
	// Prepare remains outside substitution. An internal panic before return
	// cannot be represented as a successfully captured partial Session.
	a.prepareStarted = true
	a.session, err = coordinator.Prepare(a.ctx, l7network.PrepareRequest{Identity: a.networkIdentity, Plan: a.networkPlan})
	a.prepareReturned = true
	a.successfulPrepare = err == nil && a.session != nil
	if err != nil || a.session == nil || !a.current() {
		return resultErr
	}
	a.lossDone = make(chan struct{})
	go func() {
		defer close(a.lossDone)
		select {
		case <-a.session.Loss():
			a.lost.Store(true)
			a.cancel()
		case <-a.stop:
		}
	}()
	metadata := a.session.Metadata()
	if metadata.Identity != a.networkIdentity || metadata.Status != l7network.StatusHostPrepared || metadata.RawPacketIsolationVerified {
		return resultErr
	}
	view, err := a.session.ProcessNamespace(a.networkIdentity)
	if err != nil || !a.current() {
		return resultErr
	}
	user, network, err := view.DuplicateForNamespaceProcess()
	userErr := a.capture(&a.namespace[0], user)
	networkErr := a.capture(&a.namespace[1], network)
	if err != nil || userErr != nil || networkErr != nil || !a.current() {
		return resultErr
	}
	a.namespacePins, err = minimalPreexecNamespacePins(a.namespace)
	if err != nil || !a.current() {
		return resultErr
	}
	a.seed, err = ops.seed(a.ctx) // Preserve the actual owner even with an error.
	if err != nil || a.seed == nil || a.seed.self != a.seed || !a.current() {
		return resultErr
	}
	if err := a.assembleConfig(); err != nil || !a.current() || a.validatePreparedFiles() != nil {
		return resultErr
	}
	owner.source.mu.Lock()
	defer owner.source.mu.Unlock()
	if owner.attempt != a || owner.closed || !owner.preparationCurrent(host) || !a.current() {
		return resultErr
	}
	a.prepared = true
	return nil
}

func (owner *minimalTemplateAssetOwner) preparationCurrent(host *minimalPreexecHost) bool {
	if owner == nil || owner.self != owner || owner.source == nil || owner.source.self != owner.source ||
		host == nil || !host.current() || host.provider != owner.source.provider || !owner.source.matchesAssociation() ||
		owner.reservation == nil || owner.reservation.Identity() != owner.identity || owner.reservation.Context() != owner.preparation ||
		owner.reservation.OwnedContext() != owner.context || !minimalTemplateClaimMatches(owner.identity, owner.source) ||
		!owner.sealed || owner.lease == nil || minimalTemplateContextError(owner.preparation) != nil || !minimalTemplateOwnerCurrent(owner.context) {
		return false
	}
	p, ok := owner.preparation.Deadline()
	template, templateErr := owner.reservation.TemplateIdentity()
	request, requestErr := owner.reservation.RequestCorrelation()
	return ok && p == owner.preparationDeadline && time.Now().Before(p) && templateErr == nil && requestErr == nil &&
		template == owner.template && template == host.association.template && request == owner.request
}

func (a *minimalPreexecAttempt) current() bool {
	return a != nil && !a.retired.Load() && !a.lost.Load() && minimalTemplateContextError(a.ctx) == nil && a.owner.preparationCurrent(a.host) &&
		a.owner.lease.ConfirmCurrent(a.ctx) == nil
}

func (a *minimalPreexecAttempt) capture(slot **os.File, file *os.File, other ...*os.File) error {
	protected := append(other, a.owner.files[0], a.owner.files[1], a.hostFiles[0], a.hostFiles[1], a.hostFiles[2],
		a.directory, a.namespace[0], a.namespace[1], a.fcFile, a.configFile)
	if a.seed != nil {
		seed, _ := a.seed.borrowFile()
		protected = append(protected, seed)
	}
	return minimalPreexecCaptureFile(slot, file, protected)
}

func (a *minimalPreexecAttempt) borrowHostFiles() error {
	borrowed, release, err := a.host.beginBorrow()
	if err != nil {
		return err
	}
	defer release()
	if !a.current() || a.host.checkFiles(a.ctx, borrowed) != nil {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	for index, file := range borrowed {
		if !a.current() {
			return sandboxruntime.ErrMinimalLaunchUnavailable
		}
		duplicate, err := a.ops.duplicate(file)
		captureErr := a.capture(&a.hostFiles[index], duplicate, borrowed[:]...)
		if err != nil || captureErr != nil || !a.current() {
			return sandboxruntime.ErrMinimalLaunchUnavailable
		}
	}
	return a.host.checkFiles(a.ctx, a.hostFiles)
}

func (a *minimalPreexecAttempt) createDirectory() error {
	name := a.owner.identity.RuntimeGeneration
	if !sandboxruntime.ValidMinimalLaunchID(name) || !a.current() {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	root := int(a.hostFiles[0].Fd())
	if unix.Mkdirat(root, name, 0o700) != nil {
		return sandboxruntime.ErrMinimalLaunchUnavailable // Never open/reuse a collision.
	}
	a.directoryCreated = true // Retain entry uncertainty even if Open fails.
	fd, err := unix.Openat(root, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if fd >= 0 {
		a.directory = os.NewFile(uintptr(fd), "minimal-preexec-owner-directory")
	}
	if err != nil || a.directory == nil || !a.current() {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	a.directoryPin, err = minimalPreexecInputPin(a.ctx, a.directory, 0, a.host.uid, [32]byte{})
	if err != nil {
		return err
	}
	return a.checkDirectory()
}

func (a *minimalPreexecAttempt) checkDirectory() error {
	actual, err := minimalPreexecInputPin(a.ctx, a.directory, 0, a.host.uid, [32]byte{})
	var entry unix.Stat_t
	if err != nil || actual != a.directoryPin || unix.Fstatat(int(a.hostFiles[0].Fd()), a.owner.identity.RuntimeGeneration, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		entry.Mode&unix.S_IFMT != unix.S_IFDIR || entry.Mode&0o7777 != 0o700 || entry.Uid != a.host.uid || uint64(entry.Dev) != actual.Device || entry.Ino != actual.Inode {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return nil
}

func (a *minimalPreexecAttempt) issuePublicIdentity() error {
	c := a.owner.identity
	identity := l7network.Identity{SandboxID: c.SandboxID, ExecutionID: c.ExecutionID, WorkerID: c.WorkerID, RuntimeGenerationID: c.RuntimeGeneration,
		PolicySnapshotID: a.host.input.proxy.Policy.PlanMetadata().PolicySnapshot.ID}
	seen := make(map[string]bool)
	for _, id := range []string{identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.RuntimeGenerationID, identity.PolicySnapshotID} {
		if !sandboxruntime.ValidMinimalLaunchID(id) || strings.ContainsAny(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ.") || seen[id] {
			return sandboxruntime.ErrMinimalLaunchUnavailable
		}
		seen[id] = true
	}
	seen[c.PlanID] = true
	draws := make(map[[32]byte]bool)
	fields := []*string{&identity.PlanID, &identity.ProxySessionID, &identity.ProxyGenerationID, &identity.TopologyGenerationID, &identity.RuleGenerationID,
		&a.publicGenerations[0], &a.publicGenerations[1], &a.publicGenerations[2]}
	for _, field := range fields {
		draw, err := a.drawPublic(draws)
		if err != nil {
			return err
		}
		// Preserve every entropy byte while staying inside the shared 64-byte
		// grammar. A letter prefix avoids numeric-only metadata rejection.
		value := "g-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(draw[:]))
		if seen[value] {
			return sandboxruntime.ErrMinimalLaunchUnavailable
		}
		seen[value], *field = true, value
	}
	nonce, err := a.drawPublic(draws)
	if err != nil {
		return err
	}
	a.networkIdentity, a.bootNonce = identity, nonce
	a.networkPlan = a.host.input.proxy.Policy.PlanMetadata()
	a.networkPlan.ID, a.networkPlan.Proxy.ProxySessionID = identity.PlanID, identity.ProxySessionID
	if !reflect.DeepEqual(a.networkPlan, networkenforcement.SanitizePlan(a.networkPlan)) {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return nil
}

func (a *minimalPreexecAttempt) drawPublic(seen map[[32]byte]bool) ([32]byte, error) {
	var value [32]byte
	defer clear(value[:])
	if !a.current() {
		return [32]byte{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	n, err := a.ops.entropy(value[:])
	if err != nil || n != len(value) || value == ([32]byte{}) || seen[value] || !a.current() {
		return [32]byte{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	seen[value] = true
	return value, nil
}

func minimalPreexecNamespacePins(files [2]*os.File) (minimalControlNamespaces, error) {
	if files[0] == nil || files[1] == nil || validateL8RuntimeOwnerNamespacePair(int(files[0].Fd()), int(files[1].Fd())) != nil {
		return minimalControlNamespaces{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	var pins [2]l8RuntimeOwnerNSIdentity
	for index, file := range files {
		pin, err := l8RuntimeOwnerStatNamespaceFD(int(file.Fd()))
		kind, kindErr := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_NSTYPE)
		if err != nil || kindErr != nil || kind != []int{unix.CLONE_NEWUSER, unix.CLONE_NEWNET}[index] {
			return minimalControlNamespaces{}, sandboxruntime.ErrMinimalLaunchUnavailable
		}
		pins[index] = pin
	}
	return minimalControlNamespaces{UserDevice: pins[0].device, UserInode: pins[0].inode, NetworkDevice: pins[1].device, NetworkInode: pins[1].inode}, nil
}

func newMinimalPreexecNetwork(input minimalPreexecHostInputs, _ l7network.Identity, plan networkenforcement.Plan) (*l7network.Coordinator, error) {
	proxyConfig := input.proxy
	proxyConfig.Policy = networkenforcement.NewPolicyProxyPolicyInput(plan, input.proxy.Policy.AllowlistRules)
	adapter, err := policyproxy.New(proxyConfig)
	if err != nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	proxy, err := l7network.NewProductionProxy(adapter)
	if err != nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	lifecycle, err := linuxtopology.New(input.topology)
	if err != nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	topology, err := l7network.NewLinuxTopology(lifecycle)
	if err != nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	tap, err := l7network.NewLinuxTAP(input.tap)
	if err != nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	executor, err := linuxrules.NewProductionExecutor(input.rules)
	if err != nil {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return l7network.New(l7network.Options{Enabled: true, Proxy: proxy, Topology: topology, TAP: tap,
		Rules: linuxrules.NewAdapter(executor, linuxrules.AdapterOptions{}), GuestIsolation: minimalPreexecNoGuest{}, VMTermination: minimalPreexecNoGuest{},
		StateDir: input.networkStateDirectory, CleanupTimeout: input.cleanupTimeout})
}

// Incapable dependencies, not selected guest/terminal adapters. There is no
// exec caller or guest inspection transition in this assembler.
type minimalPreexecNoGuest struct{}

func (minimalPreexecNoGuest) VerifyRunningGuestRawPacketIsolation(context.Context, l7network.RunningGuestRawPacketIsolationRequest) (l7network.RunningGuestRawPacketIsolationProof, error) {
	return l7network.RunningGuestRawPacketIsolationProof{}, sandboxruntime.ErrMinimalLaunchUnavailable
}
func (minimalPreexecNoGuest) VerifyVMTermination(context.Context, l7network.VMTerminationRequest) (l7network.VMTerminationProof, error) {
	return l7network.VMTerminationProof{}, sandboxruntime.ErrMinimalLaunchUnavailable
}

// Called only by the same owner's admitted Finalize, after setupDone. No
// source/host mutex is held during callbacks, file closure or observer joins.
func (a *minimalPreexecAttempt) cleanup(ctx context.Context) {
	defer func() {
		if recover() != nil {
			a.closeErr = sandboxruntime.ErrMinimalLaunchUnavailable
		}
	}()
	if !a.filesClosed {
		// Consume each os.File once, never retry a raw descriptor number.
		a.filesClosed = true
		for _, file := range []*os.File{a.configFile, a.fcFile, a.namespace[0], a.namespace[1], a.directory, a.hostFiles[2], a.hostFiles[1], a.hostFiles[0]} {
			if file != nil && file.Close() != nil {
				a.closeErr = sandboxruntime.ErrMinimalLaunchUnavailable
			}
		}
		if a.seed != nil && a.seed.close() != nil {
			a.closeErr = sandboxruntime.ErrMinimalLaunchUnavailable
		}
	}
	a.stopOnce.Do(func() { close(a.stop) })
	if !minimalPreexecWait(ctx, a.contextDone) || a.lossDone != nil && !minimalPreexecWait(ctx, a.lossDone) || minimalTemplateContextError(ctx) != nil {
		return
	}
	if a.rollbackComplete {
		return
	}
	if a.session == nil {
		// Constructor failure has no Session. An unreturned Session after an
		// internal Prepare panic cannot be recovered or called clean here.
		a.rollbackComplete = !a.prepareStarted || a.prepareReturned
		return
	}
	if a.session.AbortBeforeVM(ctx, a.networkIdentity) != nil {
		return // Keep this Session and its rollback journal for a later retry.
	}
	if a.successfulPrepare && !minimalPreexecWait(ctx, a.session.Loss()) {
		return // Notification boundary only, not a join of underlying tasks.
	}
	a.rollbackComplete = true
}

func minimalPreexecWait[T any](ctx context.Context, done <-chan T) bool {
	if minimalTemplateContextError(ctx) != nil {
		return false
	}
	deadline, _ := ctx.Deadline()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-done:
		return minimalTemplateContextError(ctx) == nil
	case <-ctx.Done():
	case <-timer.C:
	}
	return false
}
