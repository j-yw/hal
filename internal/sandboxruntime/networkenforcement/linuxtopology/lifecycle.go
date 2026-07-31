package linuxtopology

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"time"
)

type Lifecycle struct {
	mu         sync.Mutex
	config     Config
	supported  bool
	production bool
	active     map[string]*Session
	stopped    map[string]Metadata
}

type Session struct {
	mu        sync.Mutex
	identity  Identity
	mapping   Mapping
	metadata  Metadata
	keeper    ProcessHandle
	mapper    ProcessHandle
	namespace *NamespaceHandle
	losses    chan Loss
	lossOnce  sync.Once
	stopping  bool
}

func New(input Config) (*Lifecycle, error) {
	config := input
	if config.CleanupTimeout == 0 {
		config.CleanupTimeout = defaultCleanupTimeout
	}
	if config.InspectionTimeout == 0 {
		config.InspectionTimeout = defaultInspectionTimeout
	}
	if config.InspectionInterval == 0 {
		config.InspectionInterval = defaultInspectionInterval
	}
	if config.OutputLimit == 0 {
		config.OutputLimit = defaultOutputLimit
	}
	config.Environment = append([]string(nil), config.Environment...)

	lifecycle := &Lifecycle{
		config:  config,
		active:  make(map[string]*Session),
		stopped: make(map[string]Metadata),
	}
	if !config.Enabled {
		return lifecycle, nil
	}
	if !validToolPaths(config.Tools) || !validEnvironment(config.Environment) ||
		config.CleanupTimeout <= 0 || config.CleanupTimeout > time.Minute ||
		config.InspectionTimeout <= 0 || config.InspectionTimeout > time.Minute ||
		config.InspectionInterval <= 0 || config.InspectionInterval > time.Second ||
		config.OutputLimit <= 0 || config.OutputLimit > maxOutputLimit {
		return nil, ErrInvalidTools
	}

	defaults := config.Starter == nil || config.Runner == nil || config.OpenNamespaces == nil
	supported, starter, runner, opener := platformDependencies()
	lifecycle.supported = supported
	lifecycle.production = defaults
	if config.Starter == nil {
		config.Starter = starter
	}
	if config.Runner == nil {
		config.Runner = runner
	}
	if config.OpenNamespaces == nil {
		config.OpenNamespaces = opener
	}
	if defaults && supported && !executableToolPaths(config.Tools) {
		return nil, ErrInvalidTools
	}
	lifecycle.config = config
	return lifecycle, nil
}

func (l *Lifecycle) Start(ctx context.Context, request StartRequest) (*Session, error) {
	if l == nil || !l.config.Enabled {
		return nil, ErrDisabled
	}
	if !l.supported {
		return nil, ErrUnsupported
	}
	if !validIdentity(request.Identity) {
		return nil, ErrInvalidIdentity
	}
	if !validMapping(request.Mapping) {
		return nil, ErrInvalidMapping
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrStartFailed
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if current := l.active[request.Identity.SandboxID]; current != nil {
		current.mu.Lock()
		sameIdentity := current.identity == request.Identity
		sameMapping := current.mapping == request.Mapping
		status := current.metadata.Status
		current.mu.Unlock()
		if sameIdentity && sameMapping && status == StatusActive {
			return current, nil
		}
		if current.identity.TopologyGenerationID == request.Identity.TopologyGenerationID {
			return nil, ErrIdentityMismatch
		}
		return nil, ErrTopologyCollision
	}

	keeper, err := l.config.Starter.Start(ctx, l.keeperSpec())
	if err != nil || keeper == nil || keeper.PID() <= 0 {
		return nil, ErrStartFailed
	}

	owned, err := l.openInitialNamespaces(ctx, keeper)
	if err != nil {
		if l.rollback(nil, nil, keeper) != nil {
			return nil, ErrCleanupIncomplete
		}
		return nil, ErrStartFailed
	}

	files, err := owned.extraFiles()
	if err != nil {
		if l.rollback(nil, owned, keeper) != nil {
			return nil, ErrCleanupIncomplete
		}
		return nil, ErrStartFailed
	}
	mappingSpec := l.mappingSpec(request.Mapping, files)
	mapper, startErr := l.config.Starter.Start(ctx, mappingSpec)
	closeFiles(files)
	if startErr != nil || mapper == nil || mapper.PID() <= 0 {
		if l.rollback(nil, owned, keeper) != nil {
			return nil, ErrCleanupIncomplete
		}
		return nil, ErrStartFailed
	}

	if err := l.inspect(ctx, keeper, mapper, owned, request.Mapping); err != nil {
		if l.rollback(mapper, owned, keeper) != nil {
			return nil, ErrCleanupIncomplete
		}
		return nil, ErrInspectionFailed
	}
	if processDone(keeper) || processDone(mapper) {
		if l.rollback(mapper, owned, keeper) != nil {
			return nil, ErrCleanupIncomplete
		}
		return nil, ErrStartFailed
	}

	session := &Session{
		identity:  request.Identity,
		mapping:   request.Mapping,
		metadata:  Metadata{Identity: request.Identity, Status: StatusActive, Inspected: true},
		keeper:    keeper,
		mapper:    mapper,
		namespace: owned,
		losses:    make(chan Loss, 1),
	}
	l.active[request.Identity.SandboxID] = session
	go session.watch(ProcessRoleKeeper, keeper)
	go session.watch(ProcessRoleMapping, mapper)
	return session, nil
}

func (l *Lifecycle) Stop(_ context.Context, identity Identity) (Metadata, error) {
	if l == nil || !l.config.Enabled {
		return Metadata{}, ErrDisabled
	}
	if !l.supported {
		return Metadata{}, ErrUnsupported
	}
	if !validIdentity(identity) {
		return Metadata{}, ErrInvalidIdentity
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	session := l.active[identity.SandboxID]
	if session == nil {
		if stopped, ok := l.stopped[identity.SandboxID]; ok {
			if stopped.Identity == identity {
				return stopped, nil
			}
			return Metadata{}, ErrStaleGeneration
		}
		return Metadata{}, ErrStaleGeneration
	}
	if session.identity.TopologyGenerationID != identity.TopologyGenerationID {
		return Metadata{}, ErrStaleGeneration
	}
	if session.identity != identity {
		return Metadata{}, ErrIdentityMismatch
	}

	session.mu.Lock()
	session.stopping = true
	mapper := session.mapper
	owned := session.namespace
	keeper := session.keeper
	session.mu.Unlock()

	cleanupErr := l.cleanup(mapper, owned, keeper)
	session.mu.Lock()
	if cleanupErr != nil {
		session.metadata.Status = StatusCleanupIncomplete
		metadata := session.metadata
		session.mu.Unlock()
		return metadata, ErrCleanupIncomplete
	}
	session.mapper = nil
	session.keeper = nil
	session.namespace = nil
	session.metadata.Status = StatusStopped
	metadata := session.metadata
	session.mu.Unlock()
	delete(l.active, identity.SandboxID)
	l.stopped[identity.SandboxID] = metadata
	return metadata, nil
}

func (l *Lifecycle) keeperSpec() ProcessSpec {
	return ProcessSpec{
		Role: ProcessRoleKeeper,
		Path: l.config.Tools.Unshare,
		Args: []string{
			"--user", "--map-current-user", "--net", "--fork", "--kill-child=TERM",
			"--", l.config.Tools.Keeper, "infinity",
		},
		Env:         append([]string(nil), l.config.Environment...),
		OutputLimit: l.config.OutputLimit,
	}
}

func (l *Lifecycle) mappingSpec(mapping Mapping, files []*os.File) ProcessSpec {
	return ProcessSpec{
		Role: ProcessRoleMapping,
		Path: l.config.Tools.Pasta,
		Args: []string{
			"--foreground", "--quiet",
			"--userns", "/proc/self/fd/3",
			"--netns", "/proc/self/fd/4",
			"--map-host-loopback", mapping.GuestProxyAddress,
			"--no-map-gw",
			"-t", "none", "-u", "none", "-T", "none", "-U", "none",
			"-I", mapping.NamespaceInterface,
		},
		Env:         append([]string(nil), l.config.Environment...),
		ExtraFiles:  append([]*os.File(nil), files...),
		OutputLimit: l.config.OutputLimit,
	}
}

func (l *Lifecycle) inspectionSpec(files []*os.File) ProcessSpec {
	return ProcessSpec{
		Role: ProcessRoleInspection,
		Path: l.config.Tools.Nsenter,
		Args: []string{
			"--preserve-credentials",
			"--user=/proc/self/fd/3",
			"--net=/proc/self/fd/4",
			"--", l.config.Tools.IP, "-json", "link", "show",
		},
		Env:         append([]string(nil), l.config.Environment...),
		ExtraFiles:  append([]*os.File(nil), files...),
		OutputLimit: l.config.OutputLimit,
	}
}

func (l *Lifecycle) openInitialNamespaces(ctx context.Context, keeper ProcessHandle) (*NamespaceHandle, error) {
	if !l.production {
		return l.config.OpenNamespaces(keeper.PID())
	}
	deadline := time.Now().Add(l.config.InspectionTimeout)
	for {
		handle, err := l.config.OpenNamespaces(keeper.PID())
		if err == nil {
			return handle, nil
		}
		if time.Now().After(deadline) || processDone(keeper) {
			return nil, ErrStartFailed
		}
		if err := waitInterval(ctx, l.config.InspectionInterval); err != nil {
			return nil, ErrStartFailed
		}
	}
}

func (l *Lifecycle) inspect(parent context.Context, keeper, mapper ProcessHandle, owned *NamespaceHandle, mapping Mapping) error {
	ctx, cancel := context.WithTimeout(parent, l.config.InspectionTimeout)
	defer cancel()
	for {
		if processDone(keeper) || processDone(mapper) {
			return ErrInspectionFailed
		}
		current, err := l.config.OpenNamespaces(keeper.PID())
		if err == nil {
			correlated := current.Correlates(owned)
			_ = current.Close()
			if correlated {
				files, fileErr := owned.extraFiles()
				if fileErr == nil {
					output, runErr := l.config.Runner.Run(ctx, l.inspectionSpec(files))
					closeFiles(files)
					if runErr == nil && int64(len(output)) <= l.config.OutputLimit && validLinkInspection(output, mapping.NamespaceInterface) {
						return nil
					}
				}
			}
		}
		if err := waitInterval(ctx, l.config.InspectionInterval); err != nil {
			return ErrInspectionFailed
		}
	}
}

func validLinkInspection(output []byte, mappingInterface string) bool {
	var links []struct {
		Index int      `json:"ifindex"`
		Name  string   `json:"ifname"`
		Flags []string `json:"flags"`
	}
	if len(output) == 0 || json.Unmarshal(output, &links) != nil {
		return false
	}
	indices := make(map[int]struct{}, len(links))
	loopbackOK := false
	mappingOK := false
	for _, link := range links {
		if link.Index <= 0 {
			return false
		}
		if _, duplicate := indices[link.Index]; duplicate {
			return false
		}
		indices[link.Index] = struct{}{}
		up := slices.Contains(link.Flags, "UP")
		switch link.Name {
		case "lo":
			if loopbackOK || !up || !slices.Contains(link.Flags, "LOOPBACK") {
				return false
			}
			loopbackOK = true
		case mappingInterface:
			if mappingOK || !up {
				return false
			}
			mappingOK = true
		}
	}
	return loopbackOK && mappingOK
}

func (l *Lifecycle) rollback(mapper ProcessHandle, owned *NamespaceHandle, keeper ProcessHandle) error {
	return l.cleanup(mapper, owned, keeper)
}

func (l *Lifecycle) cleanup(mapper ProcessHandle, owned *NamespaceHandle, keeper ProcessHandle) error {
	ctx, cancel := context.WithTimeout(context.Background(), l.config.CleanupTimeout)
	defer cancel()
	var result error
	if mapper != nil {
		result = errors.Join(result, mapper.Terminate(ctx))
	}
	if owned != nil {
		result = errors.Join(result, owned.Close())
	}
	if keeper != nil {
		result = errors.Join(result, keeper.Terminate(ctx))
	}
	return result
}

func (s *Session) Metadata() Metadata {
	if s == nil {
		return Metadata{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metadata
}

func (s *Session) MarshalJSON() ([]byte, error) { return json.Marshal(s.Metadata()) }

func (s *Session) Losses() <-chan Loss {
	if s == nil {
		return nil
	}
	return s.losses
}

func (s *Session) NamespaceHandle() (*NamespaceHandle, error) {
	if s == nil {
		return nil, ErrStopped
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.namespace == nil || s.metadata.Status == StatusStopped {
		return nil, ErrStopped
	}
	return s.namespace.Duplicate()
}

func (s *Session) watch(role ProcessRole, process ProcessHandle) {
	<-process.Done()
	s.mu.Lock()
	if s.stopping || s.metadata.Status == StatusStopped || s.metadata.Status == StatusCleanupIncomplete {
		s.mu.Unlock()
		return
	}
	s.metadata.Status = StatusLost
	loss := Loss{
		TopologyGenerationID: s.identity.TopologyGenerationID,
		Component:            role,
		Reason:               LossReasonProcessExited,
	}
	s.mu.Unlock()
	s.lossOnce.Do(func() {
		select {
		case s.losses <- loss:
		default:
		}
	})
}

func processDone(process ProcessHandle) bool {
	select {
	case <-process.Done():
		return true
	default:
		return false
	}
}

func waitInterval(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
