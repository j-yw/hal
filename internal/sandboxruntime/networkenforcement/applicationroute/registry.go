package applicationroute

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// RouteHandler is one registered application route. Registry owns leaf
// lifecycle and dispatch; callers compose leaves only through Registry.
type RouteHandler interface {
	Definition() Definition
	Start(context.Context) error
	Handle(context.Context, Request) (Response, error)
	Close(context.Context) error
}

// Handler is the single composed application-route seam consumed by L6.
// L6 matches a parsed reserved path against Definitions and supplies the exact
// selected route ID to Handle.
type Handler interface {
	Definitions() []Definition
	Start(context.Context) error
	Handle(context.Context, RouteID, Request) (Response, error)
	Close(context.Context) error
}

type RegistryState string

const (
	RegistryStateUnstarted         RegistryState = "unstarted"
	RegistryStateStarting          RegistryState = "starting"
	RegistryStateStarted           RegistryState = "started"
	RegistryStateClosing           RegistryState = "closing"
	RegistryStateClosed            RegistryState = "closed"
	RegistryStateCleanupIncomplete RegistryState = "cleanup_incomplete"
)

type routeEntry struct {
	handler    RouteHandler
	definition Definition
}

// Registry is a lightweight handle to live application-route state. Keeping
// synchronization behind an unexported pointer makes copied handles safe to
// reject from serialization and formatting without copying locks or counters.
type Registry struct {
	state *registryState
}

var _ Handler = (*Registry)(nil)

type registryState struct {
	mu          sync.Mutex
	condition   *sync.Cond
	state       RegistryState
	entries     []routeEntry
	unconfirmed []bool
	dispatches  sync.WaitGroup
}

type trackedResponseBody struct {
	body        io.ReadCloser
	closeOnce   sync.Once
	releaseOnce sync.Once
	release     func()
}

func NewRegistry(handlers ...RouteHandler) (*Registry, error) {
	shared := &registryState{state: RegistryStateUnstarted}
	shared.condition = sync.NewCond(&shared.mu)
	registry := &Registry{state: shared}
	for _, handler := range handlers {
		if err := registry.Register(handler); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func (registry *Registry) Register(handler RouteHandler) error {
	shared := registry.sharedState()
	if shared == nil {
		return ErrRegistryClosed
	}
	shared.mu.Lock()
	stateErr := shared.registrationErrorLocked()
	shared.mu.Unlock()
	if stateErr != nil {
		return stateErr
	}
	if nilHandler(handler) {
		return ErrHandlerRequired
	}
	definition := handler.Definition()
	if err := ValidateDefinition(definition); err != nil {
		return ErrInvalidRoute
	}

	shared.mu.Lock()
	defer shared.mu.Unlock()
	if stateErr := shared.registrationErrorLocked(); stateErr != nil {
		return stateErr
	}
	for _, existing := range shared.entries {
		if existing.definition.ID == definition.ID || prefixesOverlap(existing.definition.Prefix, definition.Prefix) {
			return ErrRouteCollision
		}
	}
	shared.entries = append(shared.entries, routeEntry{handler: handler, definition: definition})
	return nil
}

func (registry *Registry) RouteIDs() []RouteID {
	definitions := registry.Definitions()
	ids := make([]RouteID, len(definitions))
	for index, definition := range definitions {
		ids[index] = definition.ID
	}
	return ids
}

func (registry *Registry) Definitions() []Definition {
	shared := registry.sharedState()
	if shared == nil {
		return nil
	}
	shared.mu.Lock()
	defer shared.mu.Unlock()
	definitions := make([]Definition, len(shared.entries))
	for index, entry := range shared.entries {
		definitions[index] = entry.definition
	}
	sort.Slice(definitions, func(left, right int) bool {
		if definitions[left].ID != definitions[right].ID {
			return definitions[left].ID < definitions[right].ID
		}
		return definitions[left].Prefix < definitions[right].Prefix
	})
	return definitions
}

func (registry *Registry) Start(ctx context.Context) error {
	shared := registry.sharedState()
	if shared == nil {
		return ErrRegistryClosed
	}
	shared.mu.Lock()
	switch shared.state {
	case RegistryStateUnstarted:
		shared.state = RegistryStateStarting
	case RegistryStateStarting, RegistryStateStarted:
		shared.mu.Unlock()
		return ErrRegistryStarted
	default:
		shared.mu.Unlock()
		return ErrRegistryClosed
	}
	entries := append([]routeEntry(nil), shared.entries...)
	shared.mu.Unlock()

	for index, entry := range entries {
		if err := entry.handler.Start(ctx); err != nil {
			shared.mu.Lock()
			shared.state = RegistryStateClosing
			shared.unconfirmed = make([]bool, len(entries))
			for closeIndex := 0; closeIndex <= index; closeIndex++ {
				shared.unconfirmed[closeIndex] = true
			}
			shared.mu.Unlock()

			failed := shared.closeUnconfirmed(ctx, entries)
			shared.finishClose(failed)
			return ErrHandlerStart
		}
	}

	shared.mu.Lock()
	shared.unconfirmed = make([]bool, len(entries))
	for index := range shared.unconfirmed {
		shared.unconfirmed[index] = true
	}
	shared.state = RegistryStateStarted
	shared.condition.Broadcast()
	shared.mu.Unlock()
	return nil
}

func (registry *Registry) Handle(ctx context.Context, id RouteID, request Request) (Response, error) {
	shared := registry.sharedState()
	if shared == nil {
		return Response{}, ErrRegistryClosed
	}
	shared.mu.Lock()
	switch shared.state {
	case RegistryStateUnstarted, RegistryStateStarting:
		shared.mu.Unlock()
		return Response{}, ErrRegistryNotStarted
	case RegistryStateStarted:
	default:
		shared.mu.Unlock()
		return Response{}, ErrRegistryClosed
	}
	var selected routeEntry
	found := false
	for _, entry := range shared.entries {
		if entry.definition.ID == id {
			selected = entry
			found = true
			break
		}
	}
	if !found {
		shared.mu.Unlock()
		return Response{}, ErrUnknownRoute
	}
	if err := ValidateRequestBounds(selected.definition.Limits, request); err != nil {
		shared.mu.Unlock()
		return Response{}, err
	}
	shared.mu.Unlock()

	if err := validateRequestLiveShape(selected.definition, request); err != nil {
		return Response{}, err
	}

	shared.mu.Lock()
	if shared.state != RegistryStateStarted {
		shared.mu.Unlock()
		return Response{}, ErrRegistryClosed
	}
	shared.dispatches.Add(1)
	shared.mu.Unlock()

	transferred := false
	defer func() {
		if !transferred {
			shared.dispatches.Done()
		}
	}()

	response, err := selected.handler.Handle(ctx, request)
	if err != nil {
		closeDiscardedResponseBody(response.Body)
		return Response{}, ErrHandlerDispatch
	}
	if err := ValidateResponseBounds(selected.definition.Limits, response); err != nil {
		closeDiscardedResponseBody(response.Body)
		return Response{}, err
	}
	if response.Body == nil {
		return response, nil
	}
	response.Body = newTrackedResponseBody(response.Body, shared.dispatches.Done)
	transferred = true
	return response, nil
}

// Dispatch is the compatibility spelling for composed exact-route handling.
func (registry *Registry) Dispatch(ctx context.Context, id RouteID, request Request) (Response, error) {
	return registry.Handle(ctx, id, request)
}

func (registry *Registry) Close(ctx context.Context) error {
	if registry == nil {
		return nil
	}
	shared := registry.state
	if shared == nil {
		return ErrRegistryClosed
	}
	shared.mu.Lock()
	for shared.state == RegistryStateStarting || shared.state == RegistryStateClosing {
		shared.condition.Wait()
	}
	switch shared.state {
	case RegistryStateClosed:
		shared.mu.Unlock()
		return nil
	case RegistryStateUnstarted:
		shared.state = RegistryStateClosed
		shared.condition.Broadcast()
		shared.mu.Unlock()
		return nil
	case RegistryStateStarted, RegistryStateCleanupIncomplete:
		shared.state = RegistryStateClosing
	default:
		shared.mu.Unlock()
		return ErrRegistryClosed
	}
	entries := append([]routeEntry(nil), shared.entries...)
	shared.mu.Unlock()

	shared.dispatches.Wait()
	failed := shared.closeUnconfirmed(ctx, entries)
	shared.finishClose(failed)
	if failed {
		return ErrHandlerClose
	}
	return nil
}

func (registry *Registry) State() RegistryState {
	if registry == nil {
		return RegistryStateClosed
	}
	shared := registry.state
	if shared == nil {
		return ""
	}
	shared.mu.Lock()
	defer shared.mu.Unlock()
	return shared.state
}

func (registry *Registry) sharedState() *registryState {
	if registry == nil {
		return nil
	}
	return registry.state
}

func (shared *registryState) closeUnconfirmed(ctx context.Context, entries []routeEntry) bool {
	failed := false
	for index := len(entries) - 1; index >= 0; index-- {
		shared.mu.Lock()
		needsClose := index < len(shared.unconfirmed) && shared.unconfirmed[index]
		shared.mu.Unlock()
		if !needsClose {
			continue
		}
		if err := entries[index].handler.Close(ctx); err != nil {
			failed = true
			continue
		}
		shared.mu.Lock()
		shared.unconfirmed[index] = false
		shared.mu.Unlock()
	}
	return failed
}

func (shared *registryState) finishClose(failed bool) {
	shared.mu.Lock()
	if failed {
		shared.state = RegistryStateCleanupIncomplete
	} else {
		shared.state = RegistryStateClosed
	}
	shared.condition.Broadcast()
	shared.mu.Unlock()
}

func (shared *registryState) registrationErrorLocked() error {
	switch shared.state {
	case RegistryStateUnstarted:
		return nil
	case RegistryStateStarting, RegistryStateStarted:
		return ErrRegistryStarted
	default:
		return ErrRegistryClosed
	}
}

func newTrackedResponseBody(body io.ReadCloser, release func()) *trackedResponseBody {
	return &trackedResponseBody{body: body, release: release}
}

func (body *trackedResponseBody) Read(buffer []byte) (int, error) {
	count, err := body.body.Read(buffer)
	if err == io.EOF {
		body.releaseOwnership()
	}
	return count, err
}

func (body *trackedResponseBody) Close() error {
	body.closeOnce.Do(func() {
		_ = body.body.Close()
	})
	body.releaseOwnership()
	return nil
}

func (body *trackedResponseBody) releaseOwnership() {
	body.releaseOnce.Do(body.release)
}

func closeDiscardedResponseBody(body io.ReadCloser) {
	if body != nil {
		_ = body.Close()
	}
}

func prefixesOverlap(left, right string) bool {
	return strings.HasPrefix(left, right) || strings.HasPrefix(right, left)
}

func nilHandler(handler RouteHandler) bool {
	if handler == nil {
		return true
	}
	value := reflect.ValueOf(handler)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (Registry) MarshalJSON() ([]byte, error) { return nil, ErrLiveRouteStateNotSerializable }
func (Registry) MarshalText() ([]byte, error) { return nil, ErrLiveRouteStateNotSerializable }
func (Registry) Error() string                { return "applicationroute.Registry{live}" }
func (Registry) String() string               { return "applicationroute.Registry{live}" }
func (Registry) GoString() string             { return "applicationroute.Registry{live}" }
func (Registry) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("applicationroute.Registry{live}"))
}
