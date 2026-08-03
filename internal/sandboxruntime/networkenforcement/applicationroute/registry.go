package applicationroute

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"sync"
)

type Handler interface {
	Definition() Definition
	Start(context.Context) error
	Handle(context.Context, Request) (Response, error)
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
	handler    Handler
	definition Definition
}

type Registry struct {
	mu          sync.Mutex
	condition   *sync.Cond
	state       RegistryState
	entries     []routeEntry
	unconfirmed []bool
	dispatches  sync.WaitGroup
}

func NewRegistry(handlers ...Handler) (*Registry, error) {
	registry := &Registry{state: RegistryStateUnstarted}
	registry.condition = sync.NewCond(&registry.mu)
	for _, handler := range handlers {
		if err := registry.Register(handler); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func (registry *Registry) Register(handler Handler) error {
	if registry == nil {
		return ErrRegistryClosed
	}
	registry.mu.Lock()
	stateErr := registry.registrationErrorLocked()
	registry.mu.Unlock()
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

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if stateErr := registry.registrationErrorLocked(); stateErr != nil {
		return stateErr
	}
	for _, existing := range registry.entries {
		if existing.definition.ID == definition.ID || prefixesOverlap(existing.definition.Prefix, definition.Prefix) {
			return ErrRouteCollision
		}
	}
	registry.entries = append(registry.entries, routeEntry{handler: handler, definition: definition})
	return nil
}

func (registry *Registry) RouteIDs() []RouteID {
	if registry == nil {
		return nil
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	ids := make([]RouteID, len(registry.entries))
	for index, entry := range registry.entries {
		ids[index] = entry.definition.ID
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	return ids
}

func (registry *Registry) Start(ctx context.Context) error {
	if registry == nil {
		return ErrRegistryClosed
	}
	registry.mu.Lock()
	switch registry.state {
	case RegistryStateUnstarted:
		registry.state = RegistryStateStarting
	case RegistryStateStarting, RegistryStateStarted:
		registry.mu.Unlock()
		return ErrRegistryStarted
	default:
		registry.mu.Unlock()
		return ErrRegistryClosed
	}
	entries := append([]routeEntry(nil), registry.entries...)
	registry.mu.Unlock()

	for index, entry := range entries {
		if err := entry.handler.Start(ctx); err != nil {
			registry.mu.Lock()
			registry.state = RegistryStateClosing
			registry.unconfirmed = make([]bool, len(entries))
			for closeIndex := 0; closeIndex <= index; closeIndex++ {
				registry.unconfirmed[closeIndex] = true
			}
			registry.mu.Unlock()

			failed := registry.closeUnconfirmed(ctx, entries)
			registry.finishClose(failed)
			return ErrHandlerStart
		}
	}

	registry.mu.Lock()
	registry.unconfirmed = make([]bool, len(entries))
	for index := range registry.unconfirmed {
		registry.unconfirmed[index] = true
	}
	registry.state = RegistryStateStarted
	registry.condition.Broadcast()
	registry.mu.Unlock()
	return nil
}

func (registry *Registry) Dispatch(ctx context.Context, id RouteID, request Request) (Response, error) {
	if registry == nil {
		return Response{}, ErrRegistryClosed
	}
	registry.mu.Lock()
	switch registry.state {
	case RegistryStateUnstarted, RegistryStateStarting:
		registry.mu.Unlock()
		return Response{}, ErrRegistryNotStarted
	case RegistryStateStarted:
	default:
		registry.mu.Unlock()
		return Response{}, ErrRegistryClosed
	}
	var selected routeEntry
	found := false
	for _, entry := range registry.entries {
		if entry.definition.ID == id {
			selected = entry
			found = true
			break
		}
	}
	if !found {
		registry.mu.Unlock()
		return Response{}, ErrUnknownRoute
	}
	if err := ValidateRequestBounds(selected.definition.Limits, request); err != nil {
		registry.mu.Unlock()
		return Response{}, err
	}
	registry.dispatches.Add(1)
	registry.mu.Unlock()
	defer registry.dispatches.Done()

	response, err := selected.handler.Handle(ctx, request)
	if err != nil {
		return Response{}, ErrHandlerDispatch
	}
	if err := ValidateResponseBounds(selected.definition.Limits, response); err != nil {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return Response{}, err
	}
	return response, nil
}

func (registry *Registry) Close(ctx context.Context) error {
	if registry == nil {
		return nil
	}
	registry.mu.Lock()
	for registry.state == RegistryStateStarting || registry.state == RegistryStateClosing {
		registry.condition.Wait()
	}
	switch registry.state {
	case RegistryStateClosed:
		registry.mu.Unlock()
		return nil
	case RegistryStateUnstarted:
		registry.state = RegistryStateClosed
		registry.condition.Broadcast()
		registry.mu.Unlock()
		return nil
	case RegistryStateStarted, RegistryStateCleanupIncomplete:
		registry.state = RegistryStateClosing
	default:
		registry.mu.Unlock()
		return ErrRegistryClosed
	}
	entries := append([]routeEntry(nil), registry.entries...)
	registry.mu.Unlock()

	registry.dispatches.Wait()
	failed := registry.closeUnconfirmed(ctx, entries)
	registry.finishClose(failed)
	if failed {
		return ErrHandlerClose
	}
	return nil
}

func (registry *Registry) State() RegistryState {
	if registry == nil {
		return RegistryStateClosed
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.state
}

func (registry *Registry) closeUnconfirmed(ctx context.Context, entries []routeEntry) bool {
	failed := false
	for index := len(entries) - 1; index >= 0; index-- {
		registry.mu.Lock()
		needsClose := index < len(registry.unconfirmed) && registry.unconfirmed[index]
		registry.mu.Unlock()
		if !needsClose {
			continue
		}
		if err := entries[index].handler.Close(ctx); err != nil {
			failed = true
			continue
		}
		registry.mu.Lock()
		registry.unconfirmed[index] = false
		registry.mu.Unlock()
	}
	return failed
}

func (registry *Registry) finishClose(failed bool) {
	registry.mu.Lock()
	if failed {
		registry.state = RegistryStateCleanupIncomplete
	} else {
		registry.state = RegistryStateClosed
	}
	registry.condition.Broadcast()
	registry.mu.Unlock()
}

func prefixesOverlap(left, right string) bool {
	return strings.HasPrefix(left, right) || strings.HasPrefix(right, left)
}

func (registry *Registry) registrationErrorLocked() error {
	switch registry.state {
	case RegistryStateUnstarted:
		return nil
	case RegistryStateStarting, RegistryStateStarted:
		return ErrRegistryStarted
	default:
		return ErrRegistryClosed
	}
}

func nilHandler(handler Handler) bool {
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

func (*Registry) MarshalJSON() ([]byte, error) { return nil, ErrLiveRouteStateNotSerializable }
func (*Registry) MarshalText() ([]byte, error) { return nil, ErrLiveRouteStateNotSerializable }
func (*Registry) String() string               { return "applicationroute.Registry{live}" }
func (*Registry) GoString() string             { return "applicationroute.Registry{live}" }
