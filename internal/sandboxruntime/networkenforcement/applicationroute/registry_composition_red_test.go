package applicationroute

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
)

var _ Handler = (*Registry)(nil)
var _ RouteHandler = (*fakeApplicationRouteHandler)(nil)

func TestL8ApplicationRouteRegistryComposesSortedCopySafeDefinitions(t *testing.T) {
	registry, err := NewRegistry(
		newFakeApplicationRouteHandler("zeta", RouteID("zeta"), "/.well-known/hal/application/zeta/"),
		newFakeApplicationRouteHandler("credential", RouteCredentialHTTPV1, CredentialHTTPV1Prefix),
		newFakeApplicationRouteHandler("alpha", RouteID("alpha"), "/.well-known/hal/application/alpha/"),
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	var composed Handler = registry
	want := []Definition{
		newFakeApplicationRouteHandler("alpha", RouteID("alpha"), "/.well-known/hal/application/alpha/").def,
		newFakeApplicationRouteHandler("credential", RouteCredentialHTTPV1, CredentialHTTPV1Prefix).def,
		newFakeApplicationRouteHandler("zeta", RouteID("zeta"), "/.well-known/hal/application/zeta/").def,
	}
	got := composed.Definitions()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Definitions() = %#v, want %#v", got, want)
	}
	got[0].ID = "mutated"
	got[0].Prefix = "/.well-known/hal/application/mutated/"
	got[0].Limits.MaxRequestBodyBytes = 1
	if again := composed.Definitions(); !reflect.DeepEqual(again, want) {
		t.Fatalf("Definitions() after caller mutation = %#v, want %#v", again, want)
	}
}

func TestL8ApplicationRouteRegistryHandlerDispatchesExactRouteAndUnknownFailsClosed(t *testing.T) {
	credential := newFakeApplicationRouteHandler("credential", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	sibling := newFakeApplicationRouteHandler("sibling", RouteID("sibling"), "/.well-known/hal/application/sibling/")
	registry, err := NewRegistry(credential, sibling)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	var composed Handler = registry
	if err := composed.Start(context.Background()); err != nil {
		t.Fatalf("Handler.Start() error = %v", err)
	}

	response, err := composed.Handle(context.Background(), RouteCredentialHTTPV1, validOwnedApplicationRouteRequest())
	if err != nil {
		t.Fatalf("Handler.Handle() error = %v", err)
	}
	if response.Body == nil {
		t.Fatal("Handler.Handle() response body = nil, want tracked response")
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatalf("read Handler.Handle() response body: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("Handler.Handle() response Body.Close() error = %v", err)
	}
	if got := credential.handleCalls(); got != 1 {
		t.Fatalf("credential handler calls = %d, want 1", got)
	}
	if got := sibling.handleCalls(); got != 0 {
		t.Fatalf("sibling handler calls = %d, want 0", got)
	}

	if response, err := composed.Handle(context.Background(), RouteID("unknown"), validOwnedApplicationRouteRequest()); !errors.Is(err, ErrUnknownRoute) || response.Body != nil {
		t.Fatalf("Handler.Handle(unknown) = body:%T error:%v, want empty response and ErrUnknownRoute", response.Body, err)
	}
	if got := credential.handleCalls(); got != 1 {
		t.Fatalf("credential handler calls after unknown route = %d, want 1", got)
	}
	if got := sibling.handleCalls(); got != 0 {
		t.Fatalf("sibling handler calls after unknown route = %d, want 0", got)
	}
	if err := composed.Close(context.Background()); err != nil {
		t.Fatalf("Handler.Close() error = %v", err)
	}
}

func TestL8ApplicationRouteRegistryLeafRejectionCollisionAndLifecycleRemainExact(t *testing.T) {
	var typedNil *fakeApplicationRouteHandler
	if registry, err := NewRegistry(typedNil); !errors.Is(err, ErrHandlerRequired) || registry != nil {
		t.Fatalf("NewRegistry(typed nil leaf) = %#v, %v, want nil and ErrHandlerRequired", registry, err)
	}

	first := newFakeApplicationRouteHandler("first", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	registry, err := NewRegistry(first)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	collision := newFakeApplicationRouteHandler("collision", RouteID("collision"), CredentialHTTPV1Prefix+"child/")
	if err := registry.Register(collision); !errors.Is(err, ErrRouteCollision) {
		t.Fatalf("Register(overlapping leaf) error = %v, want ErrRouteCollision", err)
	}

	var events []string
	var eventMu sync.Mutex
	first.events, first.eventMu = &events, &eventMu
	second := newFakeApplicationRouteHandler("second", RouteID("second"), "/.well-known/hal/application/second/")
	second.events, second.eventMu = &events, &eventMu
	if err := registry.Register(second); err != nil {
		t.Fatalf("Register(second) error = %v", err)
	}
	var composed Handler = registry
	if err := composed.Start(context.Background()); err != nil {
		t.Fatalf("Handler.Start() error = %v", err)
	}
	if err := composed.Close(context.Background()); err != nil {
		t.Fatalf("Handler.Close() error = %v", err)
	}
	if want := []string{"start:first", "start:second", "close:second", "close:first"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("composed lifecycle events = %#v, want %#v", events, want)
	}
}
