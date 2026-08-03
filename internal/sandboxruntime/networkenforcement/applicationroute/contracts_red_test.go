package applicationroute

import (
	"context"
	"errors"
	"io"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestL8ApplicationRouteReservedContractsAndBounds(t *testing.T) {
	if got, want := string(RouteCredentialHTTPV1), "credential-http-v1"; got != want {
		t.Fatalf("RouteCredentialHTTPV1 = %q, want %q", got, want)
	}
	if got, want := CredentialHTTPV1Prefix, "/.well-known/hal/credential-http/v1/"; got != want {
		t.Fatalf("CredentialHTTPV1Prefix = %q, want %q", got, want)
	}

	definition := Definition{
		ID:     RouteCredentialHTTPV1,
		Prefix: CredentialHTTPV1Prefix,
		Limits: StreamLimits{
			MaxRequestHeaderBytes:  32 << 10,
			MaxRequestBodyBytes:    16 << 20,
			MaxResponseHeaderBytes: 32 << 10,
			MaxResponseBodyBytes:   64 << 20,
			MaxEventBytes:          2 << 20,
		},
	}
	if err := ValidateDefinition(definition); err != nil {
		t.Fatalf("ValidateDefinition() error = %v", err)
	}

	request := Request{
		Metadata: RequestMetadata{
			Method:        "POST",
			ContentType:   "application/json",
			HeaderBytes:   128,
			ContentLength: 7,
		},
		Body: strings.NewReader(`{"x":1}`),
	}
	if err := ValidateRequestBounds(definition.Limits, request); err != nil {
		t.Fatalf("ValidateRequestBounds() error = %v", err)
	}

	request.Metadata.ContentLength = definition.Limits.MaxRequestBodyBytes + 1
	err := ValidateRequestBounds(definition.Limits, request)
	if !errors.Is(err, ErrStreamBounds) {
		t.Fatalf("ValidateRequestBounds() error = %v, want ErrStreamBounds", err)
	}
	assertApplicationRouteErrorSafe(t, err)
	request.Metadata.ContentLength = 0
	request.Metadata.HeaderBytes = definition.Limits.MaxRequestHeaderBytes + 1
	err = ValidateRequestBounds(definition.Limits, request)
	if !errors.Is(err, ErrStreamBounds) {
		t.Fatalf("ValidateRequestBounds(header overflow) error = %v, want ErrStreamBounds", err)
	}

	response := Response{
		Metadata: ResponseMetadata{
			StatusCode:    200,
			ContentType:   "text/event-stream",
			HeaderBytes:   128,
			ContentLength: definition.Limits.MaxResponseBodyBytes + 1,
			Streaming:     true,
		},
		Body: io.NopCloser(strings.NewReader("event")),
	}
	err = ValidateResponseBounds(definition.Limits, response)
	if !errors.Is(err, ErrStreamBounds) {
		t.Fatalf("ValidateResponseBounds() error = %v, want ErrStreamBounds", err)
	}
	assertApplicationRouteErrorSafe(t, err)
	response.Metadata.ContentLength = 0
	response.Metadata.HeaderBytes = definition.Limits.MaxResponseHeaderBytes + 1
	err = ValidateResponseBounds(definition.Limits, response)
	if !errors.Is(err, ErrStreamBounds) {
		t.Fatalf("ValidateResponseBounds(header overflow) error = %v, want ErrStreamBounds", err)
	}
	response.Metadata.HeaderBytes = 0
	response.Metadata.MaxEventBytes = definition.Limits.MaxEventBytes + 1
	err = ValidateResponseBounds(definition.Limits, response)
	if !errors.Is(err, ErrStreamBounds) {
		t.Fatalf("ValidateResponseBounds(event overflow) error = %v, want ErrStreamBounds", err)
	}
}

func TestL8ApplicationRouteDefinitionValidationRejectsUnsafeOrUnboundedRoutes(t *testing.T) {
	valid := Definition{
		ID:     RouteCredentialHTTPV1,
		Prefix: CredentialHTTPV1Prefix,
		Limits: StreamLimits{
			MaxRequestHeaderBytes:  1,
			MaxRequestBodyBytes:    1,
			MaxResponseHeaderBytes: 1,
			MaxResponseBodyBytes:   1,
			MaxEventBytes:          1,
		},
	}

	tests := []struct {
		name   string
		mutate func(*Definition)
	}{
		{name: "missing id", mutate: func(got *Definition) { got.ID = "" }},
		{name: "unsafe id", mutate: func(got *Definition) { got.ID = "project route/secret" }},
		{name: "missing prefix", mutate: func(got *Definition) { got.Prefix = "" }},
		{name: "noncanonical prefix", mutate: func(got *Definition) { got.Prefix = "/other/" }},
		{name: "unbounded request headers", mutate: func(got *Definition) { got.Limits.MaxRequestHeaderBytes = 0 }},
		{name: "unbounded request body", mutate: func(got *Definition) { got.Limits.MaxRequestBodyBytes = 0 }},
		{name: "unbounded response headers", mutate: func(got *Definition) { got.Limits.MaxResponseHeaderBytes = 0 }},
		{name: "unbounded response body", mutate: func(got *Definition) { got.Limits.MaxResponseBodyBytes = 0 }},
		{name: "unbounded event", mutate: func(got *Definition) { got.Limits.MaxEventBytes = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := valid
			tt.mutate(&got)
			err := ValidateDefinition(got)
			if !errors.Is(err, ErrInvalidRoute) {
				t.Fatalf("ValidateDefinition() error = %v, want ErrInvalidRoute", err)
			}
			assertApplicationRouteErrorSafe(t, err)
		})
	}
}

func TestL8ApplicationRouteRegistryRejectsReversePrefixOverlap(t *testing.T) {
	child := newFakeApplicationRouteHandler(
		"child",
		RouteID("credential-http-v1-child"),
		CredentialHTTPV1Prefix+"child/",
	)
	registry, err := NewRegistry(child)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	parent := newFakeApplicationRouteHandler("parent", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	err = registry.Register(parent)
	if !errors.Is(err, ErrRouteCollision) {
		t.Fatalf("Register(parent over child) error = %v, want ErrRouteCollision", err)
	}
	assertApplicationRouteErrorSafe(t, err)
	if got, want := registry.RouteIDs(), []RouteID{"credential-http-v1-child"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("RouteIDs() after reverse collision = %#v, want %#v", got, want)
	}
}

func TestL8ApplicationRouteRegistryRejectsNilAndInvalidHandlers(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Register(nil); !errors.Is(err, ErrHandlerRequired) {
		t.Fatalf("Register(nil) error = %v, want ErrHandlerRequired", err)
	}
	invalid := newFakeApplicationRouteHandler("invalid", RouteID("unsafe route/raw-secret"), "/project/raw-secret/")
	if err := registry.Register(invalid); !errors.Is(err, ErrInvalidRoute) {
		t.Fatalf("Register(invalid) error = %v, want ErrInvalidRoute", err)
	} else {
		assertApplicationRouteErrorSafe(t, err)
	}
	if got := registry.RouteIDs(); len(got) != 0 {
		t.Fatalf("RouteIDs() after invalid handlers = %#v, want empty", got)
	}
	constructed, err := NewRegistry(nil)
	if !errors.Is(err, ErrHandlerRequired) {
		t.Fatalf("NewRegistry(nil) error = %v, want ErrHandlerRequired", err)
	}
	if constructed != nil {
		t.Fatalf("NewRegistry(nil) registry = %#v, want nil", constructed)
	}
}

func TestL8ApplicationRouteRegistryRegistrationAndCollisionAreDeterministic(t *testing.T) {
	first := newFakeApplicationRouteHandler("first", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	registry, err := NewRegistry(first)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if got, want := registry.RouteIDs(), []RouteID{RouteCredentialHTTPV1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("RouteIDs() = %#v, want %#v", got, want)
	}

	tests := []struct {
		name    string
		handler Handler
	}{
		{
			name:    "same id and prefix",
			handler: newFakeApplicationRouteHandler("duplicate", RouteCredentialHTTPV1, CredentialHTTPV1Prefix),
		},
		{
			name:    "overlapping reserved prefix",
			handler: newFakeApplicationRouteHandler("overlap", RouteID("credential-http-v1-child"), CredentialHTTPV1Prefix+"child/"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.Register(tt.handler)
			if !errors.Is(err, ErrRouteCollision) {
				t.Fatalf("Register() error = %v, want ErrRouteCollision", err)
			}
			assertApplicationRouteErrorSafe(t, err)
			if got, want := registry.RouteIDs(), []RouteID{RouteCredentialHTTPV1}; !reflect.DeepEqual(got, want) {
				t.Fatalf("RouteIDs() after collision = %#v, want %#v", got, want)
			}
		})
	}
	sibling := newFakeApplicationRouteHandler(
		"sibling",
		RouteID("credential-http-v1-sibling"),
		"/.well-known/hal/credential-http/v1-sibling/",
	)
	if err := registry.Register(sibling); err != nil {
		t.Fatalf("Register(nonoverlapping sibling) error = %v", err)
	}
	wantIDs := []RouteID{RouteCredentialHTTPV1, "credential-http-v1-sibling"}
	if got := registry.RouteIDs(); !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("RouteIDs() after sibling = %#v, want %#v", got, wantIDs)
	}
}

func TestL8ApplicationRouteRegistryRouteIDsAreSortedCopies(t *testing.T) {
	registry, err := NewRegistry(
		newFakeApplicationRouteHandler("zeta", RouteID("zeta"), "/.well-known/hal/application/zeta/"),
		newFakeApplicationRouteHandler("credential", RouteCredentialHTTPV1, CredentialHTTPV1Prefix),
		newFakeApplicationRouteHandler("alpha", RouteID("alpha"), "/.well-known/hal/application/alpha/"),
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	want := []RouteID{"alpha", RouteCredentialHTTPV1, "zeta"}
	got := registry.RouteIDs()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RouteIDs() = %#v, want %#v", got, want)
	}
	got[0] = "mutated"
	if again := registry.RouteIDs(); !reflect.DeepEqual(again, want) {
		t.Fatalf("RouteIDs() after caller mutation = %#v, want %#v", again, want)
	}
}

func TestL8ApplicationRouteRegistryStartCloseAndRollbackOrdering(t *testing.T) {
	var events []string
	var eventMu sync.Mutex
	newHandler := func(name string, id RouteID, prefix string) *fakeApplicationRouteHandler {
		handler := newFakeApplicationRouteHandler(name, id, prefix)
		handler.events = &events
		handler.eventMu = &eventMu
		return handler
	}

	first := newHandler("first", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	second := newHandler("second", RouteID("reserved-two"), "/.well-known/hal/application/two/")
	registry, err := NewRegistry(first, second)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got, want := events, []string{"start:first", "start:second", "close:second", "close:first"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lifecycle events = %#v, want %#v", got, want)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("second Close() error = %v, want idempotent nil", err)
	}

	events = nil
	first = newHandler("first", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	second = newHandler("second", RouteID("reserved-two"), "/.well-known/hal/application/two/")
	rawStartErr := errors.New("listen https://user:secret@private.example.test/token")
	second.startErr = rawStartErr
	third := newHandler("third", RouteID("reserved-three"), "/.well-known/hal/application/three/")
	registry, err = NewRegistry(first, second, third)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	err = registry.Start(context.Background())
	if !errors.Is(err, ErrHandlerStart) {
		t.Fatalf("Start() error = %v, want ErrHandlerStart", err)
	}
	if errors.Is(err, rawStartErr) {
		t.Fatal("Start() error unwraps raw handler start failure")
	}
	assertApplicationRouteErrorSafe(t, err)
	if got, want := events, []string{"start:first", "start:second", "close:second", "close:first"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("failed start events = %#v, want %#v", got, want)
	}
	if got := registry.State(); got != RegistryStateClosed {
		t.Fatalf("State() after failed Start = %q, want %q", got, RegistryStateClosed)
	}
	if _, dispatchErr := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, Request{}); !errors.Is(dispatchErr, ErrRegistryClosed) {
		t.Fatalf("Dispatch() after failed Start error = %v, want ErrRegistryClosed", dispatchErr)
	}
}

func TestL8ApplicationRouteRegistryFailedStartAwaitsFailingHandlerClose(t *testing.T) {
	first := newFakeApplicationRouteHandler("first", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	failing := newFakeApplicationRouteHandler("failing", RouteID("reserved-failing"), "/.well-known/hal/application/failing/")
	failing.startErr = errors.New("start token=raw-start-secret at https://private.example.test")
	failing.closeEntered = make(chan struct{})
	failing.closeRelease = make(chan struct{})
	registry, err := NewRegistry(first, failing)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	startDone := make(chan error, 1)
	go func() { startDone <- registry.Start(context.Background()) }()
	<-failing.closeEntered
	select {
	case err := <-startDone:
		t.Fatalf("Start() returned before failing handler Close completed: %v", err)
	default:
	}
	if _, dispatchErr := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, Request{}); !errors.Is(dispatchErr, ErrRegistryClosed) {
		t.Fatalf("Dispatch() during failed-Start rollback error = %v, want ErrRegistryClosed", dispatchErr)
	}
	close(failing.closeRelease)
	if err := <-startDone; !errors.Is(err, ErrHandlerStart) {
		t.Fatalf("Start() error = %v, want ErrHandlerStart", err)
	}
	if got := registry.State(); got != RegistryStateClosed {
		t.Fatalf("State() after rollback = %q, want %q", got, RegistryStateClosed)
	}
}

func TestL8ApplicationRouteRegistryRollbackContinuesAndDropsRawCauses(t *testing.T) {
	var events []string
	var eventMu sync.Mutex
	newHandler := func(name string, id RouteID, prefix string) *fakeApplicationRouteHandler {
		handler := newFakeApplicationRouteHandler(name, id, prefix)
		handler.events, handler.eventMu = &events, &eventMu
		return handler
	}
	first := newHandler("first", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	second := newHandler("second", RouteID("reserved-two"), "/.well-known/hal/application/two/")
	failing := newHandler("failing", RouteID("reserved-failing"), "/.well-known/hal/application/failing/")
	rawStartErr := errors.New("start api-key=raw-start-secret host=private.example.test")
	rawFailingCloseErr := errors.New("rollback failing token=raw-failing-close /Users/alice/private")
	rawSecondCloseErr := errors.New("rollback second token=raw-second-close https://private.example.test")
	rawFirstCloseErr := errors.New("rollback first token=raw-first-close /tmp/private.sock")
	failing.startErr = rawStartErr
	failing.closeErr = rawFailingCloseErr
	second.closeErr = rawSecondCloseErr
	first.closeErr = rawFirstCloseErr

	registry, err := NewRegistry(first, second, failing)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	err = registry.Start(context.Background())
	if !errors.Is(err, ErrHandlerStart) {
		t.Fatalf("Start() error = %v, want ErrHandlerStart", err)
	}
	for _, raw := range []error{rawStartErr, rawFailingCloseErr, rawSecondCloseErr, rawFirstCloseErr} {
		if errors.Is(err, raw) {
			t.Fatalf("Start() error unwraps raw cause %v", raw)
		}
	}
	assertApplicationRouteErrorSafe(t, err)
	if got, want := events, []string{
		"start:first",
		"start:second",
		"start:failing",
		"close:failing",
		"close:second",
		"close:first",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rollback events = %#v, want %#v", got, want)
	}
	if got := registry.State(); got != RegistryStateClosed {
		t.Fatalf("State() after rollback failures = %q, want %q", got, RegistryStateClosed)
	}
	if _, dispatchErr := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, Request{}); !errors.Is(dispatchErr, ErrRegistryClosed) {
		t.Fatalf("Dispatch() after rollback failures error = %v, want ErrRegistryClosed", dispatchErr)
	}
}

func TestL8ApplicationRouteRegistryRejectsLateRegistrationAndRestart(t *testing.T) {
	registry, err := NewRegistry(newFakeApplicationRouteHandler("first", RouteCredentialHTTPV1, CredentialHTTPV1Prefix))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	late := newFakeApplicationRouteHandler("late", RouteID("reserved-late"), "/.well-known/hal/application/late/")
	if err := registry.Register(late); !errors.Is(err, ErrRegistryStarted) {
		t.Fatalf("Register() after Start error = %v, want ErrRegistryStarted", err)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := registry.Register(late); !errors.Is(err, ErrRegistryClosed) {
		t.Fatalf("Register() after Close error = %v, want ErrRegistryClosed", err)
	}
	if err := registry.Start(context.Background()); !errors.Is(err, ErrRegistryClosed) {
		t.Fatalf("Start() after Close error = %v, want ErrRegistryClosed", err)
	}
}

func TestL8ApplicationRouteRegistryCloseContinuesInReverseOrderAndSanitizes(t *testing.T) {
	var events []string
	var eventMu sync.Mutex
	first := newFakeApplicationRouteHandler("first", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	first.events, first.eventMu = &events, &eventMu
	rawFirstCloseErr := errors.New("close api-key=first-secret at https://first.private.invalid")
	first.closeErr = rawFirstCloseErr
	second := newFakeApplicationRouteHandler("second", RouteID("reserved-two"), "/.well-known/hal/application/two/")
	second.events, second.eventMu = &events, &eventMu
	rawSecondCloseErr := errors.New("close token=second-secret at /Users/alice/private.sock")
	second.closeErr = rawSecondCloseErr

	registry, err := NewRegistry(first, second)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	err = registry.Close(context.Background())
	if !errors.Is(err, ErrHandlerClose) {
		t.Fatalf("Close() error = %v, want ErrHandlerClose", err)
	}
	for _, raw := range []error{rawFirstCloseErr, rawSecondCloseErr} {
		if errors.Is(err, raw) {
			t.Fatalf("Close() error unwraps raw cause %v", raw)
		}
	}
	assertApplicationRouteErrorSafe(t, err)
	if got, want := events, []string{"start:first", "start:second", "close:second", "close:first"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("close failure events = %#v, want %#v", got, want)
	}
}

func TestL8ApplicationRouteRegistryCloseStopsAdmissionAndDrainsAcceptedDispatch(t *testing.T) {
	handler := newFakeApplicationRouteHandler("credential", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	handler.handleEntered = make(chan struct{})
	handler.handleRelease = make(chan struct{})
	registry, err := NewRegistry(handler)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	dispatchDone := make(chan error, 1)
	go func() {
		_, err := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, Request{
			Metadata: RequestMetadata{Method: "POST", ContentType: "application/json", ContentLength: 2},
			Body:     strings.NewReader("{}"),
		})
		dispatchDone <- err
	}()
	<-handler.handleEntered

	closeDone := make(chan error, 1)
	go func() { closeDone <- registry.Close(context.Background()) }()
	waitForApplicationRouteState(t, registry, RegistryStateClosing)

	if _, err := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, Request{
		Metadata: RequestMetadata{Method: "POST", ContentType: "application/json", ContentLength: 2},
		Body:     strings.NewReader("{}"),
	}); !errors.Is(err, ErrRegistryClosed) {
		t.Fatalf("Dispatch() during Close error = %v, want ErrRegistryClosed", err)
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before accepted dispatch drained: %v", err)
	default:
	}

	close(handler.handleRelease)
	if err := <-dispatchDone; err != nil {
		t.Fatalf("accepted Dispatch() error = %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if handler.closeSawActive {
		t.Fatal("handler Close observed an active accepted dispatch")
	}
	if got := registry.State(); got != RegistryStateClosed {
		t.Fatalf("State() = %q, want %q", got, RegistryStateClosed)
	}
}

func TestL8ApplicationRouteRegistryConcurrentDispatchFailsClosed(t *testing.T) {
	handler := newFakeApplicationRouteHandler("credential", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	registry, err := NewRegistry(handler)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	newRequest := func() Request {
		return Request{
			Metadata: RequestMetadata{Method: "POST", ContentType: "application/json", ContentLength: 2},
			Body:     strings.NewReader("{}"),
		}
	}
	if _, err := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, newRequest()); !errors.Is(err, ErrRegistryNotStarted) {
		t.Fatalf("Dispatch() before Start error = %v, want ErrRegistryNotStarted", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := registry.Dispatch(context.Background(), RouteID("unknown"), newRequest()); !errors.Is(err, ErrUnknownRoute) {
		t.Fatalf("Dispatch() unknown route error = %v, want ErrUnknownRoute", err)
	}

	const calls = 64
	errs := make(chan error, calls)
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, newRequest())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Dispatch() error = %v", err)
		}
	}
	if got := handler.handleCalls(); got != calls {
		t.Fatalf("handler calls = %d, want %d", got, calls)
	}

	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, newRequest()); !errors.Is(err, ErrRegistryClosed) {
		t.Fatalf("Dispatch() after Close error = %v, want ErrRegistryClosed", err)
	}
}

func TestL8ApplicationRouteHandlerErrorsAreSanitized(t *testing.T) {
	handler := newFakeApplicationRouteHandler("credential", RouteCredentialHTTPV1, CredentialHTTPV1Prefix)
	rawErr := errors.New("api-key=raw-ticket host=private.example.test path=/Users/alice/private")
	handler.handleErr = rawErr
	registry, err := NewRegistry(handler)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	_, err = registry.Dispatch(context.Background(), RouteCredentialHTTPV1, Request{
		Metadata: RequestMetadata{Method: "POST", ContentType: "application/json", ContentLength: 2},
		Body:     strings.NewReader("{}"),
	})
	if !errors.Is(err, ErrHandlerDispatch) {
		t.Fatalf("Dispatch() error = %v, want ErrHandlerDispatch", err)
	}
	if errors.Is(err, rawErr) {
		t.Fatal("Dispatch() error unwraps raw handler error")
	}
	assertApplicationRouteErrorSafe(t, err)
}

func TestL8ApplicationRouteSanitizedErrorContractIsStable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "handler required", err: ErrHandlerRequired, want: "application route handler is required"},
		{name: "invalid route", err: ErrInvalidRoute, want: "application route invalid"},
		{name: "route collision", err: ErrRouteCollision, want: "application route collision"},
		{name: "handler start", err: ErrHandlerStart, want: "application route handler start failed"},
		{name: "handler close", err: ErrHandlerClose, want: "application route handler close failed"},
		{name: "handler dispatch", err: ErrHandlerDispatch, want: "application route handler dispatch failed"},
		{name: "registry closed", err: ErrRegistryClosed, want: "application route registry closed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("error text = %q, want %q", got, tt.want)
			}
			if errors.Unwrap(tt.err) != nil {
				t.Fatalf("sentinel unwrap = %v, want nil", errors.Unwrap(tt.err))
			}
			assertApplicationRouteErrorSafe(t, tt.err)
		})
	}
}

type fakeApplicationRouteHandler struct {
	name      string
	def       Definition
	startErr  error
	handleErr error
	closeErr  error
	events    *[]string
	eventMu   *sync.Mutex

	mu      sync.Mutex
	handles int
	active  int

	handleEntered  chan struct{}
	handleRelease  chan struct{}
	closeEntered   chan struct{}
	closeRelease   chan struct{}
	closeSawActive bool
}

var _ Handler = (*fakeApplicationRouteHandler)(nil)

func newFakeApplicationRouteHandler(name string, id RouteID, prefix string) *fakeApplicationRouteHandler {
	return &fakeApplicationRouteHandler{
		name: name,
		def: Definition{
			ID:     id,
			Prefix: prefix,
			Limits: StreamLimits{
				MaxRequestHeaderBytes:  32 << 10,
				MaxRequestBodyBytes:    16 << 20,
				MaxResponseHeaderBytes: 32 << 10,
				MaxResponseBodyBytes:   64 << 20,
				MaxEventBytes:          2 << 20,
			},
		},
	}
}

func (handler *fakeApplicationRouteHandler) Definition() Definition { return handler.def }

func (handler *fakeApplicationRouteHandler) Start(context.Context) error {
	handler.record("start:" + handler.name)
	return handler.startErr
}

func (handler *fakeApplicationRouteHandler) Handle(context.Context, Request) (Response, error) {
	handler.mu.Lock()
	handler.handles++
	handler.active++
	handler.mu.Unlock()
	defer func() {
		handler.mu.Lock()
		handler.active--
		handler.mu.Unlock()
	}()
	if handler.handleEntered != nil {
		close(handler.handleEntered)
		<-handler.handleRelease
	}
	if handler.handleErr != nil {
		return Response{}, handler.handleErr
	}
	return Response{
		Metadata: ResponseMetadata{StatusCode: 200, ContentType: "application/json", ContentLength: 2},
		Body:     io.NopCloser(strings.NewReader("{}")),
	}, nil
}

func (handler *fakeApplicationRouteHandler) Close(context.Context) error {
	handler.mu.Lock()
	handler.closeSawActive = handler.active != 0
	handler.mu.Unlock()
	handler.record("close:" + handler.name)
	if handler.closeEntered != nil {
		close(handler.closeEntered)
		<-handler.closeRelease
	}
	return handler.closeErr
}

func waitForApplicationRouteState(t *testing.T, registry *Registry, want RegistryState) {
	t.Helper()
	for i := 0; i < 10000; i++ {
		if registry.State() == want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("State() = %q, want %q", registry.State(), want)
}

func (handler *fakeApplicationRouteHandler) handleCalls() int {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.handles
}

func (handler *fakeApplicationRouteHandler) record(event string) {
	if handler.events == nil {
		return
	}
	handler.eventMu.Lock()
	defer handler.eventMu.Unlock()
	*handler.events = append(*handler.events, event)
}

func assertApplicationRouteErrorSafe(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want sanitized error")
	}
	text := err.Error()
	for _, unsafe := range []string{
		"raw-ticket",
		"secret",
		"private.example.test",
		"/Users/alice",
		"api-key=",
		"http://",
		"https://",
	} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("error %q contains unsafe value %q", text, unsafe)
		}
	}
}
