package applicationroute

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestL8ApplicationRouteRegistryDrainsAcceptedResponseBodyOwnership(t *testing.T) {
	tests := []struct {
		name         string
		releaseByEOF bool
	}{
		{name: "eof", releaseByEOF: true},
		{name: "body close"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := newOwnedApplicationRouteBody(tt.releaseByEOF, nil)
			handler := newOwnedApplicationRouteHandler(Response{
				Metadata: ResponseMetadata{StatusCode: 200, ContentType: "application/json", ContentLength: 2},
				Body:     body,
			}, nil)
			registry, err := NewRegistry(handler)
			if err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			if err := registry.Start(context.Background()); err != nil {
				t.Fatalf("Start() error = %v", err)
			}

			response, err := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, validOwnedApplicationRouteRequest())
			if err != nil {
				t.Fatalf("Dispatch() error = %v", err)
			}
			if response.Body == nil {
				t.Fatal("Dispatch() response body = nil, want tracked body ownership")
			}

			if tt.releaseByEOF {
				// Start the blocking read before Close so EOF is the event that
				// releases the accepted response-body ownership.
				readDone := make(chan error, 1)
				go func() {
					_, readErr := response.Body.Read(make([]byte, 1))
					readDone <- readErr
				}()
				<-body.readEntered
				body.pendingRead = readDone
			}

			closeResults := make(chan error, 2)
			go func() { closeResults <- registry.Close(context.Background()) }()
			go func() { closeResults <- registry.Close(context.Background()) }()
			waitForApplicationRouteState(t, registry, RegistryStateClosing)

			if _, dispatchErr := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, validOwnedApplicationRouteRequest()); !errors.Is(dispatchErr, ErrRegistryClosed) {
				t.Errorf("Dispatch() during response drain error = %v, want ErrRegistryClosed", dispatchErr)
			}
			select {
			case <-handler.closeEntered:
				t.Error("handler Close entered before accepted response body reached EOF or Close")
			case <-time.After(50 * time.Millisecond):
			}
			select {
			case closeErr := <-closeResults:
				t.Errorf("Registry.Close() returned before response-body release: %v", closeErr)
			case <-time.After(10 * time.Millisecond):
			}

			if tt.releaseByEOF {
				body.releaseRead()
				if readErr := <-body.pendingRead; !errors.Is(readErr, io.EOF) {
					t.Fatalf("response body Read() error = %v, want EOF", readErr)
				}
			} else {
				closeOwnedApplicationRouteBodyTwice(t, response.Body)
			}

			select {
			case <-handler.closeEntered:
			case <-time.After(time.Second):
				t.Fatal("handler Close did not enter after response-body release")
			}
			handler.releaseClose()
			for range 2 {
				if closeErr := <-closeResults; closeErr != nil {
					t.Fatalf("Registry.Close() error = %v", closeErr)
				}
			}
			if err := registry.Close(context.Background()); err != nil {
				t.Fatalf("repeated Registry.Close() error = %v", err)
			}
			// EOF releases the registry drain separately from ownership of the
			// underlying body; a later repeated Close must still reach it once.
			if tt.releaseByEOF {
				closeOwnedApplicationRouteBodyTwice(t, response.Body)
			}
			if got := handler.closeCallCount(); got != 1 {
				t.Fatalf("handler Close calls = %d, want exactly 1", got)
			}
			if got := body.closeCallCount(); got != 1 {
				t.Fatalf("underlying response body Close calls = %d, want exactly 1", got)
			}
		})
	}
}

func TestL8ApplicationRouteRegistryReleasesNilResponseBodySynchronously(t *testing.T) {
	handler := newOwnedApplicationRouteHandler(Response{
		Metadata: ResponseMetadata{StatusCode: 204, ContentType: "application/json"},
	}, nil)
	registry, err := NewRegistry(handler)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	response, err := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, validOwnedApplicationRouteRequest())
	if err != nil || response.Body != nil {
		t.Fatalf("Dispatch() = body:%T error:%v, want synchronous nil-body release", response.Body, err)
	}
	go func() {
		<-handler.closeEntered
		handler.releaseClose()
	}()
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close() error = %v", err)
	}
}

func TestL8ApplicationRouteRegistryClosesDiscardedResponseBodies(t *testing.T) {
	rawHandlerErr := errors.New("handler api-key=raw-handler-secret")
	rawCloseErr := errors.New("body close token=raw-close-secret")
	tests := []struct {
		name      string
		response  Response
		handleErr error
		wantErr   error
	}{
		{
			name: "handler error",
			response: Response{
				Metadata: ResponseMetadata{StatusCode: 200, ContentType: "application/json", ContentLength: 2},
			},
			handleErr: rawHandlerErr,
			wantErr:   ErrHandlerDispatch,
		},
		{
			name: "invalid response",
			response: Response{
				Metadata: ResponseMetadata{StatusCode: 200, ContentType: "application/json", ContentLength: 6 << 20},
			},
			wantErr: ErrStreamBounds,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := newOwnedApplicationRouteBody(false, rawCloseErr)
			tt.response.Body = body
			handler := newOwnedApplicationRouteHandler(tt.response, tt.handleErr)
			registry, err := NewRegistry(handler)
			if err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			if err := registry.Start(context.Background()); err != nil {
				t.Fatalf("Start() error = %v", err)
			}

			response, dispatchErr := registry.Dispatch(context.Background(), RouteCredentialHTTPV1, validOwnedApplicationRouteRequest())
			if response.Body != nil || !errors.Is(dispatchErr, tt.wantErr) {
				t.Fatalf("Dispatch() = body:%T error:%v, want discarded body and %v", response.Body, dispatchErr, tt.wantErr)
			}
			if errors.Is(dispatchErr, rawHandlerErr) || errors.Is(dispatchErr, rawCloseErr) ||
				strings.Contains(dispatchErr.Error(), "raw-") {
				t.Fatalf("Dispatch() error exposes discarded-body cause: %v", dispatchErr)
			}
			if got := body.closeCallCount(); got != 1 {
				t.Fatalf("discarded body Close calls = %d, want exactly 1", got)
			}

			go func() {
				<-handler.closeEntered
				handler.releaseClose()
			}()
			if err := registry.Close(context.Background()); err != nil {
				t.Fatalf("Registry.Close() error = %v", err)
			}
		})
	}
}

func TestL8ApplicationRouteRegistryValueFormsDenyLiveInspection(t *testing.T) {
	forms := []struct {
		name string
		make func(*Registry) any
	}{
		{name: "pointer", make: func(registry *Registry) any { return registry }},
		{name: "value", make: func(registry *Registry) any { return *registry }},
		{name: "pointer interface", make: func(registry *Registry) any { var value any = registry; return value }},
		{name: "value interface", make: func(registry *Registry) any { var value any = *registry; return value }},
	}
	for _, tt := range forms {
		t.Run(tt.name, func(t *testing.T) {
			poison := newPoisonApplicationRouteHandler()
			registry, err := NewRegistry(poison)
			if err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			poison.armed = true
			assertApplicationRouteRegistryFormDenied(t, tt.make(registry), poison)
		})
	}
}

func assertApplicationRouteRegistryFormDenied(t *testing.T, value any, poison *poisonApplicationRouteHandler) {
	t.Helper()
	payload, err := json.Marshal(value)
	if len(payload) != 0 || !errors.Is(err, ErrLiveRouteStateNotSerializable) {
		t.Errorf("json.Marshal(%T) = %q, %v, want stable live-state denial", value, payload, err)
	}
	if marshaler, ok := value.(json.Marshaler); !ok {
		t.Errorf("%T does not implement json.Marshaler", value)
	} else if payload, marshalErr := marshaler.MarshalJSON(); len(payload) != 0 || marshalErr != ErrLiveRouteStateNotSerializable {
		t.Errorf("MarshalJSON(%T) = %q, %v, want stable live-state denial", value, payload, marshalErr)
	}
	if marshaler, ok := value.(encoding.TextMarshaler); !ok {
		t.Errorf("%T does not implement encoding.TextMarshaler", value)
	} else if payload, marshalErr := marshaler.MarshalText(); len(payload) != 0 || marshalErr != ErrLiveRouteStateNotSerializable {
		t.Errorf("MarshalText(%T) = %q, %v, want stable live-state denial", value, payload, marshalErr)
	}
	if errorValue, ok := value.(error); !ok {
		t.Errorf("%T does not implement safe error rendering", value)
	} else {
		assertApplicationRouteRegistryRenderedSafe(t, errorValue.Error())
	}
	if stringer, ok := value.(fmt.Stringer); !ok {
		t.Errorf("%T does not implement fmt.Stringer", value)
	} else {
		assertApplicationRouteRegistryRenderedSafe(t, stringer.String())
	}
	if stringer, ok := value.(fmt.GoStringer); !ok {
		t.Errorf("%T does not implement fmt.GoStringer", value)
	} else {
		assertApplicationRouteRegistryRenderedSafe(t, stringer.GoString())
	}
	for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v"} {
		rendered, panicked := formatApplicationRouteRegistryWithoutPanic(format, value)
		if panicked != nil {
			t.Errorf("fmt.Sprintf(%q, %T) traversed poison state: %v", format, value, panicked)
			continue
		}
		assertApplicationRouteRegistryRenderedSafe(t, rendered)
	}
	if poison.invoked {
		t.Error("Registry live inspection traversed poison handler state")
	}
}

func formatApplicationRouteRegistryWithoutPanic(format string, value any) (rendered string, panicked any) {
	defer func() { panicked = recover() }()
	return fmt.Sprintf(format, value), nil
}

func assertApplicationRouteRegistryRenderedSafe(t *testing.T, rendered string) {
	t.Helper()
	for _, unsafe := range []string{"handler-state=raw-secret", "private.example.test", "https://"} {
		if strings.Contains(rendered, unsafe) {
			t.Errorf("Registry rendering %q exposes %q", rendered, unsafe)
		}
	}
}

func closeOwnedApplicationRouteBodyTwice(t *testing.T, body io.ReadCloser) {
	t.Helper()
	results := make(chan error, 2)
	go func() { results <- body.Close() }()
	go func() { results <- body.Close() }()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("response body Close() error = %v, want nil", err)
		}
	}
}

type ownedApplicationRouteHandler struct {
	definition   Definition
	response     Response
	handleErr    error
	closeEntered chan struct{}
	closeRelease chan struct{}
	closeOnce    sync.Once
	releaseOnce  sync.Once

	mu         sync.Mutex
	closeCalls int
}

func newOwnedApplicationRouteHandler(response Response, handleErr error) *ownedApplicationRouteHandler {
	return &ownedApplicationRouteHandler{
		definition:   newFakeApplicationRouteHandler("owned", RouteCredentialHTTPV1, CredentialHTTPV1Prefix).def,
		response:     response,
		handleErr:    handleErr,
		closeEntered: make(chan struct{}),
		closeRelease: make(chan struct{}),
	}
}

func (handler *ownedApplicationRouteHandler) Definition() Definition { return handler.definition }
func (*ownedApplicationRouteHandler) Start(context.Context) error    { return nil }
func (handler *ownedApplicationRouteHandler) Handle(context.Context, Request) (Response, error) {
	return handler.response, handler.handleErr
}
func (handler *ownedApplicationRouteHandler) Close(context.Context) error {
	handler.mu.Lock()
	handler.closeCalls++
	handler.mu.Unlock()
	handler.closeOnce.Do(func() { close(handler.closeEntered) })
	<-handler.closeRelease
	return nil
}
func (handler *ownedApplicationRouteHandler) releaseClose() {
	handler.releaseOnce.Do(func() { close(handler.closeRelease) })
}
func (handler *ownedApplicationRouteHandler) closeCallCount() int {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.closeCalls
}

type ownedApplicationRouteBody struct {
	blockRead   bool
	closeErr    error
	readEntered chan struct{}
	readRelease chan struct{}
	readOnce    sync.Once
	releaseOnce sync.Once
	pendingRead chan error

	mu         sync.Mutex
	closeCalls int
}

func newOwnedApplicationRouteBody(blockRead bool, closeErr error) *ownedApplicationRouteBody {
	return &ownedApplicationRouteBody{
		blockRead:   blockRead,
		closeErr:    closeErr,
		readEntered: make(chan struct{}),
		readRelease: make(chan struct{}),
	}
}

func (body *ownedApplicationRouteBody) Read([]byte) (int, error) {
	if body.blockRead {
		body.readOnce.Do(func() { close(body.readEntered) })
		<-body.readRelease
	}
	return 0, io.EOF
}
func (body *ownedApplicationRouteBody) Close() error {
	body.mu.Lock()
	body.closeCalls++
	body.mu.Unlock()
	return body.closeErr
}
func (body *ownedApplicationRouteBody) releaseRead() {
	body.releaseOnce.Do(func() { close(body.readRelease) })
}
func (body *ownedApplicationRouteBody) closeCallCount() int {
	body.mu.Lock()
	defer body.mu.Unlock()
	return body.closeCalls
}

func validOwnedApplicationRouteRequest() Request {
	return Request{
		Metadata: RequestMetadata{Method: "POST", ContentType: "application/json", ContentLength: 2},
		Body:     strings.NewReader("{}"),
	}
}
