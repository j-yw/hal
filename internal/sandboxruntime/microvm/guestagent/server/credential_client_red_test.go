package server

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestL8D6GuestServerCredentialClientOptionIsExplicitAndDefaultsInert(t *testing.T) {
	field, ok := reflect.TypeOf(Options{}).FieldByName("CredentialClient")
	if !ok || field.Type.String() != "*credentialclient.Client" || field.Tag != "" {
		t.Fatalf("Options.CredentialClient = %#v, want exact explicit process-local pointer", field)
	}
	transport := newL4BlockingTransport()
	backend := &l4FakeBackend{}
	server, err := New(Options{Transport: transport, Backend: backend})
	if err != nil {
		t.Fatalf("New(default v1 options) error = %v", err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(default v1 options) error = %v", err)
	}
	if transport.serveCalls.Load() != 0 || backend.closeCalls.Load() != 1 {
		t.Fatal("nil CredentialClient changed the existing default v1 lifecycle")
	}
}

func TestL8D6GuestServerDoesNotConstructCredentialOrSocketAuthority(t *testing.T) {
	for _, name := range []string{"contracts.go", "server.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{
			"credentialclient.NewClient(", "NewControlAcceptExpectation(",
			"net.Listen(", "ListenConfig", "unix.Bind(", "syscall.Bind(",
		} {
			if strings.Contains(string(source), forbidden) {
				t.Fatalf("%s contains forbidden credential/socket constructor %q", name, forbidden)
			}
		}
	}
}

func TestL8D6GuestServerStartsAndJoinsExplicitCredentialLifecycle(t *testing.T) {
	transport := newL4BlockingTransport()
	backend := &l4FakeBackend{}
	owned, err := New(Options{Transport: transport, Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	credential := &l8D6CredentialLifecycleProbe{started: make(chan struct{})}
	owned.credentialLifecycle = credential

	serveDone := make(chan error, 1)
	go func() { serveDone <- owned.Serve(context.Background()) }()
	select {
	case <-credential.started:
	case err := <-serveDone:
		t.Fatalf("Serve returned before starting credential lifecycle: %v", err)
	case <-time.After(time.Second):
		t.Fatal("root server did not start the explicit credential lifecycle")
	}
	if err := owned.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if credential.serves.Load() != 1 || credential.closes.Load() != 1 {
		t.Fatalf("credential lifecycle calls = serve %d close %d, want 1/1", credential.serves.Load(), credential.closes.Load())
	}
}

func TestL8D6GuestServerContainsCredentialLifecycleFailure(t *testing.T) {
	for _, test := range []struct {
		name              string
		serveErr          error
		servePanics       bool
		closePanics       bool
		returnImmediately bool
	}{
		{name: "error", serveErr: errors.New("raw credential lifecycle error canary")},
		{name: "serve_panic", servePanics: true},
		{name: "close_panic", closePanics: true, returnImmediately: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			owned, err := New(Options{Transport: newL4BlockingTransport(), Backend: &l4FakeBackend{}})
			if err != nil {
				t.Fatal(err)
			}
			credential := &l8D6CredentialLifecycleProbe{
				started: make(chan struct{}), serveErr: test.serveErr, servePanics: test.servePanics,
				closePanics: test.closePanics, returnImmediately: test.returnImmediately,
			}
			owned.credentialLifecycle = credential
			err = owned.Serve(context.Background())
			if err == nil || strings.Contains(err.Error(), "canary") || owned.State() != StateFailed {
				t.Fatalf("Serve() error/state = %v/%s, want sanitized terminal failure", err, owned.State())
			}
			if credential.serves.Load() != 1 || credential.closes.Load() != 1 {
				t.Fatalf("credential lifecycle calls = serve %d close %d, want 1/1", credential.serves.Load(), credential.closes.Load())
			}
		})
	}
}

type l8D6CredentialLifecycleProbe struct {
	started           chan struct{}
	serveStarted      atomic.Bool
	serves            atomic.Uint32
	closes            atomic.Uint32
	serveErr          error
	servePanics       bool
	closePanics       bool
	returnImmediately bool
}

func (probe *l8D6CredentialLifecycleProbe) Serve(ctx context.Context) error {
	probe.serves.Add(1)
	probe.serveStarted.Store(true)
	close(probe.started)
	if probe.servePanics {
		panic("raw credential lifecycle panic canary")
	}
	if probe.serveErr != nil {
		return probe.serveErr
	}
	if probe.returnImmediately {
		return nil
	}
	<-ctx.Done()
	return nil
}

func (probe *l8D6CredentialLifecycleProbe) ServeStarted() bool {
	return probe.serveStarted.Load()
}

func (probe *l8D6CredentialLifecycleProbe) Close(context.Context) error {
	probe.closes.Add(1)
	if probe.closePanics {
		panic("raw credential lifecycle close panic canary")
	}
	return nil
}
