package server

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
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
