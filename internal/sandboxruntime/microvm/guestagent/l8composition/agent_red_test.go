package l8composition

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	guestserver "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
)

func TestL8D6GuestAgentWrapperHasNoCredentialOrListenerConstructionAuthority(t *testing.T) {
	source, err := os.ReadFile("agent_red.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"credentialclient", "credentialhelper", "net.Listen(", "ListenConfig", "unix.Bind(",
		"NewClient(", "NewControlAcceptExpectation(", "/cmd", "/sandboxworker", "/firecrackerhost",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("Agent wrapper contains forbidden construction authority %q", forbidden)
		}
	}
	typeOf := reflect.TypeOf(Agent{})
	if typeOf.NumField() != 2 || typeOf.Field(0).Name != "compositionLiveValue" || typeOf.Field(1).Name != "server" || typeOf.Field(1).Type.String() != "*server.Server" {
		t.Fatalf("Agent fields = %#v, want only live marker and root server owner", reflect.VisibleFields(typeOf))
	}
}

func TestL8D6GuestAgentNilCredentialClientPreservesV1Lifecycle(t *testing.T) {
	transport := newAgentRedV1Transport()
	backend := &agentRedBackend{}
	agent, err := NewAgent(guestserver.Options{Transport: transport, Backend: backend})
	if err != nil {
		t.Fatalf("NewAgent(default v1) error = %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- agent.Serve(context.Background()) }()
	select {
	case <-transport.started:
	case err := <-serveDone:
		t.Fatalf("v1 Serve returned before shutdown: %v", err)
	case <-time.After(time.Second):
		t.Fatal("v1 transport was not served")
	}
	if err := agent.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown(default v1) error = %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve(default v1) error = %v", err)
	}
	if transport.calls.Load() != 1 || backend.closes.Load() != 1 || agent.State() != guestserver.StateStopped {
		t.Fatal("nil CredentialClient changed v1 ownership or terminal state")
	}
}

func TestL8D6GuestAgentOwnsExplicitCredentialClientThroughTerminalClose(t *testing.T) {
	clientTransport := &agentRedCredentialTransport{}
	clientOptions := validClientOptions()
	clientOptions.Transport = clientTransport
	client, _, err := NewClient(clientOptions)
	if err != nil {
		t.Fatal(err)
	}
	v1Transport := newAgentRedV1Transport()
	agent, err := NewAgent(guestserver.Options{
		Transport: v1Transport, Backend: &agentRedBackend{}, CredentialClient: client,
	})
	if err != nil {
		t.Fatalf("NewAgent(explicit credential client) error = %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- agent.Serve(context.Background()) }()
	select {
	case <-v1Transport.started:
	case err := <-serveDone:
		t.Fatalf("Agent.Serve returned before shutdown: %v", err)
	case <-time.After(time.Second):
		t.Fatal("v1 server was not started")
	}
	if err := agent.Shutdown(context.Background()); err != nil {
		t.Fatalf("Agent.Shutdown error = %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Agent.Serve error = %v", err)
	}
	if clientTransport.closes.Load() != 1 {
		t.Fatalf("credential client transport closes = %d, want one synchronous terminal close", clientTransport.closes.Load())
	}
}

func TestL8D6GuestAgentRejectsNilAndDoesNotContainCredentialConstructors(t *testing.T) {
	var agent *Agent
	if err := agent.Serve(context.Background()); !errors.Is(err, ErrAgentCompositionDependencyUnaccepted) {
		t.Fatalf("nil Agent Serve error = %v", err)
	}
}

type agentRedV1Transport struct {
	started chan struct{}
	calls   atomic.Uint32
}

func newAgentRedV1Transport() *agentRedV1Transport {
	return &agentRedV1Transport{started: make(chan struct{}, 1)}
}

func (transport *agentRedV1Transport) Serve(ctx context.Context, _ guestserver.Limits, _ guestserver.Handler) error {
	transport.calls.Add(1)
	transport.started <- struct{}{}
	<-ctx.Done()
	return nil
}

type agentRedBackend struct{ closes atomic.Uint32 }

func (*agentRedBackend) Ready(context.Context) error { return nil }
func (*agentRedBackend) Exec(context.Context, guestserver.ExecPlan) (guestserver.ExecResult, error) {
	return guestserver.ExecResult{}, nil
}
func (*agentRedBackend) CopyIn(context.Context, guestserver.CopyInPlan) (guestserver.CopyResult, error) {
	return guestserver.CopyResult{}, nil
}
func (*agentRedBackend) CopyOut(context.Context, guestserver.CopyOutPlan) (guestserver.CopyResult, error) {
	return guestserver.CopyResult{}, nil
}
func (backend *agentRedBackend) Close(context.Context) error {
	backend.closes.Add(1)
	return nil
}

type agentRedCredentialTransport struct{ closes atomic.Uint32 }

func (*agentRedCredentialTransport) ReceiveController(context.Context, credentialclient.ControllerReceiveRequest) (credentialclient.ControllerPacket, error) {
	return credentialclient.ControllerPacket{}, errors.New("unexpected controller receive")
}
func (*agentRedCredentialTransport) SendController(context.Context, credentialclient.ControllerSendPacket) error {
	return errors.New("unexpected controller send")
}
func (*agentRedCredentialTransport) ReceiveHelper(context.Context, credentialclient.HelperReceiveRequest) (credentialclient.HelperPacket, error) {
	return credentialclient.HelperPacket{}, errors.New("unexpected helper receive")
}
func (*agentRedCredentialTransport) SendHelper(context.Context, credentialclient.HelperSendPacket) error {
	return errors.New("unexpected helper send")
}
func (transport *agentRedCredentialTransport) Close(context.Context) error {
	transport.closes.Add(1)
	return nil
}
