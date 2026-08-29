package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"
)

func TestProductionRunFailsClosed(t *testing.T) {
	if code := productionRun(nil); code != failClosedExit {
		t.Fatalf("productionRun() = %d, want %d", code, failClosedExit)
	}
	if code := productionRun([]string{"extra"}); code != failClosedExit {
		t.Fatalf("productionRun(extra) = %d, want %d", code, failClosedExit)
	}
}

func TestRunHelperRejectsMissingTypedNilAndExtraArgs(t *testing.T) {
	valid := validHelperOptions()
	var nilCore *stubHelperCore
	var nilTransport *stubHelperTransport
	var nilHost *stubHelperHost
	var nilRuntime *stubHelperRuntime
	var nilFactory *stubHelperFactory
	tests := []struct {
		name    string
		args    []string
		options l8composition.HelperOptions
	}{
		{name: "zero options", options: l8composition.HelperOptions{}},
		{name: "extra args", args: []string{"extra"}, options: valid},
		{name: "nil core", options: withHelperCore(valid, nil)},
		{name: "typed nil core", options: withHelperCore(valid, nilCore)},
		{name: "nil transport", options: withHelperTransport(valid, nil)},
		{name: "typed nil transport", options: withHelperTransport(valid, nilTransport)},
		{name: "nil host", options: withHelperHost(valid, nil)},
		{name: "typed nil host", options: withHelperHost(valid, nilHost)},
		{name: "nil runtime", options: withHelperRuntime(valid, nil)},
		{name: "typed nil runtime", options: withHelperRuntime(valid, nilRuntime)},
		{name: "nil factory", options: withHelperFactory(valid, nil)},
		{name: "typed nil factory", options: withHelperFactory(valid, nilFactory)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if test.args != nil {
				if code := productionRun(test.args); code != failClosedExit {
					t.Fatalf("productionRun() = %d, want %d", code, failClosedExit)
				}
				return
			}
			if code := runHelper(test.options); code != failClosedExit {
				t.Fatalf("runHelper() = %d, want %d", code, failClosedExit)
			}
		})
	}
}

func TestRunHelperFailsClosedAfterSuccessfulComposition(t *testing.T) {
	if code := runHelper(validHelperOptions()); code != failClosedExit {
		t.Fatalf("runHelper(valid) = %d, want %d", code, failClosedExit)
	}
}

func TestUnsupportedPlatformStubFailsClosed(t *testing.T) {
	source, err := os.ReadFile("main_other.go")
	if err != nil {
		t.Fatalf("ReadFile(main_other.go): %v", err)
	}
	if !strings.Contains(string(source), "os.Exit(127)") {
		t.Fatal("unsupported helper platform does not fail closed")
	}
}

func TestProductionHelperDoesNotInstallDefaultSSHOrListen(t *testing.T) {
	for _, name := range []string{"run.go", "main_linux.go", "main_other.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		text := string(source)
		for _, forbidden := range []string{
			"sshrelay.NewHelperExtension",
			"sshrelay.NewClientExtension",
			"l8composition.NewClient",
			"net.Listen",
			"net.Dial",
			"unix.Socket",
			"unix.Listen",
			"unix.Bind",
			"SOCK_STREAM",
			"SOCK_SEQPACKET",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains live helper marker %q", name, forbidden)
			}
		}
	}
}

func validHelperOptions() l8composition.HelperOptions {
	return l8composition.HelperOptions{
		Core:      &stubHelperCore{},
		Transport: &stubHelperTransport{},
		Policy:    credentialhelper.NewHelperPolicy(),
		Host:      &stubHelperHost{},
		Runtime:   &stubHelperRuntime{},
		SSH: credentialhelper.ExtensionRegistration{
			Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
			Factory:    &stubHelperFactory{},
		},
	}
}

func withHelperCore(options l8composition.HelperOptions, core credentialhelper.Core) l8composition.HelperOptions {
	options.Core = core
	return options
}

func withHelperTransport(options l8composition.HelperOptions, transport credentialhelper.Transport) l8composition.HelperOptions {
	options.Transport = transport
	return options
}

func withHelperHost(options l8composition.HelperOptions, host credentialhelper.ExtensionHost) l8composition.HelperOptions {
	options.Host = host
	return options
}

func withHelperRuntime(options l8composition.HelperOptions, runtime credentialhelper.ServiceRuntime) l8composition.HelperOptions {
	options.Runtime = runtime
	return options
}

func withHelperFactory(options l8composition.HelperOptions, factory credentialhelper.ExtensionFactory) l8composition.HelperOptions {
	options.SSH.Factory = factory
	return options
}

type stubHelperCore struct{}

func (*stubHelperCore) BeginPrepare(context.Context, credentialhelper.CorePrepareRequest) (credentialhelper.CorePreparation, error) {
	return nil, nil
}
func (*stubHelperCore) BeginExec(context.Context, credentialhelper.CoreExecRequest, credentialmemory.BorrowedView) (credentialhelper.CoreExecution, error) {
	return nil, nil
}
func (*stubHelperCore) Renew(context.Context, credentialhelper.CoreRenewRequest) error {
	return nil
}
func (*stubHelperCore) Revoke(context.Context, credentialhelper.CoreRevokeRequest) (credentialhelper.CoreCleanupResult, error) {
	return credentialhelper.CoreCleanupResult{}, nil
}
func (*stubHelperCore) Inspect(context.Context, credentialhelper.CoreInspectRequest) (credentialhelper.CoreInspection, error) {
	return credentialhelper.CoreInspection{}, nil
}
func (*stubHelperCore) Close(context.Context) error { return nil }

type stubHelperTransport struct{}

func (*stubHelperTransport) Receive(context.Context, credentialhelper.ReceiveRequest) (credentialhelper.ReceivedPacket, error) {
	return credentialhelper.ReceivedPacket{}, nil
}
func (*stubHelperTransport) Send(context.Context, credentialhelper.SendPacket) error {
	return nil
}
func (*stubHelperTransport) Close(context.Context) error { return nil }

type stubHelperHost struct{}

func (*stubHelperHost) CreateSSHAgentEndpoint(context.Context, credentialhelper.SSHAgentEndpointRequest) (credentialhelper.SSHAgentEndpoint, error) {
	return nil, nil
}
func (*stubHelperHost) PublishSSHAcceptedConnection(context.Context, credentialhelper.SSHAcceptedPublication, credentialhelper.SSHAgentConnection) error {
	return nil
}

type stubHelperRuntime struct{}

func (*stubHelperRuntime) Bootstrap(context.Context) (credentialhelper.ServiceBootstrap, error) {
	return credentialhelper.ServiceBootstrap{}, nil
}
func (*stubHelperRuntime) BindAgent(context.Context, credentialhelper.ServiceAgentBindingRequest, credentialhelper.ReceivedCapability) error {
	return nil
}
func (*stubHelperRuntime) ObserveJob(context.Context, credentialhelper.ServiceJobObservationRequest) (credentialhelper.ServiceJobObservation, error) {
	return credentialhelper.ServiceJobObservation{}, nil
}
func (*stubHelperRuntime) Loss() <-chan credentialhelper.ServiceLoss { return nil }
func (*stubHelperRuntime) BeginCleanup() (credentialhelper.ServiceCleanupBudget, error) {
	return nil, nil
}
func (*stubHelperRuntime) Close(context.Context) error { return nil }

type stubHelperFactory struct{}

func (*stubHelperFactory) Open(context.Context, credentialhelper.ExtensionOpenRequest) (credentialhelper.ExtensionSession, error) {
	return &stubHelperSession{}, nil
}

type stubHelperSession struct{}

func (*stubHelperSession) Prepare(context.Context, credentialhelper.ExtensionPrepareRequest) (credentialhelper.ExtensionPrepareResult, error) {
	return credentialhelper.ExtensionPrepareResult{}, nil
}
func (*stubHelperSession) BindExec(context.Context, credentialhelper.ExtensionExecRequest) (credentialhelper.ExtensionExecResult, error) {
	return credentialhelper.ExtensionExecResult{}, nil
}
func (*stubHelperSession) Renew(context.Context, credentialhelper.ExtensionRenewRequest) error {
	return nil
}
func (*stubHelperSession) Revoke(context.Context, credentialhelper.ExtensionRevokeRequest) (credentialhelper.ExtensionCleanupResult, error) {
	return credentialhelper.ExtensionCleanupResult{}, nil
}
func (*stubHelperSession) Close(context.Context) error { return nil }
