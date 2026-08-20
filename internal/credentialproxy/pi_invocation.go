package credentialproxy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/credentialmemory"
)

var (
	ErrPiInvocationConfig              = errors.New("credential proxy Pi invocation configuration invalid")
	ErrPiInvocationEnvironment         = errors.New("credential proxy Pi invocation environment failed")
	ErrLivePiInvocationNotSerializable = errors.New("credential proxy live Pi invocation is not serializable")
)

type PiCodingAgentDirectoryProof interface {
	InspectOwnedEmptyPrivateDirectory(context.Context, string) error
}

type PiTransientEnvironmentSink interface {
	ClearEnvironment(string) error
	MaxEnvironmentValueBytes(string) int
	WriteEnvironment(string, []byte) error
}

type AzureResponsesPiInvocationConfig struct {
	Definition           ServiceDefinition
	LocalAuthority       string
	Ticket               *JobTicket
	TicketStore          *TicketStore
	Correlation          TicketCorrelation
	CodingAgentDirectory string
	DirectoryProof       PiCodingAgentDirectoryProof
}

func (AzureResponsesPiInvocationConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrLivePiInvocationNotSerializable
}
func (AzureResponsesPiInvocationConfig) MarshalText() ([]byte, error) {
	return nil, ErrLivePiInvocationNotSerializable
}
func (AzureResponsesPiInvocationConfig) String() string {
	return "credentialproxy.AzureResponsesPiInvocationConfig{live}"
}
func (AzureResponsesPiInvocationConfig) GoString() string {
	return "credentialproxy.AzureResponsesPiInvocationConfig{live}"
}
func (AzureResponsesPiInvocationConfig) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialproxy.AzureResponsesPiInvocationConfig{live}"))
}

type AzureResponsesPiInvocation struct {
	config    AzureResponsesPiInvocationConfig
	arguments []string
	localBase string
}

func NewAzureResponsesPiInvocation(config AzureResponsesPiInvocationConfig) (*AzureResponsesPiInvocation, error) {
	if ValidateServiceDefinition(config.Definition) != nil || !validLocalRuntimeAuthority(config.LocalAuthority) ||
		config.Ticket == nil || config.TicketStore == nil || !validTicketCorrelation(config.Correlation) ||
		!validPrivateCodingAgentDirectory(config.CodingAgentDirectory) || config.DirectoryProof == nil || typedNil(config.DirectoryProof) {
		return nil, ErrPiInvocationConfig
	}
	policy := config.Definition.SealedInvocationPolicy()
	localBase := "http://" + config.LocalAuthority + applicationRouteDeploymentBase(config.Definition)
	if len(localBase) > 512 {
		return nil, ErrPiInvocationConfig
	}
	return &AzureResponsesPiInvocation{
		config:    config,
		arguments: policy.Arguments(),
		localBase: localBase,
	}, nil
}

func (invocation *AzureResponsesPiInvocation) Arguments() []string {
	if invocation == nil {
		return nil
	}
	return append([]string(nil), invocation.arguments...)
}

func (invocation *AzureResponsesPiInvocation) WriteTransientEnvironment(ctx context.Context, sink PiTransientEnvironmentSink) error {
	if invocation == nil || ctx == nil || sink == nil || typedNil(sink) {
		return ErrPiInvocationEnvironment
	}
	if err := ctx.Err(); err != nil {
		return ErrPiInvocationEnvironment
	}
	config := invocation.config
	if err := config.DirectoryProof.InspectOwnedEmptyPrivateDirectory(ctx, config.CodingAgentDirectory); err != nil {
		return ErrPiInvocationEnvironment
	}
	if err := config.TicketStore.Validate(ctx, config.Ticket, config.Correlation); err != nil {
		return ErrPiInvocationEnvironment
	}
	for _, name := range config.Definition.SealedInvocationPolicy().ClearedEnvironmentKeys() {
		if sink.ClearEnvironment(name) != nil {
			return ErrPiInvocationEnvironment
		}
	}
	for _, entry := range []struct {
		name  string
		value string
	}{
		{name: "AZURE_OPENAI_BASE_URL", value: invocation.localBase},
		{name: "AZURE_OPENAI_API_VERSION", value: config.Definition.SealedAPIVersion()},
		{name: "PI_CODING_AGENT_DIR", value: config.CodingAgentDirectory},
	} {
		value := []byte(entry.value)
		if sink.MaxEnvironmentValueBytes(entry.name) < len(value) || sink.WriteEnvironment(entry.name, value) != nil {
			wipeBytes(value)
			return ErrPiInvocationEnvironment
		}
		wipeBytes(value)
	}
	ticket, err := credentialmemory.NewLockedMapping(JobTicketEncodedBytes)
	if err != nil {
		return ErrPiInvocationEnvironment
	}
	defer ticket.Destroy()
	if err := ticket.Load(ctx, func(destination []byte) (int, error) {
		return config.Ticket.CopyTo(destination)
	}); err != nil {
		return ErrPiInvocationEnvironment
	}
	writeErr := ticket.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		return view.WriteTo(ctx, &piEnvironmentValueSink{
			sink: sink,
			name: "AZURE_OPENAI_API_KEY",
		})
	})
	if writeErr != nil {
		return ErrPiInvocationEnvironment
	}
	if err := config.TicketStore.Validate(ctx, config.Ticket, config.Correlation); err != nil {
		return ErrPiInvocationEnvironment
	}
	return nil
}

func applicationRouteDeploymentBase(definition ServiceDefinition) string {
	return "/.well-known/hal/credential-http/v1/" + string(definition.ServiceID()) +
		"/deployments/" + definition.SealedDeployment()
}

func validPrivateCodingAgentDirectory(path string) bool {
	return path != "" && len(path) <= 512 && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsAny(path, "\x00\r\n") && path != "/"
}

type piEnvironmentValueSink struct {
	sink PiTransientEnvironmentSink
	name string
}

func (sink *piEnvironmentValueSink) MaxCredentialBytes() int {
	return sink.sink.MaxEnvironmentValueBytes(sink.name)
}

func (sink *piEnvironmentValueSink) WriteCredential(value []byte) error {
	if len(value) != JobTicketEncodedBytes || sink.sink.WriteEnvironment(sink.name, value) != nil {
		return ErrPiInvocationEnvironment
	}
	return nil
}

func (AzureResponsesPiInvocation) MarshalJSON() ([]byte, error) {
	return nil, ErrLivePiInvocationNotSerializable
}
func (AzureResponsesPiInvocation) MarshalText() ([]byte, error) {
	return nil, ErrLivePiInvocationNotSerializable
}
func (AzureResponsesPiInvocation) String() string {
	return "credentialproxy.AzureResponsesPiInvocation{live}"
}
func (AzureResponsesPiInvocation) GoString() string {
	return "credentialproxy.AzureResponsesPiInvocation{live}"
}
func (AzureResponsesPiInvocation) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialproxy.AzureResponsesPiInvocation{live}"))
}
