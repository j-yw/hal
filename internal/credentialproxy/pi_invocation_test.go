package credentialproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestL8D3PiAzureResponsesInvocationIsSealedAndWritesTransientBinding(t *testing.T) {
	definition, err := NewAzureOpenAIResponsesV1Definition("example.com", 443, "example.com", TLSRootPolicySystem, "deployment-one", "2026-06-01")
	if err != nil {
		t.Fatal(err)
	}
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{
		now:     func() time.Time { return time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC) },
		entropy: bytes.NewReader(bytes.Repeat([]byte{0x91}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC))
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	directory := &l8D3CodingAgentDirectory{}
	invocation, err := NewAzureResponsesPiInvocation(AzureResponsesPiInvocationConfig{
		Definition: definition, LocalAuthority: "runtime-credential.internal:8080", Ticket: ticket,
		TicketStore: store, Correlation: activation.Correlation,
		CodingAgentDirectory: "/run/hal/pi-empty/job-one", DirectoryProof: directory,
	})
	if err != nil {
		t.Fatalf("NewAzureResponsesPiInvocation() error: %v", err)
	}

	wantArguments := []string{
		"--provider", "azure-openai-responses", "--model", "deployment-one", "--offline",
		"--no-extensions", "--no-prompt-templates", "--no-themes", "--no-session",
	}
	if got := invocation.Arguments(); !reflect.DeepEqual(got, wantArguments) {
		t.Fatalf("Arguments() = %#v, want %#v", got, wantArguments)
	}
	arguments := invocation.Arguments()
	arguments[0] = "--api-key"
	if reflect.DeepEqual(invocation.Arguments(), arguments) {
		t.Fatal("Arguments() returned mutable alias")
	}

	sink := &l8D3PiEnvironmentSink{ambient: map[string][]byte{
		"AZURE_OPENAI_API_KEY":             []byte("ambient-key"),
		"AZURE_OPENAI_BASE_URL":            []byte("https://override.invalid"),
		"AZURE_OPENAI_RESOURCE_NAME":       []byte("ambient-resource"),
		"AZURE_OPENAI_DEPLOYMENT_NAME_MAP": []byte("other=override"),
		"OPENAI_API_KEY":                   []byte("ambient-openai"),
		"HTTP_PROXY":                       []byte("http://ambient.invalid"),
	}}
	if err := invocation.WriteTransientEnvironment(context.Background(), sink); err != nil {
		t.Fatalf("WriteTransientEnvironment() error: %v", err)
	}
	if directory.count != 1 {
		t.Fatalf("directory inspections = %d, want 1", directory.count)
	}
	want := map[string]string{
		"AZURE_OPENAI_BASE_URL":    "http://runtime-credential.internal:8080/.well-known/hal/credential-http/v1/azure-openai-responses-v1/deployments/deployment-one",
		"AZURE_OPENAI_API_VERSION": "2026-06-01",
		"PI_CODING_AGENT_DIR":      "/run/hal/pi-empty/job-one",
	}
	for name, value := range want {
		if got := string(sink.values[name]); got != value {
			t.Errorf("environment %s = %q, want %q", name, got, value)
		}
	}
	ticketValue := make([]byte, JobTicketEncodedBytes)
	_, _ = ticket.CopyTo(ticketValue)
	if !bytes.Equal(sink.values["AZURE_OPENAI_API_KEY"], ticketValue) {
		t.Fatal("transient API key is not exact one-job ticket")
	}
	for _, name := range definition.SealedInvocationPolicy().ClearedEnvironmentKeys() {
		if !sink.cleared[name] {
			t.Errorf("ambient provider key %s was not cleared", name)
		}
	}
	for _, rendered := range []string{fmt.Sprint(invocation), fmt.Sprintf("%#v", invocation), fmt.Sprintf("%#v", *invocation)} {
		if rendered != "credentialproxy.AzureResponsesPiInvocation{live}" || bytes.Contains([]byte(rendered), ticketValue) {
			t.Fatalf("invocation formatting = %q", rendered)
		}
	}
	if _, err := json.Marshal(invocation); !errors.Is(err, ErrLivePiInvocationNotSerializable) {
		t.Fatalf("Marshal() error = %v, want denial", err)
	}
}

func TestL8D3PiAzureResponsesInvocationFailsBeforeEnvironmentWhenDirectoryProofIsAbsent(t *testing.T) {
	definition, err := NewAzureOpenAIResponsesV1Definition("example.com", 443, "example.com", TLSRootPolicySystem, "deployment-one", "2026-06-01")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	store, err := newTicketStore("daemon-generation-01", ticketStoreDeps{now: func() time.Time { return now }, entropy: bytes.NewReader(bytes.Repeat([]byte{0x92}, 64))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activation := l8D3TicketActivation(t, now)
	ticket, err := store.Issue(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	proof := &l8D3CodingAgentDirectory{err: errors.New("raw path /home/user/.pi api-key=canary")}
	invocation, err := NewAzureResponsesPiInvocation(AzureResponsesPiInvocationConfig{
		Definition: definition, LocalAuthority: "runtime-credential.internal:8080", Ticket: ticket,
		TicketStore: store, Correlation: activation.Correlation,
		CodingAgentDirectory: "/run/hal/pi-empty/job-one", DirectoryProof: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := &l8D3PiEnvironmentSink{}
	if err := invocation.WriteTransientEnvironment(context.Background(), sink); !errors.Is(err, ErrPiInvocationEnvironment) || bytes.Contains([]byte(err.Error()), []byte("canary")) {
		t.Fatalf("WriteTransientEnvironment() error = %v, want sanitized failure", err)
	}
	if len(sink.values) != 0 || len(sink.cleared) != 0 {
		t.Fatalf("sink mutated before directory proof: values=%v cleared=%v", sink.values, sink.cleared)
	}
}

type l8D3CodingAgentDirectory struct {
	count int
	err   error
}

func (proof *l8D3CodingAgentDirectory) InspectOwnedEmptyPrivateDirectory(context.Context, string) error {
	proof.count++
	return proof.err
}

type l8D3PiEnvironmentSink struct {
	ambient map[string][]byte
	values  map[string][]byte
	cleared map[string]bool
}

func (sink *l8D3PiEnvironmentSink) ClearEnvironment(name string) error {
	if sink.cleared == nil {
		sink.cleared = make(map[string]bool)
	}
	if sink.ambient != nil {
		delete(sink.ambient, name)
	}
	sink.cleared[name] = true
	return nil
}

func (sink *l8D3PiEnvironmentSink) MaxEnvironmentValueBytes(string) int { return 1024 }

func (sink *l8D3PiEnvironmentSink) WriteEnvironment(name string, value []byte) error {
	if sink.values == nil {
		sink.values = make(map[string][]byte)
	}
	sink.values[name] = append([]byte(nil), value...)
	return nil
}
