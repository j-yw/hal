package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	guestsession "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

func TestL8D6V2ControlFoundationPublicAPIIsExact(t *testing.T) {
	constructor := reflect.TypeOf(NewProductionL8V2ControlBridge)
	wantConstructor := reflect.TypeOf((func(*ProductionVsockBridge, sandboxruntime.JobCredentialIdentitySeed, ed25519.PrivateKey, [32]byte) (*ProductionL8V2ControlBridge, error))(nil))
	if constructor != wantConstructor {
		t.Fatalf("NewProductionL8V2ControlBridge type = %v, want %v", constructor, wantConstructor)
	}

	bridgeType := reflect.TypeOf((*ProductionL8V2ControlBridge)(nil))
	l8D6AssertExactExportedMethodSet(t, bridgeType, map[string]reflect.Type{
		"Close":         reflect.TypeOf((func(*ProductionL8V2ControlBridge) error)(nil)),
		"Format":        reflect.TypeOf((func(*ProductionL8V2ControlBridge, fmt.State, rune))(nil)),
		"MarshalJSON":   reflect.TypeOf((func(*ProductionL8V2ControlBridge) ([]byte, error))(nil)),
		"OpenReadiness": reflect.TypeOf((func(*ProductionL8V2ControlBridge, context.Context, sandboxruntime.Target) (*L8V2ControlReadinessSession, error))(nil)),
		"String":        reflect.TypeOf((func(*ProductionL8V2ControlBridge) string)(nil)),
	})

	sessionType := reflect.TypeOf((*L8V2ControlReadinessSession)(nil))
	l8D6AssertExactExportedMethodSet(t, sessionType, map[string]reflect.Type{
		"Close":       reflect.TypeOf((func(*L8V2ControlReadinessSession) error)(nil)),
		"Done":        reflect.TypeOf((func(*L8V2ControlReadinessSession) <-chan struct{})(nil)),
		"Format":      reflect.TypeOf((func(*L8V2ControlReadinessSession, fmt.State, rune))(nil)),
		"MarshalJSON": reflect.TypeOf((func(*L8V2ControlReadinessSession) ([]byte, error))(nil)),
		"Readiness":   reflect.TypeOf((func(*L8V2ControlReadinessSession) L8V2ControlReadiness)(nil)),
		"String":      reflect.TypeOf((func(*L8V2ControlReadinessSession) string)(nil)),
	})

	readinessType := reflect.TypeOf(L8V2ControlReadiness{})
	l8D6AssertExactExportedMethodSet(t, readinessType, map[string]reflect.Type{
		"Format":                 reflect.TypeOf((func(L8V2ControlReadiness, fmt.State, rune))(nil)),
		"GuestHelperGeneration":  reflect.TypeOf((func(L8V2ControlReadiness) string)(nil)),
		"GuestSessionGeneration": reflect.TypeOf((func(L8V2ControlReadiness) string)(nil)),
		"MarshalJSON":            reflect.TypeOf((func(L8V2ControlReadiness) ([]byte, error))(nil)),
		"String":                 reflect.TypeOf((func(L8V2ControlReadiness) string)(nil)),
	})
	if readinessType.NumField() != 2 || readinessType.Field(0).Name != "guestSessionGeneration" || readinessType.Field(1).Name != "guestHelperGeneration" {
		t.Fatalf("L8V2ControlReadiness fields = %v, want two private generation fields", readinessType)
	}
}

func TestL8D6V2ControlFoundationAuthenticatesCanonicalReadinessAndOwnsOneSession(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	target := l8D6V2ControlTarget(seed)
	key, nonce := l8D6V2ControlAuthority(t)
	host, guest := net.Pipe()
	processDone := make(chan struct{})
	stream := &l8D6V2ControlTestStream{Conn: host, processDone: processDone}
	connector := &l8D6V2ControlTestConnector{stream: stream}
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x51}, 16)), time.Now)
	if err != nil {
		t.Fatalf("new bridge: %v", err)
	}

	guestResult := make(chan l8D6V2ControlGuestResult, 1)
	go l8D6ServeV2ControlGuest(guest, seed, key.Public().(ed25519.PublicKey), nonce, guestResult)

	session, err := bridge.OpenReadiness(context.Background(), target)
	if err != nil {
		t.Fatalf("OpenReadiness: %v", err)
	}
	if session == nil || connector.calls != 1 || !reflect.DeepEqual(connector.targets, []sandboxruntime.Target{target}) {
		t.Fatalf("session/connector = %#v/%d/%#v", session, connector.calls, connector.targets)
	}
	guestState := <-guestResult
	if guestState.err != nil {
		t.Fatalf("guest protocol: %v", guestState.err)
	}
	readiness := session.Readiness()
	if got, want := readiness.GuestSessionGeneration(), base64.RawURLEncoding.EncodeToString(guestState.sessionID[:]); got != want {
		t.Fatalf("guest session generation = %q, want %q", got, want)
	}
	if got := readiness.GuestHelperGeneration(); got != "helper-generation-v1" {
		t.Fatalf("helper generation = %q", got)
	}
	select {
	case <-session.Done():
		t.Fatal("session was terminal before close")
	default:
	}
	if second, secondErr := bridge.OpenReadiness(context.Background(), target); second != nil || !errors.Is(secondErr, ErrL8V2ControlInvalid) {
		t.Fatalf("second OpenReadiness = %#v, %v", second, secondErr)
	}
	if connector.calls != 1 {
		t.Fatalf("connector calls after second open = %d, want 1", connector.calls)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("session Close: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("session second Close: %v", err)
	}
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("session Done did not close")
	}
	if err := bridge.Close(); err != nil {
		t.Fatalf("bridge Close: %v", err)
	}
	if err := bridge.Close(); err != nil {
		t.Fatalf("bridge second Close: %v", err)
	}
}

func TestL8D6V2ControlFoundationReturnMatrixAndPanicContainment(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	target := l8D6V2ControlTarget(seed)
	key, nonce := l8D6V2ControlAuthority(t)
	rawErr := errors.New("/private/runtime.sock OPENAI_API_KEY=secret")
	var typedNil *l8D6V2ControlTestStream
	tests := []struct {
		name      string
		connector *l8D6V2ControlTestConnector
	}{
		{name: "nil success", connector: &l8D6V2ControlTestConnector{}},
		{name: "typed nil success", connector: &l8D6V2ControlTestConnector{stream: typedNil}},
		{name: "nil error", connector: &l8D6V2ControlTestConnector{err: rawErr}},
		{name: "value plus error", connector: &l8D6V2ControlTestConnector{stream: &l8D6V2ControlTestStream{}, err: rawErr}},
		{name: "panic", connector: &l8D6V2ControlTestConnector{panicValue: rawErr}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bridge, err := newProductionL8V2ControlBridgeWithDependencies(tt.connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x52}, 16)), time.Now)
			if err != nil {
				t.Fatalf("new bridge: %v", err)
			}
			session, openErr := bridge.OpenReadiness(context.Background(), target)
			if session != nil || (!errors.Is(openErr, ErrL8V2ControlUnavailable) && !errors.Is(openErr, ErrL8V2ControlInvalid)) {
				t.Fatalf("OpenReadiness = %#v, %v", session, openErr)
			}
			for _, forbidden := range []string{"/private", "runtime.sock", "OPENAI_API_KEY", "secret"} {
				if strings.Contains(openErr.Error(), forbidden) {
					t.Fatalf("error leaked %q: %v", forbidden, openErr)
				}
			}
			if tt.connector.calls != 1 {
				t.Fatalf("connector calls = %d, want 1", tt.connector.calls)
			}
			if second, secondErr := bridge.OpenReadiness(context.Background(), target); second != nil || !errors.Is(secondErr, ErrL8V2ControlInvalid) {
				t.Fatalf("second OpenReadiness = %#v, %v", second, secondErr)
			}
			if tt.connector.calls != 1 {
				t.Fatalf("connector retried after terminal failure: %d", tt.connector.calls)
			}
		})
	}
}

func TestL8D6V2ControlFoundationRejectsIdentityBeforeConnector(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	key, nonce := l8D6V2ControlAuthority(t)
	tests := []struct {
		name   string
		mutate func(*sandboxruntime.Target)
	}{
		{name: "runtime", mutate: func(target *sandboxruntime.Target) { target.Runtime.RuntimeID = "different-runtime" }},
		{name: "target", mutate: func(target *sandboxruntime.Target) { target.ID = "different-runtime" }},
		{name: "driver", mutate: func(target *sandboxruntime.Target) { target.Runtime.Driver = sandboxruntime.DriverRootlessPodman }},
		{name: "provider", mutate: func(target *sandboxruntime.Target) { target.Provider = "different-provider" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := &l8D6V2ControlTestConnector{}
			bridge, err := newProductionL8V2ControlBridgeWithDependencies(connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x53}, 16)), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			target := l8D6V2ControlTarget(seed)
			tt.mutate(&target)
			if session, openErr := bridge.OpenReadiness(context.Background(), target); session != nil || !errors.Is(openErr, ErrL8V2ControlInvalid) {
				t.Fatalf("OpenReadiness = %#v, %v", session, openErr)
			}
			if connector.calls != 0 {
				t.Fatalf("connector called %d times before identity rejection", connector.calls)
			}
		})
	}
}

func TestL8D6V2ControlFoundationProcessLossTerminalizesOwner(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	key, nonce := l8D6V2ControlAuthority(t)
	host, guest := net.Pipe()
	processDone := make(chan struct{})
	stream := &l8D6V2ControlTestStream{Conn: host, processDone: processDone}
	connector := &l8D6V2ControlTestConnector{stream: stream}
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x54}, 16)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	guestResult := make(chan l8D6V2ControlGuestResult, 1)
	go l8D6ServeV2ControlGuest(guest, seed, key.Public().(ed25519.PublicKey), nonce, guestResult)
	session, err := bridge.OpenReadiness(context.Background(), l8D6V2ControlTarget(seed))
	if err != nil {
		t.Fatal(err)
	}
	if result := <-guestResult; result.err != nil {
		t.Fatal(result.err)
	}
	close(processDone)
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("process loss did not terminalize session")
	}
	if stream.closeCalls() != 1 {
		t.Fatalf("stream close calls = %d, want 1", stream.closeCalls())
	}
}

func TestL8D6V2ControlFoundationValuesDenyProjection(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	key, nonce := l8D6V2ControlAuthority(t)
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(&l8D6V2ControlTestConnector{}, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x55}, 16)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	readiness := L8V2ControlReadiness{guestSessionGeneration: "session-generation", guestHelperGeneration: "helper-generation"}
	values := []any{bridge, (*L8V2ControlReadinessSession)(nil), readiness}
	for _, value := range values {
		if encoded, marshalErr := json.Marshal(value); marshalErr == nil || encoded != nil || !errors.Is(marshalErr, ErrL8V2ControlSerialization) {
			t.Fatalf("json.Marshal(%T) = %q, %v", value, encoded, marshalErr)
		}
		for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), fmt.Sprintf("%+v", value)} {
			if strings.Contains(rendered, "session-generation") || strings.Contains(rendered, "helper-generation") || strings.Contains(rendered, base64.RawURLEncoding.EncodeToString(nonce[:])) {
				t.Fatalf("format %T leaked authority: %q", value, rendered)
			}
		}
	}
}

func l8D6AssertExactExportedMethodSet(t *testing.T, typ reflect.Type, want map[string]reflect.Type) {
	t.Helper()
	if typ.NumMethod() != len(want) {
		t.Fatalf("%v methods = %d, want %d", typ, typ.NumMethod(), len(want))
	}
	for name, methodType := range want {
		method, ok := typ.MethodByName(name)
		if !ok || method.Type != methodType {
			t.Fatalf("%v.%s = %v/%t, want %v", typ, name, method.Type, ok, methodType)
		}
	}
}

func l8D6V2ControlSeed(t *testing.T) sandboxruntime.JobCredentialIdentitySeed {
	t.Helper()
	seed := sandboxruntime.JobCredentialIdentitySeed{
		SandboxID: "sandbox-v2", ExecutionID: "execution-v2", WorkerID: "worker-v2", HostID: "host-v2",
		RuntimeDriver: "microvm", RuntimeID: "fc-runtime-v2", RuntimeGeneration: "runtime-generation-v2",
		FirecrackerProcessGeneration: "process-generation-v2", VsockGeneration: "vsock-generation-v2",
		WorkerJobID: "job-v2", SubmissionID: "submission-v2", PlanID: "plan-v2",
		ActivationGeneration: "activation-v2", CredentialGeneration: "credential-v2",
		AdmissionGrantID: "grant-v2", PrincipalID: "principal-v2", TemplatePolicyID: "template-v2", WorkspacePolicyID: "workspace-v2",
		ControllerKeyGeneration: "controller-key-v2", GuestBootGeneration: "guest-boot-v2",
		GuestImageGeneration: "guest-image-v2", GuestImageDigest: "sha256-" + strings.Repeat("a", 64),
		AdmissionGrantRevision: 1, BindingIDs: []string{"binding-v2"},
		DeliveryModes: []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeFileTmpfs},
		IssuedAt:      time.Now().UTC().Add(-time.Minute),
	}
	if err := sandboxruntime.ValidateJobCredentialIdentitySeed(seed); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	return seed
}

func l8D6V2ControlTarget(seed sandboxruntime.JobCredentialIdentitySeed) sandboxruntime.Target {
	return sandboxruntime.Target{
		ID: seed.RuntimeID, Provider: firecracker.BackendID,
		Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverMicroVM, RuntimeID: seed.RuntimeID},
	}
}

func l8D6V2ControlAuthority(t *testing.T) (ed25519.PrivateKey, [32]byte) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x42}, len(nonce)))
	return key, nonce
}

type l8D6V2ControlTestConnector struct {
	mu         sync.Mutex
	stream     l8V2ControlStream
	err        error
	panicValue any
	calls      int
	targets    []sandboxruntime.Target
}

func (connector *l8D6V2ControlTestConnector) OpenL8V2Control(_ context.Context, target sandboxruntime.Target) (l8V2ControlStream, error) {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	connector.calls++
	connector.targets = append(connector.targets, target)
	if connector.panicValue != nil {
		panic(connector.panicValue)
	}
	return connector.stream, connector.err
}

type l8D6V2ControlTestStream struct {
	net.Conn
	processDone <-chan struct{}
	mu          sync.Mutex
	closes      int
}

func (stream *l8D6V2ControlTestStream) ProcessDone() <-chan struct{} {
	if stream == nil {
		return nil
	}
	return stream.processDone
}

func (stream *l8D6V2ControlTestStream) Close() error {
	if stream == nil {
		return nil
	}
	stream.mu.Lock()
	stream.closes++
	first := stream.closes == 1
	stream.mu.Unlock()
	if first && stream.Conn != nil {
		return stream.Conn.Close()
	}
	return nil
}

func (stream *l8D6V2ControlTestStream) closeCalls() int {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.closes
}

type l8D6V2ControlGuestResult struct {
	sessionID [32]byte
	err       error
}

func l8D6ServeV2ControlGuest(conn net.Conn, seed sandboxruntime.JobCredentialIdentitySeed, publicKey ed25519.PublicKey, nonce [32]byte, result chan<- l8D6V2ControlGuestResult) {
	defer conn.Close()
	finish := func(sessionID [32]byte, err error) {
		result <- l8D6V2ControlGuestResult{sessionID: sessionID, err: err}
	}
	preface, err := frame.Read(conn, 512)
	if err != nil || string(preface) != `{"protocolVersion":"guest-agent-v2","operation":"readiness"}` {
		finish([32]byte{}, fmt.Errorf("preface = %q, %v", preface, err))
		return
	}
	identity, err := l8D6V2ControlSessionIdentity(seed, nonce)
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	guestHandshake, hello, err := guestsession.NewGuestHandshake(guestsession.GuestHandshakeConfig{
		Identity: identity, PinnedControllerPublicKey: publicKey,
	})
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	if _, err := conn.Write(hello); err != nil {
		finish([32]byte{}, err)
		return
	}
	auth, err := l8D6ReadHandshakeWire(conn)
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	state, err := guestHandshake.AcceptControllerAuth(auth)
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	guestFinished, err := state.SealFinished()
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	if _, err := conn.Write(guestFinished); err != nil {
		finish([32]byte{}, err)
		return
	}
	controllerFinished, err := l8D6ReadSecureWire(conn)
	if err != nil || state.OpenFinished(controllerFinished) != nil {
		finish([32]byte{}, fmt.Errorf("controller finished: %v", err))
		return
	}
	requestWire, err := l8D6ReadSecureWire(conn)
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	requestPayload, err := state.OpenApplication(requestWire, func(frameType guestsession.FrameType, _ []byte) error {
		if frameType != guestsession.FrameTypeControlRequest {
			return errors.New("wrong frame type")
		}
		return nil
	})
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	request, err := v2control.DecodeReadinessRequest(requestPayload)
	guestsession.DestroyBytes(requestPayload)
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	response, err := v2control.NewReadinessSuccessResponse(request, "helper-generation-v1")
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	payload, err := v2control.EncodeReadinessSuccessResponse(response)
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	responseWire, err := state.SealApplication(guestsession.FrameTypeControlResponse, payload)
	guestsession.DestroyBytes(payload)
	if err != nil {
		finish([32]byte{}, err)
		return
	}
	if _, err := conn.Write(responseWire); err != nil {
		finish([32]byte{}, err)
		return
	}
	guestsession.DestroyBytes(responseWire)
	finish(state.SessionID(), nil)
	_, _ = io.Copy(io.Discard, conn)
}

func l8D6V2ControlSessionIdentity(seed sandboxruntime.JobCredentialIdentitySeed, nonce [32]byte) (guestsession.Identity, error) {
	digest, err := hex.DecodeString(strings.TrimPrefix(seed.GuestImageDigest, "sha256-"))
	if err != nil || len(digest) != 32 {
		return guestsession.Identity{}, errors.New("bad image digest")
	}
	identity := guestsession.Identity{
		Channel: guestsession.ChannelControl, GuestBootNonce: nonce,
		GuestCID: guestsession.GuestCID, GuestPort: guestsession.ControlPort,
		ControllerKeyGeneration: seed.ControllerKeyGeneration,
		RuntimeID:               seed.RuntimeID, RuntimeGeneration: seed.RuntimeGeneration,
		FirecrackerProcessGeneration: seed.FirecrackerProcessGeneration,
		VsockGeneration:              seed.VsockGeneration, BootGeneration: seed.GuestBootGeneration,
		ImageGeneration: seed.GuestImageGeneration,
	}
	copy(identity.ImageSHA256[:], digest)
	return identity, nil
}

func l8D6ReadHandshakeWire(reader io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	length, err := guestsession.ParseHandshakeLength(prefix[:])
	if err != nil {
		return nil, err
	}
	wire := make([]byte, 4+int(length))
	copy(wire, prefix[:])
	if _, err := io.ReadFull(reader, wire[4:]); err != nil {
		return nil, err
	}
	return wire, nil
}

func l8D6ReadSecureWire(reader io.Reader) ([]byte, error) {
	prefix := make([]byte, guestsession.SecureRecordHeaderBytes)
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return nil, err
	}
	header, err := guestsession.ParseRecordHeaderPrefix(prefix, guestsession.ChannelControl)
	if err != nil {
		return nil, err
	}
	wire := make([]byte, len(prefix)+int(header.CiphertextLength))
	copy(wire, prefix)
	if _, err := io.ReadFull(reader, wire[len(prefix):]); err != nil {
		return nil, err
	}
	return wire, nil
}
