package firecrackerhost

import (
	"bufio"
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
	"os"
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
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x51}, 64)), time.Now)
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
			bridge, err := newProductionL8V2ControlBridgeWithDependencies(tt.connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x52}, 64)), time.Now)
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
			bridge, err := newProductionL8V2ControlBridgeWithDependencies(connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x53}, 64)), time.Now)
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
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x54}, 64)), time.Now)
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

func TestL8D6V2ControlFoundationCloseWinsConcurrentOpenPublication(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	key, nonce := l8D6V2ControlAuthority(t)
	host, guest := net.Pipe()
	processDone := make(chan struct{})
	connector := &l8D6V2ControlBlockingConnector{
		stream:  &l8D6V2ControlTestStream{Conn: host, processDone: processDone},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x56}, 64)), time.Now)
	if err != nil {
		t.Fatal(err)
	}

	type openResult struct {
		session *L8V2ControlReadinessSession
		err     error
	}
	opened := make(chan openResult, 1)
	go func() {
		session, openErr := bridge.OpenReadiness(context.Background(), l8D6V2ControlTarget(seed))
		opened <- openResult{session: session, err: openErr}
	}()
	<-connector.entered
	if err := bridge.Close(); err != nil {
		t.Fatalf("concurrent bridge Close: %v", err)
	}
	guestResult := make(chan l8D6V2ControlGuestResult, 1)
	go l8D6ServeV2ControlGuest(guest, seed, key.Public().(ed25519.PublicKey), nonce, guestResult)
	close(connector.release)

	result := <-opened
	if result.session != nil {
		_ = result.session.Close()
		t.Fatalf("OpenReadiness published a session after Close: %#v", result.session)
	}
	if !errors.Is(result.err, ErrL8V2ControlUnavailable) {
		t.Fatalf("OpenReadiness error = %v, want ErrL8V2ControlUnavailable", result.err)
	}
	select {
	case guestState := <-guestResult:
		if guestState.err == nil {
			t.Fatal("guest completed authenticated readiness after bridge Close")
		}
	case <-time.After(time.Second):
		t.Fatal("guest exchange did not terminate after close won publication")
	}
}

func TestL8D6V2ControlFoundationCloseSynchronouslyOwnsAdmittedHandshakeStream(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	key, nonce := l8D6V2ControlAuthority(t)
	host, guest := net.Pipe()
	processDone := make(chan struct{})
	stream := &l8D6V2ControlBlockingCloseStream{
		l8D6V2ControlTestStream: &l8D6V2ControlTestStream{Conn: host, processDone: processDone},
		closeEntered:            make(chan struct{}),
		closeRelease:            make(chan struct{}),
	}
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(
		&l8D6V2ControlTestConnector{stream: stream},
		seed,
		key,
		nonce,
		bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64)),
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}

	prefaceRead := make(chan struct{})
	releaseGuest := make(chan struct{})
	guestResult := make(chan error, 1)
	go func() {
		defer guest.Close()
		preface, readErr := frame.Read(guest, l8V2ControlCompatibilityLimit)
		if readErr == nil && string(preface) != l8V2ControlCompatibilityPayload {
			readErr = errors.New("unexpected compatibility preface")
		}
		close(prefaceRead)
		<-releaseGuest
		if readErr != nil {
			guestResult <- readErr
			return
		}
		identity, identityErr := l8D6V2ControlSessionIdentity(seed, nonce)
		if identityErr != nil {
			guestResult <- identityErr
			return
		}
		_, hello, helloErr := guestsession.NewGuestHandshake(guestsession.GuestHandshakeConfig{
			Identity: identity, PinnedControllerPublicKey: key.Public().(ed25519.PublicKey),
		})
		if helloErr != nil {
			guestResult <- helloErr
			return
		}
		_, writeErr := guest.Write(hello)
		guestsession.DestroyBytes(hello)
		guestResult <- writeErr
	}()

	type openResult struct {
		session *L8V2ControlReadinessSession
		err     error
	}
	opened := make(chan openResult, 1)
	go func() {
		session, openErr := bridge.OpenReadiness(context.Background(), l8D6V2ControlTarget(seed))
		opened <- openResult{session: session, err: openErr}
	}()
	select {
	case <-prefaceRead:
	case <-time.After(time.Second):
		t.Fatal("guest did not observe compatibility preface")
	}

	closed := make(chan error, 1)
	go func() { closed <- bridge.Close() }()
	select {
	case <-stream.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("bridge Close did not close admitted stream")
	}
	returnedEarly := false
	var closeErr error
	select {
	case closeErr = <-closed:
		returnedEarly = true
	default:
	}
	close(stream.closeRelease)
	if !returnedEarly {
		closeErr = <-closed
	}
	close(releaseGuest)
	result := <-opened
	guestErr := <-guestResult

	if returnedEarly {
		t.Fatal("bridge Close returned before admitted stream Close completed")
	}
	if closeErr != nil {
		t.Fatalf("bridge Close: %v", closeErr)
	}
	if result.session != nil || !errors.Is(result.err, ErrL8V2ControlUnavailable) {
		t.Fatalf("OpenReadiness after concurrent Close = %#v, %v", result.session, result.err)
	}
	if guestErr == nil {
		t.Fatal("guest wrote handshake bytes after bridge Close returned")
	}
	if got := stream.closeCalls(); got != 1 {
		t.Fatalf("admitted stream Close calls = %d, want 1", got)
	}
}

func TestL8D6V2ControlFoundationClosePanicDoesNotDeadlockAdmittedAttempt(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	key, nonce := l8D6V2ControlAuthority(t)
	host, guest := net.Pipe()
	stream := &l8D6V2ControlPanicCloseStream{
		l8D6V2ControlTestStream: &l8D6V2ControlTestStream{Conn: host, processDone: make(chan struct{})},
	}
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(
		&l8D6V2ControlTestConnector{stream: stream}, seed, key, nonce,
		bytes.NewReader(bytes.Repeat([]byte{0x5b}, 64)), time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	prefaceRead := make(chan struct{})
	go func() {
		_, _ = frame.Read(guest, l8V2ControlCompatibilityLimit)
		close(prefaceRead)
		_, _ = io.Copy(io.Discard, guest)
	}()
	type openResult struct {
		session *L8V2ControlReadinessSession
		err     error
	}
	opened := make(chan openResult, 1)
	go func() {
		session, openErr := bridge.OpenReadiness(context.Background(), l8D6V2ControlTarget(seed))
		opened <- openResult{session: session, err: openErr}
	}()
	select {
	case <-prefaceRead:
	case <-time.After(time.Second):
		_ = guest.Close()
		t.Fatal("guest did not observe compatibility preface")
	}
	closed := make(chan error, 1)
	go func() { closed <- bridge.Close() }()
	var closeErr error
	returned := false
	select {
	case closeErr = <-closed:
		returned = true
	case <-time.After(100 * time.Millisecond):
	}
	_ = guest.Close()
	if !returned {
		closeErr = <-closed
	}
	result := <-opened
	if !returned {
		t.Fatal("bridge Close deadlocked after admitted stream Close panic")
	}
	if !errors.Is(closeErr, ErrL8V2ControlUnavailable) {
		t.Fatalf("bridge Close error = %v, want ErrL8V2ControlUnavailable", closeErr)
	}
	if result.session != nil || !errors.Is(result.err, ErrL8V2ControlUnavailable) {
		t.Fatalf("OpenReadiness after Close panic = %#v, %v", result.session, result.err)
	}
	if got := stream.closeCalls; got != 1 {
		t.Fatalf("panic stream Close calls = %d, want 1", got)
	}
}

func TestL8D6V2ControlFoundationZeroValueSessionCloseIsTotal(t *testing.T) {
	result := make(chan any, 1)
	go func() {
		defer func() { result <- recover() }()
		if err := (&L8V2ControlReadinessSession{}).Close(); err != nil {
			result <- err
		}
	}()
	select {
	case got := <-result:
		if got != nil {
			t.Fatalf("zero-value Close result = %v, want nil without panic", got)
		}
	case <-time.After(time.Second):
		t.Fatal("zero-value Close blocked")
	}
}

func TestL8D6V2ControlFoundationContainsStreamPanics(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	key, nonce := l8D6V2ControlAuthority(t)
	stream := &l8D6V2ControlPanicStream{processDone: make(chan struct{}), closePanic: errors.New("/private/close secret")}
	connector := &l8D6V2ControlTestConnector{stream: stream}
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(connector, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x57}, 64)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if session, openErr := bridge.OpenReadiness(context.Background(), l8D6V2ControlTarget(seed)); session != nil || !errors.Is(openErr, ErrL8V2ControlUnavailable) {
		t.Fatalf("OpenReadiness = %#v, %v", session, openErr)
	}
	if stream.closeCalls != 1 {
		t.Fatalf("panic stream Close calls = %d, want 1", stream.closeCalls)
	}
}

func TestL8D6V2ControlFoundationLegacyUnsupportedEnvelopeIsExact(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	key, nonce := l8D6V2ControlAuthority(t)
	tests := []struct {
		name    string
		payload string
		want    error
	}{
		{name: "exact", payload: l8V2ControlLegacyUnsupported, want: ErrL8V2ControlUnsupported},
		{name: "noncanonical whitespace", payload: l8V2ControlLegacyUnsupported + "\n", want: ErrL8V2ControlInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, guest := net.Pipe()
			stream := &l8D6V2ControlTestStream{Conn: host, processDone: make(chan struct{})}
			bridge, err := newProductionL8V2ControlBridgeWithDependencies(&l8D6V2ControlTestConnector{stream: stream}, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x58}, 64)), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				defer guest.Close()
				_, _ = frame.Read(guest, l8V2ControlCompatibilityLimit)
				_ = frame.Write(guest, []byte(tt.payload), l8V2ControlCompatibilityLimit)
			}()
			if session, openErr := bridge.OpenReadiness(context.Background(), l8D6V2ControlTarget(seed)); session != nil || !errors.Is(openErr, tt.want) {
				t.Fatalf("OpenReadiness = %#v, %v, want %v", session, openErr, tt.want)
			}
		})
	}
}

func TestL8D6V2ControlFoundationRejectsAuthenticatedWrongIdentity(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	guestSeed := seed
	guestSeed.RuntimeGeneration = "wrong-runtime-generation"
	key, nonce := l8D6V2ControlAuthority(t)
	host, guest := net.Pipe()
	stream := &l8D6V2ControlTestStream{Conn: host, processDone: make(chan struct{})}
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(&l8D6V2ControlTestConnector{stream: stream}, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x59}, 64)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	guestResult := make(chan l8D6V2ControlGuestResult, 1)
	go l8D6ServeV2ControlGuest(guest, guestSeed, key.Public().(ed25519.PublicKey), nonce, guestResult)
	if session, openErr := bridge.OpenReadiness(context.Background(), l8D6V2ControlTarget(seed)); session != nil || !errors.Is(openErr, ErrL8V2ControlInvalid) {
		t.Fatalf("OpenReadiness = %#v, %v", session, openErr)
	}
	select {
	case <-guestResult:
	case <-time.After(time.Second):
		t.Fatal("wrong-identity guest did not terminate")
	}
}

func TestL8D6V2ControlFoundationProductionConnectorBindsPortAndRetainedOwnership(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	seed := l8D6V2ControlSeed(t)
	seed.RuntimeID = "fc-production-test"
	key, nonce := l8D6V2ControlAuthority(t)
	connectLines := make(chan string, 2)
	guestResult := make(chan l8D6V2ControlGuestResult, 1)
	serverErr := make(chan error, 1)
	go func() {
		first, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		firstReader := bufio.NewReader(first)
		line, err := firstReader.ReadString('\n')
		if err == nil {
			connectLines <- line
			_, err = io.WriteString(first, "OK 1073741824\n")
		}
		if err == nil {
			_, err = frame.Read(firstReader, 1024)
		}
		if err == nil {
			err = frame.Write(first, []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready"}`), 1024)
		}
		_ = first.Close()
		if err != nil {
			serverErr <- err
			return
		}

		second, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		secondReader := bufio.NewReader(second)
		line, err = secondReader.ReadString('\n')
		if err == nil {
			connectLines <- line
			_, err = io.WriteString(second, "OK 1073741824\n")
		}
		if err != nil {
			_ = second.Close()
			serverErr <- err
			return
		}
		serverErr <- nil
		l8D6ServeV2ControlGuest(second, seed, key.Public().(ed25519.PublicKey), nonce, guestResult)
	}()

	_, generation, err := fixture.bridge.ActivateSession(context.Background(), firecracker.ProductionVsockSessionRequest{
		Handle: fixture.handle, RuntimeID: seed.RuntimeID, SocketPath: fixture.paths.VsockSocketPath,
	})
	if err != nil {
		t.Fatalf("ActivateSession: %v", err)
	}
	target := l8D6V2ControlTarget(seed)
	target.Runtime.Metadata = &sandboxruntime.RuntimeMetadata{ProcessLaunch: &sandboxruntime.RuntimeProcessLaunchMetadata{
		ProcessID: fixture.handle.ID, ProcessIDSource: fixture.handle.Source,
	}}
	bridge, err := NewProductionL8V2ControlBridge(fixture.bridge, seed, key, nonce)
	if err != nil {
		t.Fatalf("NewProductionL8V2ControlBridge: %v", err)
	}
	session, err := bridge.OpenReadiness(context.Background(), target)
	if err != nil {
		t.Fatalf("OpenReadiness: %v", err)
	}
	if serverFailure := <-serverErr; serverFailure != nil {
		t.Fatalf("serve production connector: %v", serverFailure)
	}
	if result := <-guestResult; result.err != nil {
		t.Fatalf("guest protocol: %v", result.err)
	}
	if got, want := []string{<-connectLines, <-connectLines}, []string{"CONNECT 1024\n", "CONNECT 1025\n"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("connect lines = %#v, want %#v", got, want)
	}
	retainedSession := fixture.bridge.session(seed.RuntimeID)
	retainedSession.wire.mu.Lock()
	retained := len(retainedSession.wire.active)
	retainedSession.wire.mu.Unlock()
	if retained != 1 {
		t.Fatalf("retained port-1025 streams = %d, want 1", retained)
	}

	fixture.bridge.InvalidateSession(firecracker.ProductionVsockSessionRequest{Handle: fixture.handle, RuntimeID: seed.RuntimeID}, generation)
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("retained socket authority loss did not terminalize owner")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("session Close after invalidation: %v", err)
	}
}

func TestL8D6V2ControlFoundationValuesDenyProjection(t *testing.T) {
	seed := l8D6V2ControlSeed(t)
	key, nonce := l8D6V2ControlAuthority(t)
	bridge, err := newProductionL8V2ControlBridgeWithDependencies(&l8D6V2ControlTestConnector{}, seed, key, nonce, bytes.NewReader(bytes.Repeat([]byte{0x55}, 64)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	readiness := L8V2ControlReadiness{guestSessionGeneration: "session-generation", guestHelperGeneration: "helper-generation"}
	values := []any{bridge, &L8V2ControlReadinessSession{}, readiness}
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

type l8D6V2ControlBlockingConnector struct {
	stream  l8V2ControlStream
	entered chan struct{}
	release chan struct{}
}

func (connector *l8D6V2ControlBlockingConnector) OpenL8V2Control(context.Context, sandboxruntime.Target) (l8V2ControlStream, error) {
	close(connector.entered)
	<-connector.release
	return connector.stream, nil
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

type l8D6V2ControlBlockingCloseStream struct {
	*l8D6V2ControlTestStream
	closeEntered chan struct{}
	closeRelease chan struct{}
	enterOnce    sync.Once
}

func (stream *l8D6V2ControlBlockingCloseStream) Close() error {
	stream.enterOnce.Do(func() { close(stream.closeEntered) })
	<-stream.closeRelease
	return stream.l8D6V2ControlTestStream.Close()
}

type l8D6V2ControlPanicCloseStream struct {
	*l8D6V2ControlTestStream
	closeCalls int
}

func (stream *l8D6V2ControlPanicCloseStream) Close() error {
	stream.closeCalls++
	panic("close panic")
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

type l8D6V2ControlPanicStream struct {
	processDone <-chan struct{}
	closePanic  any
	closeCalls  int
}

func (*l8D6V2ControlPanicStream) Read([]byte) (int, error)  { panic("read panic") }
func (*l8D6V2ControlPanicStream) Write([]byte) (int, error) { panic("write panic") }
func (*l8D6V2ControlPanicStream) SetDeadline(time.Time) error {
	panic("deadline panic")
}
func (stream *l8D6V2ControlPanicStream) ProcessDone() <-chan struct{} { return stream.processDone }
func (stream *l8D6V2ControlPanicStream) Close() error {
	stream.closeCalls++
	panic(stream.closePanic)
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
