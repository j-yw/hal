package credentialclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestSSHConnectionCapabilityMethodSetIsExact(t *testing.T) {
	t.Parallel()

	assertInterfaceMethods(t, reflect.TypeOf((*SSHConnectionCapability)(nil)).Elem(), map[string]string{
		"SHA256":   "func() [32]uint8",
		"Read":     "func(context.Context, credentialmemory.CredentialSink) (credentialclient.SSHIOResult, error)",
		"Write":    "func(context.Context, credentialmemory.BorrowedView) (credentialclient.SSHIOResult, error)",
		"Shutdown": "func(context.Context, credentialclient.SSHShutdownDirection) error",
		"Close":    "func(context.Context) error",
	})
}

func TestSSHIOResultAndShutdownCatalogAreClosed(t *testing.T) {
	t.Parallel()

	result, err := NewSSHIOResult(credentialprotocol.SSHAgentMaxFrameBytes, true, true)
	if err != nil {
		t.Fatalf("NewSSHIOResult() error = %v", err)
	}
	if result.ByteCount() != credentialprotocol.SSHAgentMaxFrameBytes || !result.EOF() || !result.Truncated() {
		t.Fatalf("result = (%d, %t, %t)", result.ByteCount(), result.EOF(), result.Truncated())
	}
	if invalid, err := NewSSHIOResult(credentialprotocol.SSHAgentMaxFrameBytes+1, false, false); !errors.Is(err, ErrSSHIOResult) || invalid != (SSHIOResult{}) {
		t.Fatalf("oversized result = (%v, %v), want zero/ErrSSHIOResult", invalid, err)
	}
	assertFailsClosed(t, result)

	if SSHShutdownRead != 1 || SSHShutdownWrite != 2 || SSHShutdownBoth != 3 {
		t.Fatalf("shutdown catalog = %d, %d, %d", SSHShutdownRead, SSHShutdownWrite, SSHShutdownBoth)
	}
	for _, direction := range []SSHShutdownDirection{SSHShutdownRead, SSHShutdownWrite, SSHShutdownBoth} {
		if err := ValidateSSHShutdownDirection(direction); err != nil || direction.String() == "unknown" {
			t.Errorf("valid direction %d = (%q, %v)", direction, direction.String(), err)
		}
	}
	for _, direction := range []SSHShutdownDirection{0, 4, 255} {
		if err := ValidateSSHShutdownDirection(direction); !errors.Is(err, ErrSSHShutdownDirection) || direction.String() != "unknown" {
			t.Errorf("invalid direction %d = (%q, %v)", direction, direction.String(), err)
		}
	}
}

func TestSSHAcceptedPacketExposesOnlySafeArmAndTransferredView(t *testing.T) {
	t.Parallel()

	digest := [32]byte{0x41}
	issuer := &sshTestIssuer{digest: digest}
	packet := mustSSHTestPacket(t, digest, issuer)
	if got := packet.Type(); got != credentialprotocol.PacketTypeSSHAcceptedFD {
		t.Fatalf("Type() = %v", got)
	}
	accepted, ok := packet.SSHAccepted()
	if !ok {
		t.Fatal("SSHAccepted() did not return the SSH arm")
	}
	if accepted.Revision() != 7 || accepted.BindingIndex() != 2 || accepted.Ordinal() != 3 || accepted.CapabilitySHA256() != digest {
		t.Fatalf("SSH arm metadata = revision %d binding %d ordinal %d digest %x", accepted.Revision(), accepted.BindingIndex(), accepted.Ordinal(), accepted.CapabilitySHA256())
	}
	connection := accepted.Connection()
	if !configuredDependency(connection) || reflect.TypeOf(connection) == reflect.TypeOf(issuer) {
		t.Fatal("Connection() returned no parent-owned view or exposed the issuer")
	}
	if connection.SHA256() != digest {
		t.Fatalf("connection SHA256 = %x, want %x", connection.SHA256(), digest)
	}
	if _, err := connection.Read(context.Background(), sshTestSink{capacity: 8}); !errors.Is(err, ErrExtensionPacketOwnership) {
		t.Fatalf("Read before transfer error = %v", err)
	}
	if got := issuer.reads.Load(); got != 0 {
		t.Fatalf("issuer Read calls before transfer = %d", got)
	}

	if err := commitExtensionPacketOwnership(packet); err != nil {
		t.Fatalf("commitExtensionPacketOwnership() error = %v", err)
	}
	issuer.readResult = mustSSHIOResult(t, 8, false, true)
	result, err := connection.Read(context.Background(), sshTestSink{capacity: 8})
	if err != nil || result.ByteCount() != 8 || !result.Truncated() {
		t.Fatalf("transferred Read() = (%v, %v)", result, err)
	}
	issuer.writeResult = mustSSHIOResult(t, 5, false, false)
	result, err = connection.Write(context.Background(), sshTestView{length: 5})
	if err != nil || result.ByteCount() != 5 || result.EOF() || result.Truncated() {
		t.Fatalf("transferred Write() = (%v, %v)", result, err)
	}

	assertFailsClosed(t, accepted)
	assertFailsClosed(t, connection)
	formatted := fmt.Sprintf("%#v", packet)
	if strings.Contains(formatted, "issuer-secret") || !strings.Contains(formatted, "redacted") {
		t.Fatalf("packet formatting = %q", formatted)
	}
	if encoded, err := json.Marshal(connection); !errors.Is(err, ErrLiveValueSerialization) || strings.Contains(string(encoded), "issuer-secret") {
		t.Fatalf("connection JSON = (%q, %v)", encoded, err)
	}
}

func TestSSHConnectionViewRejectsTypedNilInputsWithoutCallingIssuer(t *testing.T) {
	t.Parallel()

	digest := [32]byte{0x42}
	issuer := &sshTestIssuer{digest: digest}
	packet := mustSSHTestPacket(t, digest, issuer)
	if err := commitExtensionPacketOwnership(packet); err != nil {
		t.Fatal(err)
	}
	accepted, _ := packet.SSHAccepted()
	connection := accepted.Connection()
	var nilSink *sshTestPointerSink
	var nilView *sshTestPointerView
	var nilContext *sshTestContext
	for name, call := range map[string]func() error{
		"nil context read":       func() error { _, err := connection.Read(nil, sshTestSink{capacity: 8}); return err },
		"typed nil context read": func() error { _, err := connection.Read(nilContext, sshTestSink{capacity: 8}); return err },
		"typed nil sink":         func() error { _, err := connection.Read(context.Background(), nilSink); return err },
		"typed nil view":         func() error { _, err := connection.Write(context.Background(), nilView); return err },
		"unknown shutdown":       func() error { return connection.Shutdown(context.Background(), 99) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s succeeded", name)
		}
	}
	if issuer.reads.Load() != 0 || issuer.writes.Load() != 0 || issuer.shutdowns.Load() != 0 {
		t.Fatalf("issuer calls = read %d write %d shutdown %d", issuer.reads.Load(), issuer.writes.Load(), issuer.shutdowns.Load())
	}
}

func TestSSHConnectionViewDependencyPanicsAreContainedAndClosed(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		invoke func(SSHConnectionCapability) error
	}{
		{
			name: "sink capacity panic",
			invoke: func(connection SSHConnectionCapability) error {
				_, err := connection.Read(context.Background(), sshPanicSink{})
				return err
			},
		},
		{
			name: "view length panic",
			invoke: func(connection SSHConnectionCapability) error {
				_, err := connection.Write(context.Background(), sshPanicView{})
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			digest := [32]byte{0x47}
			issuer := &sshTestIssuer{digest: digest}
			packet := mustSSHTestPacket(t, digest, issuer)
			if err := commitExtensionPacketOwnership(packet); err != nil {
				t.Fatal(err)
			}
			accepted, _ := packet.SSHAccepted()
			if err := test.invoke(accepted.Connection()); !errors.Is(err, ErrExtensionPacketOwnership) {
				t.Fatalf("operation error = %v", err)
			}
			if got := issuer.closes.Load(); got != 1 {
				t.Fatalf("issuer Close calls = %d, want 1", got)
			}
		})
	}
}

func TestSSHConnectionViewInvalidIssuerResultClosesAndSanitizes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		configure func(*sshTestIssuer)
		invoke    func(SSHConnectionCapability) error
	}{
		{
			name: "read zero without EOF",
			configure: func(issuer *sshTestIssuer) {
				issuer.readResult = mustSSHIOResult(t, 0, false, false)
			},
			invoke: func(connection SSHConnectionCapability) error {
				_, err := connection.Read(context.Background(), sshTestSink{capacity: 8})
				return err
			},
		},
		{
			name: "partial write",
			configure: func(issuer *sshTestIssuer) {
				issuer.writeResult = mustSSHIOResult(t, 4, false, false)
			},
			invoke: func(connection SSHConnectionCapability) error {
				_, err := connection.Write(context.Background(), sshTestView{length: 5})
				return err
			},
		},
		{
			name: "issuer error",
			configure: func(issuer *sshTestIssuer) {
				issuer.readErr = errors.New("raw-issuer-secret")
			},
			invoke: func(connection SSHConnectionCapability) error {
				_, err := connection.Read(context.Background(), sshTestSink{capacity: 8})
				return err
			},
		},
		{
			name:      "issuer panic",
			configure: func(issuer *sshTestIssuer) { issuer.readPanic = true },
			invoke: func(connection SSHConnectionCapability) error {
				_, err := connection.Read(context.Background(), sshTestSink{capacity: 8})
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			digest := [32]byte{0x43}
			issuer := &sshTestIssuer{digest: digest}
			test.configure(issuer)
			packet := mustSSHTestPacket(t, digest, issuer)
			if err := commitExtensionPacketOwnership(packet); err != nil {
				t.Fatal(err)
			}
			accepted, _ := packet.SSHAccepted()
			err := test.invoke(accepted.Connection())
			if !errors.Is(err, ErrExtensionPacketOwnership) || strings.Contains(err.Error(), "raw-issuer-secret") {
				t.Fatalf("operation error = %v, want sanitized ownership error", err)
			}
			if got := issuer.closes.Load(); got != 1 {
				t.Fatalf("issuer Close calls = %d, want 1", got)
			}
			if err := accepted.Connection().Shutdown(context.Background(), SSHShutdownBoth); !errors.Is(err, ErrExtensionPacketOwnership) {
				t.Fatalf("operation after terminal close error = %v", err)
			}
		})
	}
}

func TestSSHConnectionCloseSerializesWithActiveOperations(t *testing.T) {
	digest := [32]byte{0x44}
	readStarted := make(chan struct{})
	readRelease := make(chan struct{})
	issuer := &sshTestIssuer{
		digest:      digest,
		readResult:  mustSSHIOResult(t, 1, false, false),
		readStarted: readStarted,
		readRelease: readRelease,
	}
	packet := mustSSHTestPacket(t, digest, issuer)
	if err := commitExtensionPacketOwnership(packet); err != nil {
		t.Fatal(err)
	}
	accepted, _ := packet.SSHAccepted()
	connection := accepted.Connection()

	readDone := make(chan error, 1)
	go func() {
		_, err := connection.Read(context.Background(), sshTestSink{capacity: 8})
		readDone <- err
	}()
	<-readStarted

	closeDone := make(chan error, 2)
	go func() { closeDone <- connection.Close(context.Background()) }()
	go func() { closeDone <- connection.Close(context.Background()) }()
	assertEventually(t, func() bool {
		packet.ownership.mu.Lock()
		defer packet.ownership.mu.Unlock()
		return packet.ownership.phase == sshConnectionClosing
	})
	if issuer.closes.Load() != 0 {
		t.Fatal("issuer closed before active Read returned")
	}
	if _, err := connection.Read(context.Background(), sshTestSink{capacity: 8}); !errors.Is(err, ErrExtensionPacketOwnership) {
		t.Fatalf("new Read during close error = %v", err)
	}
	close(readRelease)
	if err := <-readDone; err != nil {
		t.Fatalf("active Read error = %v", err)
	}
	for range 2 {
		if err := <-closeDone; err != nil {
			t.Fatalf("Close error = %v", err)
		}
	}
	if got := issuer.closes.Load(); got != 1 {
		t.Fatalf("issuer Close calls = %d, want 1", got)
	}
}

func TestSSHConnectionCloseTimeoutCanBeRetriedWithoutDoubleClose(t *testing.T) {
	digest := [32]byte{0x45}
	readStarted := make(chan struct{})
	readRelease := make(chan struct{})
	issuer := &sshTestIssuer{
		digest:      digest,
		readResult:  mustSSHIOResult(t, 1, false, false),
		readStarted: readStarted,
		readRelease: readRelease,
	}
	packet := mustSSHTestPacket(t, digest, issuer)
	if err := commitExtensionPacketOwnership(packet); err != nil {
		t.Fatal(err)
	}
	accepted, _ := packet.SSHAccepted()
	connection := accepted.Connection()
	readDone := make(chan error, 1)
	go func() {
		_, err := connection.Read(context.Background(), sshTestSink{capacity: 8})
		readDone <- err
	}()
	<-readStarted

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := connection.Close(ctx); !errors.Is(err, ErrExtensionPacketOwnership) {
		t.Fatalf("timed Close error = %v", err)
	}
	if issuer.closes.Load() != 0 {
		t.Fatal("timed Close invoked issuer while Read remained active")
	}
	close(readRelease)
	if err := <-readDone; err != nil {
		t.Fatalf("active Read error = %v", err)
	}
	if err := connection.Close(context.Background()); err != nil {
		t.Fatalf("retry Close error = %v", err)
	}
	if err := connection.Close(context.Background()); err != nil {
		t.Fatalf("latched Close error = %v", err)
	}
	if got := issuer.closes.Load(); got != 1 {
		t.Fatalf("issuer Close calls = %d, want 1", got)
	}
}

func TestSSHConnectionCloseSanitizesIssuerErrorAndPanic(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		closeErr   error
		closePanic bool
	}{
		{name: "error", closeErr: errors.New("raw-close-secret")},
		{name: "panic", closePanic: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			digest := [32]byte{0x46}
			issuer := &sshTestIssuer{digest: digest, closeErr: test.closeErr, closePanic: test.closePanic}
			packet := mustSSHTestPacket(t, digest, issuer)
			if err := commitExtensionPacketOwnership(packet); err != nil {
				t.Fatal(err)
			}
			accepted, _ := packet.SSHAccepted()
			err := accepted.Connection().Close(context.Background())
			if !errors.Is(err, ErrExtensionPacketOwnership) || strings.Contains(err.Error(), "raw-close-secret") {
				t.Fatalf("Close error = %v", err)
			}
			if got := issuer.closes.Load(); got != 1 {
				t.Fatalf("issuer Close calls = %d, want 1", got)
			}
			if err := accepted.Connection().Close(context.Background()); !errors.Is(err, ErrExtensionPacketOwnership) {
				t.Fatalf("latched Close error = %v", err)
			}
		})
	}
}

func TestSSHConnectionConstructorRejectsDigestMismatchAndPanicsWithCleanup(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		issuer *sshTestIssuer
	}{
		{name: "mismatch", issuer: &sshTestIssuer{digest: [32]byte{0x51}}},
		{name: "zero digest", issuer: &sshTestIssuer{}},
		{name: "digest panic", issuer: &sshTestIssuer{digestPanic: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := sshTestPacketMetadata([32]byte{0x52})
			packet, err := newExtensionPacket(credentialprotocol.PacketTypeSSHAcceptedFD, metadata, test.issuer)
			if !errors.Is(err, ErrExtensionPacketMetadata) || packet.ownership != nil {
				t.Fatalf("newExtensionPacket() = (%v, %v)", packet, err)
			}
			if got := test.issuer.closes.Load(); got != 1 {
				t.Fatalf("issuer Close calls = %d, want 1", got)
			}
		})
	}
}

func mustSSHTestPacket(t *testing.T, digest [32]byte, issuer SSHConnectionCapability) ExtensionPacket {
	t.Helper()
	packet, err := newExtensionPacket(credentialprotocol.PacketTypeSSHAcceptedFD, sshTestPacketMetadata(digest), issuer)
	if err != nil {
		t.Fatalf("newExtensionPacket() error = %v", err)
	}
	return packet
}

func sshTestPacketMetadata(digest [32]byte) extensionPacketMetadata {
	return extensionPacketMetadata{
		identityDigest:   [32]byte{1},
		revision:         7,
		bindingIndex:     2,
		ordinal:          3,
		capabilitySHA256: digest,
	}
}

func mustSSHIOResult(t *testing.T, byteCount uint64, eof, truncated bool) SSHIOResult {
	t.Helper()
	result, err := NewSSHIOResult(byteCount, eof, truncated)
	if err != nil {
		t.Fatalf("NewSSHIOResult() error = %v", err)
	}
	return result
}

func assertEventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

type sshTestIssuer struct {
	digest      [32]byte
	digestPanic bool
	readResult  SSHIOResult
	readErr     error
	readPanic   bool
	writeResult SSHIOResult
	writeErr    error
	shutdownErr error
	closeErr    error
	closePanic  bool
	readStarted chan struct{}
	readRelease chan struct{}
	startedOnce sync.Once
	reads       atomic.Uint32
	writes      atomic.Uint32
	shutdowns   atomic.Uint32
	closes      atomic.Uint32
}

func (issuer *sshTestIssuer) SHA256() [32]byte {
	if issuer.digestPanic {
		panic("raw-digest-panic-secret")
	}
	return issuer.digest
}

func (issuer *sshTestIssuer) Read(context.Context, credentialmemory.CredentialSink) (SSHIOResult, error) {
	issuer.reads.Add(1)
	if issuer.readPanic {
		panic("raw-read-panic-secret")
	}
	if issuer.readStarted != nil {
		issuer.startedOnce.Do(func() { close(issuer.readStarted) })
	}
	if issuer.readRelease != nil {
		<-issuer.readRelease
	}
	return issuer.readResult, issuer.readErr
}

func (issuer *sshTestIssuer) Write(context.Context, credentialmemory.BorrowedView) (SSHIOResult, error) {
	issuer.writes.Add(1)
	return issuer.writeResult, issuer.writeErr
}

func (issuer *sshTestIssuer) Shutdown(context.Context, SSHShutdownDirection) error {
	issuer.shutdowns.Add(1)
	return issuer.shutdownErr
}

func (issuer *sshTestIssuer) Close(context.Context) error {
	issuer.closes.Add(1)
	if issuer.closePanic {
		panic("raw-close-panic-secret")
	}
	return issuer.closeErr
}

func (*sshTestIssuer) String() string   { return "issuer-secret" }
func (*sshTestIssuer) GoString() string { return "issuer-secret" }

type sshTestSink struct{ capacity int }

func (sink sshTestSink) MaxCredentialBytes() int         { return sink.capacity }
func (sshTestSink) WriteCredential([]byte) error         { return nil }
func (*sshTestPointerSink) MaxCredentialBytes() int      { return 8 }
func (*sshTestPointerSink) WriteCredential([]byte) error { return nil }

type sshTestPointerSink struct{}

type sshTestView struct{ length int }

func (view sshTestView) Len() int                                                  { return view.length }
func (sshTestView) CopyTo(context.Context, *credentialmemory.LockedMapping) error  { return nil }
func (sshTestView) WriteTo(context.Context, credentialmemory.CredentialSink) error { return nil }

type sshTestPointerView struct{}

func (*sshTestPointerView) Len() int                                                      { return 1 }
func (*sshTestPointerView) CopyTo(context.Context, *credentialmemory.LockedMapping) error { return nil }
func (*sshTestPointerView) WriteTo(context.Context, credentialmemory.CredentialSink) error {
	return nil
}

type sshPanicSink struct{}

func (sshPanicSink) MaxCredentialBytes() int      { panic("raw-sink-panic-secret") }
func (sshPanicSink) WriteCredential([]byte) error { return nil }

type sshPanicView struct{}

func (sshPanicView) Len() int                                                       { panic("raw-view-panic-secret") }
func (sshPanicView) CopyTo(context.Context, *credentialmemory.LockedMapping) error  { return nil }
func (sshPanicView) WriteTo(context.Context, credentialmemory.CredentialSink) error { return nil }

type sshTestContext struct{}

func (*sshTestContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*sshTestContext) Done() <-chan struct{}       { return nil }
func (*sshTestContext) Err() error                  { return nil }
func (*sshTestContext) Value(any) any               { return nil }
