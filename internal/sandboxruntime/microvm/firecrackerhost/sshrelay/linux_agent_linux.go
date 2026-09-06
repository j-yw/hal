//go:build linux

package sshrelay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const maxUnixEndpointPathBytes = len(syscall.RawSockaddrUnix{}.Path) - 1

type peerCredentialReader interface {
	Read(uintptr, []byte) (int, error)
}

type syscallPeerCredentialReader struct{}

type linuxAgentDialer struct {
	liveValue
	path        string
	expectedUID uint32
	expectedGID uint32
}

type linuxPeerVerifier struct {
	liveValue
	expectedUID uint32
	expectedGID uint32
	reader      peerCredentialReader
}

type linuxAgentConnection struct {
	liveValue
	connection *net.UnixConn
	ioMu       sync.Mutex
	closeMu    sync.Mutex
	mu         sync.Mutex
	closed     bool
}

type rejectedNetConnection struct {
	liveValue
	connection net.Conn
	closeMu    sync.Mutex
	closed     bool
}

func NewLinuxAgentDialer(options LinuxAgentDialerOptions) (AgentDialer, error) {
	if !validUnixEndpointPath(options.EndpointPath) {
		return nil, ErrInvalidArgument
	}
	return &linuxAgentDialer{
		path:        options.EndpointPath,
		expectedUID: options.ExpectedUID,
		expectedGID: options.ExpectedGID,
	}, nil
}

func NewLinuxPeerVerifier(options LinuxPeerVerifierOptions) (PeerVerifier, error) {
	return &linuxPeerVerifier{
		expectedUID: options.ExpectedUID,
		expectedGID: options.ExpectedGID,
		reader:      syscallPeerCredentialReader{},
	}, nil
}

func (dialer *linuxAgentDialer) Open(ctx context.Context) (AgentConnection, error) {
	if dialer == nil || !configuredDependency(ctx) || ctx.Err() != nil {
		return nil, ErrAgentOpen
	}
	if err := inspectUnixEndpointOwner(dialer.path, dialer.expectedUID, dialer.expectedGID); err != nil {
		return nil, ErrAgentOpen
	}
	networkDialer := net.Dialer{}
	connection, err := networkDialer.DialContext(ctx, "unix", dialer.path)
	if err != nil {
		return nil, ErrAgentOpen
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || unixConnection == nil {
		return &rejectedNetConnection{connection: connection}, ErrAgentOpen
	}
	result := &linuxAgentConnection{connection: unixConnection}
	if ctx.Err() != nil {
		return result, ErrAgentOpen
	}
	return result, nil
}

func (verifier *linuxPeerVerifier) Verify(ctx context.Context, connection AgentConnection, identity ConfigIdentity) (PeerProof, error) {
	if verifier == nil || !configuredDependency(ctx) || ctx.Err() != nil || !validConfigIdentity(identity) {
		return PeerProof{}, ErrAgentPeer
	}
	linuxConnection, ok := connection.(*linuxAgentConnection)
	if !ok || linuxConnection == nil || linuxConnection.connection == nil {
		return PeerProof{}, ErrAgentPeer
	}
	linuxConnection.mu.Lock()
	closed := linuxConnection.closed
	linuxConnection.mu.Unlock()
	if closed {
		return PeerProof{}, ErrAgentPeer
	}
	raw, err := linuxConnection.connection.SyscallConn()
	if err != nil {
		return PeerProof{}, ErrAgentPeer
	}
	var controlErr error
	if err := raw.Control(func(descriptor uintptr) {
		controlErr = verifier.verifyDescriptor(descriptor)
	}); err != nil || controlErr != nil || ctx.Err() != nil {
		return PeerProof{}, ErrAgentPeer
	}
	return NewPeerProof(identity, connection)
}

func (verifier *linuxPeerVerifier) verifyDescriptor(descriptor uintptr) error {
	if verifier == nil || !configuredDependency(verifier.reader) {
		return ErrAgentPeer
	}
	var credentials syscall.Ucred
	encoded := unsafe.Slice((*byte)(unsafe.Pointer(&credentials)), int(unsafe.Sizeof(credentials)))
	count, err := verifier.reader.Read(descriptor, encoded)
	if err != nil || count != len(encoded) {
		return ErrAgentPeer
	}
	if credentials.Pid <= 0 || credentials.Uid != verifier.expectedUID || credentials.Gid != verifier.expectedGID {
		return ErrAgentPeer
	}
	return nil
}

func (syscallPeerCredentialReader) Read(descriptor uintptr, destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, ErrAgentPeer
	}
	length := uint32(len(destination))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		descriptor,
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_PEERCRED),
		uintptr(unsafe.Pointer(&destination[0])),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	if errno != 0 {
		return int(length), errno
	}
	return int(length), nil
}

func (connection *linuxAgentConnection) RoundTrip(ctx context.Context, request []byte) ([]byte, error) {
	if connection == nil || !configuredDependency(ctx) || ctx.Err() != nil {
		return nil, ErrAgentIO
	}
	metadata, err := credentialprotocol.ValidateSSHAgentOuterFrame(request)
	if err != nil || metadata.Class != credentialprotocol.SSHAgentMessageClassClientRequest {
		return nil, ErrAgentIO
	}
	connection.ioMu.Lock()
	defer connection.ioMu.Unlock()
	connection.mu.Lock()
	closed := connection.closed
	unixConnection := connection.connection
	connection.mu.Unlock()
	if closed || unixConnection == nil {
		return nil, ErrAgentIO
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := unixConnection.SetDeadline(deadline); err != nil {
			return nil, ErrAgentIO
		}
	}
	deadlineSet := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = unixConnection.SetDeadline(time.Now())
		close(deadlineSet)
	})
	defer func() {
		if !stop() {
			<-deadlineSet
		}
		_ = unixConnection.SetDeadline(time.Time{})
	}()
	if err := writeFull(unixConnection, request); err != nil {
		return nil, ErrAgentIO
	}
	if ctx.Err() != nil {
		return nil, ErrAgentIO
	}
	var header [credentialprotocol.SSHAgentFrameHeaderBytes]byte
	if _, err := io.ReadFull(unixConnection, header[:]); err != nil {
		return nil, ErrAgentIO
	}
	if ctx.Err() != nil {
		return nil, ErrAgentIO
	}
	payloadLength := binary.BigEndian.Uint32(header[:])
	if payloadLength < credentialprotocol.SSHAgentMinPayloadBytes || payloadLength > credentialprotocol.SSHAgentMaxPayloadBytes {
		return nil, ErrAgentIO
	}
	response := make([]byte, credentialprotocol.SSHAgentFrameHeaderBytes+int(payloadLength))
	copy(response, header[:])
	if _, err := io.ReadFull(unixConnection, response[credentialprotocol.SSHAgentFrameHeaderBytes:]); err != nil {
		credentialprotocol.WipeSSHAgentBytes(response)
		return nil, ErrAgentIO
	}
	if ctx.Err() != nil {
		credentialprotocol.WipeSSHAgentBytes(response)
		return nil, ErrAgentIO
	}
	metadata, err = credentialprotocol.ValidateSSHAgentOuterFrame(response)
	if err != nil || metadata.Class != credentialprotocol.SSHAgentMessageClassResponse {
		credentialprotocol.WipeSSHAgentBytes(response)
		return nil, ErrAgentIO
	}
	if ctx.Err() != nil {
		credentialprotocol.WipeSSHAgentBytes(response)
		return nil, ErrAgentIO
	}
	return response, nil
}

func (connection *linuxAgentConnection) Close(ctx context.Context) error {
	if connection == nil || !configuredDependency(ctx) {
		return ErrInvalidArgument
	}
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	connection.mu.Lock()
	if connection.closed {
		connection.mu.Unlock()
		return nil
	}
	unixConnection := connection.connection
	connection.mu.Unlock()
	if unixConnection != nil {
		if err := unixConnection.Close(); err != nil {
			return ErrCleanupIncomplete
		}
	}
	connection.mu.Lock()
	connection.closed = true
	connection.connection = nil
	connection.mu.Unlock()
	return nil
}

func (*rejectedNetConnection) RoundTrip(context.Context, []byte) ([]byte, error) {
	return nil, ErrAgentIO
}

func (connection *rejectedNetConnection) Close(ctx context.Context) error {
	if connection == nil || !configuredDependency(ctx) {
		return ErrInvalidArgument
	}
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	if connection.closed {
		return nil
	}
	if !configuredDependency(connection.connection) || connection.connection.Close() != nil {
		return ErrCleanupIncomplete
	}
	connection.connection = nil
	connection.closed = true
	return nil
}

func inspectUnixEndpointOwner(path string, expectedUID, expectedGID uint32) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return ErrAgentOpen
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || stat.Uid != expectedUID || stat.Gid != expectedGID {
		return ErrAgentOpen
	}
	return nil
}

func validUnixEndpointPath(path string) bool {
	return len(path) > 0 && len(path) <= maxUnixEndpointPathBytes && filepath.IsAbs(path) &&
		filepath.Clean(path) == path && !strings.ContainsRune(path, '\x00')
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil || written <= 0 || written > len(value) {
			return ErrAgentIO
		}
		value = value[written:]
	}
	return nil
}

var _ AgentDialer = (*linuxAgentDialer)(nil)
var _ PeerVerifier = (*linuxPeerVerifier)(nil)
var _ AgentConnection = (*linuxAgentConnection)(nil)
var _ AgentConnection = (*rejectedNetConnection)(nil)
