package sshrelay

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
)

type clientPump struct {
	session         *clientSession
	accepted        acceptedPacket
	guest           credentialclient.SSHConnectionCapability
	relay           RelayConnection
	ctx             context.Context
	cancel          context.CancelFunc
	ownershipCtx    context.Context
	ownershipCancel context.CancelFunc
	started         chan struct{}
	done            chan struct{}
}

func (pump *clientPump) run() {
	close(pump.started)
	waitErr := safeWaitTransferred(pump.ownershipCtx, pump.accepted)
	ownershipTimedOut := pump.ownershipCtx.Err() != nil
	pump.ownershipCancel()
	if waitErr != nil {
		pump.cleanup(false, ownershipTimedOut || errors.Is(waitErr, ErrDependency))
		return
	}
	if pump.ctx.Err() != nil {
		pump.cleanup(true, false)
		return
	}
	fatal := pump.loop()
	pump.cleanup(true, fatal)
}

func (pump *clientPump) loop() bool {
	for {
		request, eof, terminal, fatal := pump.readRequest()
		if terminal {
			return fatal
		}
		if eof {
			return fatal
		}
		response, terminal, responseFatal := pump.roundTrip(request)
		requestCleanupFailed := request.Destroy() != nil
		if terminal {
			return requestCleanupFailed || responseFatal
		}
		writeFailed := pump.writeResponse(response)
		responseCleanupFailed := response.Destroy() != nil
		if writeFailed {
			return requestCleanupFailed || responseCleanupFailed
		}
		if requestCleanupFailed || responseCleanupFailed {
			return true
		}
	}
}

func (pump *clientPump) readRequest() (*credentialmemory.LockedMapping, bool, bool, bool) {
	mapping, err := credentialmemory.NewLockedMapping(credentialprotocol.SSHAgentMaxFrameBytes)
	if err != nil {
		return nil, false, true, false
	}
	eof := false
	loadErr := mapping.Load(pump.ctx, func(region []byte) (int, error) {
		sink := newBoundedSink(region)
		result, readErr := safeGuestRead(pump.ctx, pump.guest, sink)
		written, sinkFailed := sink.seal()
		if readErr != nil || sinkFailed {
			return 0, ErrPumpFailed
		}
		if result.EOF() {
			if result.ByteCount() != 0 || result.Truncated() || written != 0 {
				return 0, ErrPumpFailed
			}
			eof = true
			return 0, nil
		}
		if result.Truncated() || result.ByteCount() == 0 || result.ByteCount() != uint64(written) ||
			!validCompleteFrame(region[:written]) {
			return 0, ErrPumpFailed
		}
		return written, nil
	})
	if loadErr != nil || pump.ctx.Err() != nil {
		fatal := mapping.Destroy() != nil
		return nil, false, true, fatal
	}
	if eof {
		fatal := mapping.Destroy() != nil
		return nil, true, false, fatal
	}
	return mapping, false, false, false
}

func (pump *clientPump) roundTrip(request *credentialmemory.LockedMapping) (*credentialmemory.LockedMapping, bool, bool) {
	response, err := credentialmemory.NewLockedMapping(credentialprotocol.SSHAgentMaxFrameBytes)
	if err != nil {
		return nil, true, false
	}
	loadErr := response.Load(pump.ctx, func(region []byte) (int, error) {
		sink := newBoundedSink(region)
		borrowErr := request.Borrow(pump.ctx, func(view credentialmemory.BorrowedView) error {
			return safeRelayRoundTrip(pump.ctx, pump.relay, view, sink)
		})
		written, sinkFailed := sink.seal()
		if borrowErr != nil || sinkFailed || written == 0 {
			return 0, ErrPumpFailed
		}
		metadata, validationErr := credentialprotocol.ValidateSSHAgentOuterFrame(region[:written])
		if validationErr != nil || metadata.Class != credentialprotocol.SSHAgentMessageClassResponse {
			return 0, ErrPumpFailed
		}
		return written, nil
	})
	if loadErr != nil || pump.ctx.Err() != nil {
		fatal := response.Destroy() != nil
		return nil, true, fatal
	}
	return response, false, false
}

func (pump *clientPump) writeResponse(response *credentialmemory.LockedMapping) bool {
	return response.Borrow(pump.ctx, func(view credentialmemory.BorrowedView) error {
		result, err := safeGuestWrite(pump.ctx, pump.guest, view)
		if err != nil || result.EOF() || result.Truncated() || result.ByteCount() != uint64(view.Len()) {
			return ErrPumpFailed
		}
		return nil
	}) != nil
}

func (pump *clientPump) cleanup(transferred, fatal bool) {
	pump.cancel()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), clientRelayCleanupTimeout)
	defer cancel()
	if transferred {
		if safeGuestShutdown(cleanupCtx, pump.guest, credentialclient.SSHShutdownBoth) != nil {
			fatal = true
		}
		if safeGuestClose(cleanupCtx, pump.guest) != nil {
			fatal = true
		}
	}
	retain := RelayConnection(nil)
	if safeRelayClose(cleanupCtx, pump.relay) != nil {
		retain = pump.relay
	}
	pump.session.finishPump(pump, retain, fatal || cleanupCtx.Err() != nil)
}

type boundedSink struct {
	mu      sync.Mutex
	target  []byte
	written int
	active  bool
	failed  bool
}

func newBoundedSink(target []byte) *boundedSink {
	return &boundedSink{target: target, active: true}
}

func (sink *boundedSink) MaxCredentialBytes() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if !sink.active {
		return 0
	}
	return len(sink.target)
}

func (sink *boundedSink) WriteCredential(value []byte) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if !sink.active || sink.failed || len(value) > len(sink.target)-sink.written {
		sink.failed = true
		return ErrPumpFailed
	}
	copy(sink.target[sink.written:], value)
	sink.written += len(value)
	return nil
}

func (sink *boundedSink) seal() (written int, failed bool) {
	sink.mu.Lock()
	written = sink.written
	failed = sink.failed
	sink.active = false
	sink.target = nil
	sink.mu.Unlock()
	return written, failed
}

func validCompleteFrame(frame []byte) bool {
	if len(frame) < credentialprotocol.SSHAgentFrameHeaderBytes {
		return false
	}
	payloadLength := binary.BigEndian.Uint32(frame[:credentialprotocol.SSHAgentFrameHeaderBytes])
	return payloadLength >= credentialprotocol.SSHAgentMinPayloadBytes &&
		payloadLength <= credentialprotocol.SSHAgentMaxPayloadBytes &&
		len(frame) == credentialprotocol.SSHAgentFrameHeaderBytes+int(payloadLength)
}

func safeGuestRead(ctx context.Context, connection credentialclient.SSHConnectionCapability, sink credentialmemory.CredentialSink) (result credentialclient.SSHIOResult, err error) {
	defer func() {
		if recover() != nil {
			result = credentialclient.SSHIOResult{}
			err = ErrPumpFailed
		}
	}()
	result, err = connection.Read(ctx, sink)
	if err != nil {
		return credentialclient.SSHIOResult{}, ErrPumpFailed
	}
	return result, nil
}

func safeGuestWrite(ctx context.Context, connection credentialclient.SSHConnectionCapability, source credentialmemory.BorrowedView) (result credentialclient.SSHIOResult, err error) {
	defer func() {
		if recover() != nil {
			result = credentialclient.SSHIOResult{}
			err = ErrPumpFailed
		}
	}()
	result, err = connection.Write(ctx, source)
	if err != nil {
		return credentialclient.SSHIOResult{}, ErrPumpFailed
	}
	return result, nil
}

func safeGuestShutdown(ctx context.Context, connection credentialclient.SSHConnectionCapability, direction credentialclient.SSHShutdownDirection) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrCleanupIncomplete
		}
	}()
	if connection.Shutdown(ctx, direction) != nil {
		return ErrCleanupIncomplete
	}
	return nil
}

func safeGuestClose(ctx context.Context, connection credentialclient.SSHConnectionCapability) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrCleanupIncomplete
		}
	}()
	if connection.Close(ctx) != nil {
		return ErrCleanupIncomplete
	}
	return nil
}

func safeRelayRoundTrip(ctx context.Context, connection RelayConnection, request credentialmemory.BorrowedView, response credentialmemory.CredentialSink) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrPumpFailed
		}
	}()
	if !configured(connection) || !configured(request) || !configured(response) {
		return ErrPumpFailed
	}
	if connection.RoundTrip(ctx, request, response) != nil {
		return ErrPumpFailed
	}
	return nil
}

var _ credentialmemory.CredentialSink = (*boundedSink)(nil)
