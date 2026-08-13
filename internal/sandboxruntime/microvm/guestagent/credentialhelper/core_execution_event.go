package credentialhelper

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"reflect"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type CoreOutputBody interface {
	Len() uint32
	SHA256() [32]byte
	Borrow(context.Context, func(credentialmemory.BorrowedView) error) error
	Destroy(context.Context) error
}

type CoreExecutionEventKind uint8

const (
	CoreExecutionEventOutput   CoreExecutionEventKind = 1
	CoreExecutionEventComplete CoreExecutionEventKind = 2
)

type CoreExecutionEvent struct {
	liveValue
	kind     CoreExecutionEventKind
	output   CoreOutputResult
	body     CoreOutputBody
	complete CoreExecResult
}

func NewCoreExecutionOutputEvent(ctx context.Context, output CoreOutputResult, body CoreOutputBody) (event CoreExecutionEvent, err error) {
	if ctx == nil {
		return CoreExecutionEvent{}, ErrContractInvalidArgument
	}
	if body == nil || typedNil(body) {
		return CoreExecutionEvent{}, ErrContractTypedNil
	}
	owned := true
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = body.Destroy(ctx)
			panic(recovered)
		}
		if owned {
			if destroyErr := body.Destroy(ctx); destroyErr != nil {
				event = CoreExecutionEvent{}
				err = ErrContractOwnership
			}
		}
	}()
	bodySHA := body.SHA256()
	if !validCoreOutputResult(output) || body.Len() != 56+output.byteCount || bodySHA == ([32]byte{}) || !validCoreOutputBody(ctx, output, body, bodySHA) {
		return CoreExecutionEvent{}, ErrContractResultMatrix
	}
	event = CoreExecutionEvent{kind: CoreExecutionEventOutput, output: output, body: body}
	owned = false
	return event, nil
}

type coreOutputBodyValidationSink struct {
	output        CoreOutputResult
	bodySHA       [32]byte
	callbackCount uint8
	writeCount    uint8
	valid         bool
	invalid       bool
}

func (sink *coreOutputBodyValidationSink) MaxCredentialBytes() int {
	return 56 + int(sink.output.byteCount)
}

func (sink *coreOutputBodyValidationSink) WriteCredential(wire []byte) error {
	if sink.writeCount != 0 {
		sink.writeCount = 2
		sink.invalid = true
		return ErrContractResultMatrix
	}
	sink.writeCount = 1
	if len(wire) != sink.MaxCredentialBytes() || binary.BigEndian.Uint64(wire[0:8]) == 0 ||
		credentialprotocol.HelperExecStreamKind(wire[8]) != sink.output.kind || wire[10] != 0 || wire[11] != 0 ||
		binary.BigEndian.Uint64(wire[12:20]) != sink.output.offset || binary.BigEndian.Uint32(wire[20:24]) != sink.output.byteCount {
		sink.invalid = true
		return ErrContractResultMatrix
	}
	wantFlags := credentialprotocol.HelperExecStreamFlagsNone
	if sink.output.eof {
		wantFlags = credentialprotocol.HelperExecStreamFlagEOF
	}
	if credentialprotocol.HelperExecStreamFlags(wire[9]) != wantFlags {
		sink.invalid = true
		return ErrContractResultMatrix
	}
	payloadSHA := sha256.Sum256(wire[56:])
	wireSHA := sha256.Sum256(wire)
	if subtle.ConstantTimeCompare(wire[24:56], sink.output.sha256[:]) != 1 ||
		subtle.ConstantTimeCompare(payloadSHA[:], sink.output.sha256[:]) != 1 ||
		subtle.ConstantTimeCompare(wireSHA[:], sink.bodySHA[:]) != 1 {
		sink.invalid = true
		return ErrContractResultMatrix
	}
	sink.valid = true
	return nil
}

func validCoreOutputBody(ctx context.Context, output CoreOutputResult, body CoreOutputBody, bodySHA [32]byte) bool {
	sink := &coreOutputBodyValidationSink{output: output, bodySHA: bodySHA}
	err := body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		if sink.callbackCount != 0 {
			sink.callbackCount = 2
			sink.invalid = true
			return ErrContractResultMatrix
		}
		sink.callbackCount = 1
		if view == nil || typedNil(view) || view.Len() != sink.MaxCredentialBytes() {
			sink.invalid = true
			return ErrContractResultMatrix
		}
		return view.WriteTo(ctx, sink)
	})
	return err == nil && sink.callbackCount == 1 && sink.writeCount == 1 && sink.valid && !sink.invalid
}

func NewCoreExecutionCompleteEvent(complete CoreExecResult) (CoreExecutionEvent, error) {
	if !validCoreExecResult(complete) {
		return CoreExecutionEvent{}, ErrContractResultMatrix
	}
	return CoreExecutionEvent{kind: CoreExecutionEventComplete, complete: complete}, nil
}

func (event CoreExecutionEvent) Kind() CoreExecutionEventKind { return event.kind }

func (event CoreExecutionEvent) Output() (CoreOutputResult, CoreOutputBody, bool) {
	if event.kind != CoreExecutionEventOutput || event.body == nil || typedNil(event.body) {
		return CoreOutputResult{}, nil, false
	}
	return event.output, event.body, true
}

func (event CoreExecutionEvent) Complete() (CoreExecResult, bool) {
	if event.kind != CoreExecutionEventComplete {
		return CoreExecResult{}, false
	}
	return event.complete, true
}

func typedNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validCoreOutputResult(value CoreOutputResult) bool {
	if !validCoreCapabilityDigest(value.execution.digest) || !validCoreOutputKind(value.kind) {
		return false
	}
	emptyDigest := sha256.Sum256(nil)
	return !value.eof && value.byteCount > 0 && value.byteCount <= credentialprotocol.MaxHelperExecStreamPayloadBytes && value.sha256 != ([32]byte{}) && !value.truncated ||
		value.eof && value.byteCount == 0 && value.sha256 == emptyDigest
}

func validCoreExecResult(value CoreExecResult) bool {
	return validCoreCapabilityDigest(value.execution.digest) && validCoreExit(value.exitCategory, value.exitCode) &&
		validCoreStreamSummary(value.stdinBytes, value.stdinSHA256) &&
		validCoreStreamSummary(value.stdoutBytes, value.stdoutSHA256) &&
		validCoreStreamSummary(value.stderrBytes, value.stderrSHA256) &&
		value.stdinTranscriptSHA256 != ([32]byte{}) && value.execTransactionSHA256 != ([32]byte{})
}
