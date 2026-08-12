package credentialhelper

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type eventBody struct {
	length     uint32
	digest     [32]byte
	destroyed  int
	destroyCtx context.Context
	destroyErr error
	panicOnLen bool
	canonical  []byte
}

type eventContextKey struct{}

type eventBorrowedView struct{ canonical []byte }

func (view eventBorrowedView) Len() int { return len(view.canonical) }
func (eventBorrowedView) CopyTo(context.Context, *credentialmemory.LockedMapping) error {
	return errors.New("unexpected copy")
}
func (view eventBorrowedView) WriteTo(_ context.Context, sink credentialmemory.CredentialSink) error {
	if len(view.canonical) > sink.MaxCredentialBytes() {
		return errors.New("destination too small")
	}
	return sink.WriteCredential(view.canonical)
}

func canonicalCoreOutputBody(revision uint64, kind credentialprotocol.HelperExecStreamKind, offset uint64, payload []byte, eof bool) []byte {
	wire := make([]byte, 56+len(payload))
	binary.BigEndian.PutUint64(wire[0:8], revision)
	wire[8] = byte(kind)
	if eof {
		wire[9] = byte(credentialprotocol.HelperExecStreamFlagEOF)
	}
	binary.BigEndian.PutUint64(wire[12:20], offset)
	binary.BigEndian.PutUint32(wire[20:24], uint32(len(payload)))
	digest := sha256.Sum256(payload)
	copy(wire[24:56], digest[:])
	copy(wire[56:], payload)
	return wire
}

func (body *eventBody) Len() uint32 {
	if body.panicOnLen {
		panic("test panic")
	}
	return body.length
}
func (body *eventBody) SHA256() [32]byte { return body.digest }
func (body *eventBody) Borrow(ctx context.Context, callback func(credentialmemory.BorrowedView) error) error {
	return callback(eventBorrowedView{canonical: body.canonical})
}
func (body *eventBody) Destroy(ctx context.Context) error {
	body.destroyed++
	body.destroyCtx = ctx
	return body.destroyErr
}

func TestCoreExecutionEventOwnershipAndArms(t *testing.T) {
	ctx := context.WithValue(context.Background(), eventContextKey{}, "owned-context")
	execution := CoreExecutionCapability{digest: sha256.Sum256([]byte("execution"))}
	payloadDigest := sha256.Sum256([]byte("payload"))
	output, err := NewCoreOutputResult(execution, credentialprotocol.HelperExecStreamStdout, 0, 7, payloadDigest, false, false)
	if err != nil {
		t.Fatal(err)
	}
	canonical := canonicalCoreOutputBody(7, credentialprotocol.HelperExecStreamStdout, 0, []byte("payload"), false)
	body := &eventBody{length: 63, digest: sha256.Sum256(canonical), canonical: canonical}
	event, err := NewCoreExecutionOutputEvent(ctx, output, body)
	if err != nil || body.destroyed != 0 || event.Kind() != CoreExecutionEventOutput {
		t.Fatalf("output event = %v, destroyed %d", err, body.destroyed)
	}
	gotOutput, gotBody, ok := event.Output()
	if !ok || gotOutput.SHA256() != payloadDigest || gotBody != body {
		t.Fatal("output arm changed")
	}
	if _, ok := event.Complete(); ok {
		t.Fatal("output event exposed complete arm")
	}

	invalidBody := &eventBody{length: 64, digest: body.digest, canonical: canonical}
	if _, err := NewCoreExecutionOutputEvent(ctx, output, invalidBody); !errors.Is(err, ErrContractResultMatrix) || invalidBody.destroyed != 1 || invalidBody.destroyCtx != ctx {
		t.Fatalf("invalid body = %v, destroyed %d", err, invalidBody.destroyed)
	}
	destroyFailure := &eventBody{length: 64, digest: body.digest, canonical: canonical, destroyErr: errors.New("destroy failed")}
	if _, err := NewCoreExecutionOutputEvent(ctx, output, destroyFailure); !errors.Is(err, ErrContractOwnership) || destroyFailure.destroyed != 1 {
		t.Fatalf("destroy failure = %v, calls %d", err, destroyFailure.destroyed)
	}
	var typedNilBody *eventBody
	if _, err := NewCoreExecutionOutputEvent(ctx, output, typedNilBody); !errors.Is(err, ErrContractTypedNil) {
		t.Fatalf("typed nil error = %v", err)
	}
}

func TestCoreExecutionOutputEventDestroysOnPanic(t *testing.T) {
	ctx := context.Background()
	execution := CoreExecutionCapability{digest: sha256.Sum256([]byte("execution"))}
	output, err := NewCoreOutputResult(execution, credentialprotocol.HelperExecStreamStdout, 0, 1, sha256.Sum256([]byte("x")), false, false)
	if err != nil {
		t.Fatal(err)
	}
	body := &eventBody{panicOnLen: true}
	defer func() {
		if recover() == nil || body.destroyed != 1 || body.destroyCtx != ctx {
			t.Fatalf("panic cleanup = destroyed %d", body.destroyed)
		}
	}()
	_, _ = NewCoreExecutionOutputEvent(ctx, output, body)
}

func TestCoreExecutionOutputEventRejectsUnboundCanonicalBody(t *testing.T) {
	ctx := context.Background()
	execution := CoreExecutionCapability{digest: sha256.Sum256([]byte("execution"))}
	payload := []byte("payload")
	output, err := NewCoreOutputResult(execution, credentialprotocol.HelperExecStreamStdout, 9, uint32(len(payload)), sha256.Sum256(payload), false, false)
	if err != nil {
		t.Fatal(err)
	}
	valid := canonicalCoreOutputBody(7, credentialprotocol.HelperExecStreamStdout, 9, payload, false)
	changedKind := append([]byte(nil), valid...)
	changedKind[8] = byte(credentialprotocol.HelperExecStreamStderr)
	changedPayload := append([]byte(nil), valid...)
	changedPayload[len(changedPayload)-1]++
	for _, test := range []struct {
		name string
		wire []byte
		hash [32]byte
	}{
		{name: "body digest mismatch", wire: valid, hash: sha256.Sum256([]byte("other"))},
		{name: "kind mismatch", wire: changedKind, hash: sha256.Sum256(changedKind)},
		{name: "payload mismatch", wire: changedPayload, hash: sha256.Sum256(changedPayload)},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &eventBody{length: uint32(len(test.wire)), digest: test.hash, canonical: test.wire}
			if _, err := NewCoreExecutionOutputEvent(ctx, output, body); !errors.Is(err, ErrContractResultMatrix) || body.destroyed != 1 {
				t.Fatalf("event error = %v, destroyed = %d", err, body.destroyed)
			}
		})
	}
}

func TestCoreExecutionCompleteEventCarriesOnlyCompleteArm(t *testing.T) {
	execution := CoreExecutionCapability{digest: sha256.Sum256([]byte("execution"))}
	empty := sha256.Sum256(nil)
	result, err := NewCoreExecResult(
		execution, CoreExecExitExited, 0,
		0, empty, sha256.Sum256([]byte("stdin-transcript")),
		0, empty, false, 0, empty, false,
		sha256.Sum256([]byte("exec-transaction")),
	)
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewCoreExecutionCompleteEvent(result)
	if err != nil || event.Kind() != CoreExecutionEventComplete {
		t.Fatalf("complete event = %v", err)
	}
	complete, ok := event.Complete()
	if !ok || complete.ExecTransactionSHA256() != result.ExecTransactionSHA256() {
		t.Fatal("complete arm changed")
	}
	if _, _, ok := event.Output(); ok {
		t.Fatal("complete event exposed output arm")
	}
}
