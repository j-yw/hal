package credentialprotocol

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
)

type helperExecObservedTestView struct {
	payload       []byte
	length        int
	lenPanic      any
	writePanic    any
	writeErr      error
	suppressError bool
	writes        int
	writeCalls    atomic.Int32
	afterWrite    func()
}

func (view *helperExecObservedTestView) Len() int {
	if view.lenPanic != nil {
		panic(view.lenPanic)
	}
	if view.length >= 0 {
		return view.length
	}
	return len(view.payload)
}

func (*helperExecObservedTestView) CopyTo(context.Context, *credentialmemory.LockedMapping) error {
	return errors.New("unused")
}

func (view *helperExecObservedTestView) WriteTo(ctx context.Context, sink credentialmemory.CredentialSink) error {
	view.writeCalls.Add(1)
	if view.writePanic != nil {
		panic(view.writePanic)
	}
	if view.writeErr != nil {
		return view.writeErr
	}
	writes := view.writes
	if writes == 0 {
		writes = 1
	}
	var first error
	for index := 0; index < writes; index++ {
		if err := sink.WriteCredential(view.payload); err != nil && first == nil {
			first = err
		}
	}
	if view.afterWrite != nil {
		view.afterWrite()
	}
	if view.suppressError {
		return nil
	}
	return first
}

type helperExecObservedNilContext struct{}

func (*helperExecObservedNilContext) Deadline() (deadline time.Time, ok bool) {
	panic("context touched")
}
func (*helperExecObservedNilContext) Done() <-chan struct{} { panic("context touched") }
func (*helperExecObservedNilContext) Err() error            { panic("context touched") }
func (*helperExecObservedNilContext) Value(any) any         { panic("context touched") }

type helperExecObservedNilView struct{}

func (*helperExecObservedNilView) Len() int { panic("view touched") }
func (*helperExecObservedNilView) CopyTo(context.Context, *credentialmemory.LockedMapping) error {
	panic("view touched")
}
func (*helperExecObservedNilView) WriteTo(context.Context, credentialmemory.CredentialSink) error {
	panic("view touched")
}

func TestHelperExecObservationsOneUseOpaqueAndConcurrent(t *testing.T) {
	private := []byte("private")
	digest := sha256.Sum256(private)
	observation, err := NewHelperExecPrivateObservation(7, uint32(len(private)), digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	alias := observation
	for _, value := range []any{observation, &observation} {
		if got := fmt.Sprintf("%v|%+v|%#v|%s|%q", value, value, value, value, value); strings.Contains(got, fmt.Sprintf("%x", digest)) || strings.Contains(got, "private") {
			t.Fatalf("opaque formatting leaked metadata: %q", got)
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrHelperExecObservationSerialization) {
			t.Fatalf("marshal error = %v", err)
		}
		if _, err := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, ErrHelperExecObservationSerialization) {
			t.Fatalf("text error = %v", err)
		}
	}

	correlation := testHelperExecTransactionCorrelation(t)
	transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, private))
	results := make(chan error, 2)
	var proposalsMu sync.Mutex
	var proposals []*HelperExecPayloadProposal
	for _, candidate := range []HelperExecPrivateObservation{observation, alias} {
		go func(candidate HelperExecPrivateObservation) {
			proposal, err := transaction.ProposeObservedPrivate(correlation, candidate)
			if proposal != nil {
				proposalsMu.Lock()
				proposals = append(proposals, proposal)
				proposalsMu.Unlock()
			}
			results <- err
		}(candidate)
	}
	var success, used int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrHelperExecPrivateObservationUsed):
			used++
		default:
			t.Fatalf("concurrent result = %v", err)
		}
	}
	if success != 1 || used != 1 || len(proposals) != 1 {
		t.Fatalf("success=%d used=%d proposals=%d", success, used, len(proposals))
	}
	proposals[0].Wipe()
}

func TestHelperExecObservedAdmissionNormalComparisonEOFAndFailureMatrix(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	private := []byte("private")
	body := testHelperExecTransactionBody(t, private)
	transaction := mustHelperExecTransaction(t, correlation, body)
	commitObservedPrivate(t, transaction, correlation, private)
	commitObservedStdin(t, transaction, correlation, 0, []byte("stdin"), false)
	commitObservedStdin(t, transaction, correlation, 5, nil, true)
	snapshot := transaction.Snapshot()
	result, err := transaction.Complete(acceptedHelperExecResponse(7, 5, sha256.Sum256([]byte("stdin")), snapshot.ExecTransactionSHA256))
	if err != nil {
		t.Fatal(err)
	}

	replay, err := NewHelperExecComparisonTransaction(correlation, body, result)
	if err != nil {
		t.Fatal(err)
	}
	commitObservedPrivate(t, replay, correlation, private)
	commitObservedStdin(t, replay, correlation, 0, []byte("stdin"), false)
	commitObservedStdin(t, replay, correlation, 5, nil, true)
	if _, err := replay.ReplayResult(); err != nil {
		t.Fatal(err)
	}

	bad := mustHelperExecTransaction(t, correlation, body)
	changed := sha256.Sum256([]byte("changed"))
	if _, err := NewHelperExecPrivateObservation(7, uint32(len(private)), sha256.Sum256(private), changed); !errors.Is(err, ErrHelperExecPrivateObservation) {
		t.Fatalf("private mismatch = %v", err)
	}
	if _, err := NewHelperExecStreamObservation(7, HelperExecStreamStdout, HelperExecStreamFlagsNone, 0, 1, changed, changed); !errors.Is(err, ErrHelperExecStreamObservation) {
		t.Fatalf("direction = %v", err)
	}
	bad.Close()
}

func TestHelperExecObservedAdmissionRaceAndNoPayloadRetention(t *testing.T) {
	for _, typeOf := range []reflect.Type{
		reflect.TypeOf(helperExecPrivateObservationOwner{}), reflect.TypeOf(helperExecStreamObservationOwner{}), reflect.TypeOf(helperExecObservedStdinSink{}),
	} {
		for index := 0; index < typeOf.NumField(); index++ {
			kind := typeOf.Field(index).Type.Kind()
			if kind == reflect.Slice || kind == reflect.String || kind == reflect.Map || kind == reflect.Interface || kind == reflect.Func {
				t.Fatalf("%s retains %s field %s", typeOf.Name(), kind, typeOf.Field(index).Name)
			}
		}
	}

	correlation := testHelperExecTransactionCorrelation(t)
	transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
	grantHelperExecCredit(t, transaction, correlation, 0)
	payload := []byte("race")
	digest := sha256.Sum256(payload)
	observation, err := NewHelperExecStreamObservation(7, HelperExecStreamStdin, HelperExecStreamFlagsNone, 0, uint32(len(payload)), digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	alias := observation
	var successes atomic.Int32
	var used atomic.Int32
	var proposalMu sync.Mutex
	var winning *HelperExecPayloadProposal
	var wg sync.WaitGroup
	for _, candidate := range []HelperExecStreamObservation{observation, alias} {
		wg.Add(1)
		go func(candidate HelperExecStreamObservation) {
			defer wg.Done()
			proposal, err := transaction.ProposeObservedStdin(context.Background(), correlation, candidate, &helperExecObservedTestView{payload: payload, length: -1})
			switch {
			case err == nil:
				successes.Add(1)
				proposalMu.Lock()
				winning = proposal
				proposalMu.Unlock()
			case errors.Is(err, ErrHelperExecStreamObservationUsed):
				used.Add(1)
			default:
				t.Errorf("race error = %v", err)
			}
		}(candidate)
	}
	wg.Wait()
	if successes.Load() != 1 || used.Load() != 1 || winning == nil || winning.owner.slot != nil {
		t.Fatalf("success=%d used=%d proposal=%v", successes.Load(), used.Load(), winning)
	}
	winning.Wipe()
}

func TestHelperExecObservedAdmissionNoViewOrSinkRetention(t *testing.T) {
	for _, typeOf := range []reflect.Type{reflect.TypeOf(helperExecTransactionOwner{}), reflect.TypeOf(helperExecPayloadProposalOwner{}), reflect.TypeOf(helperExecPrivateObservationOwner{}), reflect.TypeOf(helperExecStreamObservationOwner{})} {
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.Type == reflect.TypeOf((*credentialmemory.BorrowedView)(nil)).Elem() || field.Type == reflect.TypeOf((*credentialmemory.CredentialSink)(nil)).Elem() || field.Type.Kind() == reflect.Func {
				t.Fatalf("%s retains scoped field %s", typeOf.Name(), field.Name)
			}
		}
	}
	source, err := os.ReadFile("helper_exec_transaction_observation.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"BorrowedView\n", "CredentialSink\n", "[]byte\n"} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("observation source retains scoped marker %q", forbidden)
		}
	}
}

func TestHelperExecObservedTypedNilPreTouchMatrix(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	payload := []byte("stdin")
	digest := sha256.Sum256(payload)
	for name, inputs := range map[string]struct {
		ctx  context.Context
		view credentialmemory.BorrowedView
	}{
		"plain context": {ctx: nil, view: &helperExecObservedTestView{payload: payload, length: -1}},
		"typed context": {ctx: (*helperExecObservedNilContext)(nil), view: &helperExecObservedTestView{payload: payload, length: -1}},
		"plain view":    {ctx: context.Background(), view: nil},
		"typed view":    {ctx: context.Background(), view: (*helperExecObservedNilView)(nil)},
	} {
		t.Run(name, func(t *testing.T) {
			transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
			grantHelperExecCredit(t, transaction, correlation, 0)
			observation, err := NewHelperExecStreamObservation(7, HelperExecStreamStdin, HelperExecStreamFlagsNone, 0, uint32(len(payload)), digest, digest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := transaction.ProposeObservedStdin(inputs.ctx, correlation, observation, inputs.view); !errors.Is(err, ErrHelperExecTransactionStream) {
				t.Fatalf("error = %v", err)
			}
			if transaction.Terminal() || observation.owner.used {
				t.Fatal("pre-touch rejection consumed state")
			}
		})
	}
}

func TestHelperExecObservedCommitWipesSupersededHashOwnersBeforeTransfer(t *testing.T) {
	source, err := os.ReadFile("helper_exec_transaction_state.go")
	if err != nil {
		t.Fatal(err)
	}
	wipeAt := strings.Index(string(source), "currentStdinHash.Wipe()")
	transferAt := strings.Index(string(source), "transaction.stdinHash = owner.candidateStdinHash")
	if wipeAt < 0 || transferAt < 0 || wipeAt >= transferAt {
		t.Fatal("superseded stdin hash owner is not wiped before candidate transfer")
	}

	correlation := testHelperExecTransactionCorrelation(t)
	transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
	grantHelperExecCredit(t, transaction, correlation, 0)
	oldStdin, oldTranscript := transaction.owner.stdinHash, transaction.owner.transcriptHash
	payload := []byte("stdin")
	proposal := mustObservedStdinProposal(t, transaction, correlation, 0, payload, false, &helperExecObservedTestView{payload: payload, length: -1})
	newStdin, newTranscript := proposal.owner.candidateStdinHash, proposal.owner.candidateTranscriptHash
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
	assertHelperExecSHA256Wiped(t, oldStdin)
	assertHelperExecSHA256Wiped(t, oldTranscript)
	if transaction.owner.stdinHash != newStdin || transaction.owner.transcriptHash != newTranscript || proposal.owner.candidateStdinHash != nil || proposal.owner.candidateTranscriptHash != nil {
		t.Fatal("candidate ownership was not atomically transferred")
	}
}

func TestHelperExecObservedProposalSourceCommitMatrix(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	private := []byte("private")
	legacy := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, private))
	body, err := NewHelperExecPrivateBody(7, sha256.Sum256(private), private)
	if err != nil {
		t.Fatal(err)
	}
	legacyProposal, err := legacy.ProposePrivate(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	if legacyProposal.owner.source != helperExecProposalSourceLegacy {
		t.Fatal("legacy proposal source changed")
	}
	legacyProposal.Wipe()

	observed := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, private))
	digest := sha256.Sum256(private)
	observation, err := NewHelperExecPrivateObservation(7, uint32(len(private)), digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := observed.ProposeObservedPrivate(correlation, observation)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.owner.source != helperExecProposalSourceObserved || !proposal.owner.observedReady || proposal.owner.slot != nil {
		t.Fatal("observed proposal authority mismatch")
	}
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestHelperExecObservedExternalFailureAndPanicSanitization(t *testing.T) {
	secret := "secret-external-cause"
	cases := map[string]func() *helperExecObservedTestView{
		"length panic": func() *helperExecObservedTestView { return &helperExecObservedTestView{length: -1, lenPanic: secret} },
		"write panic": func() *helperExecObservedTestView {
			return &helperExecObservedTestView{payload: []byte("x"), length: -1, writePanic: secret}
		},
		"write error": func() *helperExecObservedTestView {
			return &helperExecObservedTestView{payload: []byte("x"), length: -1, writeErr: errors.New(secret)}
		},
		"no write": func() *helperExecObservedTestView {
			return &helperExecObservedTestView{payload: []byte("x"), length: -1, writes: -1}
		},
		"duplicate": func() *helperExecObservedTestView {
			return &helperExecObservedTestView{payload: []byte("x"), length: -1, writes: 2, suppressError: true}
		},
	}
	for name, makeView := range cases {
		t.Run(name, func(t *testing.T) {
			correlation := testHelperExecTransactionCorrelation(t)
			transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
			grantHelperExecCredit(t, transaction, correlation, 0)
			payload := []byte("x")
			digest := sha256.Sum256(payload)
			observation, err := NewHelperExecStreamObservation(7, HelperExecStreamStdin, HelperExecStreamFlagsNone, 0, 1, digest, digest)
			if err != nil {
				t.Fatal(err)
			}
			_, err = transaction.ProposeObservedStdin(context.Background(), correlation, observation, makeView())
			if !errors.Is(err, ErrHelperExecTransactionStream) || strings.Contains(fmt.Sprint(err), secret) || !transaction.Terminal() {
				t.Fatalf("error=%v terminal=%t", err, transaction.Terminal())
			}
		})
	}
}

func TestHelperExecObservedTransactionBindingAndPrecedence(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	private := []byte("private")
	digest := sha256.Sum256(private)
	malformed := HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{used: true}}
	terminal := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, private))
	terminal.Close()
	if _, err := terminal.ProposeObservedPrivate(correlation, malformed); !errors.Is(err, ErrHelperExecPrivateObservation) {
		t.Fatalf("structural precedence = %v", err)
	}

	used, err := NewHelperExecPrivateObservation(7, uint32(len(private)), digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	used.owner.used = true
	if _, err := terminal.ProposeObservedPrivate(correlation, used); !errors.Is(err, ErrHelperExecPrivateObservationUsed) {
		t.Fatalf("used precedence = %v", err)
	}

	bound, err := NewHelperExecPrivateObservation(7, uint32(len(private)), digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	live := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, private))
	if _, err := live.ProposeObservedPrivate(changedHelperExecIdentity(correlation), bound); !errors.Is(err, ErrHelperExecTransactionCorrelation) || !live.Terminal() {
		t.Fatalf("correlation binding = %v", err)
	}
}

func TestHelperExecConfiguredDependencyTypedNilPreTouch(t *testing.T) {
	if !helperExecConfiguredDependencyNil(nil) || !helperExecConfiguredDependencyNil((*helperExecObservedNilView)(nil)) || !helperExecConfiguredDependencyNil((chan int)(nil)) || !helperExecConfiguredDependencyNil((func())(nil)) || !helperExecConfiguredDependencyNil((map[string]int)(nil)) || !helperExecConfiguredDependencyNil([]byte(nil)) {
		t.Fatal("nil-capable kind was not detected")
	}
	if helperExecConfiguredDependencyNil(context.Background()) || helperExecConfiguredDependencyNil(1) {
		t.Fatal("configured dependency was classified nil")
	}
}

func TestHelperExecObservedStdinCoreSequentialBorrowScope(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
	grantHelperExecCredit(t, transaction, correlation, 0)
	payload := []byte("stdin")
	view := &helperExecObservedTestView{payload: payload, length: -1}
	proposal := mustObservedStdinProposal(t, transaction, correlation, 0, payload, false, view)
	coreSink := &helperExecObservedCaptureSink{maximum: len(payload)}
	if err := view.WriteTo(context.Background(), coreSink); err != nil {
		proposal.Wipe()
		t.Fatal(err)
	}
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
	if view.writeCalls.Load() != 2 || string(coreSink.payload) != string(payload) {
		t.Fatalf("sequential scope calls=%d payload=%q", view.writeCalls.Load(), coreSink.payload)
	}
}

func TestHelperExecObservedConstantTimeBindingFunctions(t *testing.T) {
	left := sha256.Sum256([]byte("left"))
	right := left
	if !helperExecDigestsEqual(left, right) {
		t.Fatal("equal digest rejected")
	}
	right[31]++
	if helperExecDigestsEqual(left, right) {
		t.Fatal("changed digest accepted")
	}
	correlation := testHelperExecTransactionCorrelation(t)
	if !helperExecTransactionCorrelationEqual(correlation, correlation) || helperExecTransactionCorrelationEqual(correlation, changedHelperExecRequest(correlation)) || helperExecTransactionCorrelationEqual(correlation, changedHelperExecIdentity(correlation)) {
		t.Fatal("correlation equality drift")
	}
	changedRevision := correlation
	changedRevision.revision++
	if helperExecTransactionCorrelationEqual(correlation, changedRevision) {
		t.Fatal("revision drift accepted")
	}
	source, err := os.ReadFile("helper_exec_transaction_state.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(source), "subtle.ConstantTimeCompare(left.requestID[:], right.requestID[:])") != 1 || strings.Count(string(source), "subtle.ConstantTimeCompare(left.identityDigest[:], right.identityDigest[:])") != 1 {
		t.Fatal("correlation helper is not the exact two-comparison implementation")
	}
}

func TestHelperExecReadinessExactAPIAndOpacity(t *testing.T) {
	wantMethods := []string{"Format", "GoString", "MarshalBinary", "MarshalJSON", "MarshalText", "String"}
	for _, value := range []any{HelperExecPrivateObservation{}, HelperExecStreamObservation{}} {
		typeOf := reflect.TypeOf(value)
		if typeOf.NumField() != 1 || typeOf.Field(0).Name != "owner" || typeOf.Field(0).IsExported() || typeOf.Field(0).Type.Kind() != reflect.Pointer {
			t.Fatalf("%s layout is not one private owner pointer", typeOf.Name())
		}
		var got []string
		for index := 0; index < typeOf.NumMethod(); index++ {
			got = append(got, typeOf.Method(index).Name)
		}
		if !reflect.DeepEqual(got, wantMethods) {
			t.Fatalf("%s methods = %v", typeOf.Name(), got)
		}
		pointer := reflect.PointerTo(typeOf)
		if pointer.NumMethod() != 9 {
			t.Fatalf("%s pointer methods = %d", typeOf.Name(), pointer.NumMethod())
		}
	}
	if _, ok := any(HelperExecPrivateObservation{}).(io.Writer); ok {
		t.Fatal("private observation exposes writer")
	}
}

type helperExecObservedCaptureSink struct {
	maximum int
	payload []byte
}

func (sink *helperExecObservedCaptureSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *helperExecObservedCaptureSink) WriteCredential(payload []byte) error {
	sink.payload = append(sink.payload[:0], payload...)
	return nil
}

func commitObservedPrivate(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation, private []byte) {
	t.Helper()
	digest := sha256.Sum256(private)
	observation, err := NewHelperExecPrivateObservation(correlation.Revision(), uint32(len(private)), digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := transaction.ProposeObservedPrivate(correlation, observation)
	if err != nil {
		t.Fatal(err)
	}
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
}

func commitObservedStdin(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation, offset uint64, payload []byte, eof bool) {
	t.Helper()
	grantHelperExecCredit(t, transaction, correlation, offset)
	proposal := mustObservedStdinProposal(t, transaction, correlation, offset, payload, eof, &helperExecObservedTestView{payload: payload, length: -1})
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
}

func mustObservedStdinProposal(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation, offset uint64, payload []byte, eof bool, view credentialmemory.BorrowedView) *HelperExecPayloadProposal {
	t.Helper()
	flags := HelperExecStreamFlagsNone
	if eof {
		flags = HelperExecStreamFlagEOF
	}
	digest := sha256.Sum256(payload)
	observation, err := NewHelperExecStreamObservation(correlation.Revision(), HelperExecStreamStdin, flags, offset, uint32(len(payload)), digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := transaction.ProposeObservedStdin(context.Background(), correlation, observation, view)
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}
