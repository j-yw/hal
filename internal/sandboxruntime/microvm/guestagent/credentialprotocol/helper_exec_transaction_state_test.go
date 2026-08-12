package credentialprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"sync"
	"testing"
)

func TestHelperExecTransactionCountTrailerVectorAndCreditExclusion(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	body := testHelperExecTransactionBody(t, nil)
	transaction := mustHelperExecTransaction(t, correlation, body)

	if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}); err != nil {
		t.Fatal(err)
	}
	commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, 7, 0, []byte("alpha"), false))
	if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 5}); err != nil {
		t.Fatal(err)
	}
	commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, 7, 5, []byte("beta"), false))
	if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 9}); err != nil {
		t.Fatal(err)
	}
	commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, 7, 9, nil, true))

	snapshot := transaction.Snapshot()
	if !snapshot.StdinEOF || snapshot.StdinBytes != 9 || snapshot.StdinOffset != 9 || snapshot.StdinRecordCount != 3 {
		t.Fatalf("stdin snapshot = %#v", snapshot)
	}
	wantStdin := sha256.Sum256([]byte("alphabeta"))
	wantTranscript := independentHelperExecTranscript([]helperExecVectorRecord{
		{offset: 0, payload: []byte("alpha")},
		{offset: 5, payload: []byte("beta")},
		{flags: HelperExecStreamFlagEOF, offset: 9},
	})
	wantTransaction := independentHelperExecTransactionDigest(t, correlation, body, wantStdin, wantTranscript, 9)
	response := acceptedHelperExecResponse(7, 9, wantStdin, wantTransaction)
	result, err := transaction.Complete(response)
	if err != nil {
		t.Fatal(err)
	}
	if result.StdinSHA256() != wantStdin || result.StdinTranscriptSHA256() != wantTranscript || result.ExecTransactionSHA256() != wantTransaction || result.StdinRecordCount() != 3 {
		t.Fatal("completed digests or count differ from independent count-trailer construction")
	}
	if got := hex.EncodeToString(wantTranscript[:]); got != "3735bb44b865ba294f65785f269d8c329ba2fcff41fcff2157cd963feab0876a" {
		t.Fatalf("transcript vector = %s", got)
	}

	// Credit timing and repetition are deliberately absent from every digest.
	second := mustHelperExecTransaction(t, correlation, body)
	for _, record := range []struct {
		offset  uint64
		payload []byte
		eof     bool
	}{{0, []byte("alpha"), false}, {5, []byte("beta"), false}, {9, nil, true}} {
		if err := second.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: record.offset}); err != nil {
			t.Fatal(err)
		}
		commitHelperExecPayload(t, second, correlation, mustHelperExecStdinBody(t, 7, record.offset, record.payload, record.eof))
	}
	secondResult, err := second.Complete(response)
	if err != nil {
		t.Fatal(err)
	}
	if secondResult.ExecTransactionSHA256() != result.ExecTransactionSHA256() {
		t.Fatal("equivalent input with fresh credits changed transaction digest")
	}
}

func TestHelperExecTransactionPrivateAndStdinUseOneWipedProposalSlot(t *testing.T) {
	private := []byte("opaque-http-binding")
	correlation := testHelperExecTransactionCorrelation(t)
	body := testHelperExecTransactionBody(t, private)
	transaction := mustHelperExecTransaction(t, correlation, body)

	privateBody, err := NewHelperExecPrivateBody(7, sha256.Sum256(private), private)
	if err != nil {
		t.Fatal(err)
	}
	privateAlias := *privateBody
	privateSource := privateBody.state.privateBinding
	proposal, err := transaction.ProposePrivate(correlation, privateBody)
	if err != nil {
		t.Fatal(err)
	}
	proposalAlias := *proposal
	if privateAlias.state == nil || !privateAlias.state.wiped || privateAlias.PrivateBindingLength() != 0 {
		t.Fatal("private body was not wiped through aliases after ownership transfer")
	}
	if len(privateSource) == 0 || &proposal.owner.slot[0] != &privateSource[0] || cap(proposal.owner.slot) != cap(privateSource) {
		t.Fatal("private proposal copied instead of detaching the exact validated backing array")
	}
	assertHelperExecOnlyOneSlot(t, transaction)
	owned := privateSource
	destination := make([]byte, len(private), len(private)+17)
	for index := range destination[:cap(destination)] {
		destination[:cap(destination)][index] = 0x5a
	}
	if count, err := proposal.CopyPayload(destination); err != nil || count != len(private) || !bytes.Equal(destination, private) {
		t.Fatalf("private copy = %d, %v", count, err)
	}
	if !bytes.Equal(destination[len(destination):cap(destination)], make([]byte, cap(destination)-len(destination))) {
		t.Fatal("copy left stale destination capacity")
	}
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(owned[:cap(owned)], make([]byte, cap(owned))) || !proposalAlias.Wiped() {
		t.Fatal("private commit did not wipe the complete slot capacity through aliases")
	}
	if !transaction.Snapshot().ReadyForLaunch {
		t.Fatal("normal transaction did not reach the pre-launch decision after exact private commit")
	}

	if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}); err != nil {
		t.Fatal(err)
	}
	streamBody := mustHelperExecStdinBody(t, 7, 0, []byte("stdin"), false)
	streamAlias := *streamBody
	streamSource := streamBody.state.payload
	streamProposal, err := transaction.ProposeStdin(correlation, streamBody)
	if err != nil {
		t.Fatal(err)
	}
	if !streamAlias.state.wiped {
		t.Fatal("stdin body was not wiped after proposal transfer")
	}
	if &streamProposal.owner.slot[0] != &streamSource[0] || cap(streamProposal.owner.slot) != cap(streamSource) {
		t.Fatal("stdin proposal copied instead of detaching the exact validated backing array")
	}
	assertHelperExecOnlyOneSlot(t, transaction)
	streamOwned := streamSource
	streamDestination := make([]byte, len("stdin"))
	if _, err := streamProposal.CopyPayload(streamDestination); err != nil {
		t.Fatal(err)
	}
	if err := streamProposal.Commit(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(streamOwned[:cap(streamOwned)], make([]byte, cap(streamOwned))) {
		t.Fatal("stdin commit did not wipe the complete slot capacity")
	}
}

func TestHelperExecTransactionTerminalMismatchIsNonadvancing(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*HelperExecTransaction)
		run   func(*testing.T, *HelperExecTransaction, HelperExecTransactionCorrelation)
	}{
		{name: "credit request", run: func(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation) {
			err := transaction.GrantStdinCredit(changedHelperExecRequest(correlation), HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0})
			if !errors.Is(err, ErrHelperExecTransactionCorrelation) {
				t.Fatalf("error = %v", err)
			}
		}},
		{name: "credit identity", run: func(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation) {
			err := transaction.GrantStdinCredit(changedHelperExecIdentity(correlation), HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0})
			if !errors.Is(err, ErrHelperExecTransactionCorrelation) {
				t.Fatalf("error = %v", err)
			}
		}},
		{name: "credit revision", run: func(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation) {
			err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 8, StreamKind: HelperExecStreamStdin, NextOffset: 0})
			if !errors.Is(err, ErrHelperExecTransactionCredit) {
				t.Fatalf("error = %v", err)
			}
		}},
		{name: "credit offset", run: func(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation) {
			err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 1})
			if !errors.Is(err, ErrHelperExecTransactionCredit) {
				t.Fatalf("error = %v", err)
			}
		}},
		{name: "stream without credit", run: func(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation) {
			body := mustHelperExecStdinBody(t, 7, 0, []byte("x"), false)
			source := body.state.payload
			if _, err := transaction.ProposeStdin(correlation, body); !errors.Is(err, ErrHelperExecTransactionCredit) {
				t.Fatalf("error = %v", err)
			}
			if body.state != nil && !body.state.wiped {
				t.Fatal("rejected stream body was not wiped")
			}
			assertHelperExecZeroCapacity(t, source)
		}},
		{name: "stream offset", run: func(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation) {
			if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}); err != nil {
				t.Fatal(err)
			}
			if _, err := transaction.ProposeStdin(correlation, mustHelperExecStdinBody(t, 7, 1, []byte("x"), false)); !errors.Is(err, ErrHelperExecTransactionStream) {
				t.Fatalf("error = %v", err)
			}
		}},
		{name: "aggregate", setup: func(transaction *HelperExecTransaction) {
			transaction.owner.stdinOffset = uint64(transaction.owner.stdinMax)
			transaction.owner.stdinBytes = uint64(transaction.owner.stdinMax)
		}, run: func(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation) {
			if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: transaction.owner.stdinOffset}); err != nil {
				t.Fatal(err)
			}
			if _, err := transaction.ProposeStdin(correlation, mustHelperExecStdinBody(t, 7, transaction.owner.stdinOffset, []byte("x"), false)); !errors.Is(err, ErrHelperExecTransactionStream) {
				t.Fatalf("error = %v", err)
			}
		}},
		{name: "record count overflow", setup: func(transaction *HelperExecTransaction) {
			transaction.owner.stdinRecords = ^uint32(0)
		}, run: func(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation) {
			if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}); err != nil {
				t.Fatal(err)
			}
			if _, err := transaction.ProposeStdin(correlation, mustHelperExecStdinBody(t, 7, 0, nil, true)); !errors.Is(err, ErrHelperExecTransactionRecordCount) {
				t.Fatalf("error = %v", err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			correlation := testHelperExecTransactionCorrelation(t)
			transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
			if test.setup != nil {
				test.setup(transaction)
			}
			before := transaction.Snapshot()
			test.run(t, transaction, correlation)
			after := transaction.Snapshot()
			if !after.Terminal || after.StdinOffset != before.StdinOffset || after.StdinBytes != before.StdinBytes || after.StdinRecordCount != before.StdinRecordCount || after.StdinEOF != before.StdinEOF {
				t.Fatalf("terminal denial advanced logical input: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestHelperExecTransactionUniqueEOFAndExactCompletion(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	body := testHelperExecTransactionBody(t, nil)
	transaction := mustHelperExecTransaction(t, correlation, body)
	if _, err := transaction.Complete(HelperResponseBody{}); !errors.Is(err, ErrHelperExecTransactionIncomplete) {
		t.Fatalf("completion before EOF = %v", err)
	}
	if transaction.Terminal() {
		t.Fatal("incomplete completion attempt terminalized the transaction")
	}
	if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}); err != nil {
		t.Fatal(err)
	}
	commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, 7, 0, nil, true))
	if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}); !errors.Is(err, ErrHelperExecTransactionCredit) {
		t.Fatalf("post-EOF credit = %v", err)
	}
	if !transaction.Terminal() {
		t.Fatal("second EOF path was not terminal")
	}

	transaction = mustHelperExecTransaction(t, correlation, body)
	if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}); err != nil {
		t.Fatal(err)
	}
	commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, 7, 0, nil, true))
	wrong := acceptedHelperExecResponse(7, 0, sha256.Sum256(nil), [32]byte{1})
	before := transaction.Snapshot()
	if _, err := transaction.Complete(wrong); !errors.Is(err, ErrHelperExecTransactionResult) {
		t.Fatalf("mismatched completion = %v", err)
	}
	after := transaction.Snapshot()
	if !after.Terminal || after.StdinRecordCount != before.StdinRecordCount || after.StdinBytes != before.StdinBytes {
		t.Fatalf("mismatched result advanced stream: before=%#v after=%#v", before, after)
	}
}

func TestHelperExecTransactionComparisonReplayRequiresFullExactTransaction(t *testing.T) {
	private := []byte("opaque-http-binding")
	correlation := testHelperExecTransactionCorrelation(t)
	body := testHelperExecTransactionBody(t, private)
	original := mustHelperExecTransaction(t, correlation, body)
	commitHelperExecPrivate(t, original, correlation, private)
	if err := original.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}); err != nil {
		t.Fatal(err)
	}
	commitHelperExecPayload(t, original, correlation, mustHelperExecStdinBody(t, 7, 0, []byte("payload"), false))
	if err := original.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 7}); err != nil {
		t.Fatal(err)
	}
	commitHelperExecPayload(t, original, correlation, mustHelperExecStdinBody(t, 7, 7, nil, true))
	digest := original.Snapshot().ExecTransactionSHA256
	response := acceptedHelperExecResponse(7, 7, sha256.Sum256([]byte("payload")), digest)
	cached, err := original.Complete(response)
	if err != nil {
		t.Fatal(err)
	}

	replay, err := NewHelperExecComparisonTransaction(correlation, body, cached)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Snapshot().ComparisonOnly || replay.Snapshot().ReadyForLaunch {
		t.Fatal("comparison replay exposed launch permission")
	}
	privateBody, err := NewHelperExecPrivateBody(7, sha256.Sum256(private), private)
	if err != nil {
		t.Fatal(err)
	}
	privateSource := privateBody.state.privateBinding
	proposal, err := replay.ProposePrivate(correlation, privateBody)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.owner.slot != nil {
		t.Fatal("comparison private proposal retained payload bytes")
	}
	assertHelperExecZeroCapacity(t, privateSource)
	destination := bytes.Repeat([]byte{0xa5}, len(private))
	if count, err := proposal.CopyPayload(destination); count != 0 || !errors.Is(err, ErrHelperExecProposalComparisonOnly) {
		t.Fatalf("comparison private copy = %d, %v", count, err)
	}
	if !bytes.Equal(destination, make([]byte, len(destination))) {
		t.Fatal("comparison copy denial did not wipe destination")
	}
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
	if replay.Snapshot().ReadyForLaunch {
		t.Fatal("comparison private commit exposed launch permission")
	}
	if err := replay.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}); err != nil {
		t.Fatal(err)
	}
	commitHelperExecComparisonPayload(t, replay, correlation, mustHelperExecStdinBody(t, 7, 0, []byte("payload"), false))
	if _, err := replay.ReplayResult(); !errors.Is(err, ErrHelperExecTransactionIncomplete) {
		t.Fatalf("replay before EOF = %v", err)
	}
	if err := replay.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 7}); err != nil {
		t.Fatal(err)
	}
	commitHelperExecComparisonPayload(t, replay, correlation, mustHelperExecStdinBody(t, 7, 7, nil, true))
	got, err := replay.ReplayResult()
	if err != nil {
		t.Fatal(err)
	}
	if !reflectHelperExecResponseEqual(got, response) {
		t.Fatalf("replayed response differs: %#v", got)
	}

	changedBody := body
	changedBody.Plan.Arguments = []string{"/bin/echo", "changed"}
	if _, err := NewHelperExecComparisonTransaction(correlation, changedBody, cached); !errors.Is(err, ErrHelperExecTransactionReplayMismatch) {
		t.Fatalf("changed replay begin = %v", err)
	}

	if _, err := NewHelperExecComparisonTransaction(changedHelperExecRequest(correlation), body, cached); !errors.Is(err, ErrHelperExecTransactionCorrelation) {
		t.Fatalf("cross-request replay = %v", err)
	}
}

func TestHelperExecTransactionRechunkedReplayDoesNotMatch(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	body := testHelperExecTransactionBody(t, nil)
	original := mustHelperExecTransaction(t, correlation, body)
	for _, record := range []struct {
		offset  uint64
		payload []byte
		eof     bool
	}{{0, []byte("ab"), false}, {2, []byte("cd"), false}, {4, nil, true}} {
		if err := original.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: record.offset}); err != nil {
			t.Fatal(err)
		}
		commitHelperExecPayload(t, original, correlation, mustHelperExecStdinBody(t, 7, record.offset, record.payload, record.eof))
	}
	snapshot := original.Snapshot()
	cached, err := original.Complete(acceptedHelperExecResponse(7, 4, sha256.Sum256([]byte("abcd")), snapshot.ExecTransactionSHA256))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewHelperExecComparisonTransaction(correlation, body, cached)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []struct {
		offset  uint64
		payload []byte
		eof     bool
	}{{0, []byte("abcd"), false}, {4, nil, true}} {
		if err := replay.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: record.offset}); err != nil {
			t.Fatal(err)
		}
		commitHelperExecComparisonPayload(t, replay, correlation, mustHelperExecStdinBody(t, 7, record.offset, record.payload, record.eof))
	}
	if _, err := replay.ReplayResult(); !errors.Is(err, ErrHelperExecTransactionReplayMismatch) {
		t.Fatalf("rechunked replay = %v", err)
	}
}

func TestHelperExecTransactionComparisonMismatchAtEarliestSafePoint(t *testing.T) {
	private := []byte("private-one")
	correlation := testHelperExecTransactionCorrelation(t)
	body := testHelperExecTransactionBody(t, private)
	original := mustHelperExecTransaction(t, correlation, body)
	commitHelperExecPrivate(t, original, correlation, private)
	grantHelperExecCredit(t, original, correlation, 0)
	commitHelperExecPayload(t, original, correlation, mustHelperExecStdinBody(t, 7, 0, []byte("stdin-one"), false))
	grantHelperExecCredit(t, original, correlation, uint64(len("stdin-one")))
	commitHelperExecPayload(t, original, correlation, mustHelperExecStdinBody(t, 7, uint64(len("stdin-one")), nil, true))
	snapshot := original.Snapshot()
	cached, err := original.Complete(acceptedHelperExecResponse(7, snapshot.StdinBytes, snapshot.StdinSHA256, snapshot.ExecTransactionSHA256))
	if err != nil {
		t.Fatal(err)
	}

	replay, err := NewHelperExecComparisonTransaction(correlation, body, cached)
	if err != nil {
		t.Fatal(err)
	}
	wrongPrivate := []byte("private-two")
	privateBody, err := NewHelperExecPrivateBody(7, sha256.Sum256(wrongPrivate), wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replay.ProposePrivate(correlation, privateBody); !errors.Is(err, ErrHelperExecTransactionPrivate) || !replay.Terminal() || !privateBody.state.wiped {
		t.Fatalf("private mismatch = %v, terminal=%v", err, replay.Terminal())
	}

	replay, err = NewHelperExecComparisonTransaction(correlation, body, cached)
	if err != nil {
		t.Fatal(err)
	}
	commitHelperExecPrivate(t, replay, correlation, private)
	grantHelperExecCredit(t, replay, correlation, 0)
	commitHelperExecComparisonPayload(t, replay, correlation, mustHelperExecStdinBody(t, 7, 0, []byte("stdin-two"), false))
	grantHelperExecCredit(t, replay, correlation, uint64(len("stdin-two")))
	commitHelperExecComparisonPayload(t, replay, correlation, mustHelperExecStdinBody(t, 7, uint64(len("stdin-two")), nil, true))
	if _, err := replay.ReplayResult(); !errors.Is(err, ErrHelperExecTransactionReplayMismatch) || !replay.Terminal() {
		t.Fatalf("stdin mismatch = %v, terminal=%v", err, replay.Terminal())
	}
}

func TestHelperExecTransactionOpaqueNonserializableAliasSafeAndConcurrent(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
	alias := *transaction
	if fmt.Sprint(correlation) != "<credentialprotocol.HelperExecTransactionCorrelation>" || fmt.Sprint(transaction) != "<credentialprotocol.HelperExecTransaction>" {
		t.Fatal("opaque formatting changed")
	}
	values := []any{correlation, *transaction, transaction.Snapshot(), HelperExecPayloadProposal{}, HelperExecTransactionResult{}}
	for _, value := range values {
		if _, err := json.Marshal(value); !errors.Is(err, ErrHelperExecTransactionSerialization) {
			t.Fatalf("json marshal %T = %v", value, err)
		}
		if marshaler, ok := value.(encoding.TextMarshaler); !ok {
			t.Fatalf("%T lacks text marshaler", value)
		} else if _, err := marshaler.MarshalText(); !errors.Is(err, ErrHelperExecTransactionSerialization) {
			t.Fatalf("text marshal %T = %v", value, err)
		}
		if marshaler, ok := value.(encoding.BinaryMarshaler); !ok {
			t.Fatalf("%T lacks binary marshaler", value)
		} else if _, err := marshaler.MarshalBinary(); !errors.Is(err, ErrHelperExecTransactionSerialization) {
			t.Fatalf("binary marshal %T = %v", value, err)
		}
	}

	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_ = alias.Snapshot()
			_ = transaction.Snapshot()
		}()
	}
	wait.Wait()
	alias.Close()
	if !transaction.Terminal() {
		t.Fatal("transaction alias did not share terminal ownership")
	}
}

func TestHelperExecTransactionZeroPrivateAndCreditRecordDenials(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
	if !transaction.Snapshot().PrivateComplete {
		t.Fatal("zero private declaration was not implicitly complete")
	}
	private, err := NewHelperExecPrivateBody(7, sha256.Sum256([]byte("x")), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	privateSource := private.state.privateBinding
	if _, err := transaction.ProposePrivate(correlation, private); !errors.Is(err, ErrHelperExecTransactionPrivate) || !transaction.Terminal() || !private.state.wiped {
		t.Fatalf("zero-private proposal = %v, terminal=%v, wiped=%v", err, transaction.Terminal(), private.state.wiped)
	}
	assertHelperExecZeroCapacity(t, privateSource)

	tests := []struct {
		name string
		run  func(*testing.T, *HelperExecTransaction)
	}{
		{name: "duplicate credit", run: func(t *testing.T, transaction *HelperExecTransaction) {
			credit := HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: 0}
			if err := transaction.GrantStdinCredit(correlation, credit); err != nil {
				t.Fatal(err)
			}
			if err := transaction.GrantStdinCredit(correlation, credit); !errors.Is(err, ErrHelperExecTransactionCredit) {
				t.Fatalf("duplicate credit = %v", err)
			}
		}},
		{name: "wrong credit kind", run: func(t *testing.T, transaction *HelperExecTransaction) {
			if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdout}); !errors.Is(err, ErrHelperExecTransactionCredit) {
				t.Fatalf("wrong credit kind = %v", err)
			}
		}},
		{name: "wrong record kind", run: func(t *testing.T, transaction *HelperExecTransaction) {
			grantHelperExecCredit(t, transaction, correlation, 0)
			body, err := NewHelperExecStreamBody(7, HelperExecStreamStdout, HelperExecStreamFlagsNone, 0, sha256.Sum256([]byte("x")), []byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := transaction.ProposeStdin(correlation, body); !errors.Is(err, ErrHelperExecTransactionStream) {
				t.Fatalf("wrong record kind = %v", err)
			}
		}},
		{name: "EOF with payload", run: func(t *testing.T, transaction *HelperExecTransaction) {
			grantHelperExecCredit(t, transaction, correlation, 0)
			body := mustHelperExecStdinBody(t, 7, 0, []byte("x"), false)
			body.state.flags = HelperExecStreamFlagEOF
			if _, err := transaction.ProposeStdin(correlation, body); !errors.Is(err, ErrHelperExecTransactionStream) {
				t.Fatalf("EOF payload = %v", err)
			}
		}},
		{name: "non-EOF empty", run: func(t *testing.T, transaction *HelperExecTransaction) {
			grantHelperExecCredit(t, transaction, correlation, 0)
			body := mustHelperExecStdinBody(t, 7, 0, nil, true)
			body.state.flags = HelperExecStreamFlagsNone
			if _, err := transaction.ProposeStdin(correlation, body); !errors.Is(err, ErrHelperExecTransactionStream) {
				t.Fatalf("empty data record = %v", err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
			before := transaction.Snapshot()
			test.run(t, transaction)
			after := transaction.Snapshot()
			if !after.Terminal || after.StdinOffset != before.StdinOffset || after.StdinBytes != before.StdinBytes || after.StdinRecordCount != before.StdinRecordCount {
				t.Fatalf("denial advanced transaction: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestHelperExecTransactionProposalDenialsAndCloseWipeFullCapacity(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	newProposal := func(t *testing.T) (*HelperExecTransaction, *HelperExecPayloadProposal, []byte) {
		t.Helper()
		transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
		grantHelperExecCredit(t, transaction, correlation, 0)
		proposal, err := transaction.ProposeStdin(correlation, mustHelperExecStdinBody(t, 7, 0, []byte("secret"), false))
		if err != nil {
			t.Fatal(err)
		}
		owned := proposal.owner.slot[:cap(proposal.owner.slot)]
		return transaction, proposal, owned
	}

	t.Run("commit before copy", func(t *testing.T) {
		transaction, proposal, owned := newProposal(t)
		if err := proposal.Commit(); !errors.Is(err, ErrHelperExecProposalConsumed) || !transaction.Terminal() {
			t.Fatalf("commit before copy = %v, terminal=%v", err, transaction.Terminal())
		}
		assertHelperExecZeroCapacity(t, owned)
	})
	t.Run("explicit abandon", func(t *testing.T) {
		transaction, proposal, owned := newProposal(t)
		proposal.Wipe()
		if !proposal.Wiped() || !transaction.Terminal() {
			t.Fatal("abandoned proposal did not terminalize shared ownership")
		}
		assertHelperExecZeroCapacity(t, owned)
	})
	t.Run("close pending", func(t *testing.T) {
		transaction, _, owned := newProposal(t)
		transaction.Close()
		if !transaction.Terminal() {
			t.Fatal("close did not terminalize")
		}
		assertHelperExecZeroCapacity(t, owned)
	})
	for _, size := range []int{5, 7} {
		t.Run(fmt.Sprintf("copy size %d", size), func(t *testing.T) {
			transaction, proposal, owned := newProposal(t)
			destination := bytes.Repeat([]byte{0x5a}, size+19)[:size]
			if count, err := proposal.CopyPayload(destination); count != 0 || !errors.Is(err, ErrHelperExecProposalDestination) || !transaction.Terminal() {
				t.Fatalf("copy = %d, %v, terminal=%v", count, err, transaction.Terminal())
			}
			assertHelperExecZeroCapacity(t, destination)
			assertHelperExecZeroCapacity(t, owned)
		})
	}

	t.Run("comparison commit before copy", func(t *testing.T) {
		cached := completeEmptyHelperExecTransaction(t, correlation)
		replay, err := NewHelperExecComparisonTransaction(correlation, testHelperExecTransactionBody(t, nil), cached)
		if err != nil {
			t.Fatal(err)
		}
		grantHelperExecCredit(t, replay, correlation, 0)
		proposal, err := replay.ProposeStdin(correlation, mustHelperExecStdinBody(t, 7, 0, nil, true))
		if err != nil {
			t.Fatal(err)
		}
		if err := proposal.Commit(); err != nil {
			t.Fatalf("comparison in-place commit = %v", err)
		}
		if replay.Snapshot().ReadyForLaunch {
			t.Fatal("comparison became launch ready")
		}
	})
}

func TestHelperExecTransactionMaximumSlotIsBoundedAndFullyWiped(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	body := testHelperExecTransactionBody(t, nil)
	body.Plan.StdinMaxBytes = MaxHelperExecStreamPayloadBytes
	transaction := mustHelperExecTransaction(t, correlation, body)
	payload := bytes.Repeat([]byte{0x6d}, MaxHelperExecStreamPayloadBytes)
	grantHelperExecCredit(t, transaction, correlation, 0)
	proposal, err := transaction.ProposeStdin(correlation, mustHelperExecStdinBody(t, 7, 0, payload, false))
	if err != nil {
		t.Fatal(err)
	}
	if cap(proposal.owner.slot) > MaxHelperExecStreamPayloadBytes {
		t.Fatalf("slot capacity = %d", cap(proposal.owner.slot))
	}
	owned := proposal.owner.slot[:cap(proposal.owner.slot)]
	destination := make([]byte, len(payload))
	if _, err := proposal.CopyPayload(destination); err != nil {
		t.Fatal(err)
	}
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
	assertHelperExecZeroCapacity(t, owned)
}

func TestHelperExecTransactionPayloadDetachHasNoSecondAllocation(t *testing.T) {
	privateBacking := make([]byte, 31)
	privateState := &helperExecPrivateState{}
	if allocations := testing.AllocsPerRun(1000, func() {
		privateState.privateBinding = privateBacking
		privateState.wiped = false
		transferred := takeHelperExecPrivatePayload(privateState)
		if &transferred[0] != &privateBacking[0] || cap(transferred) != cap(privateBacking) {
			panic("private detach changed backing ownership")
		}
	}); allocations != 0 {
		t.Fatalf("private detach allocations = %v", allocations)
	}

	streamBacking := make([]byte, 47)
	streamState := &helperExecStreamState{}
	if allocations := testing.AllocsPerRun(1000, func() {
		streamState.payload = streamBacking
		streamState.wiped = false
		transferred := takeHelperExecStreamPayload(streamState)
		if &transferred[0] != &streamBacking[0] || cap(transferred) != cap(streamBacking) {
			panic("stream detach changed backing ownership")
		}
	}); allocations != 0 {
		t.Fatalf("stream detach allocations = %v", allocations)
	}
}

func TestHelperExecTransactionHashStateDisposedOnFailureAndCompletion(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	for _, complete := range []bool{false, true} {
		t.Run(fmt.Sprintf("complete=%v", complete), func(t *testing.T) {
			transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
			stdinHash := transaction.owner.stdinHash
			transcriptHash := transaction.owner.transcriptHash
			execHash := transaction.owner.execHash
			grantHelperExecCredit(t, transaction, correlation, 0)
			commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, 7, 0, []byte("non-aligned-secret"), false))
			if complete {
				grantHelperExecCredit(t, transaction, correlation, uint64(len("non-aligned-secret")))
				commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, 7, uint64(len("non-aligned-secret")), nil, true))
			} else {
				err := transaction.GrantStdinCredit(changedHelperExecRequest(correlation), HelperExecCreditBody{Revision: 7, StreamKind: HelperExecStreamStdin, NextOffset: uint64(len("non-aligned-secret"))})
				if !errors.Is(err, ErrHelperExecTransactionCorrelation) {
					t.Fatalf("terminal failure = %v", err)
				}
			}
			if transaction.owner.stdinHash != nil || transaction.owner.transcriptHash != nil || transaction.owner.execHash != nil {
				t.Fatal("terminal state retained streaming hash ownership")
			}
			assertHelperExecSHA256Wiped(t, stdinHash)
			assertHelperExecSHA256Wiped(t, transcriptHash)
			assertHelperExecSHA256Wiped(t, execHash)
		})
	}
}

func TestHelperExecTransactionSHA256VectorsAndCompleteWipe(t *testing.T) {
	for _, size := range []int{0, 1, 55, 56, 63, 64, 65, 4097} {
		for _, chunkSize := range []int{17, size + 1} {
			t.Run(fmt.Sprintf("bytes=%d/chunk=%d", size, chunkSize), func(t *testing.T) {
				payload := make([]byte, size)
				for index := range payload {
					payload[index] = byte(index*31 + 7)
				}
				owner := newHelperExecSHA256()
				for offset := 0; offset < len(payload); {
					end := offset + chunkSize
					if end > len(payload) {
						end = len(payload)
					}
					owner.Write(payload[offset:end])
					offset = end
				}
				if got, want := owner.Sum256(), sha256.Sum256(payload); got != want {
					t.Fatalf("digest = %x, want %x", got, want)
				}
				owner.Wipe()
				assertHelperExecSHA256Wiped(t, owner)
			})
		}
	}
}

func TestHelperExecTransactionCompletionMatrixAndResponseClone(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	newComplete := func(t *testing.T) (*HelperExecTransaction, HelperResponseBody) {
		t.Helper()
		transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
		grantHelperExecCredit(t, transaction, correlation, 0)
		commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, 7, 0, nil, true))
		snapshot := transaction.Snapshot()
		return transaction, acceptedHelperExecResponse(7, 0, sha256.Sum256(nil), snapshot.ExecTransactionSHA256)
	}
	tests := []struct {
		name   string
		mutate func(*HelperResponseBody)
	}{
		{"type", func(value *HelperResponseBody) { value.RequestType = PacketTypeRenew }},
		{"disposition", func(value *HelperResponseBody) { value.Disposition = ResponseDispositionCleanupRetry }},
		{"revision", func(value *HelperResponseBody) { value.Revision++ }},
		{"stdin bytes", func(value *HelperResponseBody) { value.Exec.StdinBytes++ }},
		{"stdin digest", func(value *HelperResponseBody) { value.Exec.StdinSHA256[0]++ }},
		{"exec digest", func(value *HelperResponseBody) { value.Exec.ExecTransactionSHA256[0]++ }},
		{"safe codec", func(value *HelperResponseBody) { value.Exec.ExitCode = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction, response := newComplete(t)
			test.mutate(&response)
			if _, err := transaction.Complete(response); !errors.Is(err, ErrHelperExecTransactionResult) || !transaction.Terminal() {
				t.Fatalf("completion = %v, terminal=%v", err, transaction.Terminal())
			}
		})
	}

	transaction, response := newComplete(t)
	want := *response.Exec
	result, err := transaction.Complete(response)
	if err != nil {
		t.Fatal(err)
	}
	response.Exec.StdinBytes = 99
	fromResult := result.Response()
	fromResult.Exec.StdinBytes = 88
	replay, err := NewHelperExecComparisonTransaction(correlation, testHelperExecTransactionBody(t, nil), result)
	if err != nil {
		t.Fatal(err)
	}
	grantHelperExecCredit(t, replay, correlation, 0)
	commitHelperExecComparisonPayload(t, replay, correlation, mustHelperExecStdinBody(t, 7, 0, nil, true))
	got, err := replay.ReplayResult()
	if err != nil {
		t.Fatal(err)
	}
	if got.Exec == nil || *got.Exec != want {
		t.Fatal("cached safe response was mutated through an external pointer alias")
	}

	rejectedTransaction, _ := newComplete(t)
	rejected := HelperResponseBody{RequestType: PacketTypeExec, Disposition: ResponseDispositionRejected, Revision: 7, FailureCode: FailureCodeExecFailed}
	if _, err := rejectedTransaction.Complete(rejected); err != nil {
		t.Fatalf("validated safe rejected result = %v", err)
	}

	proofs := []HelperBindingProof{{BindingID: "binding-1", Mode: DeliveryModeHTTPProxy, ProofID: "proof-1"}}
	generic := HelperResponseBody{Prepare: &HelperPrepareResponseResult{BindingProofs: proofs}}
	cloned := cloneHelperExecResponse(generic)
	proofs[0].ProofID = "mutated"
	generic.Prepare.BindingProofs[0].BindingID = "mutated"
	if cloned.Prepare.BindingProofs[0].BindingID != "binding-1" || cloned.Prepare.BindingProofs[0].ProofID != "proof-1" {
		t.Fatal("safe response clone retained a slice alias")
	}
}

func TestHelperExecTransactionRequestIDExcludedFromDigest(t *testing.T) {
	firstCorrelation := testHelperExecTransactionCorrelation(t)
	secondCorrelation := changedHelperExecRequest(firstCorrelation)
	first := completeEmptyHelperExecTransaction(t, firstCorrelation)
	second := completeEmptyHelperExecTransaction(t, secondCorrelation)
	if first.ExecTransactionSHA256() != second.ExecTransactionSHA256() {
		t.Fatal("request ID changed the logical exec transaction digest")
	}
	if _, err := NewHelperExecComparisonTransaction(secondCorrelation, testHelperExecTransactionBody(t, nil), first); !errors.Is(err, ErrHelperExecTransactionCorrelation) {
		t.Fatalf("cross-request comparison = %v", err)
	}
}

func TestHelperExecTransactionConcurrentCommitCopyCloseSingleWinner(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	for iteration := 0; iteration < 100; iteration++ {
		transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
		grantHelperExecCredit(t, transaction, correlation, 0)
		proposal, err := transaction.ProposeStdin(correlation, mustHelperExecStdinBody(t, 7, 0, []byte("secret"), false))
		if err != nil {
			t.Fatal(err)
		}
		owned := proposal.owner.slot[:cap(proposal.owner.slot)]
		destination := make([]byte, len("secret"))
		copyResult := make(chan error, 1)
		commitResult := make(chan error, 1)
		var wait sync.WaitGroup
		wait.Add(3)
		go func() { defer wait.Done(); _, err := proposal.CopyPayload(destination); copyResult <- err }()
		go func() { defer wait.Done(); commitResult <- proposal.Commit() }()
		go func() { defer wait.Done(); transaction.Close() }()
		wait.Wait()
		copyErr, commitErr := <-copyResult, <-commitResult
		if commitErr == nil && copyErr != nil {
			t.Fatalf("iteration %d: commit succeeded without the required copy: copy=%v commit=%v", iteration, copyErr, commitErr)
		}
		if !transaction.Terminal() || transaction.Snapshot().ReadyForLaunch {
			t.Fatalf("iteration %d: copy=%v commit=%v snapshot=%#v", iteration, copyErr, commitErr, transaction.Snapshot())
		}
		if err := proposal.Commit(); err == nil {
			t.Fatalf("iteration %d: proposal finalized twice", iteration)
		}
		if copyErr == nil && !bytes.Equal(destination, []byte("secret")) {
			t.Fatalf("iteration %d: successful copy was not exact", iteration)
		}
		if copyErr != nil {
			assertHelperExecZeroCapacity(t, destination)
		}
		assertHelperExecZeroCapacity(t, owned)
	}
}

func TestHelperExecTransactionOpaqueFormattingAndSeededUnmarshal(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
	snapshot := transaction.Snapshot()
	proposal := HelperExecPayloadProposal{owner: &helperExecPayloadProposalOwner{length: 9}}
	result := HelperExecTransactionResult{state: helperExecTransactionResultState{correlation: correlation, valid: true}}
	values := []struct {
		name    string
		value   any
		pointer any
		state   func() any
	}{
		{"HelperExecTransactionCorrelation", correlation, &correlation, func() any {
			return [3]any{correlation.RequestID(), correlation.IdentityDigest(), correlation.Revision()}
		}},
		{"HelperExecTransaction", *transaction, transaction, func() any {
			return struct {
				owner    *helperExecTransactionOwner
				snapshot HelperExecTransactionSnapshot
			}{transaction.owner, transaction.Snapshot()}
		}},
		{"HelperExecPayloadProposal", proposal, &proposal, func() any {
			return struct {
				owner  *helperExecPayloadProposalOwner
				length uint32
			}{proposal.owner, proposal.owner.length}
		}},
		{"HelperExecTransactionSnapshot", snapshot, &snapshot, func() any { return snapshot }},
		{"HelperExecTransactionResult", result, &result, func() any {
			return struct {
				correlation HelperExecTransactionCorrelation
				valid       bool
			}{result.state.correlation, result.state.valid}
		}},
	}
	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%x"}
	for _, item := range values {
		want := "<credentialprotocol." + item.name + ">"
		for _, value := range []any{item.value, item.pointer} {
			for _, format := range formats {
				if got := fmt.Sprintf(format, value); got != want {
					t.Fatalf("format %s %T = %q", format, value, got)
				}
			}
			if _, err := json.Marshal(value); !errors.Is(err, ErrHelperExecTransactionSerialization) {
				t.Fatalf("JSON marshal %T = %v", value, err)
			}
			if _, err := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, ErrHelperExecTransactionSerialization) {
				t.Fatalf("text marshal %T = %v", value, err)
			}
			if _, err := value.(encoding.BinaryMarshaler).MarshalBinary(); !errors.Is(err, ErrHelperExecTransactionSerialization) {
				t.Fatalf("binary marshal %T = %v", value, err)
			}
		}
		before := item.state()
		if err := json.Unmarshal([]byte(`{"seed":"mutation"}`), item.pointer); !errors.Is(err, ErrHelperExecTransactionSerialization) {
			t.Fatalf("JSON unmarshal %T = %v", item.pointer, err)
		}
		if err := item.pointer.(encoding.TextUnmarshaler).UnmarshalText([]byte("mutation")); !errors.Is(err, ErrHelperExecTransactionSerialization) {
			t.Fatalf("text unmarshal %T = %v", item.pointer, err)
		}
		if err := item.pointer.(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte{1, 2, 3}); !errors.Is(err, ErrHelperExecTransactionSerialization) {
			t.Fatalf("binary unmarshal %T = %v", item.pointer, err)
		}
		after := item.state()
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("seeded unmarshal mutated %s", item.name)
		}
	}
}

type helperExecVectorRecord struct {
	flags   HelperExecStreamFlags
	offset  uint64
	payload []byte
}

func independentHelperExecTranscript(records []helperExecVectorRecord) [32]byte {
	h := sha256.New()
	writeOpaque16(h, "hal/l8/guest-helper/stdin-transcript/v1")
	var scalar [8]byte
	for _, record := range records {
		_, _ = h.Write([]byte{byte(record.flags)})
		binary.BigEndian.PutUint64(scalar[:], record.offset)
		_, _ = h.Write(scalar[:])
		binary.BigEndian.PutUint32(scalar[:4], uint32(len(record.payload)))
		_, _ = h.Write(scalar[:4])
		digest := sha256.Sum256(record.payload)
		_, _ = h.Write(digest[:])
		_, _ = h.Write(record.payload)
	}
	binary.BigEndian.PutUint32(scalar[:4], uint32(len(records)))
	_, _ = h.Write(scalar[:4])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func independentHelperExecTransactionDigest(t *testing.T, correlation HelperExecTransactionCorrelation, body HelperExecBody, stdin, transcript [32]byte, stdinBytes uint64) [32]byte {
	t.Helper()
	encoded, err := EncodeHelperExecBody(body)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	writeOpaque16(h, "hal/l8/guest-helper/exec-transaction/v1")
	identity := correlation.IdentityDigest()
	_, _ = h.Write(identity[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], correlation.Revision())
	_, _ = h.Write(scalar[:])
	binary.BigEndian.PutUint32(scalar[:4], uint32(len(encoded)))
	_, _ = h.Write(scalar[:4])
	_, _ = h.Write(encoded)
	binary.BigEndian.PutUint32(scalar[:4], body.PrivateBindingLength)
	_, _ = h.Write(scalar[:4])
	_, _ = h.Write(body.PrivateBindingSHA256[:])
	binary.BigEndian.PutUint64(scalar[:], stdinBytes)
	_, _ = h.Write(scalar[:])
	_, _ = h.Write(stdin[:])
	_, _ = h.Write(transcript[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func writeOpaque16(h hash.Hash, value string) {
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}

func testHelperExecTransactionCorrelation(t *testing.T) HelperExecTransactionCorrelation {
	t.Helper()
	var requestID [16]byte
	var identity [32]byte
	for index := range requestID {
		requestID[index] = byte(index + 1)
	}
	for index := range identity {
		identity[index] = byte(index + 33)
	}
	correlation, err := NewHelperExecTransactionCorrelation(requestID, identity, 7)
	if err != nil {
		t.Fatal(err)
	}
	return correlation
}

func testHelperExecTransactionBody(t *testing.T, private []byte) HelperExecBody {
	t.Helper()
	body := HelperExecBody{
		Revision:      7,
		ExecBindingID: "exec-binding-1",
		Plan: HelperExecPlan{
			Arguments: []string{"/bin/echo", "ok"}, WorkDirectory: "/workspace",
			StdinMode: HelperExecStreamModePipe, StdoutMode: HelperExecStreamModePipe, StderrMode: HelperExecStreamModePipe,
			StdinMaxBytes: 1024, StdoutMaxBytes: 1024, StderrMaxBytes: 1024,
			Timing: HelperExecTiming{Kind: HelperExecTimingTimeoutMillis, Value: 1000},
		},
	}
	if len(private) != 0 {
		body.PrivateBindingLength = uint32(len(private))
		body.PrivateBindingSHA256 = sha256.Sum256(private)
	}
	if _, err := EncodeHelperExecBody(body); err != nil {
		t.Fatal(err)
	}
	return body
}

func mustHelperExecTransaction(t *testing.T, correlation HelperExecTransactionCorrelation, body HelperExecBody) *HelperExecTransaction {
	t.Helper()
	transaction, err := NewHelperExecTransaction(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	return transaction
}

func mustHelperExecStdinBody(t *testing.T, revision uint64, offset uint64, payload []byte, eof bool) *HelperExecStreamBody {
	t.Helper()
	flags := HelperExecStreamFlagsNone
	if eof {
		flags = HelperExecStreamFlagEOF
	}
	body, err := NewHelperExecStreamBody(revision, HelperExecStreamStdin, flags, offset, sha256.Sum256(payload), payload)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func commitHelperExecPrivate(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation, private []byte) {
	t.Helper()
	body, err := NewHelperExecPrivateBody(correlation.Revision(), sha256.Sum256(private), private)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := transaction.ProposePrivate(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.Snapshot().ComparisonOnly {
		if err := proposal.Commit(); err != nil {
			t.Fatal(err)
		}
		return
	}
	destination := make([]byte, len(private))
	if _, err := proposal.CopyPayload(destination); err != nil {
		t.Fatal(err)
	}
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
}

func commitHelperExecPayload(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation, body *HelperExecStreamBody) {
	t.Helper()
	proposal, err := transaction.ProposeStdin(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	destination := make([]byte, proposal.PayloadLength())
	if _, err := proposal.CopyPayload(destination); err != nil {
		t.Fatal(err)
	}
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
}

func commitHelperExecComparisonPayload(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation, body *HelperExecStreamBody) {
	t.Helper()
	transferred := body.state.payload
	proposal, err := transaction.ProposeStdin(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.owner.slot != nil {
		t.Fatal("comparison stdin proposal retained payload bytes")
	}
	if body.state == nil || !body.state.wiped {
		t.Fatal("comparison stdin body aliases remain live")
	}
	assertHelperExecZeroCapacity(t, transferred)
	if err := proposal.Commit(); err != nil {
		t.Fatal(err)
	}
}

func acceptedHelperExecResponse(revision uint64, stdinBytes uint64, stdinDigest, transactionDigest [32]byte) HelperResponseBody {
	empty := sha256.Sum256(nil)
	return HelperResponseBody{RequestType: PacketTypeExec, Disposition: ResponseDispositionAccepted, Revision: revision, FailureCode: FailureCodeNone, Exec: &HelperExecResponseResult{
		ExitCode: 0, StdinBytes: stdinBytes, StdinSHA256: stdinDigest,
		StdoutSHA256: empty, StderrSHA256: empty, ExecTransactionSHA256: transactionDigest,
	}}
}

func changedHelperExecRequest(value HelperExecTransactionCorrelation) HelperExecTransactionCorrelation {
	value.requestID[0]++
	return value
}
func changedHelperExecIdentity(value HelperExecTransactionCorrelation) HelperExecTransactionCorrelation {
	value.identityDigest[0]++
	return value
}

func grantHelperExecCredit(t *testing.T, transaction *HelperExecTransaction, correlation HelperExecTransactionCorrelation, offset uint64) {
	t.Helper()
	if err := transaction.GrantStdinCredit(correlation, HelperExecCreditBody{Revision: correlation.Revision(), StreamKind: HelperExecStreamStdin, NextOffset: offset}); err != nil {
		t.Fatal(err)
	}
}

func completeEmptyHelperExecTransaction(t *testing.T, correlation HelperExecTransactionCorrelation) HelperExecTransactionResult {
	t.Helper()
	transaction := mustHelperExecTransaction(t, correlation, testHelperExecTransactionBody(t, nil))
	grantHelperExecCredit(t, transaction, correlation, 0)
	commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, correlation.Revision(), 0, nil, true))
	snapshot := transaction.Snapshot()
	result, err := transaction.Complete(acceptedHelperExecResponse(correlation.Revision(), 0, sha256.Sum256(nil), snapshot.ExecTransactionSHA256))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertHelperExecZeroCapacity(t *testing.T, value []byte) {
	t.Helper()
	if !bytes.Equal(value[:cap(value)], make([]byte, cap(value))) {
		t.Fatal("buffer retained bytes through capacity")
	}
}

func assertHelperExecSHA256Wiped(t *testing.T, owner *helperExecSHA256) {
	t.Helper()
	if owner == nil || *owner != (helperExecSHA256{}) {
		t.Fatal("streaming SHA-256 owner was not completely wiped")
	}
}

func assertHelperExecOnlyOneSlot(t *testing.T, transaction *HelperExecTransaction) {
	t.Helper()
	if transaction.owner.pending == nil || len(transaction.owner.pending.slot) > MaxHelperExecStreamPayloadBytes || cap(transaction.owner.pending.slot) > MaxHelperExecStreamPayloadBytes {
		t.Fatal("transaction does not own exactly one bounded pending slot")
	}
}

func reflectHelperExecResponseEqual(left, right HelperResponseBody) bool {
	leftEncoded, leftErr := EncodeHelperResponseBody(left)
	rightEncoded, rightErr := EncodeHelperResponseBody(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftEncoded, rightEncoded)
}
