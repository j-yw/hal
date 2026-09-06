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
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestHelperPrepareTransactionExactIndependentVector(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	state, err := NewHelperPrepareTransaction(correlation, begin, manifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	stageHelperPrepareFile(t, state, correlation, 1, private[0])
	stageHelperPrepareFile(t, state, correlation, 3, private[1])
	result, err := state.Commit(correlation, HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifestDigest})
	if err != nil {
		t.Fatal(err)
	}
	digest := result.TransactionSHA256()
	if got := hex.EncodeToString(digest[:]); got != "0851182ceebe5fdf7539a92e5d8420516d24f404e43240f2d8512d3db11709d4" {
		t.Fatalf("transaction digest = %s", got)
	}
	want := independentHelperPrepareTransactionDigest(correlation.IdentityDigest(), begin.ExpiryUnixNano, manifestDigest, []helperPrepareVectorFile{
		{index: 1, bytes: private[0]}, {index: 3, bytes: private[1]},
	})
	if digest != want {
		t.Fatalf("transaction digest differs from independent construction: %x != %x", digest, want)
	}
	if result.FileCount() != 2 || result.ManifestSHA256() != manifestDigest || !state.Committed() || state.Terminal() {
		t.Fatal("commit result or terminal state changed")
	}
}

func TestHelperPrepareTransactionProposalOwnershipCommitAndWipe(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	body := mustHelperPrepareFileBody(t, 1, 1, private[0])
	bodyAlias := *body
	proposal, err := state.ProposeFile(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	proposalAlias := *proposal
	if !bodyAlias.state.wiped || bodyAlias.FileLength() != 0 {
		t.Fatal("accepted file-body ownership was not wiped across aliases")
	}
	destination := make([]byte, len(private[0]))
	if count, err := proposal.CopyPrivateBytes(destination); err != nil || count != len(destination) || !bytes.Equal(destination, private[0]) {
		t.Fatalf("proposal copy = %d, %v", count, err)
	}
	proposal.Wipe()
	if !proposalAlias.Wiped() || state.Snapshot().AcceptedFileCount != 0 || state.Snapshot().PendingFile {
		t.Fatal("proposal wipe advanced transaction or failed shared wipe")
	}

	proposal, err = state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0]))
	if err != nil {
		t.Fatal(err)
	}
	owned := make([]byte, len(private[0]), len(private[0])+32)
	copy(owned, private[0])
	for index := len(owned); index < cap(owned); index++ {
		owned[:cap(owned)][index] = 0xa5
	}
	proposal.owner.privateBytes = owned
	staged := make([]byte, len(private[0]))
	if _, err := proposal.CopyPrivateBytes(staged); err != nil || !bytes.Equal(staged, private[0]) {
		t.Fatalf("staging transfer = %v", err)
	}
	if !bytes.Equal(owned[:cap(owned)], make([]byte, cap(owned))) || proposal.owner.privateBytes != nil || !proposal.owner.consumed {
		t.Fatal("successful staging transfer did not immediately wipe full proposal capacity")
	}
	if err := proposal.CommitStaged(); err != nil {
		t.Fatal(err)
	}
	if !proposal.Wiped() || !bytes.Equal(owned[:cap(owned)], make([]byte, cap(owned))) {
		t.Fatal("staging commit did not wipe full proposal capacity")
	}
	snapshot := state.Snapshot()
	if snapshot.AcceptedFileCount != 1 || snapshot.AcceptedFileBytes != uint64(len(private[0])) || snapshot.PendingFile || snapshot.NextBindingIndex != 3 {
		t.Fatalf("staging commit snapshot = %#v", snapshot)
	}
	if err := proposalAlias.CommitStaged(); !errors.Is(err, ErrHelperPrepareFileProposalWiped) {
		t.Fatalf("stale alias commit = %v", err)
	}
}

func TestHelperPrepareTransactionProposalCopyRequiresExactSinkAndWipesFailureCapacity(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	proposal, err := state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0]))
	if err != nil {
		t.Fatal(err)
	}
	for _, length := range []int{len(private[0]) - 1, len(private[0]) + 1} {
		destination := make([]byte, length, len(private[0])+32)
		for index := range destination[:cap(destination)] {
			destination[:cap(destination)][index] = 0xa5
		}
		if count, err := proposal.CopyPrivateBytes(destination); count != 0 || !errors.Is(err, ErrHelperPrepareFileProposalDestination) {
			t.Fatalf("length %d copy = %d, %v", length, count, err)
		}
		if !bytes.Equal(destination[:cap(destination)], make([]byte, cap(destination))) {
			t.Fatalf("length %d denial left stale destination capacity", length)
		}
	}
	exact := make([]byte, len(private[0]), len(private[0])+32)
	for index := range exact[:cap(exact)] {
		exact[:cap(exact)][index] = 0xa5
	}
	if count, err := proposal.CopyPrivateBytes(exact); count != len(exact) || err != nil || !bytes.Equal(exact, private[0]) {
		t.Fatalf("exact copy = %d, %v", count, err)
	}
	if !bytes.Equal(exact[len(exact):cap(exact)], make([]byte, cap(exact)-len(exact))) {
		t.Fatal("successful exact copy left stale destination tail capacity")
	}
	exact[0]++
	second := bytes.Repeat([]byte{0xa5}, len(private[0]))
	if count, err := proposal.CopyPrivateBytes(second); count != 0 || !errors.Is(err, ErrHelperPrepareFileProposalConsumed) {
		t.Fatalf("second copy = %d, %v", count, err)
	}
	if !bytes.Equal(second, make([]byte, len(second))) {
		t.Fatal("second-copy denial did not wipe destination")
	}
	proposal.Wipe()
	failed := make([]byte, len(private[0]), len(private[0])+32)
	for index := range failed[:cap(failed)] {
		failed[:cap(failed)][index] = 0x5a
	}
	if count, err := proposal.CopyPrivateBytes(failed); count != 0 || !errors.Is(err, ErrHelperPrepareFileProposalWiped) {
		t.Fatalf("wiped copy = %d, %v", count, err)
	}
	if !bytes.Equal(failed[:cap(failed)], make([]byte, cap(failed))) {
		t.Fatal("wiped proposal denial left stale destination capacity")
	}
}

func TestHelperPrepareTransactionCommitStagedRequiresSuccessfulTransfer(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	proposal, err := state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0]))
	if err != nil {
		t.Fatal(err)
	}
	owned := proposal.owner.privateBytes
	before := state.Snapshot()
	if err := proposal.CommitStaged(); !errors.Is(err, ErrHelperPrepareTransactionFile) {
		t.Fatalf("commit before copy = %v", err)
	}
	after := state.Snapshot()
	if after.AcceptedFileCount != before.AcceptedFileCount || after.AcceptedFileBytes != before.AcceptedFileBytes || after.Committed != before.Committed {
		t.Fatalf("commit before transfer advanced progress: before=%#v after=%#v", before, after)
	}
	if !after.Terminal || !proposal.Wiped() || !bytes.Equal(owned[:cap(owned)], make([]byte, cap(owned))) {
		t.Fatal("commit before transfer did not terminalize and wipe")
	}
}

func TestHelperPrepareTransactionProposalDenialMatrixIsTerminalAndNonadvancing(t *testing.T) {
	tests := []struct {
		name      string
		index     uint16
		mutate    func(*HelperPrepareFileBody)
		correlate func(*testing.T, HelperPrepareTransactionCorrelation) HelperPrepareTransactionCorrelation
		setup     func(*testing.T, *HelperPrepareTransaction, HelperPrepareTransactionCorrelation, [][]byte)
	}{
		{name: "non-file binding", index: 0},
		{name: "reordered later file", index: 3},
		{name: "revision changed", index: 1, mutate: func(body *HelperPrepareFileBody) { body.state.revision = 2 }},
		{name: "length changed", index: 1, mutate: func(body *HelperPrepareFileBody) { body.state.fileLength++ }},
		{name: "digest metadata changed", index: 1, mutate: func(body *HelperPrepareFileBody) { body.state.fileSHA256[0]++ }},
		{name: "payload changed", index: 1, mutate: func(body *HelperPrepareFileBody) { body.state.privateBytes[0]++ }},
		{name: "cross request", index: 1, correlate: changedHelperPrepareRequest},
		{name: "cross identity", index: 1, correlate: changedHelperPrepareIdentity},
		{name: "duplicate committed file", index: 1, setup: func(t *testing.T, state *HelperPrepareTransaction, correlation HelperPrepareTransactionCorrelation, private [][]byte) {
			stageHelperPrepareFile(t, state, correlation, 1, private[0])
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			correlation := testHelperPrepareTransactionCorrelation(t)
			begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
			state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
			if test.setup != nil {
				test.setup(t, state, correlation, private)
			}
			fileBytes := private[0]
			if test.index == 3 {
				fileBytes = private[1]
			}
			body := mustHelperPrepareFileBody(t, 1, test.index, fileBytes)
			alias := *body
			if test.mutate != nil {
				test.mutate(body)
			}
			gotCorrelation := correlation
			if test.correlate != nil {
				gotCorrelation = test.correlate(t, correlation)
			}
			before := state.Snapshot()
			if _, err := state.ProposeFile(gotCorrelation, body); err == nil {
				t.Fatal("invalid proposal succeeded")
			}
			after := state.Snapshot()
			assertHelperPrepareProgressEqual(t, before, after)
			if !after.Terminal || !alias.state.wiped {
				t.Fatal("denial was not terminal or did not wipe input owner")
			}
			if _, err := state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0])); !errors.Is(err, ErrHelperPrepareTransactionTerminal) {
				t.Fatalf("terminal resurrection = %v", err)
			}
		})
	}
}

func TestHelperPrepareTransactionRejectsInterleavedProposalAndWipesBothOwners(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	first, err := state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0]))
	if err != nil {
		t.Fatal(err)
	}
	secondBody := mustHelperPrepareFileBody(t, 1, 1, private[0])
	secondAlias := *secondBody
	before := state.Snapshot()
	if _, err := state.ProposeFile(correlation, secondBody); !errors.Is(err, ErrHelperPrepareTransactionFile) {
		t.Fatalf("interleaved proposal error = %v", err)
	}
	after := state.Snapshot()
	if after.AcceptedFileCount != before.AcceptedFileCount || after.AcceptedFileBytes != before.AcceptedFileBytes || !after.Terminal || after.PendingFile {
		t.Fatalf("interleaved proposal advanced progress: before=%#v after=%#v", before, after)
	}
	if !first.Wiped() || !secondAlias.state.wiped {
		t.Fatal("interleaved proposal did not wipe both private owners")
	}
}

func TestHelperPrepareTransactionCommitDenialMatrix(t *testing.T) {
	tests := []struct {
		name      string
		stageAll  bool
		mutate    func(*HelperPrepareCommitBody)
		correlate func(*testing.T, HelperPrepareTransactionCorrelation) HelperPrepareTransactionCorrelation
	}{
		{name: "missing files"},
		{name: "revision mismatch", stageAll: true, mutate: func(body *HelperPrepareCommitBody) { body.Revision = 2 }},
		{name: "manifest mismatch", stageAll: true, mutate: func(body *HelperPrepareCommitBody) { body.ManifestSHA256[0]++ }},
		{name: "cross request", stageAll: true, correlate: changedHelperPrepareRequest},
		{name: "cross identity", stageAll: true, correlate: changedHelperPrepareIdentity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			correlation := testHelperPrepareTransactionCorrelation(t)
			begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
			state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
			if test.stageAll {
				stageHelperPrepareFile(t, state, correlation, 1, private[0])
				stageHelperPrepareFile(t, state, correlation, 3, private[1])
			}
			commit := HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifestDigest}
			if test.mutate != nil {
				test.mutate(&commit)
			}
			gotCorrelation := correlation
			if test.correlate != nil {
				gotCorrelation = test.correlate(t, correlation)
			}
			before := state.Snapshot()
			if _, err := state.Commit(gotCorrelation, commit); err == nil {
				t.Fatal("invalid commit succeeded")
			}
			after := state.Snapshot()
			assertHelperPrepareProgressEqual(t, before, after)
			if !after.Terminal || after.Committed {
				t.Fatal("invalid commit did not terminalize without commit")
			}
		})
	}
}

func TestHelperPrepareTransactionBeginCorrelationCopyAndBounds(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	tests := []struct {
		name        string
		correlation HelperPrepareTransactionCorrelation
		begin       HelperPrepareBeginBody
		digest      [32]byte
	}{
		{name: "revision mismatch", correlation: correlation, begin: func() HelperPrepareBeginBody { value := begin; value.Revision = 2; return value }(), digest: manifestDigest},
		{name: "expiry mismatch", correlation: correlation, begin: func() HelperPrepareBeginBody { value := begin; value.ExpiryUnixNano++; return value }(), digest: manifestDigest},
		{name: "manifest digest mismatch", correlation: correlation, begin: begin, digest: func() [32]byte { value := manifestDigest; value[0]++; return value }()},
		{name: "invalid correlation", correlation: HelperPrepareTransactionCorrelation{}, begin: begin, digest: manifestDigest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewHelperPrepareTransaction(test.correlation, test.begin, test.digest); err == nil {
				t.Fatal("invalid begin succeeded")
			}
		})
	}
	if _, err := NewHelperPrepareTransactionCorrelation([16]byte{}, correlation.IdentityDigest(), 1, begin.ExpiryUnixNano); !errors.Is(err, ErrHelperPrepareTransactionCorrelation) {
		t.Fatalf("zero request = %v", err)
	}
	if _, err := NewHelperPrepareTransactionCorrelation(correlation.RequestID(), [32]byte{}, 1, begin.ExpiryUnixNano); !errors.Is(err, ErrHelperPrepareTransactionCorrelation) {
		t.Fatalf("zero identity = %v", err)
	}
	if _, err := NewHelperPrepareTransactionCorrelation(correlation.RequestID(), correlation.IdentityDigest(), 2, begin.ExpiryUnixNano); !errors.Is(err, ErrHelperPrepareTransactionCorrelation) {
		t.Fatalf("later revision = %v", err)
	}
	if _, err := NewHelperPrepareTransactionCorrelation(correlation.RequestID(), correlation.IdentityDigest(), 1, 0); !errors.Is(err, ErrHelperPrepareTransactionCorrelation) {
		t.Fatalf("zero expiry = %v", err)
	}

	state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	begin.Bindings[1].DeclaredFileBytes++
	begin.Bindings[1].FileSHA256[0]++
	stageHelperPrepareFile(t, state, correlation, 1, private[0])
	if state.Terminal() {
		t.Fatal("constructor retained caller manifest alias")
	}

	maximumPayload := bytes.Repeat([]byte{0x42}, MaxHelperFileBytes)
	maximumDigest := sha256.Sum256(maximumPayload)
	maximumBindings := make([]HelperBindingManifestRecord, MaxHelperBindings)
	for index := range maximumBindings {
		maximumBindings[index] = HelperBindingManifestRecord{
			BindingID: fmt.Sprintf("file-%02d", index), Mode: DeliveryModeFileTmpfs,
			TargetPath: fmt.Sprintf("private-%02d", index), DeclaredFileBytes: MaxHelperFileBytes, FileSHA256: maximumDigest,
		}
	}
	maximumBegin := HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: begin.ExpiryUnixNano, Bindings: maximumBindings}
	maximumManifest, err := ComputeHelperManifestSHA256(maximumBindings)
	if err != nil {
		t.Fatal(err)
	}
	maximum := mustHelperPrepareTransaction(t, correlation, maximumBegin, maximumManifest)
	for index := range maximumBindings {
		stageHelperPrepareFile(t, maximum, correlation, uint16(index), maximumPayload)
		if maximum.owner.pending != nil {
			t.Fatal("committed maximum file retained pending private bytes")
		}
	}
	if maximum.Snapshot().AcceptedFileBytes != MaxHelperFileAggregateBytes {
		t.Fatalf("maximum aggregate = %d", maximum.Snapshot().AcceptedFileBytes)
	}

	plusOne := append([]HelperBindingManifestRecord(nil), maximumBindings...)
	plusOne[0].DeclaredFileBytes++
	if _, err := NewHelperPrepareTransaction(correlation, HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: begin.ExpiryUnixNano, Bindings: plusOne}, [32]byte{}); err == nil {
		t.Fatal("per-file plus one begin succeeded")
	}
}

func TestHelperPrepareTransactionNoFileCommitAndCloseWipesPending(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	bindings := []HelperBindingManifestRecord{{BindingID: "ssh", Mode: DeliveryModeSSHAgent}}
	digest, err := ComputeHelperManifestSHA256(bindings)
	if err != nil {
		t.Fatal(err)
	}
	begin := HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: correlation.ExpiryUnixNano(), Bindings: bindings}
	state := mustHelperPrepareTransaction(t, correlation, begin, digest)
	result, err := state.Commit(correlation, HelperPrepareCommitBody{Revision: 1, ManifestSHA256: digest})
	if err != nil || result.FileCount() != 0 {
		t.Fatalf("no-file commit = %#v, %v", result, err)
	}

	begin, digest, private := testHelperPrepareTransactionBegin(t)
	closing := mustHelperPrepareTransaction(t, correlation, begin, digest)
	proposal, err := closing.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0]))
	if err != nil {
		t.Fatal(err)
	}
	alias := *proposal
	closing.Abort()
	closing.Close()
	if !closing.Terminal() || !proposal.Wiped() || !alias.Wiped() || closing.Committed() {
		t.Fatal("close did not terminalize and wipe pending proposal")
	}
}

func TestHelperPrepareTransactionOpaqueSerializationAndSeededUnmarshal(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	proposal, err := state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0]))
	if err != nil {
		t.Fatal(err)
	}
	complete := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	stageHelperPrepareFile(t, complete, correlation, 1, private[0])
	stageHelperPrepareFile(t, complete, correlation, 3, private[1])
	result, err := complete.Commit(correlation, HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifestDigest})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	values := []struct {
		value any
		want  string
	}{
		{correlation, "<credentialprotocol.HelperPrepareTransactionCorrelation>"},
		{&correlation, "<credentialprotocol.HelperPrepareTransactionCorrelation>"},
		{*state, "<credentialprotocol.HelperPrepareTransaction>"},
		{state, "<credentialprotocol.HelperPrepareTransaction>"},
		{*proposal, "<credentialprotocol.HelperPrepareFileProposal>"},
		{proposal, "<credentialprotocol.HelperPrepareFileProposal>"},
		{snapshot, "<credentialprotocol.HelperPrepareTransactionSnapshot>"},
		{&snapshot, "<credentialprotocol.HelperPrepareTransactionSnapshot>"},
		{result, "<credentialprotocol.HelperPrepareTransactionResult>"},
		{&result, "<credentialprotocol.HelperPrepareTransactionResult>"},
	}
	for _, test := range values {
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, test.value); got != test.want || strings.Contains(got, string(private[0])) {
				t.Errorf("format %s = %q", format, got)
			}
		}
		if _, err := json.Marshal(test.value); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
			t.Errorf("JSON marshal = %v", err)
		}
		if _, err := test.value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
			t.Errorf("text marshal = %v", err)
		}
		if _, err := test.value.(encoding.BinaryMarshaler).MarshalBinary(); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
			t.Errorf("binary marshal = %v", err)
		}
	}
	correlationBefore := correlation
	if err := json.Unmarshal([]byte(`{"private":"canary"}`), &correlation); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := correlation.UnmarshalText([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := correlation.UnmarshalBinary([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if correlation != correlationBefore {
		t.Fatal("denied correlation unmarshal mutated value")
	}
	before := state.Snapshot()
	if err := json.Unmarshal([]byte(`{"private":"canary"}`), state); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := state.UnmarshalText([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := state.UnmarshalBinary([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, state.Snapshot()) {
		t.Fatal("denied unmarshal mutated seeded state")
	}
	privateBefore := append([]byte(nil), proposal.owner.privateBytes...)
	if err := json.Unmarshal([]byte(`{"private":"canary"}`), proposal); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := proposal.UnmarshalText([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := proposal.UnmarshalBinary([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	privateAfter := make([]byte, len(private[0]))
	if _, err := proposal.CopyPrivateBytes(privateAfter); err != nil || !bytes.Equal(privateBefore, privateAfter) {
		t.Fatal("denied proposal unmarshal mutated value")
	}
	snapshotBefore := snapshot
	if err := json.Unmarshal([]byte(`{"private":"canary"}`), &snapshot); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := snapshot.UnmarshalText([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := snapshot.UnmarshalBinary([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if snapshot != snapshotBefore {
		t.Fatal("denied snapshot unmarshal mutated value")
	}
	resultBefore := result
	if err := json.Unmarshal([]byte(`{"private":"canary"}`), &result); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := result.UnmarshalText([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if err := result.UnmarshalBinary([]byte("canary")); !errors.Is(err, ErrHelperPrepareTransactionSerialization) {
		t.Fatal(err)
	}
	if result != resultBefore {
		t.Fatal("denied result unmarshal mutated value")
	}
	proposal.Wipe()
}

func TestHelperPrepareTransactionConcurrentSnapshotCloseAndWipe(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	proposal, err := state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0]))
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < 100; iteration++ {
				_ = state.Snapshot()
				_ = proposal.Wiped()
			}
		}()
	}
	group.Add(2)
	go func() { defer group.Done(); proposal.Wipe() }()
	go func() { defer group.Done(); state.Close() }()
	group.Wait()
	if !state.Terminal() || !proposal.Wiped() {
		t.Fatal("concurrent close/wipe did not settle safely")
	}
}

func TestHelperPrepareTransactionConcurrentCopyAllowsOneTransfer(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	proposal, err := state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0]))
	if err != nil {
		t.Fatal(err)
	}
	destinations := [][]byte{
		bytes.Repeat([]byte{0xa5}, len(private[0])),
		bytes.Repeat([]byte{0xa5}, len(private[0])),
	}
	errorsSeen := make([]error, 2)
	counts := make([]int, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := range destinations {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			counts[index], errorsSeen[index] = proposal.CopyPrivateBytes(destinations[index])
		}(index)
	}
	close(start)
	group.Wait()
	successes := 0
	for index := range destinations {
		if errorsSeen[index] == nil {
			successes++
			if counts[index] != len(private[0]) || !bytes.Equal(destinations[index], private[0]) {
				t.Fatalf("successful concurrent copy %d changed", index)
			}
			continue
		}
		if !errors.Is(errorsSeen[index], ErrHelperPrepareFileProposalConsumed) || counts[index] != 0 || !bytes.Equal(destinations[index], make([]byte, len(destinations[index]))) {
			t.Fatalf("denied concurrent copy %d = %d, %v, %x", index, counts[index], errorsSeen[index], destinations[index])
		}
	}
	if successes != 1 || proposal.owner.privateBytes != nil || !proposal.owner.consumed {
		t.Fatalf("concurrent transfer successes=%d", successes)
	}
	proposal.Wipe()
}

func TestHelperPrepareTransactionConcurrentCopyAndClose(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		correlation := testHelperPrepareTransactionCorrelation(t)
		begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
		state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
		proposal, err := state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, 1, private[0]))
		if err != nil {
			t.Fatal(err)
		}
		destination := bytes.Repeat([]byte{0xa5}, len(private[0]))
		var count int
		var copyErr error
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			count, copyErr = proposal.CopyPrivateBytes(destination)
		}()
		go func() {
			defer group.Done()
			<-start
			state.Close()
		}()
		close(start)
		group.Wait()
		if copyErr == nil {
			if count != len(private[0]) || !bytes.Equal(destination, private[0]) {
				t.Fatalf("iteration %d successful copy changed", iteration)
			}
		} else if !errors.Is(copyErr, ErrHelperPrepareFileProposalWiped) || count != 0 || !bytes.Equal(destination, make([]byte, len(destination))) {
			t.Fatalf("iteration %d denied copy = %d, %v, %x", iteration, count, copyErr, destination)
		}
		if !state.Terminal() || !proposal.Wiped() || proposal.owner.privateBytes != nil {
			t.Fatalf("iteration %d did not settle terminal/wiped", iteration)
		}
	}
}

func TestHelperPrepareTransactionAcceptObservedFileObservationRetainsMetadataOnlyAndIsOneUse(t *testing.T) {
	correlation := testHelperPrepareTransactionCorrelation(t)
	begin, manifestDigest, private := testHelperPrepareTransactionBegin(t)
	state := mustHelperPrepareTransaction(t, correlation, begin, manifestDigest)
	first, err := NewHelperPrepareFileObservation(1, 1, uint32(len(private[0])), sha256.Sum256(private[0]), sha256.Sum256(private[0]))
	if err != nil {
		t.Fatal(err)
	}
	alias := first
	if err := state.AcceptObservedFileObservation(correlation, first); err != nil {
		t.Fatal(err)
	}
	if err := state.AcceptObservedFileObservation(correlation, alias); !errors.Is(err, ErrHelperPrepareFileObservationUsed) {
		t.Fatalf("reuse = %v", err)
	}
	second, err := NewHelperPrepareFileObservation(1, 3, uint32(len(private[1])), sha256.Sum256(private[1]), sha256.Sum256(private[1]))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.AcceptObservedFileObservation(correlation, second); err != nil {
		t.Fatal(err)
	}
	result, err := state.Commit(correlation, HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifestDigest})
	if err != nil {
		t.Fatal(err)
	}
	if result.FileCount() != 2 || result.TransactionSHA256() == [32]byte{} {
		t.Fatalf("result = count %d digest %x", result.FileCount(), result.TransactionSHA256())
	}
}

func testHelperPrepareTransactionCorrelation(t *testing.T) HelperPrepareTransactionCorrelation {
	t.Helper()
	var requestID [16]byte
	var identity [32]byte
	for index := range requestID {
		requestID[index] = byte(index + 1)
	}
	for index := range identity {
		identity[index] = byte(index + 33)
	}
	correlation, err := NewHelperPrepareTransactionCorrelation(requestID, identity, 1, 1700000000000000000)
	if err != nil {
		t.Fatal(err)
	}
	return correlation
}

func testHelperPrepareTransactionBegin(t *testing.T) (HelperPrepareBeginBody, [32]byte, [][]byte) {
	t.Helper()
	private := [][]byte{[]byte("alpha-private"), []byte("beta-private")}
	bindings := []HelperBindingManifestRecord{
		{BindingID: "http", Mode: DeliveryModeHTTPProxy},
		{BindingID: "alpha", Mode: DeliveryModeFileTmpfs, TargetPath: "credentials/alpha", DeclaredFileBytes: uint32(len(private[0])), FileSHA256: sha256.Sum256(private[0])},
		{BindingID: "ssh", Mode: DeliveryModeSSHAgent},
		{BindingID: "beta", Mode: DeliveryModeFileTmpfs, TargetPath: "credentials/beta", DeclaredFileBytes: uint32(len(private[1])), FileSHA256: sha256.Sum256(private[1])},
	}
	digest, err := ComputeHelperManifestSHA256(bindings)
	if err != nil {
		t.Fatal(err)
	}
	return HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 1700000000000000000, Bindings: bindings}, digest, private
}

func mustHelperPrepareTransaction(t *testing.T, correlation HelperPrepareTransactionCorrelation, begin HelperPrepareBeginBody, manifestDigest [32]byte) *HelperPrepareTransaction {
	t.Helper()
	state, err := NewHelperPrepareTransaction(correlation, begin, manifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func mustHelperPrepareFileBody(t *testing.T, revision uint64, index uint16, private []byte) *HelperPrepareFileBody {
	t.Helper()
	body, err := NewHelperPrepareFileBody(revision, index, sha256.Sum256(private), private)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func stageHelperPrepareFile(t *testing.T, state *HelperPrepareTransaction, correlation HelperPrepareTransactionCorrelation, index uint16, private []byte) {
	t.Helper()
	proposal, err := state.ProposeFile(correlation, mustHelperPrepareFileBody(t, 1, index, private))
	if err != nil {
		t.Fatalf("propose file %d: %v", index, err)
	}
	destination := make([]byte, len(private))
	if count, err := proposal.CopyPrivateBytes(destination); err != nil || count != len(private) || !bytes.Equal(destination, private) {
		t.Fatalf("copy file %d = %d, %v", index, count, err)
	}
	if err := proposal.CommitStaged(); err != nil {
		t.Fatalf("commit file %d: %v", index, err)
	}
	if state.owner.pending != nil {
		t.Fatalf("file %d retained private proposal", index)
	}
}

func changedHelperPrepareRequest(t *testing.T, correlation HelperPrepareTransactionCorrelation) HelperPrepareTransactionCorrelation {
	t.Helper()
	requestID := correlation.RequestID()
	requestID[0]++
	changed, err := NewHelperPrepareTransactionCorrelation(requestID, correlation.IdentityDigest(), correlation.Revision(), correlation.ExpiryUnixNano())
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func changedHelperPrepareIdentity(t *testing.T, correlation HelperPrepareTransactionCorrelation) HelperPrepareTransactionCorrelation {
	t.Helper()
	identity := correlation.IdentityDigest()
	identity[0]++
	changed, err := NewHelperPrepareTransactionCorrelation(correlation.RequestID(), identity, correlation.Revision(), correlation.ExpiryUnixNano())
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func assertHelperPrepareProgressEqual(t *testing.T, before, after HelperPrepareTransactionSnapshot) {
	t.Helper()
	after.Terminal = before.Terminal
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("progress mutated: before=%#v after=%#v", before, after)
	}
}

type helperPrepareVectorFile struct {
	index uint16
	bytes []byte
}

func independentHelperPrepareTransactionDigest(identity [32]byte, expiry int64, manifest [32]byte, files []helperPrepareVectorFile) [32]byte {
	encoded := make([]byte, 0)
	domain := []byte("hal/l8/guest-helper/prepare-transaction/v1")
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(domain)))
	encoded = append(encoded, u16[:]...)
	encoded = append(encoded, domain...)
	encoded = append(encoded, identity[:]...)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], 1)
	encoded = append(encoded, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], uint64(expiry))
	encoded = append(encoded, u64[:]...)
	encoded = append(encoded, manifest[:]...)
	binary.BigEndian.PutUint16(u16[:], uint16(len(files)))
	encoded = append(encoded, u16[:]...)
	for _, file := range files {
		binary.BigEndian.PutUint16(u16[:], file.index)
		encoded = append(encoded, u16[:]...)
		var u32 [4]byte
		binary.BigEndian.PutUint32(u32[:], uint32(len(file.bytes)))
		encoded = append(encoded, u32[:]...)
		digest := sha256.Sum256(file.bytes)
		encoded = append(encoded, digest[:]...)
	}
	return sha256.Sum256(encoded)
}
