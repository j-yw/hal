package credentialprotocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

func TestHelperExecTransactionSeedMatchesDirectTransaction(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	body := testHelperExecTransactionBody(t, nil)
	seed, err := NewHelperExecTransactionSeed(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	seeded, err := seed.Begin()
	if err != nil {
		t.Fatal(err)
	}
	direct := mustHelperExecTransaction(t, correlation, body)
	for _, transaction := range []*HelperExecTransaction{seeded, direct} {
		grantHelperExecCredit(t, transaction, correlation, 0)
		commitHelperExecPayload(t, transaction, correlation, mustHelperExecStdinBody(t, correlation.Revision(), 0, nil, true))
	}
	if seeded.Snapshot().ExecTransactionSHA256 != direct.Snapshot().ExecTransactionSHA256 {
		t.Fatal("seed changed the canonical exec transaction")
	}
	if _, err := seed.Begin(); !errors.Is(err, ErrHelperExecTransactionBegin) {
		t.Fatalf("second begin error = %v", err)
	}
}

func TestHelperExecTransactionSeedAliasesShareOneUse(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	seed, err := NewHelperExecTransactionSeed(correlation, testHelperExecTransactionBody(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	aliases := make([]HelperExecTransactionSeed, 64)
	for index := range aliases {
		aliases[index] = seed
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for index := range aliases {
		wait.Add(1)
		go func(alias HelperExecTransactionSeed) {
			defer wait.Done()
			transaction, beginErr := alias.Begin()
			if beginErr == nil {
				successes.Add(1)
				transaction.Close()
			}
		}(aliases[index])
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful begins = %d, want 1", successes.Load())
	}
	if seed.owner == nil || !seed.owner.consumed || seed.owner.correlation != (HelperExecTransactionCorrelation{}) || seed.owner.execHash != nil || seed.owner.execBodySHA256 != ([32]byte{}) {
		t.Fatal("consumed seed retained initialized state")
	}
}

func TestHelperExecTransactionSeedComparisonAndClose(t *testing.T) {
	correlation := testHelperExecTransactionCorrelation(t)
	body := testHelperExecTransactionBody(t, nil)
	cached := completeEmptyHelperExecTransaction(t, correlation)
	seed, err := NewHelperExecTransactionSeed(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := seed.BeginComparison(cached)
	if err != nil || !comparison.Snapshot().ComparisonOnly {
		t.Fatalf("comparison = %v, %v", comparison, err)
	}
	retryable, err := NewHelperExecTransactionSeed(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	changed := cached
	changed.state.execBodySHA256[0]++
	if _, err := retryable.BeginComparison(changed); !errors.Is(err, ErrHelperExecTransactionResult) {
		t.Fatalf("changed comparison error = %v", err)
	}
	transaction, err := retryable.Begin()
	if err != nil || transaction == nil {
		t.Fatalf("failed comparison consumed seed: %v", err)
	}
	transaction.Close()
	for _, test := range []struct {
		name   string
		mutate func(*HelperExecTransactionResult)
	}{
		{"missing record", func(result *HelperExecTransactionResult) { result.state.stdinRecordCount = 0 }},
		{"missing transcript", func(result *HelperExecTransactionResult) { result.state.transcriptSHA256 = [32]byte{} }},
		{"invalid response", func(result *HelperExecTransactionResult) { result.state.response = HelperResponseBody{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := cached
			test.mutate(&invalid)
			candidate, err := NewHelperExecTransactionSeed(correlation, body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := candidate.BeginComparison(invalid); !errors.Is(err, ErrHelperExecTransactionResult) {
				t.Fatalf("invalid comparison error = %v", err)
			}
			candidate.Close()
		})
	}

	closed, err := NewHelperExecTransactionSeed(correlation, body)
	if err != nil {
		t.Fatal(err)
	}
	alias := closed
	owner := closed.owner
	alias.Close()
	closed.Close()
	if _, err := closed.Begin(); !errors.Is(err, ErrHelperExecTransactionBegin) {
		t.Fatalf("closed begin error = %v", err)
	}
	if owner == nil || !owner.closed || owner.correlation != (HelperExecTransactionCorrelation{}) || owner.execHash != nil || owner.privateSHA256 != ([32]byte{}) {
		t.Fatal("closed seed retained state")
	}
}

func TestHelperExecTransactionSeedShapeAndOpacity(t *testing.T) {
	typeOf := reflect.TypeOf(HelperExecTransactionSeed{})
	if typeOf.NumField() != 1 || typeOf.Field(0).Name != "owner" || typeOf.Field(0).Type != reflect.TypeOf((*helperExecTransactionSeedOwner)(nil)) {
		t.Fatalf("seed shape = %v", typeOf)
	}
	correlation := testHelperExecTransactionCorrelation(t)
	seed, err := NewHelperExecTransactionSeed(correlation, testHelperExecTransactionBody(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	before := seed.owner
	if got := fmt.Sprintf("%#v", seed); got != "<credentialprotocol.HelperExecTransactionSeed>" {
		t.Fatalf("format = %q", got)
	}
	if encoded, err := json.Marshal(seed); encoded != nil || !errors.Is(err, ErrHelperExecTransactionSerialization) {
		t.Fatalf("marshal = %q, %v", encoded, err)
	}
	if err := json.Unmarshal([]byte(`{"owner":"leak"}`), &seed); !errors.Is(err, ErrHelperExecTransactionSerialization) || seed.owner != before {
		t.Fatalf("unmarshal = %v, owner changed %v", err, seed.owner != before)
	}
}
