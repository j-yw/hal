package linuxrules

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

type fakeNFTExecutor struct {
	mu                      sync.Mutex
	expected                ExpectedRuleSet
	present                 bool
	inspection              []byte
	postApplyMutation       string
	applyErrorAfterMutation bool
	delay                   time.Duration
	batches                 [][]byte
	listCalls               int
	quarantineCalls         int
	deleteCalls             int
	concurrent              int
	maxConcurrent           int
}

func newFakeNFTExecutor(expected ExpectedRuleSet) *fakeNFTExecutor {
	return &fakeNFTExecutor{expected: expected}
}

func (f *fakeNFTExecutor) ApplyBatch(_ context.Context, _ NamespaceHandle, batch []byte) error {
	f.enter()
	defer f.leave()

	f.mu.Lock()
	f.batches = append(f.batches, append([]byte(nil), batch...))
	text := string(batch)
	switch {
	case strings.Contains(text, "hal-quarantine"):
		f.quarantineCalls++
		f.present = true
		f.inspection = quarantineInspectionJSON(f.expected)
	case strings.Contains(text, "delete table") && !strings.Contains(text, "add table"):
		f.deleteCalls++
		f.present = false
		f.inspection = nil
	default:
		f.present = true
		if f.inspection == nil {
			f.inspection = expectedInspectionJSON(f.expected)
		}
		if f.postApplyMutation != "" {
			f.inspection = mutateInspectionJSON(f.inspection, f.postApplyMutation)
		}
	}
	shouldFail := f.applyErrorAfterMutation && !strings.Contains(text, "hal-quarantine")
	f.applyErrorAfterMutation = false
	f.mu.Unlock()
	if shouldFail {
		return errors.New("seeded raw apply failure")
	}
	return nil
}

func (f *fakeNFTExecutor) ListTableJSON(_ context.Context, _ NamespaceHandle, _ TableQuery, _ int64) ([]byte, error) {
	f.enter()
	defer f.leave()

	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if !f.present {
		return nil, ErrTableNotFound
	}
	return append([]byte(nil), f.inspection...), nil
}

func (f *fakeNFTExecutor) installExpected() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.present = true
	f.inspection = expectedInspectionJSON(f.expected)
}

func (f *fakeNFTExecutor) enter() {
	f.mu.Lock()
	f.concurrent++
	if f.concurrent > f.maxConcurrent {
		f.maxConcurrent = f.concurrent
	}
	delay := f.delay
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
}

func (f *fakeNFTExecutor) leave() {
	f.mu.Lock()
	f.concurrent--
	f.mu.Unlock()
}

func mutateInspectionJSON(payload []byte, mutation string) []byte {
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		return payload
	}
	objects := document["nftables"].([]any)
	switch mutation {
	case "extra_rule":
		objects = append(objects, cloneJSONValue(objects[len(objects)-1]))
	case "missing_rule":
		objects = objects[:len(objects)-1]
	case "reordered_rule":
		objects[2], objects[3] = objects[3], objects[2]
	case "wrong_verdict", "jump", "goto", "nat":
		rule := objects[2].(map[string]any)["rule"].(map[string]any)
		expressions := rule["expr"].([]any)
		key := "drop"
		if mutation != "wrong_verdict" {
			key = mutation
		}
		expressions[len(expressions)-1] = map[string]any{key: nil}
	case "wrong_interface":
		rule := objects[3].(map[string]any)["rule"].(map[string]any)
		expressions := rule["expr"].([]any)
		match := expressions[0].(map[string]any)["match"].(map[string]any)
		match["right"] = "other0"
	case "wrong_generation":
		rule := objects[2].(map[string]any)["rule"].(map[string]any)
		rule["comment"] = "hal-owner-safe-generation-other-established"
	}
	document["nftables"] = objects
	mutated, _ := json.Marshal(document)
	return mutated
}

func cloneJSONValue(value any) any {
	payload, _ := json.Marshal(value)
	var clone any
	_ = json.Unmarshal(payload, &clone)
	return clone
}
