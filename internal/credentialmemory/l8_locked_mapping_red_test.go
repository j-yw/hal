package credentialmemory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestL8CredentialMemoryOwnsLocksAndDestroysFullCapacity(t *testing.T) {
	ops := &l8MemoryOps{}
	mapping, err := newLockedMapping(64, ops)
	if err != nil {
		t.Fatalf("new locked mapping: %v", err)
	}
	canary := []byte("l8-memory-canary")
	if err := mapping.Load(context.Background(), func(dst []byte) (int, error) {
		copy(dst, canary)
		return len(canary), nil
	}); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := mapping.Destroy(); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	if got, want := ops.calls, []string{"map", "lock", "unlock", "unmap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("memory calls = %v, want %v", got, want)
	}
	if len(ops.unlockSnapshot) != 64 || !allL8Zero(ops.unlockSnapshot) {
		t.Fatalf("unlock observed nonzero or short overwrite: len=%d", len(ops.unlockSnapshot))
	}
	if len(ops.unmapSnapshot) != 64 || !allL8Zero(ops.unmapSnapshot) {
		t.Fatalf("unmap observed nonzero or short overwrite: len=%d", len(ops.unmapSnapshot))
	}
	if err := mapping.Destroy(); err != nil {
		t.Fatalf("repeated destroy is not idempotent: %v", err)
	}
	if got := len(ops.calls); got != 4 {
		t.Fatalf("repeated destroy made %d calls, want 4", got)
	}
}

func TestL8CredentialMemoryProductionConstructorsDoNotExposeSyscallInjection(t *testing.T) {
	constructor := reflect.TypeOf(NewLockedMapping)
	if got := constructor.NumIn(); got != 1 || constructor.In(0).Kind() != reflect.Int {
		t.Fatalf("NewLockedMapping signature accepts %d inputs; want capacity only", got)
	}
	hardener := reflect.TypeOf(HardenCredentialProcess)
	if got := hardener.NumIn(); got != 0 {
		t.Fatalf("HardenCredentialProcess accepts %d inputs; want no injectable operations", got)
	}
}

func TestL8CredentialMemoryPageLockFailureFailsClosed(t *testing.T) {
	ops := &l8MemoryOps{
		lockErr:   errors.New("memory-backend-private /raw/mem l8-memory-cause"),
		lockDirty: []byte("partially-touched-page"),
	}
	mapping, err := newLockedMapping(32, ops)
	if !errors.Is(err, ErrCredentialMemoryUnlocked) {
		t.Fatal("new locked mapping did not return the stable unlocked classification")
	}
	if mapping != nil {
		t.Fatal("page-lock failure returned a mapping")
	}
	if errors.Is(err, ops.lockErr) || strings.Contains(err.Error(), "memory-backend-private") || err.Error() != ErrCredentialMemoryUnlocked.Error() {
		t.Fatal("page-lock failure exposed a raw backend cause instead of the stable generic error")
	}
	if got, want := ops.calls, []string{"map", "lock", "unmap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("memory calls = %v, want %v", got, want)
	}
	if !allL8Zero(ops.unmapSnapshot) {
		t.Fatal("partial page-lock failure did not overwrite the full mapping before unmap")
	}
}

func TestL8CredentialMemoryBorrowIsSinkOnlyBoundedAndExpires(t *testing.T) {
	sourceOps := &l8MemoryOps{}
	targetOps := &l8MemoryOps{}
	source, err := newLockedMapping(64, sourceOps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Destroy() })
	target, err := newLockedMapping(64, targetOps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Destroy() })
	canary := []byte("l8-borrow-canary")
	if err := source.Load(context.Background(), func(dst []byte) (int, error) {
		copy(dst, canary)
		return len(canary), nil
	}); err != nil {
		t.Fatal(err)
	}

	var retained BorrowedView
	if err := source.Borrow(context.Background(), func(view BorrowedView) error {
		retained = view
		if got := view.Len(); got != len(canary) {
			t.Fatalf("borrow length = %d, want %d", got, len(canary))
		}
		if err := view.CopyTo(context.Background(), target); err != nil {
			t.Fatalf("copy to locked mapping: %v", err)
		}
		bounded := &l8BoundedSink{limit: len(canary)}
		if err := view.WriteTo(context.Background(), bounded); err != nil {
			t.Fatalf("write to bounded sink: %v", err)
		}
		if !reflect.DeepEqual(bounded.got, canary) {
			t.Fatal("bounded sink did not receive the exact borrowed value")
		}
		tooSmall := &l8BoundedSink{limit: len(canary) - 1}
		if err := view.WriteTo(context.Background(), tooSmall); !errors.Is(err, ErrCredentialSinkLimitExceeded) {
			t.Fatalf("short sink error = %v, want limit exceeded", err)
		}
		if len(tooSmall.got) != 0 {
			t.Fatal("short sink received partial credential bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := retained.CopyTo(context.Background(), target); !errors.Is(err, ErrBorrowedViewExpired) {
		t.Fatalf("retained borrowed view error = %v, want expired", err)
	}

	typeOfView := reflect.TypeOf((*BorrowedView)(nil)).Elem()
	for _, forbidden := range []string{"Bytes", "String", "GoString", "MarshalJSON", "MarshalText"} {
		if _, ok := typeOfView.MethodByName(forbidden); ok {
			t.Fatalf("borrowed view exposes forbidden method %s", forbidden)
		}
	}
	for label, rendered := range map[string]string{
		"format": fmt.Sprintf("%v", retained),
		"json":   string(l8MarshalJSON(t, retained)),
	} {
		if strings.Contains(rendered, string(canary)) {
			t.Fatalf("%s rendered raw borrowed credential", label)
		}
	}
}

func TestL8CredentialMemoryLoadFailureAndCancellationOverwriteCapacity(t *testing.T) {
	for _, tt := range []struct {
		name      string
		readerErr error
		wantErr   error
	}{
		{name: "reader failure", readerErr: errors.New("memory-reader-private /raw/source l8-memory-cause"), wantErr: ErrCredentialMemoryLoad},
		{name: "cancellation", readerErr: context.Canceled, wantErr: context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ops := &l8MemoryOps{}
			mapping, err := newLockedMapping(48, ops)
			if err != nil {
				t.Fatal(err)
			}
			canary := []byte("partial-sensitive-copy")
			err = mapping.Load(context.Background(), func(dst []byte) (int, error) {
				copy(dst, canary)
				return len(canary), tt.readerErr
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatal("load error classification mismatch")
			}
			if tt.wantErr == ErrCredentialMemoryLoad {
				if errors.Is(err, tt.readerErr) || strings.Contains(err.Error(), "memory-reader-private") || err.Error() != ErrCredentialMemoryLoad.Error() {
					t.Fatal("mapping load failure exposed a raw reader cause")
				}
			}
			if !allL8Zero(ops.region) {
				t.Fatal("failed load retained bytes in mapping capacity")
			}
			if err := mapping.Destroy(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestL8CredentialMemoryCancellationBeforeLoadDoesNotExposeBuffer(t *testing.T) {
	ops := &l8MemoryOps{}
	mapping, err := newLockedMapping(32, ops)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err = mapping.Load(ctx, func([]byte) (int, error) {
		called = true
		return 0, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("load error = %v, want canceled", err)
	}
	if called {
		t.Fatal("canceled load exposed the mutable mapping to its reader")
	}
	if err := mapping.Destroy(); err != nil {
		t.Fatal(err)
	}
}

func TestL8CredentialMemoryDestroyAttemptsUnmapAfterUnlockFailure(t *testing.T) {
	unlockErr := errors.New("memory-unlock-private /raw/mem l8-memory-cause")
	unmapErr := errors.New("memory-unmap-private /raw/mem l8-memory-cause")
	ops := &l8MemoryOps{unlockErr: unlockErr, unmapErr: unmapErr}
	mapping, err := newLockedMapping(32, ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := mapping.Load(context.Background(), func(dst []byte) (int, error) {
		copy(dst, []byte("destroy-canary"))
		return len("destroy-canary"), nil
	}); err != nil {
		t.Fatal(err)
	}
	err = mapping.Destroy()
	if !errors.Is(err, ErrCredentialMemoryCleanup) {
		t.Fatal("destroy did not return the stable cleanup classification")
	}
	if errors.Is(err, unlockErr) || errors.Is(err, unmapErr) || strings.Contains(err.Error(), "memory-") || err.Error() != ErrCredentialMemoryCleanup.Error() {
		t.Fatal("destroy exposed a raw unlock or unmap cause")
	}
	if got, want := ops.calls, []string{"map", "lock", "unlock", "unmap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("destroy calls = %v, want %v", got, want)
	}
	if !allL8Zero(ops.unlockSnapshot) || !allL8Zero(ops.unmapSnapshot) {
		t.Fatal("destroy failure path did not overwrite full capacity")
	}
}

func TestL8CredentialMemoryProcessStartupDisablesCoreAndDumpability(t *testing.T) {
	ops := &l8ProcessSecurityOps{}
	if err := hardenCredentialProcess(ops); err != nil {
		t.Fatalf("harden process: %v", err)
	}
	if got, want := ops.calls, []string{"core_limit_zero", "set_dumpable_false", "get_dumpable"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("process hardening calls = %v, want %v", got, want)
	}

	for _, failure := range []struct {
		name string
		ops  l8ProcessSecurityOps
	}{
		{name: "core limit", ops: l8ProcessSecurityOps{coreErr: errors.New("process-core-private /raw/core l8-memory-cause")}},
		{name: "set dumpable", ops: l8ProcessSecurityOps{setErr: errors.New("process-dump-private /raw/proc l8-memory-cause")}},
		{name: "inspect dumpable", ops: l8ProcessSecurityOps{getErr: errors.New("process-inspect-private /raw/proc l8-memory-cause")}},
		{name: "still dumpable", ops: l8ProcessSecurityOps{dumpable: true}},
	} {
		t.Run(failure.name, func(t *testing.T) {
			err := hardenCredentialProcess(&failure.ops)
			if !errors.Is(err, ErrCredentialProcessHardening) {
				t.Fatal("hardening failure was accepted")
			}
			for _, raw := range []error{failure.ops.coreErr, failure.ops.setErr, failure.ops.getErr} {
				if raw != nil && errors.Is(err, raw) {
					t.Fatal("process hardening error unwrapped a raw OS cause")
				}
			}
			if strings.Contains(err.Error(), "process-") || strings.Contains(err.Error(), "/raw/") || err.Error() != ErrCredentialProcessHardening.Error() {
				t.Fatal("process hardening error rendered a raw OS cause")
			}
		})
	}
}

type l8MemoryOps struct {
	calls          []string
	region         []byte
	lockErr        error
	lockDirty      []byte
	unlockErr      error
	unmapErr       error
	unlockSnapshot []byte
	unmapSnapshot  []byte
}

func (ops *l8MemoryOps) MapAnonymous(capacity int) ([]byte, error) {
	ops.calls = append(ops.calls, "map")
	ops.region = make([]byte, capacity)
	return ops.region, nil
}

func (ops *l8MemoryOps) Lock(region []byte) error {
	ops.calls = append(ops.calls, "lock")
	copy(region, ops.lockDirty)
	return ops.lockErr
}

func (ops *l8MemoryOps) Unlock(region []byte) error {
	ops.calls = append(ops.calls, "unlock")
	ops.unlockSnapshot = append([]byte(nil), region...)
	return ops.unlockErr
}

func (ops *l8MemoryOps) Unmap(region []byte) error {
	ops.calls = append(ops.calls, "unmap")
	ops.unmapSnapshot = append([]byte(nil), region...)
	return ops.unmapErr
}

type l8BoundedSink struct {
	limit int
	got   []byte
}

func (sink *l8BoundedSink) MaxCredentialBytes() int { return sink.limit }

func (sink *l8BoundedSink) WriteCredential(value []byte) error {
	sink.got = append([]byte(nil), value...)
	return nil
}

type l8ProcessSecurityOps struct {
	calls    []string
	coreErr  error
	setErr   error
	getErr   error
	dumpable bool
}

func (ops *l8ProcessSecurityOps) SetCoreLimitZero() error {
	ops.calls = append(ops.calls, "core_limit_zero")
	return ops.coreErr
}

func (ops *l8ProcessSecurityOps) SetDumpableFalse() error {
	ops.calls = append(ops.calls, "set_dumpable_false")
	return ops.setErr
}

func (ops *l8ProcessSecurityOps) IsDumpable() (bool, error) {
	ops.calls = append(ops.calls, "get_dumpable")
	return ops.dumpable, ops.getErr
}

func allL8Zero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func l8MarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		return []byte(err.Error())
	}
	return encoded
}
