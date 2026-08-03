package credentialmemory

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

const l8MemoryTestDeadline = 2 * time.Second

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

func TestL8CredentialMemoryCapacityAndReaderBoundsFailClosed(t *testing.T) {
	if MaxLockedMappingBytes <= 0 || MaxLockedMappingBytes > 64<<20 {
		t.Fatalf("MaxLockedMappingBytes = %d, want finite positive bound no larger than 64 MiB", MaxLockedMappingBytes)
	}
	for _, capacity := range []int{0, -1, MaxLockedMappingBytes + 1} {
		mapping, err := NewLockedMapping(capacity)
		if mapping != nil || !errors.Is(err, ErrCredentialMemoryCapacity) {
			t.Fatalf("capacity %d did not fail closed", capacity)
		}
		if err.Error() != ErrCredentialMemoryCapacity.Error() {
			t.Fatal("capacity failure did not use the stable generic message")
		}
	}

	for _, reported := range []int{-1, 17} {
		t.Run(fmt.Sprintf("reader_n_%d", reported), func(t *testing.T) {
			ops := &l8MemoryOps{}
			mapping, err := newLockedMapping(16, ops)
			if err != nil {
				t.Fatal(err)
			}
			err = mapping.Load(context.Background(), func(dst []byte) (int, error) {
				copy(dst, []byte("bounded-canary"))
				return reported, nil
			})
			if !errors.Is(err, ErrCredentialMemoryLoad) || err.Error() != ErrCredentialMemoryLoad.Error() {
				t.Fatal("invalid reader length did not return stable load failure")
			}
			if !allL8Zero(ops.region) {
				t.Fatal("invalid reader length retained bytes")
			}
			if err := mapping.Destroy(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestL8CredentialMemoryBorrowBeforeLoadAndSecondLoadFailClosed(t *testing.T) {
	ops := &l8MemoryOps{}
	mapping, err := newLockedMapping(32, ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mapping.Destroy() })
	if err := mapping.Borrow(context.Background(), func(BorrowedView) error { return nil }); !errors.Is(err, ErrCredentialMemoryUnavailable) {
		t.Fatal("borrow-before-load did not fail closed")
	}
	first := []byte("first-load")
	if err := mapping.Load(context.Background(), func(dst []byte) (int, error) {
		copy(dst, first)
		return len(first), nil
	}); err != nil {
		t.Fatal(err)
	}
	secondReaderCalled := false
	err = mapping.Load(context.Background(), func(dst []byte) (int, error) {
		secondReaderCalled = true
		copy(dst, []byte("second"))
		return len("second"), nil
	})
	if !errors.Is(err, ErrCredentialMemoryAlreadyLoaded) || secondReaderCalled {
		t.Fatal("second load was not rejected before exposing the existing mapping")
	}
	sink := &l8BoundedSink{limit: 32}
	if err := mapping.Borrow(context.Background(), func(view BorrowedView) error {
		return view.WriteTo(context.Background(), sink)
	}); err != nil {
		t.Fatal(err)
	}
	if sink.count != 1 || sink.size != len(first) || sink.digest != sha256.Sum256(first) {
		t.Fatal("rejected second load changed the first owned value")
	}
}

func TestL8CredentialMemoryConcurrentLoadAndBorrowAreRejected(t *testing.T) {
	ops := &l8MemoryOps{}
	mapping, err := newLockedMapping(32, ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mapping.Destroy() })
	loadStarted := make(chan struct{})
	releaseLoad := make(chan struct{})
	loadDone := make(chan error, 1)
	go func() {
		loadDone <- mapping.Load(context.Background(), func(dst []byte) (int, error) {
			close(loadStarted)
			if err := l8AwaitMemorySignal(releaseLoad, "release concurrent load"); err != nil {
				return 0, err
			}
			copy(dst, []byte("concurrent"))
			return len("concurrent"), nil
		})
	}()
	l8ReceiveMemoryTest(t, loadStarted, "load callback start")
	if err := mapping.Load(context.Background(), func([]byte) (int, error) { return 0, nil }); !errors.Is(err, ErrCredentialMemoryBusy) {
		t.Fatal("concurrent load did not fail closed")
	}
	if err := mapping.Borrow(context.Background(), func(BorrowedView) error { return nil }); !errors.Is(err, ErrCredentialMemoryBusy) {
		t.Fatal("borrow during load did not fail closed")
	}
	close(releaseLoad)
	if err := l8ReceiveMemoryTest(t, loadDone, "concurrent load completion"); err != nil {
		t.Fatal(err)
	}
}

func TestL8CredentialMemoryDestroyWaitsForAcceptedBorrow(t *testing.T) {
	ops := &l8MemoryOps{}
	mapping, err := newLockedMapping(32, ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := mapping.Load(context.Background(), func(dst []byte) (int, error) {
		copy(dst, []byte("borrow-window"))
		return len("borrow-window"), nil
	}); err != nil {
		t.Fatal(err)
	}
	borrowStarted := make(chan struct{})
	releaseBorrow := make(chan struct{})
	borrowDone := make(chan error, 1)
	sink := &l8BoundedSink{limit: 32}
	go func() {
		borrowDone <- mapping.Borrow(context.Background(), func(view BorrowedView) error {
			close(borrowStarted)
			if err := l8AwaitMemorySignal(releaseBorrow, "release accepted borrow"); err != nil {
				return err
			}
			return view.WriteTo(context.Background(), sink)
		})
	}()
	l8ReceiveMemoryTest(t, borrowStarted, "borrow callback start")
	if err := mapping.Borrow(context.Background(), func(BorrowedView) error { return nil }); !errors.Is(err, ErrCredentialMemoryBusy) {
		t.Fatal("second concurrent borrow did not fail closed")
	}
	if err := mapping.Load(context.Background(), func([]byte) (int, error) { return 0, nil }); !errors.Is(err, ErrCredentialMemoryBusy) {
		t.Fatal("load during accepted borrow did not fail closed")
	}
	destroyDone := make(chan error, 1)
	go func() {
		destroyDone <- mapping.Destroy()
	}()
	l8AwaitMemoryState(t, mapping, LockedMappingStateDestroying)
	if err := mapping.Borrow(context.Background(), func(BorrowedView) error { return nil }); !errors.Is(err, ErrCredentialMemoryDestroyed) {
		t.Fatal("destroying mapping accepted a new borrow")
	}
	select {
	case <-destroyDone:
		t.Fatal("destroy completed while an accepted borrow was active")
	default:
	}
	close(releaseBorrow)
	if err := l8ReceiveMemoryTest(t, borrowDone, "accepted borrow completion"); err != nil {
		t.Fatal(err)
	}
	if err := l8ReceiveMemoryTest(t, destroyDone, "destroy after borrow completion"); err != nil {
		t.Fatal(err)
	}
	if sink.count != 1 {
		t.Fatal("accepted borrow did not drain through its approved sink")
	}
	if err := mapping.Borrow(context.Background(), func(BorrowedView) error { return nil }); !errors.Is(err, ErrCredentialMemoryDestroyed) {
		t.Fatal("destroyed mapping accepted a new borrow")
	}
	if !allL8Zero(ops.unlockSnapshot) || !allL8Zero(ops.unmapSnapshot) {
		t.Fatal("destroy after borrow did not wipe before unlock/unmap")
	}
}

func TestL8CredentialMemoryDestroyWaitsForAcceptedLoadWithoutEarlyWipe(t *testing.T) {
	ops := &l8MemoryOps{}
	mapping, err := newLockedMapping(32, ops)
	if err != nil {
		t.Fatal(err)
	}
	loadStarted := make(chan struct{})
	releaseLoad := make(chan struct{})
	loadDone := make(chan error, 1)
	canary := []byte("accepted-load-window")
	go func() {
		loadDone <- mapping.Load(context.Background(), func(dst []byte) (int, error) {
			copy(dst, canary)
			close(loadStarted)
			if err := l8AwaitMemorySignal(releaseLoad, "release accepted load"); err != nil {
				return 0, err
			}
			if !reflect.DeepEqual(dst[:len(canary)], canary) {
				return 0, errors.New("mapping was wiped during accepted load")
			}
			return len(canary), nil
		})
	}()
	l8ReceiveMemoryTest(t, loadStarted, "accepted load callback start")
	destroyDone := make(chan error, 1)
	go func() { destroyDone <- mapping.Destroy() }()
	l8AwaitMemoryState(t, mapping, LockedMappingStateDestroying)
	if err := mapping.Load(context.Background(), func([]byte) (int, error) { return 0, nil }); !errors.Is(err, ErrCredentialMemoryDestroyed) {
		t.Fatal("destroying mapping accepted a new load")
	}
	if err := mapping.Borrow(context.Background(), func(BorrowedView) error { return nil }); !errors.Is(err, ErrCredentialMemoryDestroyed) {
		t.Fatal("destroying mapping accepted a new borrow")
	}
	if got := ops.calls; !reflect.DeepEqual(got, []string{"map", "lock"}) {
		t.Fatalf("destroy touched memory while accepted load was active: %v", got)
	}
	if !reflect.DeepEqual(ops.region[:len(canary)], canary) {
		t.Fatal("destroy wiped active load memory before callback return")
	}
	select {
	case err := <-destroyDone:
		t.Fatalf("destroy completed during accepted load: %v", err)
	default:
	}
	close(releaseLoad)
	if err := l8ReceiveMemoryTest(t, loadDone, "accepted load completion"); err != nil {
		t.Fatal(err)
	}
	if err := l8ReceiveMemoryTest(t, destroyDone, "destroy after load completion"); err != nil {
		t.Fatal(err)
	}
	if !allL8Zero(ops.unlockSnapshot) || !allL8Zero(ops.unmapSnapshot) {
		t.Fatal("destroy after accepted load did not wipe before unlock/unmap")
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

func TestL8CredentialMemoryAnonymousMapFailureFailsClosedWithoutCleanupCalls(t *testing.T) {
	raw := errors.New("memory-map-private /raw/mmap l8-map-cause")
	ops := &l8MemoryOps{mapErr: raw}
	mapping, err := newLockedMapping(32, ops)
	if mapping != nil {
		t.Fatal("map failure returned a mapping")
	}
	if !errors.Is(err, ErrCredentialMemoryUnavailable) || errors.Is(err, raw) || err.Error() != ErrCredentialMemoryUnavailable.Error() {
		t.Fatalf("map failure = %v, want stable non-unwrapping unavailable error", err)
	}
	if got, want := ops.calls, []string{"map"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("map failure calls = %v, want %v", got, want)
	}
	if ops.region != nil || ops.unlockSnapshot != nil || ops.unmapSnapshot != nil {
		t.Fatal("map failure attempted cleanup against a nonexistent mapping")
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
		if bounded.count != 1 || bounded.size != len(canary) || bounded.digest != sha256.Sum256(canary) {
			t.Fatal("bounded checking sink did not observe the exact borrowed value")
		}
		tooSmall := &l8BoundedSink{limit: len(canary) - 1}
		if err := view.WriteTo(context.Background(), tooSmall); !errors.Is(err, ErrCredentialSinkLimitExceeded) {
			t.Fatalf("short sink error = %v, want limit exceeded", err)
		}
		if tooSmall.count != 0 {
			t.Fatal("short sink received partial credential bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := retained.CopyTo(context.Background(), target); !errors.Is(err, ErrBorrowedViewExpired) {
		t.Fatalf("retained borrowed view error = %v, want expired", err)
	}
	assertL8CredentialMemoryLiveValue(t, "borrowed view", retained, string(canary))

	typeOfView := reflect.TypeOf((*BorrowedView)(nil)).Elem()
	for _, forbidden := range []string{"Bytes", "String", "GoString", "Format", "MarshalJSON", "MarshalText"} {
		if _, ok := typeOfView.MethodByName(forbidden); ok {
			t.Fatalf("borrowed view exposes forbidden method %s", forbidden)
		}
	}
}

func TestL8CredentialMemoryLiveStateCannotSerializeOrFormatRawState(t *testing.T) {
	ops := &l8MemoryOps{}
	mapping, err := newLockedMapping(48, ops)
	if err != nil {
		t.Fatal(err)
	}
	canary := "l8-live-memory-canary"
	if err := mapping.Load(context.Background(), func(dst []byte) (int, error) {
		copy(dst, canary)
		return len(canary), nil
	}); err != nil {
		t.Fatal(err)
	}
	assertL8CredentialMemoryLiveValue(t, "locked mapping", mapping, canary)

	typeOfMapping := reflect.TypeOf(mapping).Elem()
	for fieldIndex := 0; fieldIndex < typeOfMapping.NumField(); fieldIndex++ {
		field := typeOfMapping.Field(fieldIndex)
		if field.IsExported() {
			t.Fatalf("LockedMapping exposes live field %s", field.Name)
		}
	}
	if err := mapping.Destroy(); err != nil {
		t.Fatal(err)
	}
}

func assertL8CredentialMemoryLiveValue(t *testing.T, label string, value any, canary string) {
	t.Helper()
	jsonCodec, ok := value.(json.Marshaler)
	if !ok {
		t.Fatalf("%s does not explicitly deny JSON marshaling", label)
	}
	if encoded, err := jsonCodec.MarshalJSON(); encoded != nil || !errors.Is(err, ErrCredentialMemorySerialization) || err.Error() != ErrCredentialMemorySerialization.Error() {
		t.Fatalf("%s JSON codec did not return the stable denial", label)
	}
	if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, ErrCredentialMemorySerialization) {
		t.Fatalf("%s was serializable through encoding/json", label)
	}
	textCodec, ok := value.(encoding.TextMarshaler)
	if !ok {
		t.Fatalf("%s does not explicitly deny text marshaling", label)
	}
	if encoded, err := textCodec.MarshalText(); encoded != nil || !errors.Is(err, ErrCredentialMemorySerialization) || err.Error() != ErrCredentialMemorySerialization.Error() {
		t.Fatalf("%s text codec did not return the stable denial", label)
	}
	l8AssertCredentialMemoryAllVerbFormatting(t, label, value, []string{canary, "[108 56"})
}

func l8AssertCredentialMemoryAllVerbFormatting(t *testing.T, label string, value any, forbidden []string) {
	t.Helper()
	stableNonNil := ""
	for _, variant := range l8CredentialMemoryFormattingVariants(value) {
		if _, ok := variant.value.(fmt.Formatter); !ok {
			t.Fatalf("%s %s lacks fmt.Formatter", label, variant.name)
		}
		expected := l8CredentialMemorySafeSprintf(t, label+" "+variant.name+" %v", "%v", variant.value)
		if expected == "" {
			t.Fatalf("%s %s formatter returned empty fixed output", label, variant.name)
		}
		if !variant.nilPointer {
			if stableNonNil == "" {
				stableNonNil = expected
			} else if expected != stableNonNil {
				t.Fatalf("%s non-nil value/pointer formatter output drifted: %q != %q", label, expected, stableNonNil)
			}
		}
		for _, format := range l8CredentialMemoryFormatterVerbs() {
			rendered := l8CredentialMemorySafeSprintf(t, label+" "+variant.name+" "+format, format, variant.value)
			if rendered != expected {
				t.Fatalf("%s %s formatting %s = %q, want fixed %q", label, variant.name, format, rendered, expected)
			}
			l8CredentialMemoryRejectFormattingPoison(t, label+" "+variant.name+" "+format, rendered, forbidden)
		}
		for _, control := range []string{"%T", "%p"} {
			rendered := l8CredentialMemorySafeSprintf(t, label+" "+variant.name+" "+control, control, variant.value)
			l8CredentialMemoryRejectFormattingPoison(t, label+" "+variant.name+" "+control, rendered, forbidden)
		}
		stringer, ok := variant.value.(fmt.Stringer)
		if !ok || l8CredentialMemorySafeFormatCall(t, label+" "+variant.name+" String", stringer.String) != expected {
			t.Fatalf("%s %s String output is not the fixed formatter output", label, variant.name)
		}
		goStringer, ok := variant.value.(fmt.GoStringer)
		if !ok || l8CredentialMemorySafeFormatCall(t, label+" "+variant.name+" GoString", goStringer.GoString) != expected {
			t.Fatalf("%s %s GoString output is not the fixed formatter output", label, variant.name)
		}
	}
}

type l8CredentialMemoryFormattingVariant struct {
	name       string
	value      any
	nilPointer bool
}

func l8CredentialMemoryFormattingVariants(value any) []l8CredentialMemoryFormattingVariant {
	valueOf := reflect.ValueOf(value)
	variants := []l8CredentialMemoryFormattingVariant{{name: "interface", value: value}}
	if valueOf.Kind() == reflect.Pointer {
		variants = append(variants, l8CredentialMemoryFormattingVariant{name: "nil-pointer", value: reflect.Zero(valueOf.Type()).Interface(), nilPointer: true})
		return variants
	}
	pointer := reflect.New(valueOf.Type())
	pointer.Elem().Set(valueOf)
	variants = append(variants, l8CredentialMemoryFormattingVariant{name: "pointer", value: pointer.Interface()})
	return variants
}

func l8CredentialMemoryFormatterVerbs() []string {
	return []string{
		"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%O", "%b", "%U",
		"%e", "%E", "%f", "%F", "%g", "%G", "%c", "%t", "% 32v", "%-32v", "%032v", "%.3v", "%+32.3v", "%#q",
	}
}

func l8CredentialMemorySafeSprintf(t *testing.T, label, format string, value any) (rendered string) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", label, recovered)
		}
	}()
	return fmt.Sprintf(format, value)
}

func l8CredentialMemorySafeFormatCall(t *testing.T, label string, format func() string) (rendered string) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", label, recovered)
		}
	}()
	return format()
}

func l8CredentialMemoryRejectFormattingPoison(t *testing.T, label, rendered string, forbidden []string) {
	t.Helper()
	for _, poison := range forbidden {
		if poison != "" && strings.Contains(rendered, poison) {
			t.Fatalf("%s exposed formatting poison %q in %q", label, poison, rendered)
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

func l8ReceiveMemoryTest[T any](t *testing.T, channel <-chan T, label string) T {
	t.Helper()
	timer := time.NewTimer(l8MemoryTestDeadline)
	defer timer.Stop()
	select {
	case value := <-channel:
		return value
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", label)
		var zero T
		return zero
	}
}

func l8AwaitMemorySignal(channel <-chan struct{}, label string) error {
	timer := time.NewTimer(l8MemoryTestDeadline)
	defer timer.Stop()
	select {
	case <-channel:
		return nil
	case <-timer.C:
		return fmt.Errorf("timed out waiting for %s", label)
	}
}

func l8AwaitMemoryState(t *testing.T, mapping *LockedMapping, want LockedMappingState) {
	t.Helper()
	timer := time.NewTimer(l8MemoryTestDeadline)
	defer timer.Stop()
	for {
		if got := mapping.State(); got == want {
			return
		}
		select {
		case <-timer.C:
			t.Fatalf("mapping state = %q, want %q before deadline", mapping.State(), want)
		default:
			runtime.Gosched()
		}
	}
}

type l8MemoryOps struct {
	calls          []string
	region         []byte
	mapErr         error
	lockErr        error
	lockDirty      []byte
	unlockErr      error
	unmapErr       error
	unlockSnapshot []byte
	unmapSnapshot  []byte
}

func (ops *l8MemoryOps) MapAnonymous(capacity int) ([]byte, error) {
	ops.calls = append(ops.calls, "map")
	if ops.mapErr != nil {
		return nil, ops.mapErr
	}
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
	limit  int
	count  int
	size   int
	digest [sha256.Size]byte
}

func (sink *l8BoundedSink) MaxCredentialBytes() int { return sink.limit }

func (sink *l8BoundedSink) WriteCredential(value []byte) error {
	// This approved test sink receives one callback-scoped byte window, checks
	// it immediately, and retains only length/digest metadata.
	sink.count++
	sink.size = len(value)
	sink.digest = sha256.Sum256(value)
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
