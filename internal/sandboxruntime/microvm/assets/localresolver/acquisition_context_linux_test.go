package localresolver

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Forward every method to one real parent. Only real cancellation is arranged
// at a bounded observed read frame; no fixture errors, bytes or deadline values
// enter production. Even-numbered observations follow a completed actual Read.
type acquisitionCancelObserver struct {
	context.Context
	cancel           context.CancelFunc
	target           string
	checks, cancelAt int
	reached          bool
}

func (ctx *acquisitionCancelObserver) Err() error {
	var pcs [24]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	reader, target := false, false
	for {
		frame, more := frames.Next()
		reader = reader || strings.HasSuffix(frame.Function, ".acquisitionReader.Read")
		target = target || strings.HasSuffix(frame.Function, ctx.target)
		if !more {
			break
		}
	}
	if reader && target {
		ctx.checks++
		if ctx.cancelAt != 0 && ctx.checks == ctx.cancelAt {
			ctx.reached = true
			ctx.cancel()
		}
	}
	return ctx.Context.Err()
}

func TestMinimalAcquisitionContextCancelsInsideRealStages(t *testing.T) {
	for index, stage := range []struct {
		parent bool
		target string
		after  int
	}{
		{true, ".decodeDistributionJSONContext", 2},
		{true, ".verifyDistributionChecksumsContext", 2},
		{true, ".digestDistributionFileContext", 2},
		{false, ".verifyPinnedL7AssetContext", 2},
		{false, ".(*VerifiedL7AssetLease).confirmSourceLockedContext", 2},
		{false, ".(*VerifiedL7AssetLease).measureL8ParentEvidenceContext", 2},
		{false, ".decodeL8RetainedParentJSONContext", 2},
		{false, ".verifyL8RetainedParentChecksumsContext", 2},
		{false, ".pinMinimalFileContext", 2},
		// Three nonempty one-chunk parent pins precede the seven child pins.
		// Each pin has data and trailing-EOF reads, each checked before/after.
		{false, ".pinMinimalFileContext", 14},
		{false, ".snapshotMinimalMetadataContext", 2},
		{false, ".verifyMinimalChecksumsContext", 2},
		{false, ".(*minimalDistributionState).confirmCurrentContext", 2},
	} {
		t.Run("stage_"+strconv.Itoa(index), func(t *testing.T) {
			request := minimalDistributionFixture(t)
			verify := func(ctx context.Context) error {
				if stage.parent {
					got, err := VerifyDistributionBundleContext(ctx, DistributionRequest{RootDir: request.ParentL7.rootDir})
					if err != nil && got.rootDir != "" {
						t.Fatal("failed parent exposed usable result")
					}
					return err
				}
				got, err := VerifyL8MinimalDistributionBundleContext(ctx, request)
				if err != nil && got.state != nil {
					t.Fatal("failed acquisition retained a usable result")
				}
				if err == nil && got.ConfirmCurrent(context.Background()) != nil {
					t.Fatal("new source failed retained currentness")
				}
				if closeErr := got.Close(); closeErr != nil {
					t.Fatal("exact acquired close", closeErr)
				}
				return err
			}
			control := &acquisitionCancelObserver{Context: context.Background(), target: stage.target}
			if err := verify(control); err != nil || control.checks < stage.after {
				t.Fatal("actual stage/read control not reached", err, control.checks)
			}
			before := acquisitionFDCount(t)
			for range 3 {
				parent, cancel := context.WithCancel(context.Background())
				observed := &acquisitionCancelObserver{Context: parent, cancel: cancel, target: stage.target, cancelAt: stage.after}
				err := verify(observed)
				cancel()
				// CopyN may complete its exact byte count despite n+cancel, then
				// issue one trailing Read that rejects before touching the file.
				if !observed.reached || observed.checks < stage.after || observed.checks > stage.after+1 || !errors.Is(err, context.Canceled) {
					t.Fatal("completed read cancellation was lost", observed.reached, observed.checks, err)
				}
				if strings.Contains(err.Error(), request.RootDir) || strings.Contains(err.Error(), request.ParentL7.rootDir) {
					t.Fatal("error exposed a source path")
				}
			}
			if after := acquisitionFDCount(t); after != before {
				t.Fatalf("partial acquisition leaked handles: %d -> %d", before, after)
			}
			if err := verify(context.Background()); err != nil {
				t.Fatal("canceled caller changed original source authority", err)
			}
		})
	}
}

func acquisitionFDCount(t *testing.T) int {
	t.Helper()
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("read-only descriptor inventory", err)
	}
	return len(files)
}

type acquisitionReturnCancelObserver struct {
	context.Context
	cancel  context.CancelFunc
	reached bool
}

func (ctx *acquisitionReturnCancelObserver) Err() error {
	var pcs [16]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".pinMinimalFileContext.func1") && !ctx.reached {
			ctx.reached = true
			ctx.cancel()
		}
		if !more {
			break
		}
	}
	return ctx.Context.Err()
}

func TestMinimalAcquisitionContextOwnsPinAcrossReturnCancellation(t *testing.T) {
	request := minimalDistributionFixture(t)
	before := acquisitionFDCount(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &acquisitionReturnCancelObserver{Context: parent, cancel: cancel}
	got, err := VerifyL8MinimalDistributionBundleContext(ctx, request)
	defer got.Close()
	if !ctx.reached || !errors.Is(err, context.Canceled) || got.state != nil {
		t.Fatal("actual pin return cancellation not reached", ctx.reached, err)
	}
	if after := acquisitionFDCount(t); after != before {
		t.Fatalf("pin lost ownership between return and caller: %d -> %d", before, after)
	}
}

func TestMinimalAcquisitionContextReaderBoundsActualFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded-reader")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 128<<10)), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithCancel(context.Background())
	reader := acquisitionReader{ctx: ctx, source: file}
	buffer := make([]byte, 128<<10)
	if n, err := reader.Read(buffer); n != 32<<10 || err != nil {
		t.Fatal("unbounded underlying read", n, err)
	}
	if offset, err := file.Seek(0, io.SeekCurrent); offset != 32<<10 || err != nil {
		t.Fatal("actual file offset", offset, err)
	}
	cancel()
	if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled reader advanced", n, err)
	}
	if offset, _ := file.Seek(0, io.SeekCurrent); offset != 32<<10 {
		t.Fatal("canceled reader consumed bytes")
	}
}

func TestMinimalAcquisitionContextParentLockUsesOriginalDeadline(t *testing.T) {
	request := minimalDistributionFixture(t)
	lease, err := request.ParentL7.AcquireL7AssetLease()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	lease.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	task := make(chan string, 1)
	go func() {
		var header [128]byte
		n := runtime.Stack(header[:], false)
		words := strings.Fields(string(header[:n]))
		task <- "goroutine " + words[1] + " "
		_, err := lease.measureL8ParentEvidenceContext(ctx, request.ParentL7.Manifest, request.ParentL7.Provenance, request.ParentL7.Descriptor)
		done <- err
	}()
	// Observe this exact operation waiting on the actual retained parent lock,
	// not merely a task launched before the deadline. No stack is logged.
	id := <-task
	buffer := make([]byte, 1<<20)
	blocked := false
	for !blocked && ctx.Err() == nil {
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			blocked = blocked || strings.HasPrefix(stack, id) && strings.Contains(stack, "measureL8ParentEvidenceContext") && strings.Contains(stack, "sync.(*Mutex).lockSlow")
		}
		if !blocked {
			time.Sleep(time.Millisecond)
		}
	}
	<-ctx.Done()
	lease.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("lock wait rebased original lifetime", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parent measurement did not join after lock release")
	}
	if !blocked {
		t.Fatal("actual parent-lock wait was not reached before original deadline")
	}
	if _, err := lease.measureL8ParentEvidenceContext(context.Background(), request.ParentL7.Manifest, request.ParentL7.Provenance, request.ParentL7.Descriptor); err != nil {
		t.Fatal("cancellation consumed borrowed lease", err)
	}
}

func TestMinimalAcquisitionContextInventoryRemainsExact(t *testing.T) {
	request := minimalDistributionFixture(t)
	for _, root := range []string{request.ParentL7.rootDir, request.RootDir} {
		for _, name := range []string{"unexpected-1", "unexpected-2", "unexpected-3"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte("extra"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := VerifyDistributionBundleContext(context.Background(), DistributionRequest{RootDir: request.ParentL7.rootDir}); err == nil {
		t.Fatal("oversized parent inventory accepted")
	}
	if got, err := VerifyL8MinimalDistributionBundleContext(context.Background(), request); err == nil {
		_ = got.Close()
		t.Fatal("oversized minimal inventory accepted")
	}
}
