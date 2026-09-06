//go:build linux

package minimalprofile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A reader-owned cancellation trigger makes the private publication window
// deterministic without real tools, timing assumptions, or global hooks.
func TestMinimalPublicationCancellationBoundary(t *testing.T) {
	for _, scenario := range []string{"before_copy", "during_copy", "at_eof", "success_then_cancel"} {
		t.Run(scenario, func(t *testing.T) {
			dir := privateDir(t)
			parent, err := openDirectory(dir, true)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			data := bytes.Repeat([]byte("pinned bytes"), 4096)
			source := &cancellingReader{source: bytes.NewReader(data), cancel: cancel, scenario: scenario}
			if scenario == "before_copy" {
				cancel()
			}
			err = publishReader(ctx, parent, "output.ext4", source, hash(data))
			if scenario == "success_then_cancel" {
				if err != nil {
					t.Fatal(err)
				}
				cancel()
				actual, err := os.ReadFile(filepath.Join(dir, "output.ext4"))
				if err != nil || !bytes.Equal(actual, data) {
					t.Fatal("committed output removed or changed after cancellation")
				}
			} else {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation error=%v", err)
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("cancelled output or scratch remains: %v %v", entries, err)
				}
				if scenario == "before_copy" && source.reads != 0 {
					t.Fatal("cancelled publication read input")
				}
			}
		})
	}
}

func TestMinimalFinalHashCopyObservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	data := []byte("final measured bytes")
	var measured bytes.Buffer
	source := &cancellingReader{source: bytes.NewReader(data), cancel: cancel, scenario: "at_eof"}
	n, err := copyContext(ctx, &measured, source)
	if !errors.Is(err, context.Canceled) || n != int64(len(data)) || !bytes.Equal(data, measured.Bytes()) {
		t.Fatalf("final-read cancellation lost: n=%d err=%v", n, err)
	}
}

type cancellingReader struct {
	source   io.Reader
	cancel   context.CancelFunc
	scenario string
	reads    int
}

func (r *cancellingReader) Read(data []byte) (int, error) {
	r.reads++
	n, err := r.source.Read(data)
	if (r.scenario == "during_copy" && n > 0) || (r.scenario == "at_eof" && err == io.EOF) {
		r.cancel()
	}
	return n, err
}
