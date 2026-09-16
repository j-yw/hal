//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

// All context observations forward to the actual WithCancel owner. Only after
// its real sole reader publishes a completed, correlated CopyIn response does
// an Err observation invoke real cancellation. TryLock avoids reentry when the
// producer itself checks this context while holding its operation mutex.
type minimalCompletedCopyCancellation struct {
	context.Context
	launch   *minimalControlProducerLaunch
	cancel   context.CancelFunc
	observed atomic.Bool
}

func (ctx *minimalCompletedCopyCancellation) Err() error {
	if ctx.launch.mu.TryLock() {
		op := ctx.launch.active
		complete := op != nil && op.header.operation == guestagent.OperationCopyIn && op.received && len(op.response) > 0
		ctx.launch.mu.Unlock()
		if complete && ctx.observed.CompareAndSwap(false, true) {
			ctx.cancel()
		}
	}
	return ctx.Context.Err()
}

func TestMinimalSupervisorWorkCompletedCopyInAtActualCancellation(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		backend, verifier, _, rescue := f.guest(t, nil)
		defer rescue()
		data := []byte("completed ordinary workspace copy")
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
		var published atomic.Bool
		backend.copyIn = func(_ context.Context, plan server.CopyInPlan) (server.CopyResult, error) {
			if plan.Digest != digest || plan.DestinationPath != "/workspace/completed.txt" || string(plan.Data) != string(data) {
				return server.CopyResult{}, errors.New("unexpected ordinary copy plan")
			}
			published.Store(true)
			return server.CopyResult{Published: true, SizeBytes: int64(len(data)), Digest: digest}, nil
		}
		client, _ := minimalSupervisorWorkClient(t, f)
		original, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx := &minimalCompletedCopyCancellation{Context: original, launch: f.producer, cancel: cancel}
		result, err := client.CopyIn(ctx, guestagent.CopyInRequest{DestinationPath: "/workspace/completed.txt",
			Payload: guestagent.PayloadMetadata{Data: base64.StdEncoding.EncodeToString(data), Encoding: guestagent.PayloadEncodingBase64,
				SizeBytes: int64(len(data)), MaxBytes: 4096, Digest: digest}})
		if !published.Load() || !ctx.observed.Load() || original.Err() != context.Canceled || backend.calls.Load() != 1 || verifier.calls.Load() != 2 {
			t.Fatal("actual published/correlated response and real cancellation prerequisites were not reached")
		}
		if err != nil || result.Written.Digest != digest || result.Written.SizeBytes != int64(len(data)) {
			t.Fatal("Client discarded the original producer's completely received CopyIn publication", err)
		}
		minimalSupervisorWorkJoined(t, f)
		if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err == nil || backend.calls.Load() != 1 {
			t.Fatal("completed response preservation revived the canceled candidate")
		}
	})
}
