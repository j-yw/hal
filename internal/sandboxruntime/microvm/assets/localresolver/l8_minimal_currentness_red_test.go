package localresolver

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// The existing fixture constructs Expected from its independent synthetic
// inputs, not by decoding the candidate. No ext4, source-build or VM proof.
func minimalCurrentnessVerifiedFixture(t *testing.T) VerifiedL8MinimalDistribution {
	t.Helper()
	request := minimalDistributionFixture(t)
	verified, err := VerifyL8MinimalDistributionBundle(request)
	if err != nil {
		t.Fatal("actual minimal verifier prerequisite", err)
	}
	t.Cleanup(func() {
		if err := verified.Close(); err != nil {
			t.Error("owned fixture close", err)
		}
	})
	if _, err := SelectL8MinimalDistribution(verified); err != nil {
		t.Fatal("existing selection prerequisite", err)
	}
	// Prove the original retained parent and child pass the shared actual
	// context-aware byte checker without taking a launch lease.
	verified.state.mu.Lock()
	err = verified.state.confirmLaunchCurrent(context.Background())
	transferred := verified.state.transferred
	verified.state.mu.Unlock()
	if err != nil || transferred {
		t.Fatal("actual retained currentness prerequisite", err)
	}
	return verified
}

func TestL8MinimalUntransferredCurrentnessPreservesOwnership(t *testing.T) {
	for _, useAlias := range []bool{false, true} {
		name := "original"
		if useAlias {
			name = "shared_value_copy"
		}
		t.Run(name, func(t *testing.T) {
			verified := minimalCurrentnessVerifiedFixture(t)
			candidate := &verified
			if useAlias {
				alias := verified
				candidate = &alias
			}
			original := minimalLaunchRetainedFiles(verified)
			for range 2 {
				if err := candidate.ConfirmCurrent(context.Background()); err != nil {
					t.Fatal("current original untransferred distribution is unavailable", err)
				}
			}
			// These assertions are intentionally unreached while the new public
			// method is unavailable; they become required after the GREEN swap.
			if candidate.state != verified.state || verified.state.closed || verified.state.transferred {
				t.Fatal("currentness replaced or consumed original ownership")
			}
			for _, file := range original {
				if _, err := file.Stat(); err != nil {
					t.Fatal("currentness closed a retained descriptor", err)
				}
			}
			if _, err := SelectL8MinimalDistribution(verified); err != nil {
				t.Fatal("currentness broke existing selection", err)
			}
			lease, err := verified.TakeLaunchLease(context.Background())
			if err != nil {
				t.Fatal("read-only currentness consumed the one transfer", err)
			}
			defer lease.Close()
			if candidate.ConfirmCurrent(context.Background()) == nil {
				t.Fatal("spent distribution borrowed the transferred lease authority")
			}
			if err := candidate.Close(); err != nil || lease.ConfirmCurrent(context.Background()) != nil {
				t.Fatal("spent alias closed original launch ownership", err)
			}
		})
	}
}

func TestL8MinimalUntransferredCurrentnessCancellationIdentity(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name, expected := "canceled", context.Canceled
		if expired {
			name, expected = "expired", context.DeadlineExceeded
		}
		t.Run(name, func(t *testing.T) {
			verified := minimalCurrentnessVerifiedFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			if expired {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			}
			cancel()
			if !errors.Is(ctx.Err(), expected) {
				t.Fatal("immutable canceled context prerequisite", ctx.Err())
			}
			if err := verified.ConfirmCurrent(ctx); !errors.Is(err, expected) {
				t.Fatalf("currentness error = %v, want original %v", err, expected)
			}
			if verified.state.closed || verified.state.transferred {
				t.Fatal("canceled read changed ownership")
			}
		})
	}
}

// These controls execute independently even while valid new admission is RED.
func TestL8MinimalUntransferredCurrentnessInvalidControls(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		if (VerifiedL8MinimalDistribution{}).ConfirmCurrent(context.Background()) == nil {
			t.Fatal("zero distribution accepted")
		}
	})
	for _, state := range []string{"nil_context", "closed", "transferred"} {
		t.Run(state, func(t *testing.T) {
			verified := minimalCurrentnessVerifiedFixture(t)
			ctx := context.Background()
			switch state {
			case "nil_context":
				ctx = nil
			case "closed":
				if err := verified.Close(); err != nil {
					t.Fatal(err)
				}
			case "transferred":
				lease, err := verified.TakeLaunchLease(ctx)
				if err != nil {
					t.Fatal("actual transfer prerequisite", err)
				}
				defer lease.Close()
				if lease.ConfirmCurrent(ctx) != nil {
					t.Fatal("transferred original lease is not current")
				}
			}
			if verified.ConfirmCurrent(ctx) == nil {
				t.Fatal("invalid distribution admitted")
			}
		})
	}
}

func TestL8MinimalUntransferredCurrentnessExistingLeaseControl(t *testing.T) {
	verified := minimalCurrentnessVerifiedFixture(t)
	lease, err := verified.TakeLaunchLease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := lease.WithAssets(context.Background(), func(kernel, rootfs L8MinimalLaunchAsset) error {
		for _, asset := range []L8MinimalLaunchAsset{kernel, rootfs} {
			payload, err := io.ReadAll(asset.Source)
			if err != nil || int64(len(payload)) != asset.SizeBytes || l5SHA256(payload) != asset.SHA256 {
				t.Fatal("actual retained source control", err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
