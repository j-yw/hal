package localresolver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMinimalAcquisitionContextAdmission(t *testing.T) {
	for _, mode := range []string{"parent", "minimal"} {
		t.Run(mode, func(t *testing.T) {
			request := minimalDistributionFixture(t)
			verify := func(ctx context.Context) (bool, error) {
				if mode == "parent" {
					got, err := VerifyDistributionBundleContext(ctx, DistributionRequest{RootDir: request.ParentL7.rootDir})
					return got.rootDir != "", err
				}
				got, err := VerifyL8MinimalDistributionBundleContext(ctx, request)
				valid := got.state != nil
				if closeErr := got.Close(); closeErr != nil {
					t.Fatal("owned fixture cleanup", closeErr)
				}
				return valid, err
			}
			t.Run("actual_acquisition_control", func(t *testing.T) {
				if valid, err := verify(context.Background()); !valid || err != nil {
					t.Fatal("real acquisition control", valid, err)
				}
			})
			for _, loss := range []string{"canceled", "expired", "nil"} {
				t.Run(loss, func(t *testing.T) {
					var ctx context.Context
					var want error
					if loss == "canceled" {
						parent, cancel := context.WithCancel(context.Background())
						cancel()
						ctx, want = parent, context.Canceled
					} else if loss == "expired" {
						parent, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
						defer cancel()
						ctx, want = parent, context.DeadlineExceeded
					}
					valid, err := verify(ctx)
					if valid || err == nil || want != nil && !errors.Is(err, want) {
						t.Fatalf("lost lifetime admitted assets: valid=%v error=%v wanted=%v", valid, err, want)
					}
					if strings.Contains(err.Error(), request.RootDir) || strings.Contains(err.Error(), request.ParentL7.rootDir) {
						t.Fatal("context error exposed source path")
					}
				})
			}
		})
	}
}
