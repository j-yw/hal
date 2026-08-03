package sandboxruntime

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestL8JobCredentialLifecycleTransitionTableFailsClosed(t *testing.T) {
	now := time.Date(2026, time.August, 3, 1, 2, 3, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	active := l8ActiveProof(t, identity, 1, now, now.Add(time.Minute))
	cleanup := l8CleanupProof(t, identity, 2, now.Add(time.Second))

	tests := []struct {
		name      string
		steps     []func(*JobCredentialLifecycle) error
		wantState JobCredentialState
		wantErr   error
	}{
		{
			name: "prepare activate renew revoke",
			steps: []func(*JobCredentialLifecycle) error{
				func(l *JobCredentialLifecycle) error { return l.BeginPrepare(identity) },
				func(l *JobCredentialLifecycle) error { return l.Activate(active) },
				func(l *JobCredentialLifecycle) error { return l.BeginRenew() },
				func(l *JobCredentialLifecycle) error {
					return l.Renew(l8ActiveProof(t, identity, 2, now.Add(time.Second), now.Add(2*time.Minute)))
				},
				func(l *JobCredentialLifecycle) error { return l.BeginRevoke() },
				func(l *JobCredentialLifecycle) error { return l8RevokeError(l, cleanup, now.Add(2*time.Second)) },
			},
			wantState: JobCredentialStateRevoked,
		},
		{
			name: "cleanup without begin revoke",
			steps: []func(*JobCredentialLifecycle) error{
				func(l *JobCredentialLifecycle) error { return l.BeginPrepare(identity) },
				func(l *JobCredentialLifecycle) error { return l.Activate(active) },
				func(l *JobCredentialLifecycle) error { return l8RevokeError(l, cleanup, now.Add(2*time.Second)) },
			},
			wantState: JobCredentialStateActive,
			wantErr:   ErrJobCredentialTransition,
		},
		{
			name: "renew cannot resurrect expired",
			steps: []func(*JobCredentialLifecycle) error{
				func(l *JobCredentialLifecycle) error { return l.BeginPrepare(identity) },
				func(l *JobCredentialLifecycle) error { return l.Activate(active) },
				func(l *JobCredentialLifecycle) error { return l.Expire(now.Add(2 * time.Minute)) },
				func(l *JobCredentialLifecycle) error { return l.BeginRenew() },
			},
			wantState: JobCredentialStateExpired,
			wantErr:   ErrJobCredentialExpired,
		},
		{
			name: "loss removes active state immediately",
			steps: []func(*JobCredentialLifecycle) error{
				func(l *JobCredentialLifecycle) error { return l.BeginPrepare(identity) },
				func(l *JobCredentialLifecycle) error { return l.Activate(active) },
				func(l *JobCredentialLifecycle) error {
					return l.ObserveLoss(JobCredentialLoss{
						Identity: identity,
						Revision: 1,
						Code:     JobCredentialFailureGuestHelperUnavailable,
					})
				},
			},
			wantState: JobCredentialStateRevoking,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifecycle, err := NewJobCredentialLifecycle(identity)
			if err != nil {
				t.Fatalf("new lifecycle: %v", err)
			}
			for _, step := range tt.steps {
				err = step(lifecycle)
				if err != nil {
					break
				}
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if got := lifecycle.State(); got != tt.wantState {
				t.Fatalf("state = %q, want %q", got, tt.wantState)
			}
		})
	}
}

func TestL8JobCredentialLossRejectsNeighborAndStaleWatchers(t *testing.T) {
	now := time.Date(2026, time.August, 3, 2, 30, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	for _, tt := range []struct {
		name      string
		loss      JobCredentialLoss
		wantErr   error
		wantState JobCredentialState
	}{
		{
			name:      "same job current revision",
			loss:      JobCredentialLoss{Identity: identity, Revision: 3, Code: JobCredentialFailureGuestHelperUnavailable},
			wantState: JobCredentialStateRevoking,
		},
		{
			name: "neighbor job",
			loss: func() JobCredentialLoss {
				neighbor := identity
				neighbor.WorkerJobID = "job-neighbor"
				return JobCredentialLoss{Identity: neighbor, Revision: 3, Code: JobCredentialFailureGuestHelperUnavailable}
			}(),
			wantErr:   ErrJobCredentialIdentityMismatch,
			wantState: JobCredentialStateRevoking,
		},
		{
			name:      "stale watcher revision",
			loss:      JobCredentialLoss{Identity: identity, Revision: 2, Code: JobCredentialFailureGuestHelperUnavailable},
			wantErr:   ErrJobCredentialRevisionStale,
			wantState: JobCredentialStateRevoking,
		},
		{
			name: "stale runtime generation",
			loss: func() JobCredentialLoss {
				stale := identity
				stale.RuntimeGeneration = "runtime-generation-stale"
				return JobCredentialLoss{Identity: stale, Revision: 3, Code: JobCredentialFailureGuestHelperUnavailable}
			}(),
			wantErr:   ErrJobCredentialIdentityMismatch,
			wantState: JobCredentialStateRevoking,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lifecycle, err := NewJobCredentialLifecycle(identity)
			if err != nil {
				t.Fatal(err)
			}
			if err := lifecycle.BeginPrepare(identity); err != nil {
				t.Fatal(err)
			}
			active := l8ActiveProof(t, identity, 3, now, now.Add(time.Minute))
			if err := lifecycle.Activate(active); err != nil {
				t.Fatal(err)
			}
			err = lifecycle.ObserveLoss(tt.loss)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("loss error = %v, want %v", err, tt.wantErr)
			}
			if got := lifecycle.State(); got != tt.wantState {
				t.Fatalf("state = %q, want %q", got, tt.wantState)
			}
			if lifecycle.HasActiveProof() {
				t.Fatal("loss did not discard the active proof")
			}
			if got := lifecycle.Revision(); got != 3 {
				t.Fatalf("revision = %d, want exact prior revision 3", got)
			}
		})
	}
}

func TestL8JobCredentialIdentityAndProofOwnSliceInputs(t *testing.T) {
	now := time.Date(2026, time.August, 3, 2, 45, 0, 0, time.UTC)
	expected := l8JobCredentialIdentity(now)
	supplied := expected
	supplied.BindingIDs = append([]string(nil), expected.BindingIDs...)
	supplied.DeliveryModes = append([]JobCredentialDeliveryMode(nil), expected.DeliveryModes...)
	lifecycle, err := NewJobCredentialLifecycle(supplied)
	if err != nil {
		t.Fatal(err)
	}
	proof := l8ActiveProof(t, supplied, 1, now, now.Add(time.Minute))
	supplied.BindingIDs[0] = "binding-mutated"
	supplied.DeliveryModes[0] = JobCredentialDeliveryModeFileTmpfs
	if err := ValidateJobCredentialActiveProof(proof, expected, 1, now); err != nil {
		t.Fatal("active proof retained caller-owned identity slices")
	}
	if err := lifecycle.BeginPrepare(expected); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(l8ActiveProof(t, expected, 1, now, now.Add(time.Minute))); err != nil {
		t.Fatal("lifecycle retained caller-owned identity slices")
	}
}

func TestL8JobCredentialProofsAreDisjointCorrelatedAndCurrent(t *testing.T) {
	now := time.Date(2026, time.August, 3, 2, 0, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	active := l8ActiveProof(t, identity, 7, now, now.Add(time.Minute))
	cleanup := l8CleanupProof(t, identity, 8, now.Add(time.Second))

	if err := ValidateJobCredentialActiveProof(active, identity, 7, now.Add(30*time.Second)); err != nil {
		t.Fatalf("valid active proof: %v", err)
	}
	if err := ValidateJobCredentialCleanupProof(cleanup, identity, 8, now.Add(time.Second)); err != nil {
		t.Fatalf("valid cleanup proof: %v", err)
	}
	if ActiveProofKind(active) == CleanupProofKind(cleanup) {
		t.Fatal("active and cleanup proofs share a proof kind")
	}

	neighbor := identity
	neighbor.WorkerJobID = "job-neighbor"
	if err := ValidateJobCredentialActiveProof(active, neighbor, 7, now); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
		t.Fatalf("neighbor proof error = %v, want identity mismatch", err)
	}
	if err := ValidateJobCredentialActiveProof(active, identity, 8, now); !errors.Is(err, ErrJobCredentialRevisionStale) {
		t.Fatalf("stale revision error = %v, want revision stale", err)
	}
	if err := ValidateJobCredentialActiveProof(active, identity, 7, now.Add(2*time.Minute)); !errors.Is(err, ErrJobCredentialExpired) {
		t.Fatalf("expired proof error = %v, want expired", err)
	}

	if _, err := NewJobCredentialActiveProof(JobCredentialActiveProofInput{}); err == nil {
		t.Fatal("zero active proof input succeeded")
	}
	if _, err := NewJobCredentialCleanupProof(JobCredentialCleanupProofInput{}); err == nil {
		t.Fatal("zero cleanup proof input succeeded")
	}
}

func TestL8JobCredentialActiveProofLifetimeBoundsAndTemporalValidation(t *testing.T) {
	now := time.Date(2026, time.August, 3, 2, 15, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	if MaxJobCredentialLifetime <= 0 || MaxJobCredentialLifetime > 24*time.Hour {
		t.Fatalf("MaxJobCredentialLifetime = %s, want finite positive bound no larger than 24h", MaxJobCredentialLifetime)
	}
	validAtMaximum, err := NewJobCredentialActiveProof(JobCredentialActiveProofInput{
		ProofID:   "active-proof-maximum",
		Identity:  identity,
		Revision:  1,
		IssuedAt:  now,
		ExpiresAt: now.Add(MaxJobCredentialLifetime),
	})
	if err != nil {
		t.Fatalf("exact maximum lifetime: %v", err)
	}
	if err := ValidateJobCredentialActiveProof(validAtMaximum, identity, 1, now); err != nil {
		t.Fatalf("validate exact maximum lifetime: %v", err)
	}

	for _, tt := range []struct {
		name      string
		issuedAt  time.Time
		expiresAt time.Time
	}{
		{name: "zero issued", expiresAt: now.Add(time.Minute)},
		{name: "zero expiry", issuedAt: now},
		{name: "equal issued and expiry", issuedAt: now, expiresAt: now},
		{name: "expiry before issued", issuedAt: now, expiresAt: now.Add(-time.Nanosecond)},
		{name: "over maximum", issuedAt: now, expiresAt: now.Add(MaxJobCredentialLifetime + time.Nanosecond)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewJobCredentialActiveProof(JobCredentialActiveProofInput{
				ProofID:   "active-proof-invalid-time",
				Identity:  identity,
				Revision:  1,
				IssuedAt:  tt.issuedAt,
				ExpiresAt: tt.expiresAt,
			}); !errors.Is(err, ErrJobCredentialProofInvalid) {
				t.Fatalf("temporal proof error = %v, want invalid proof", err)
			}
		})
	}

	futureIdentity := l8JobCredentialIdentity(now.Add(time.Second))
	future := l8ActiveProof(t, futureIdentity, 1, now.Add(time.Second), now.Add(time.Minute))
	if err := ValidateJobCredentialActiveProof(future, futureIdentity, 1, now); !errors.Is(err, ErrJobCredentialProofInvalid) {
		t.Fatalf("future proof validation = %v, want invalid proof", err)
	}
	expired := l8ActiveProof(t, identity, 1, now, now.Add(time.Minute))
	if err := ValidateJobCredentialActiveProof(expired, identity, 1, now.Add(time.Minute)); !errors.Is(err, ErrJobCredentialExpired) {
		t.Fatalf("proof at exact expiry = %v, want expired", err)
	}
}

func TestL8JobCredentialCleanupProofRequiresExplicitCurrentObservation(t *testing.T) {
	now := time.Date(2026, time.August, 3, 2, 20, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	inspectedAt := now.Add(time.Second)
	proof := l8CleanupProof(t, identity, 2, inspectedAt)
	if MaxJobCredentialCleanupObservationAge <= 0 || MaxJobCredentialCleanupObservationAge > 5*time.Minute {
		t.Fatalf("MaxJobCredentialCleanupObservationAge = %s, want finite positive bound no larger than five minutes", MaxJobCredentialCleanupObservationAge)
	}
	for _, tt := range []struct {
		name       string
		observedAt time.Time
		want       error
	}{
		{name: "zero observation", want: ErrJobCredentialProofInvalid},
		{name: "future inspection", observedAt: inspectedAt.Add(-time.Nanosecond), want: ErrJobCredentialProofInvalid},
		{name: "exact inspection", observedAt: inspectedAt},
		{name: "exact currentness boundary", observedAt: inspectedAt.Add(MaxJobCredentialCleanupObservationAge)},
		{name: "stale after boundary", observedAt: inspectedAt.Add(MaxJobCredentialCleanupObservationAge + time.Nanosecond), want: ErrJobCredentialProofStale},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJobCredentialCleanupProof(proof, identity, 2, tt.observedAt)
			if !errors.Is(err, tt.want) {
				t.Fatalf("cleanup observation error = %v, want %v", err, tt.want)
			}
			if err != nil {
				if err.Error() != tt.want.Error() {
					t.Fatalf("cleanup observation error = %q, want stable %q", err, tt.want)
				}
				for _, forbidden := range []string{"cleanup-proof-1", inspectedAt.Format(time.RFC3339Nano), tt.observedAt.Format(time.RFC3339Nano)} {
					if forbidden != "" && strings.Contains(err.Error(), forbidden) {
						t.Fatalf("cleanup observation error exposed proof/time detail %q", forbidden)
					}
				}
			}
		})
	}
}

func TestL8JobCredentialCleanupProofConflictsAndRetryRequireReinspection(t *testing.T) {
	now := time.Date(2026, time.August, 3, 2, 25, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)

	if _, err := NewJobCredentialCleanupProof(JobCredentialCleanupProofInput{
		ProofID:            "cleanup-proof-inverted",
		Identity:           identity,
		Revision:           2,
		RevokedAt:          now.Add(2 * time.Second),
		AbsenceInspectedAt: now.Add(time.Second),
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	}); !errors.Is(err, ErrJobCredentialProofInvalid) {
		t.Fatalf("inspection-before-revocation error = %v, want invalid proof", err)
	}

	t.Run("identity mismatch and stale proof enter cleanup incomplete then retry", func(t *testing.T) {
		for _, tt := range []struct {
			name  string
			proof JobCredentialCleanupProof
			want  error
		}{
			{name: "stale revision", proof: l8CleanupProof(t, identity, 1, now.Add(time.Second)), want: ErrJobCredentialRevisionStale},
			{name: "neighbor identity", proof: func() JobCredentialCleanupProof {
				neighbor := identity
				neighbor.ExecutionID = "execution-neighbor"
				return l8CleanupProof(t, neighbor, 2, now.Add(time.Second))
			}(), want: ErrJobCredentialIdentityMismatch},
		} {
			t.Run(tt.name, func(t *testing.T) {
				lifecycle := l8ActiveLifecycle(t, identity, 1, now)
				if err := lifecycle.BeginRevoke(); err != nil {
					t.Fatal(err)
				}
				if err := l8RevokeError(lifecycle, tt.proof, now.Add(time.Second)); !errors.Is(err, tt.want) {
					t.Fatalf("cleanup error = %v, want %v", err, tt.want)
				}
				if got := lifecycle.State(); got != JobCredentialStateCleanupIncomplete {
					t.Fatalf("state = %q, want cleanup_incomplete", got)
				}
				reinspected := l8CleanupProofWithID(t, identity, 2, now.Add(3*time.Second), "cleanup-proof-reinspected")
				if err := l8RevokeError(lifecycle, reinspected, now.Add(3*time.Second)); err != nil {
					t.Fatalf("cleanup retry: %v", err)
				}
				if got := lifecycle.State(); got != JobCredentialStateRevoked {
					t.Fatalf("state = %q, want revoked after reinspection", got)
				}
			})
		}
	})

	t.Run("durable proof is stable but every repeated result requires current reinspection", func(t *testing.T) {
		lifecycle := l8ActiveLifecycle(t, identity, 1, now)
		if err := lifecycle.BeginRevoke(); err != nil {
			t.Fatal(err)
		}
		revokedAt := now.Add(time.Second)
		inspectedAt := now.Add(2 * time.Second)
		cleanup := l8CleanupProofWithTimes(t, identity, 2, revokedAt, inspectedAt, "cleanup-proof-final")
		durable, err := lifecycle.Revoke(cleanup, inspectedAt)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(durable, cleanup) {
			t.Fatal("initial revoke did not return its exact durable cleanup proof")
		}

		conflicting := l8CleanupProofWithTimes(t, identity, 2, revokedAt, inspectedAt, "cleanup-proof-conflict")
		if _, err := lifecycle.Revoke(conflicting, inspectedAt); !errors.Is(err, ErrJobCredentialReplayRejected) {
			t.Fatalf("conflicting repeated cleanup = %v, want replay rejected", err)
		} else if err.Error() != ErrJobCredentialReplayRejected.Error() {
			t.Fatalf("conflicting repeated cleanup error = %q, want stable replay denial", err)
		}
		staleObservation := inspectedAt.Add(MaxJobCredentialCleanupObservationAge + time.Nanosecond)
		if staleResult, err := lifecycle.Revoke(cleanup, staleObservation); !errors.Is(err, ErrJobCredentialProofStale) || !reflect.DeepEqual(staleResult, JobCredentialCleanupProof{}) {
			t.Fatalf("stale identical proof result/error = %#v/%v, want no result and stale", staleResult, err)
		} else if err.Error() != ErrJobCredentialProofStale.Error() {
			t.Fatalf("stale identical proof error = %q, want stable stale denial", err)
		}
		freshInspection := staleObservation
		fresh := l8CleanupProofWithTimes(t, identity, 2, revokedAt, freshInspection, "cleanup-proof-fresh-inspection")
		idempotent, err := lifecycle.Revoke(fresh, freshInspection)
		if err != nil {
			t.Fatalf("fresh cleanup reinspection: %v", err)
		}
		if !reflect.DeepEqual(idempotent, durable) {
			t.Fatal("fresh reinspection rewrote the exact durable cleanup proof")
		}
		if got := lifecycle.State(); got != JobCredentialStateRevoked {
			t.Fatalf("repeated cleanup changed terminal state to %q", got)
		}
	})
}

func TestL8JobCredentialLifecycleIdempotenceAndConflicts(t *testing.T) {
	now := time.Date(2026, time.August, 3, 3, 0, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	active := l8ActiveProof(t, identity, 1, now, now.Add(time.Minute))
	cleanup := l8CleanupProof(t, identity, 2, now.Add(time.Second))
	lifecycle, err := NewJobCredentialLifecycle(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.BeginPrepare(identity); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.BeginPrepare(identity); err != nil {
		t.Fatalf("same prepare is not idempotent: %v", err)
	}
	conflictingIdentity := identity
	conflictingIdentity.RuntimeGeneration = "runtime-generation-2"
	if err := lifecycle.BeginPrepare(conflictingIdentity); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
		t.Fatalf("conflicting prepare error = %v, want identity mismatch", err)
	}
	if err := lifecycle.Activate(active); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(active); err != nil {
		t.Fatalf("same active proof is not idempotent: %v", err)
	}

	conflicting := l8ActiveProof(t, conflictingIdentity, 1, now, now.Add(time.Minute))
	if err := lifecycle.Activate(conflicting); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
		t.Fatalf("conflicting active proof error = %v, want identity mismatch", err)
	}

	if err := lifecycle.BeginRevoke(); err != nil {
		t.Fatal(err)
	}
	if lifecycle.HasActiveProof() {
		t.Fatal("begin revoke retained active authority")
	}
	durable, err := lifecycle.Revoke(cleanup, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	fresh := l8CleanupProofWithTimes(t, identity, 2, now.Add(time.Second-time.Nanosecond), now.Add(2*time.Second), "cleanup-proof-idempotent-reinspection")
	idempotent, err := lifecycle.Revoke(fresh, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("reinspected revoke is not idempotent: %v", err)
	}
	if !reflect.DeepEqual(idempotent, durable) {
		t.Fatal("reinspected revoke changed the exact durable cleanup proof")
	}
	if lifecycle.HasActiveProof() {
		t.Fatal("revoked lifecycle retained active proof")
	}
	if !lifecycle.HasCleanupProof() {
		t.Fatal("revoked lifecycle omitted cleanup proof")
	}
}

func TestL8JobCredentialLifecycleFailureCancelLossAndReplayTransitions(t *testing.T) {
	now := time.Date(2026, time.August, 3, 3, 15, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)

	t.Run("prepare failure requires revoke", func(t *testing.T) {
		lifecycle, err := NewJobCredentialLifecycle(identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.BeginPrepare(identity); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.Activate(JobCredentialActiveProof{}); err == nil {
			t.Fatal("zero active proof was accepted")
		}
		if got := lifecycle.State(); got != JobCredentialStateRevoking {
			t.Fatalf("state = %q, want revoking after partial prepare failure", got)
		}
	})

	t.Run("renew failure requires revoke", func(t *testing.T) {
		lifecycle := l8ActiveLifecycle(t, identity, 1, now)
		if err := lifecycle.BeginRenew(); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.Renew(JobCredentialActiveProof{}); err == nil {
			t.Fatal("zero renewal proof was accepted")
		}
		if got := lifecycle.State(); got != JobCredentialStateRevoking {
			t.Fatalf("state = %q, want revoking after renew failure", got)
		}
	})

	t.Run("cleanup failure is durable", func(t *testing.T) {
		lifecycle := l8ActiveLifecycle(t, identity, 1, now)
		if err := lifecycle.BeginRevoke(); err != nil {
			t.Fatal(err)
		}
		if err := l8RevokeError(lifecycle, JobCredentialCleanupProof{}, now); err == nil {
			t.Fatal("zero cleanup proof was accepted")
		}
		if got := lifecycle.State(); got != JobCredentialStateCleanupIncomplete {
			t.Fatalf("state = %q, want cleanup_incomplete after failed cleanup proof", got)
		}
	})

	for _, state := range []string{"preparing", "renewing"} {
		t.Run("cancel from "+state, func(t *testing.T) {
			var lifecycle *JobCredentialLifecycle
			if state == "preparing" {
				var err error
				lifecycle, err = NewJobCredentialLifecycle(identity)
				if err != nil {
					t.Fatal(err)
				}
				if err := lifecycle.BeginPrepare(identity); err != nil {
					t.Fatal(err)
				}
			} else {
				lifecycle = l8ActiveLifecycle(t, identity, 1, now)
				if err := lifecycle.BeginRenew(); err != nil {
					t.Fatal(err)
				}
			}
			if err := lifecycle.BeginRevoke(); err != nil {
				t.Fatal(err)
			}
			if got := lifecycle.State(); got != JobCredentialStateRevoking {
				t.Fatalf("state = %q, want revoking", got)
			}
		})
	}

	for _, state := range []string{"preparing", "renewing"} {
		t.Run("loss from "+state, func(t *testing.T) {
			var lifecycle *JobCredentialLifecycle
			if state == "preparing" {
				var err error
				lifecycle, err = NewJobCredentialLifecycle(identity)
				if err != nil {
					t.Fatal(err)
				}
				if err := lifecycle.BeginPrepare(identity); err != nil {
					t.Fatal(err)
				}
			} else {
				lifecycle = l8ActiveLifecycle(t, identity, 1, now)
				if err := lifecycle.BeginRenew(); err != nil {
					t.Fatal(err)
				}
			}
			if err := lifecycle.ObserveLoss(JobCredentialLoss{Identity: identity, Revision: 1, Code: JobCredentialFailureGuestHelperUnavailable}); err != nil {
				t.Fatal(err)
			}
			if got := lifecycle.State(); got != JobCredentialStateRevoking {
				t.Fatalf("state = %q, want revoking", got)
			}
		})
	}

	t.Run("accepted proof replay revokes", func(t *testing.T) {
		lifecycle := l8ActiveLifecycle(t, identity, 1, now)
		if err := lifecycle.BeginRenew(); err != nil {
			t.Fatal(err)
		}
		replayed := l8ActiveProof(t, identity, 1, now, now.Add(time.Minute))
		if err := lifecycle.Renew(replayed); !errors.Is(err, ErrJobCredentialReplayRejected) {
			t.Fatalf("replayed proof error = %v, want replay rejected", err)
		}
		if got := lifecycle.State(); got != JobCredentialStateRevoking {
			t.Fatalf("state = %q, want revoking", got)
		}
	})
}

func TestL8JobCredentialLifecycleDefaultConstructorHasNoObservableHookState(t *testing.T) {
	constructorType := reflect.TypeOf(NewJobCredentialLifecycle)
	wantIdentityType := reflect.TypeOf(JobCredentialIdentity{})
	wantLifecycleType := reflect.TypeOf((*JobCredentialLifecycle)(nil))
	wantErrorType := reflect.TypeOf((*error)(nil)).Elem()
	if constructorType.IsVariadic() || constructorType.NumIn() != 1 || constructorType.In(0) != wantIdentityType {
		t.Fatalf("NewJobCredentialLifecycle inputs = %s, want exact nonvariadic func(JobCredentialIdentity)", constructorType)
	}
	if constructorType.NumOut() != 2 || constructorType.Out(0) != wantLifecycleType || constructorType.Out(1) != wantErrorType {
		t.Fatalf("NewJobCredentialLifecycle outputs = %s, want exact (*JobCredentialLifecycle, error)", constructorType)
	}

	now := time.Date(2026, time.August, 3, 3, 20, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	lifecycle, err := NewJobCredentialLifecycle(identity)
	if err != nil {
		t.Fatal(err)
	}
	for methodIndex := 0; methodIndex < reflect.TypeOf(lifecycle).NumMethod(); methodIndex++ {
		name := reflect.TypeOf(lifecycle).Method(methodIndex).Name
		if strings.Contains(strings.ToLower(name), "hook") || strings.Contains(strings.ToLower(name), "pause") || strings.Contains(strings.ToLower(name), "option") {
			t.Fatalf("default lifecycle exposes test seam method %s", name)
		}
	}
	active := l8ActiveProof(t, identity, 1, now, now.Add(time.Minute))
	renewed := l8ActiveProof(t, identity, 2, now.Add(time.Second), now.Add(2*time.Minute))
	result := l8AwaitLifecycleTransition(t, l8StartLifecycleTransition(func() l8LifecycleTransitionResult {
		if err := lifecycle.BeginPrepare(identity); err != nil {
			return l8LifecycleTransitionResult{err: err}
		}
		if err := lifecycle.Activate(active); err != nil {
			return l8LifecycleTransitionResult{err: err}
		}
		if err := lifecycle.BeginRenew(); err != nil {
			return l8LifecycleTransitionResult{err: err}
		}
		return l8LifecycleTransitionResult{err: lifecycle.Renew(renewed)}
	}))
	if result.err != nil {
		t.Fatalf("default constructor transition requires hook state: %v", result.err)
	}
	if lifecycle.State() != JobCredentialStateActive || !lifecycle.HasActiveProof() || lifecycle.Revision() != 2 {
		t.Fatalf("default constructor state=%q active=%t revision=%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision())
	}
}

func TestL8JobCredentialLifecycleInvalidHookablePathsNeverReachHook(t *testing.T) {
	now := time.Date(2026, time.August, 3, 3, 20, 30, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	active := l8ActiveProof(t, identity, 1, now, now.Add(time.Minute))
	revokedAt := now.Add(time.Second)
	inspectedAt := now.Add(2 * time.Second)
	cleanup := l8CleanupProofWithTimes(t, identity, 2, revokedAt, inspectedAt, "cleanup-invalid-path")

	tests := []struct {
		name          string
		transition    jobCredentialLifecycleTransition
		setup         func(*testing.T, *l8LifecyclePause) (*JobCredentialLifecycle, JobCredentialCleanupProof)
		invoke        func(*JobCredentialLifecycle) l8LifecycleTransitionResult
		wantErr       error
		wantState     JobCredentialState
		wantActive    bool
		wantRevision  uint64
		verifyActive  bool
		verifyCleanup bool
	}{
		{
			name:       "renew without begin renew",
			transition: jobCredentialLifecycleTransitionRenew,
			setup: func(t *testing.T, pause *l8LifecyclePause) (*JobCredentialLifecycle, JobCredentialCleanupProof) {
				return l8HookedActiveLifecycle(t, identity, 1, now, pause.beforeCommit), JobCredentialCleanupProof{}
			},
			invoke: func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
				return l8LifecycleTransitionResult{err: lifecycle.Renew(l8ActiveProof(t, identity, 2, now.Add(time.Second), now.Add(2*time.Minute)))}
			},
			wantErr:      ErrJobCredentialTransition,
			wantState:    JobCredentialStateActive,
			wantActive:   true,
			wantRevision: 1,
			verifyActive: true,
		},
		{
			name:       "revoke without begin revoke",
			transition: jobCredentialLifecycleTransitionRevoke,
			setup: func(t *testing.T, pause *l8LifecyclePause) (*JobCredentialLifecycle, JobCredentialCleanupProof) {
				return l8HookedActiveLifecycle(t, identity, 1, now, pause.beforeCommit), JobCredentialCleanupProof{}
			},
			invoke: func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
				proof, err := lifecycle.Revoke(cleanup, inspectedAt)
				return l8LifecycleTransitionResult{proof: proof, err: err}
			},
			wantErr:      ErrJobCredentialTransition,
			wantState:    JobCredentialStateActive,
			wantActive:   true,
			wantRevision: 1,
			verifyActive: true,
		},
		{
			name:       "observe loss for neighbor identity",
			transition: jobCredentialLifecycleTransitionObserveLoss,
			setup: func(t *testing.T, pause *l8LifecyclePause) (*JobCredentialLifecycle, JobCredentialCleanupProof) {
				return l8HookedActiveLifecycle(t, identity, 1, now, pause.beforeCommit), JobCredentialCleanupProof{}
			},
			invoke: func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
				neighbor := identity
				neighbor.WorkerJobID = "job-neighbor"
				return l8LifecycleTransitionResult{err: lifecycle.ObserveLoss(JobCredentialLoss{
					Identity: neighbor,
					Revision: 1,
					Code:     JobCredentialFailureGuestHelperUnavailable,
				})}
			},
			wantErr:      ErrJobCredentialIdentityMismatch,
			wantState:    JobCredentialStateRevoking,
			wantRevision: 1,
		},
		{
			name:       "begin revoke after durable revocation is a no-op",
			transition: jobCredentialLifecycleTransitionBeginRevoke,
			setup: func(t *testing.T, pause *l8LifecyclePause) (*JobCredentialLifecycle, JobCredentialCleanupProof) {
				lifecycle := l8HookedActiveLifecycle(t, identity, 1, now, pause.beforeCommit)
				if err := lifecycle.BeginRevoke(); err != nil {
					t.Fatal(err)
				}
				durable, err := lifecycle.Revoke(cleanup, inspectedAt)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(durable, cleanup) {
					t.Fatal("revoked setup did not retain its exact cleanup proof")
				}
				return lifecycle, durable
			},
			invoke: func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
				return l8LifecycleTransitionResult{err: lifecycle.BeginRevoke()}
			},
			wantState:     JobCredentialStateRevoked,
			wantRevision:  2,
			verifyCleanup: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pause := newL8LifecyclePause(tt.transition)
			defer pause.releaseNow()
			lifecycle, durableCleanup := tt.setup(t, pause)
			pause.arm()
			result := l8AwaitLifecycleTransitionWithoutHook(t, pause, l8StartLifecycleTransition(func() l8LifecycleTransitionResult {
				return tt.invoke(lifecycle)
			}))
			if tt.wantErr != nil {
				if !errors.Is(result.err, tt.wantErr) || result.err.Error() != tt.wantErr.Error() {
					t.Fatalf("invalid transition error = %v, want exact %v", result.err, tt.wantErr)
				}
			} else if result.err != nil {
				t.Fatalf("noncommitting transition error = %v, want nil", result.err)
			}
			if !reflect.DeepEqual(result.proof, JobCredentialCleanupProof{}) {
				t.Fatal("invalid/noncommitting transition returned cleanup proof state")
			}
			if pause.claimed.Load() {
				t.Fatal("lifecycle hook ran before transition validation or on a no-op")
			}
			if lifecycle.State() != tt.wantState || lifecycle.HasActiveProof() != tt.wantActive || lifecycle.Revision() != tt.wantRevision {
				t.Fatalf("post-transition state=%q active=%t revision=%d, want %q/%t/%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision(), tt.wantState, tt.wantActive, tt.wantRevision)
			}
			if tt.verifyActive {
				if err := lifecycle.Activate(active); err != nil {
					t.Fatalf("invalid transition changed exact active proof: %v", err)
				}
				if lifecycle.State() != tt.wantState || !lifecycle.HasActiveProof() || lifecycle.Revision() != tt.wantRevision {
					t.Fatal("exact active proof verification changed lifecycle state")
				}
			}
			if tt.verifyCleanup {
				freshInspectedAt := inspectedAt.Add(time.Second)
				fresh := l8CleanupProofWithTimes(t, identity, 2, revokedAt, freshInspectedAt, "cleanup-invalid-path-reinspection")
				stable, err := lifecycle.Revoke(fresh, freshInspectedAt)
				if err != nil {
					t.Fatalf("reinspect durable cleanup proof: %v", err)
				}
				if !reflect.DeepEqual(stable, durableCleanup) {
					t.Fatal("noncommitting begin revoke changed exact durable cleanup proof")
				}
			}
		})
	}
}

func TestL8JobCredentialLifecycleForcedRenewInterleavingsCannotResurrect(t *testing.T) {
	now := time.Date(2026, time.August, 3, 3, 21, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	renewal := l8ActiveProof(t, identity, 2, now.Add(time.Second), now.Add(2*time.Minute))
	for _, tt := range []struct {
		name      string
		contender func(*JobCredentialLifecycle) error
	}{
		{name: "loss commits while renew paused", contender: func(lifecycle *JobCredentialLifecycle) error {
			return lifecycle.ObserveLoss(JobCredentialLoss{Identity: identity, Revision: 1, Code: JobCredentialFailureGuestHelperUnavailable})
		}},
		{name: "begin revoke commits while renew paused", contender: func(lifecycle *JobCredentialLifecycle) error {
			return lifecycle.BeginRevoke()
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pause := newL8LifecyclePause(jobCredentialLifecycleTransitionRenew)
			defer pause.releaseNow()
			lifecycle := l8HookedActiveLifecycle(t, identity, 1, now, pause.beforeCommit)
			if err := lifecycle.BeginRenew(); err != nil {
				t.Fatal(err)
			}
			pause.arm()
			pausedRenew := l8StartLifecycleTransition(func() l8LifecycleTransitionResult {
				return l8LifecycleTransitionResult{err: lifecycle.Renew(renewal)}
			})
			pause.waitUntilEntered(t)
			if lifecycle.State() != JobCredentialStateRenewing || !lifecycle.HasActiveProof() || lifecycle.Revision() != 1 {
				t.Fatalf("paused renew committed early state=%q active=%t revision=%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision())
			}
			contender := l8AwaitLifecycleTransition(t, l8StartLifecycleTransition(func() l8LifecycleTransitionResult {
				return l8LifecycleTransitionResult{err: tt.contender(lifecycle)}
			}))
			if contender.err != nil {
				t.Fatalf("revoking contender did not complete while renew hook was paused: %v", contender.err)
			}
			if lifecycle.State() != JobCredentialStateRevoking || lifecycle.HasActiveProof() || lifecycle.Revision() != 1 {
				t.Fatalf("pre-resume state=%q active=%t revision=%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision())
			}
			pause.releaseNow()
			renewResult := l8AwaitLifecycleTransition(t, pausedRenew)
			if renewResult.err == nil {
				t.Fatal("renew committed a previously validated result after revocation won")
			}
			l8AssertSafeLifecycleTransitionError(t, renewResult.err, identity)
			if lifecycle.State() != JobCredentialStateRevoking || lifecycle.HasActiveProof() || lifecycle.Revision() != 1 {
				t.Fatalf("post-resume state=%q active=%t revision=%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision())
			}
		})
	}
}

func TestL8JobCredentialLifecycleForcedCleanupInterleavingsRetainExactWinner(t *testing.T) {
	now := time.Date(2026, time.August, 3, 3, 22, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	revokedAt := now.Add(2 * time.Second)
	inspectedAt := now.Add(3 * time.Second)
	for _, tt := range []struct {
		name                  string
		contender             func(*JobCredentialLifecycle) l8LifecycleTransitionResult
		contenderWins         bool
		wantContenderError    error
		contenderDurableProof JobCredentialCleanupProof
	}{
		{name: "stale cleanup loses to paused exact cleanup", contender: func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
			proof, err := lifecycle.Revoke(l8CleanupProofWithTimes(t, identity, 2, revokedAt, inspectedAt, "cleanup-stale-observation"), inspectedAt.Add(MaxJobCredentialCleanupObservationAge+time.Nanosecond))
			return l8LifecycleTransitionResult{proof: proof, err: err}
		}, wantContenderError: ErrJobCredentialProofStale},
		{name: "conflicting cleanup commits before paused exact cleanup", contenderWins: true, contenderDurableProof: l8CleanupProofWithTimes(t, identity, 2, revokedAt, inspectedAt, "cleanup-conflicting-winner"), contender: func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
			proof := l8CleanupProofWithTimes(t, identity, 2, revokedAt, inspectedAt, "cleanup-conflicting-winner")
			durable, err := lifecycle.Revoke(proof, inspectedAt)
			return l8LifecycleTransitionResult{proof: durable, err: err}
		}},
		{name: "loss completes before paused exact cleanup", contender: func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
			return l8LifecycleTransitionResult{err: lifecycle.ObserveLoss(JobCredentialLoss{Identity: identity, Revision: 2, Code: JobCredentialFailureGuestHelperUnavailable})}
		}},
		{name: "begin revoke completes before paused exact cleanup", contender: func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
			return l8LifecycleTransitionResult{err: lifecycle.BeginRevoke()}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pause := newL8LifecyclePause(jobCredentialLifecycleTransitionRevoke)
			defer pause.releaseNow()
			lifecycle := l8HookedCleanupIncompleteLifecycle(t, identity, now, pause.beforeCommit)
			exact := l8CleanupProofWithTimes(t, identity, 2, revokedAt, inspectedAt, "cleanup-paused-exact")
			pause.arm()
			pausedCleanup := l8StartLifecycleTransition(func() l8LifecycleTransitionResult {
				proof, err := lifecycle.Revoke(exact, inspectedAt)
				return l8LifecycleTransitionResult{proof: proof, err: err}
			})
			pause.waitUntilEntered(t)
			if lifecycle.State() != JobCredentialStateCleanupIncomplete || lifecycle.HasActiveProof() || lifecycle.Revision() != 2 {
				t.Fatalf("paused cleanup committed early state=%q active=%t revision=%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision())
			}
			contender := l8AwaitLifecycleTransition(t, l8StartLifecycleTransition(func() l8LifecycleTransitionResult {
				return tt.contender(lifecycle)
			}))
			if tt.wantContenderError != nil {
				if !errors.Is(contender.err, tt.wantContenderError) || contender.err.Error() != tt.wantContenderError.Error() {
					t.Fatalf("contender error = %v, want %v", contender.err, tt.wantContenderError)
				}
			} else if contender.err != nil {
				t.Fatalf("contender did not complete while cleanup hook was paused: %v", contender.err)
			}
			pause.releaseNow()
			pausedResult := l8AwaitLifecycleTransition(t, pausedCleanup)
			var durable JobCredentialCleanupProof
			if tt.contenderWins {
				if !reflect.DeepEqual(contender.proof, tt.contenderDurableProof) {
					t.Fatal("conflicting contender did not return its exact admitted proof")
				}
				if !errors.Is(pausedResult.err, ErrJobCredentialReplayRejected) {
					t.Fatalf("paused stale commit error = %v, want replay rejection", pausedResult.err)
				}
				l8AssertSafeLifecycleTransitionError(t, pausedResult.err, identity)
				durable = tt.contenderDurableProof
			} else {
				if pausedResult.err != nil {
					t.Fatalf("exact cleanup after contender: %v", pausedResult.err)
				}
				if !reflect.DeepEqual(pausedResult.proof, exact) {
					t.Fatal("exact cleanup did not retain its admitted proof")
				}
				durable = exact
			}
			if lifecycle.State() != JobCredentialStateRevoked || lifecycle.HasActiveProof() || lifecycle.Revision() != 2 {
				t.Fatalf("cleanup convergence state=%q active=%t revision=%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision())
			}
			freshInspectedAt := inspectedAt.Add(time.Second)
			fresh := l8CleanupProofWithTimes(t, identity, 2, revokedAt, freshInspectedAt, "cleanup-forced-reinspection")
			stable, err := lifecycle.Revoke(fresh, freshInspectedAt)
			if err != nil {
				t.Fatalf("post-interleaving reinspection: %v", err)
			}
			if !reflect.DeepEqual(stable, durable) {
				t.Fatal("post-interleaving reinspection did not return exact durable winner")
			}
		})
	}
}

func TestL8JobCredentialLifecycleForcedLossAndCancellationConverge(t *testing.T) {
	now := time.Date(2026, time.August, 3, 3, 23, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	loss := func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
		return l8LifecycleTransitionResult{err: lifecycle.ObserveLoss(JobCredentialLoss{Identity: identity, Revision: 1, Code: JobCredentialFailureGuestHelperUnavailable})}
	}
	revoke := func(lifecycle *JobCredentialLifecycle) l8LifecycleTransitionResult {
		return l8LifecycleTransitionResult{err: lifecycle.BeginRevoke()}
	}
	for _, tt := range []struct {
		name      string
		pause     jobCredentialLifecycleTransition
		paused    func(*JobCredentialLifecycle) l8LifecycleTransitionResult
		contender func(*JobCredentialLifecycle) l8LifecycleTransitionResult
	}{
		{name: "paused loss revalidates after cancellation revoke", pause: jobCredentialLifecycleTransitionObserveLoss, paused: loss, contender: revoke},
		{name: "paused cancellation revoke revalidates after loss", pause: jobCredentialLifecycleTransitionBeginRevoke, paused: revoke, contender: loss},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pause := newL8LifecyclePause(tt.pause)
			defer pause.releaseNow()
			lifecycle := l8HookedActiveLifecycle(t, identity, 1, now, pause.beforeCommit)
			pause.arm()
			pausedResult := l8StartLifecycleTransition(func() l8LifecycleTransitionResult { return tt.paused(lifecycle) })
			pause.waitUntilEntered(t)
			if lifecycle.State() != JobCredentialStateActive || !lifecycle.HasActiveProof() || lifecycle.Revision() != 1 {
				t.Fatalf("paused loss/cancel committed early state=%q active=%t revision=%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision())
			}
			contender := l8AwaitLifecycleTransition(t, l8StartLifecycleTransition(func() l8LifecycleTransitionResult { return tt.contender(lifecycle) }))
			l8AssertSafeLifecycleTransitionError(t, contender.err, identity)
			if contender.err != nil {
				t.Fatalf("contender failed before paused transition resumed: %v", contender.err)
			}
			pause.releaseNow()
			paused := l8AwaitLifecycleTransition(t, pausedResult)
			l8AssertSafeLifecycleTransitionError(t, paused.err, identity)
			if lifecycle.State() != JobCredentialStateRevoking || lifecycle.HasActiveProof() || lifecycle.Revision() != 1 {
				t.Fatalf("loss/cancel convergence state=%q active=%t revision=%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision())
			}
		})
	}
}

func TestL8JobCredentialFullIdentityRequiresEveryFieldAndExactCorrelation(t *testing.T) {
	now := time.Date(2026, time.August, 3, 3, 25, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	active := l8ActiveProof(t, identity, 1, now, now.Add(time.Minute))
	cleanup := l8CleanupProof(t, identity, 2, now.Add(time.Second))
	for _, tt := range l8JobCredentialIdentityMutations() {
		t.Run(tt.name, func(t *testing.T) {
			partial := identity
			tt.clear(&partial)
			if _, err := NewJobCredentialLifecycle(partial); err == nil {
				t.Fatal("partial full credential identity was accepted")
			}

			mismatched := identity
			tt.mutate(&mismatched)
			if err := ValidateJobCredentialActiveProof(active, mismatched, 1, now); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
				t.Fatalf("active proof accepted mismatched %s: %v", tt.name, err)
			}
			if err := ValidateJobCredentialCleanupProof(cleanup, mismatched, 2, now.Add(time.Second)); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
				t.Fatalf("cleanup proof accepted mismatched %s: %v", tt.name, err)
			}
			lifecycle, err := NewJobCredentialLifecycle(identity)
			if err != nil {
				t.Fatal(err)
			}
			if err := lifecycle.BeginPrepare(identity); err != nil {
				t.Fatal(err)
			}
			if err := lifecycle.BeginPrepare(mismatched); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
				t.Fatalf("lifecycle accepted mismatched %s: %v", tt.name, err)
			}
		})
	}
}

func TestL8JobCredentialRenewAndCleanupProofsRequireMonotonicAbsenceEvidence(t *testing.T) {
	now := time.Date(2026, time.August, 3, 3, 30, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	active := l8ActiveProof(t, identity, 4, now, now.Add(time.Minute))
	lifecycle, err := NewJobCredentialLifecycle(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.BeginPrepare(identity); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(active); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.BeginRenew(); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Renew(l8ActiveProof(t, identity, 4, now.Add(time.Second), now.Add(2*time.Minute))); !errors.Is(err, ErrJobCredentialRevisionStale) {
		t.Fatalf("same-revision renew error = %v, want revision stale", err)
	}

	for _, tt := range []struct {
		name   string
		mutate func(*JobCredentialCleanupProofInput)
	}{
		{name: "authority not absent", mutate: func(input *JobCredentialCleanupProofInput) { input.AuthorityAbsent = false }},
		{name: "resources not absent", mutate: func(input *JobCredentialCleanupProofInput) { input.ResourcesAbsent = false }},
		{name: "absence not inspected", mutate: func(input *JobCredentialCleanupProofInput) { input.AbsenceInspectedAt = time.Time{} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := JobCredentialCleanupProofInput{
				ProofID:            "cleanup-proof-absence",
				Identity:           identity,
				Revision:           5,
				RevokedAt:          now.Add(time.Second),
				AbsenceInspectedAt: now.Add(2 * time.Second),
				AuthorityAbsent:    true,
				ResourcesAbsent:    true,
			}
			tt.mutate(&input)
			if _, err := NewJobCredentialCleanupProof(input); err == nil {
				t.Fatal("incomplete cleanup evidence produced a cleanup proof")
			}
		})
	}
}

func TestL8JobCredentialAuthenticatedWorkerPrincipalRequiresExactAuthorityCapability(t *testing.T) {
	authority, err := NewAuthenticatedWorkerPrincipalAuthority("peercred-authority", "daemon-generation-1")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authority.IssueAuthenticatedWorkerPrincipal("principal-owner", 1001, 1002)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.ValidateAuthenticatedWorkerPrincipal(principal); err != nil {
		t.Fatalf("exact issued principal: %v", err)
	}

	copyOfAuthority := *authority
	principalFromCopy, err := copyOfAuthority.IssueAuthenticatedWorkerPrincipal("principal-owner", 1001, 1002)
	if err != nil {
		t.Fatal(err)
	}
	identicalVisibleAuthority, err := NewAuthenticatedWorkerPrincipalAuthority("peercred-authority", "daemon-generation-1")
	if err != nil {
		t.Fatal(err)
	}
	principalFromOther, err := identicalVisibleAuthority.IssueAuthenticatedWorkerPrincipal("principal-owner", 1001, 1002)
	if err != nil {
		t.Fatal(err)
	}
	issuedConcrete, ok := principal.(*authenticatedWorkerPrincipal)
	if !ok {
		t.Fatalf("principal concrete type = %T, want opaque authority-owned principal", principal)
	}
	copyOfPrincipal := *issuedConcrete
	var zeroPrincipal AuthenticatedWorkerPrincipal
	for _, tt := range []struct {
		name      string
		principal AuthenticatedWorkerPrincipal
	}{
		{name: "zero", principal: zeroPrincipal},
		{name: "copied principal", principal: &copyOfPrincipal},
		{name: "copied authority", principal: principalFromCopy},
		{name: "identical visible different authority", principal: principalFromOther},
		{name: "forged interface", principal: l8ForgedAuthenticatedWorkerPrincipal{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := authority.ValidateAuthenticatedWorkerPrincipal(tt.principal); !errors.Is(err, ErrAuthenticatedWorkerPrincipal) {
				t.Fatalf("principal validation error = %v, want authority rejection", err)
			}
		})
	}

	var nilAuthority *AuthenticatedWorkerPrincipalAuthority
	if _, err := nilAuthority.IssueAuthenticatedWorkerPrincipal("principal-owner", 1001, 1002); !errors.Is(err, ErrAuthenticatedWorkerPrincipal) {
		t.Fatalf("nil authority issue error = %v, want authority rejection", err)
	}
}

func TestL8JobCredentialLiveStateIsOpaqueAndExplicitlyDeniesSerialization(t *testing.T) {
	now := time.Date(2026, time.August, 3, 3, 45, 0, 0, time.UTC)
	identity := l8JobCredentialIdentity(now)
	lifecycle := l8ActiveLifecycle(t, identity, 1, now)
	active := l8ActiveProof(t, identity, 1, now, now.Add(time.Minute))
	cleanup := l8CleanupProof(t, identity, 2, now.Add(time.Second))
	authority, err := NewAuthenticatedWorkerPrincipalAuthority(
		"peercred-issuer-canary",
		"daemon-generation-canary",
	)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authority.IssueAuthenticatedWorkerPrincipal("principal-live-canary", 1000, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID() != "principal-live-canary" || principal.UID() != 1000 || principal.GID() != 1001 ||
		principal.AuthorityID() != "peercred-issuer-canary" || principal.AuthorityGeneration() != "daemon-generation-canary" {
		t.Fatal("authenticated principal accessors did not return its sealed provenance")
	}
	for _, liveValue := range []struct {
		label          string
		value          any
		expectedFormat string
	}{
		{label: "lifecycle", value: lifecycle, expectedFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{label: "active proof", value: active, expectedFormat: "<sandboxruntime.JobCredentialActiveProof>"},
		{label: "cleanup proof", value: cleanup, expectedFormat: "<sandboxruntime.JobCredentialCleanupProof>"},
		{label: "authority", value: authority, expectedFormat: "<sandboxruntime.AuthenticatedWorkerPrincipalAuthority>"},
		{label: "principal", value: principal, expectedFormat: "<sandboxruntime.authenticatedWorkerPrincipal>"},
	} {
		l8AssertJobCredentialLiveValue(t, liveValue.label, liveValue.value, liveValue.expectedFormat, []string{
			identity.SandboxID,
			identity.ExecutionID,
			identity.HostID,
			identity.WorkerJobID,
			identity.RuntimeGeneration,
			identity.ProxySessionID,
			identity.ProxyGenerationID,
			identity.AdmissionGrantID,
			identity.PrincipalID,
			identity.BindingIDs[0],
			"active-proof-1",
			"cleanup-proof-1",
			"principal-live-canary",
			"peercred-issuer-canary",
			"daemon-generation-canary",
			"1000",
			"1001",
		})
	}
	for _, value := range []any{lifecycle, active, cleanup, authority, principal} {
		typeOfValue := reflect.TypeOf(value)
		if typeOfValue.Kind() == reflect.Pointer {
			typeOfValue = typeOfValue.Elem()
		}
		for fieldIndex := 0; fieldIndex < typeOfValue.NumField(); fieldIndex++ {
			if field := typeOfValue.Field(fieldIndex); field.IsExported() {
				t.Fatalf("%s exposes live field %s", typeOfValue, field.Name)
			}
		}
	}
}

func l8AssertJobCredentialLiveValue(t *testing.T, label string, value any, expectedFormat string, forbidden []string) {
	t.Helper()
	jsonCodec, ok := value.(json.Marshaler)
	if !ok {
		t.Fatalf("%s does not explicitly deny JSON marshaling", label)
	}
	if encoded, err := jsonCodec.MarshalJSON(); encoded != nil || !errors.Is(err, ErrJobCredentialSerialization) || err.Error() != ErrJobCredentialSerialization.Error() {
		t.Fatalf("%s JSON codec did not return stable serialization denial", label)
	}
	if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, ErrJobCredentialSerialization) {
		t.Fatalf("%s was serializable through encoding/json", label)
	}
	textCodec, ok := value.(encoding.TextMarshaler)
	if !ok {
		t.Fatalf("%s does not explicitly deny text marshaling", label)
	}
	if encoded, err := textCodec.MarshalText(); encoded != nil || !errors.Is(err, ErrJobCredentialSerialization) || err.Error() != ErrJobCredentialSerialization.Error() {
		t.Fatalf("%s text codec did not return stable serialization denial", label)
	}
	l8AssertJobCredentialAllVerbFormatting(t, label, value, expectedFormat, forbidden)
}

func l8AssertJobCredentialAllVerbFormatting(t *testing.T, label string, value any, expectedFormat string, forbidden []string) {
	t.Helper()
	for _, variant := range l8JobCredentialFormattingVariants(value) {
		if _, ok := variant.value.(fmt.Formatter); !ok {
			t.Fatalf("%s %s lacks fmt.Formatter", label, variant.name)
		}
		if rendered := l8JobCredentialSafeSprintf(t, label+" "+variant.name+" %v", "%v", variant.value); rendered != expectedFormat {
			t.Fatalf("%s %s formatter output = %q, want exact %q", label, variant.name, rendered, expectedFormat)
		}
		for _, format := range l8JobCredentialFormatterVerbs() {
			rendered := l8JobCredentialSafeSprintf(t, label+" "+variant.name+" "+format, format, variant.value)
			if rendered != expectedFormat {
				t.Fatalf("%s %s formatting %s = %q, want fixed %q", label, variant.name, format, rendered, expectedFormat)
			}
			l8JobCredentialRejectFormattingPoison(t, label+" "+variant.name+" "+format, rendered, forbidden)
		}
		for _, control := range []string{"%T", "%p"} {
			rendered := l8JobCredentialSafeSprintf(t, label+" "+variant.name+" "+control, control, variant.value)
			l8JobCredentialRejectFormattingPoison(t, label+" "+variant.name+" "+control, rendered, forbidden)
		}
		stringer, ok := variant.value.(fmt.Stringer)
		if !ok || l8JobCredentialSafeFormatCall(t, label+" "+variant.name+" String", stringer.String) != expectedFormat {
			t.Fatalf("%s %s String output is not the fixed formatter output", label, variant.name)
		}
		goStringer, ok := variant.value.(fmt.GoStringer)
		if !ok || l8JobCredentialSafeFormatCall(t, label+" "+variant.name+" GoString", goStringer.GoString) != expectedFormat {
			t.Fatalf("%s %s GoString output is not the fixed formatter output", label, variant.name)
		}
	}
}

type l8JobCredentialFormattingVariant struct {
	name       string
	value      any
	nilPointer bool
}

func l8JobCredentialFormattingVariants(value any) []l8JobCredentialFormattingVariant {
	valueOf := reflect.ValueOf(value)
	variants := []l8JobCredentialFormattingVariant{{name: "interface", value: value}}
	if valueOf.Kind() == reflect.Pointer {
		variants = append(variants, l8JobCredentialFormattingVariant{name: "nil-pointer", value: reflect.Zero(valueOf.Type()).Interface(), nilPointer: true})
		return variants
	}
	pointer := reflect.New(valueOf.Type())
	pointer.Elem().Set(valueOf)
	variants = append(variants, l8JobCredentialFormattingVariant{name: "pointer", value: pointer.Interface()})
	return variants
}

func l8JobCredentialFormatterVerbs() []string {
	return []string{
		"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%O", "%b", "%U",
		"%e", "%E", "%f", "%F", "%g", "%G", "%c", "%t", "% 32v", "%-32v", "%032v", "%.3v", "%+32.3v", "%#q",
	}
}

func l8JobCredentialSafeSprintf(t *testing.T, label, format string, value any) (rendered string) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", label, recovered)
		}
	}()
	return fmt.Sprintf(format, value)
}

func l8JobCredentialSafeFormatCall(t *testing.T, label string, format func() string) (rendered string) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", label, recovered)
		}
	}()
	return format()
}

func l8JobCredentialRejectFormattingPoison(t *testing.T, label, rendered string, forbidden []string) {
	t.Helper()
	for _, poison := range forbidden {
		if poison != "" && strings.Contains(rendered, poison) {
			t.Fatalf("%s exposed formatting poison %q in %q", label, poison, rendered)
		}
	}
}

func TestL8JobCredentialAuthorizationIsStructurallyRequiredBeforeSourceResolution(t *testing.T) {
	authorizerType := reflect.TypeOf((*CredentialAdmissionAuthorizer)(nil)).Elem()
	registryType := reflect.TypeOf((*AuthorizedCredentialSourceRegistry)(nil)).Elem()
	method, ok := registryType.MethodByName("ResolveAuthorizedSource")
	if !ok {
		t.Fatal("authorized source registry lacks ResolveAuthorizedSource")
	}
	authorizationType := reflect.TypeOf((*CredentialAdmissionAuthorization)(nil)).Elem()
	foundAuthorization := false
	for i := 0; i < method.Type.NumIn(); i++ {
		if method.Type.In(i) == authorizationType {
			foundAuthorization = true
		}
	}
	if !foundAuthorization {
		t.Fatal("source resolution does not require an admission authorization")
	}
	if _, ok := authorizerType.MethodByName("AuthorizeJobCredentials"); !ok {
		t.Fatal("admission authorizer lacks AuthorizeJobCredentials")
	}

	var _ CredentialAdmissionAuthorizer = (*l8FakeCredentialAuthorizer)(nil)
	var _ AuthorizedCredentialSourceRegistry = (*l8FakeAuthorizedSourceRegistry)(nil)
	var _ JobCredentialRuntime = (*l8FakeJobCredentialRuntime)(nil)
}

func l8JobCredentialIdentity(now time.Time) JobCredentialIdentity {
	return JobCredentialIdentity{
		SandboxID:                    "sandbox-1",
		ExecutionID:                  "execution-1",
		WorkerID:                     "worker-1",
		HostID:                       "host-1",
		RuntimeDriver:                "microvm",
		RuntimeID:                    "runtime-1",
		RuntimeGeneration:            "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1",
		VsockGeneration:              "vsock-generation-1",
		WorkerJobID:                  "job-1",
		SubmissionID:                 "submission-1",
		PlanID:                       "plan-1",
		ActivationGeneration:         "activation-generation-1",
		CredentialGeneration:         "credential-generation-1",
		NetworkPlanID:                "network-plan-1",
		PolicySnapshotID:             "policy-snapshot-1",
		ProxySessionID:               "proxy-session-1",
		ProxyGenerationID:            "proxy-generation-1",
		TopologyGenerationID:         "topology-generation-1",
		RuleGenerationID:             "rule-generation-1",
		AdmissionGrantID:             "grant-1",
		AdmissionGrantRevision:       4,
		PrincipalID:                  "principal-1",
		BindingIDs:                   []string{"binding-http"},
		DeliveryModes:                []JobCredentialDeliveryMode{JobCredentialDeliveryModeHTTPProxy},
		IssuedAt:                     now,
	}
}

type l8JobCredentialIdentityMutation struct {
	name   string
	clear  func(*JobCredentialIdentity)
	mutate func(*JobCredentialIdentity)
}

func l8JobCredentialIdentityMutations() []l8JobCredentialIdentityMutation {
	stringField := func(name string, selectField func(*JobCredentialIdentity) *string) l8JobCredentialIdentityMutation {
		return l8JobCredentialIdentityMutation{
			name:   name,
			clear:  func(value *JobCredentialIdentity) { *selectField(value) = "" },
			mutate: func(value *JobCredentialIdentity) { *selectField(value) += "-neighbor" },
		}
	}
	return []l8JobCredentialIdentityMutation{
		stringField("sandbox_id", func(value *JobCredentialIdentity) *string { return &value.SandboxID }),
		stringField("execution_id", func(value *JobCredentialIdentity) *string { return &value.ExecutionID }),
		stringField("worker_id", func(value *JobCredentialIdentity) *string { return &value.WorkerID }),
		stringField("host_id", func(value *JobCredentialIdentity) *string { return &value.HostID }),
		stringField("runtime_driver", func(value *JobCredentialIdentity) *string { return &value.RuntimeDriver }),
		stringField("runtime_id", func(value *JobCredentialIdentity) *string { return &value.RuntimeID }),
		stringField("runtime_generation", func(value *JobCredentialIdentity) *string { return &value.RuntimeGeneration }),
		stringField("firecracker_process_generation", func(value *JobCredentialIdentity) *string { return &value.FirecrackerProcessGeneration }),
		stringField("vsock_generation", func(value *JobCredentialIdentity) *string { return &value.VsockGeneration }),
		stringField("worker_job_id", func(value *JobCredentialIdentity) *string { return &value.WorkerJobID }),
		stringField("submission_id", func(value *JobCredentialIdentity) *string { return &value.SubmissionID }),
		stringField("plan_id", func(value *JobCredentialIdentity) *string { return &value.PlanID }),
		stringField("activation_generation", func(value *JobCredentialIdentity) *string { return &value.ActivationGeneration }),
		stringField("credential_generation", func(value *JobCredentialIdentity) *string { return &value.CredentialGeneration }),
		stringField("network_plan_id", func(value *JobCredentialIdentity) *string { return &value.NetworkPlanID }),
		stringField("policy_snapshot_id", func(value *JobCredentialIdentity) *string { return &value.PolicySnapshotID }),
		stringField("proxy_session_id", func(value *JobCredentialIdentity) *string { return &value.ProxySessionID }),
		stringField("proxy_generation_id", func(value *JobCredentialIdentity) *string { return &value.ProxyGenerationID }),
		stringField("topology_generation_id", func(value *JobCredentialIdentity) *string { return &value.TopologyGenerationID }),
		stringField("rule_generation_id", func(value *JobCredentialIdentity) *string { return &value.RuleGenerationID }),
		stringField("admission_grant_id", func(value *JobCredentialIdentity) *string { return &value.AdmissionGrantID }),
		{
			name:   "admission_grant_revision",
			clear:  func(value *JobCredentialIdentity) { value.AdmissionGrantRevision = 0 },
			mutate: func(value *JobCredentialIdentity) { value.AdmissionGrantRevision++ },
		},
		stringField("principal_id", func(value *JobCredentialIdentity) *string { return &value.PrincipalID }),
		{
			name:   "binding_ids",
			clear:  func(value *JobCredentialIdentity) { value.BindingIDs = nil },
			mutate: func(value *JobCredentialIdentity) { value.BindingIDs = []string{"binding-neighbor"} },
		},
		{
			name:  "delivery_modes",
			clear: func(value *JobCredentialIdentity) { value.DeliveryModes = nil },
			mutate: func(value *JobCredentialIdentity) {
				value.DeliveryModes = []JobCredentialDeliveryMode{JobCredentialDeliveryModeFileTmpfs}
			},
		},
		{
			name:   "issued_at",
			clear:  func(value *JobCredentialIdentity) { value.IssuedAt = time.Time{} },
			mutate: func(value *JobCredentialIdentity) { value.IssuedAt = value.IssuedAt.Add(time.Second) },
		},
	}
}

func l8ActiveProof(t *testing.T, identity JobCredentialIdentity, revision uint64, issuedAt, expiresAt time.Time) JobCredentialActiveProof {
	t.Helper()
	proof, err := NewJobCredentialActiveProof(JobCredentialActiveProofInput{
		ProofID:   fmt.Sprintf("active-proof-%d", revision),
		Identity:  identity,
		Revision:  revision,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("new active proof: %v", err)
	}
	return proof
}

func l8ActiveLifecycle(t *testing.T, identity JobCredentialIdentity, revision uint64, now time.Time) *JobCredentialLifecycle {
	t.Helper()
	lifecycle, err := NewJobCredentialLifecycle(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.BeginPrepare(identity); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(l8ActiveProof(t, identity, revision, now, now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	return lifecycle
}

func l8CleanupProof(t *testing.T, identity JobCredentialIdentity, revision uint64, inspectedAt time.Time) JobCredentialCleanupProof {
	return l8CleanupProofWithID(t, identity, revision, inspectedAt, "cleanup-proof-1")
}

func l8CleanupProofWithID(t *testing.T, identity JobCredentialIdentity, revision uint64, inspectedAt time.Time, proofID string) JobCredentialCleanupProof {
	return l8CleanupProofWithTimes(t, identity, revision, inspectedAt.Add(-time.Nanosecond), inspectedAt, proofID)
}

func l8CleanupProofWithTimes(t *testing.T, identity JobCredentialIdentity, revision uint64, revokedAt, inspectedAt time.Time, proofID string) JobCredentialCleanupProof {
	t.Helper()
	proof, err := NewJobCredentialCleanupProof(JobCredentialCleanupProofInput{
		ProofID:            proofID,
		Identity:           identity,
		Revision:           revision,
		RevokedAt:          revokedAt,
		AbsenceInspectedAt: inspectedAt,
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	})
	if err != nil {
		t.Fatalf("new cleanup proof: %v", err)
	}
	return proof
}

func l8RevokeError(lifecycle *JobCredentialLifecycle, proof JobCredentialCleanupProof, observedAt time.Time) error {
	_, err := lifecycle.Revoke(proof, observedAt)
	return err
}

type l8LifecycleTransitionResult struct {
	proof JobCredentialCleanupProof
	err   error
}

type l8LifecyclePause struct {
	transition jobCredentialLifecycleTransition
	entered    chan struct{}
	release    chan struct{}
	claimed    atomic.Bool
	released   atomic.Bool
	armed      atomic.Bool
}

func newL8LifecyclePause(transition jobCredentialLifecycleTransition) *l8LifecyclePause {
	return &l8LifecyclePause{
		transition: transition,
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
}

func (pause *l8LifecyclePause) beforeCommit(transition jobCredentialLifecycleTransition) {
	if !pause.armed.Load() || transition != pause.transition || !pause.claimed.CompareAndSwap(false, true) {
		return
	}
	close(pause.entered)
	<-pause.release
}

func (pause *l8LifecyclePause) arm() {
	pause.armed.Store(true)
}

func (pause *l8LifecyclePause) waitUntilEntered(t *testing.T) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-pause.entered:
	case <-timer.C:
		t.Fatal("timed out waiting for lifecycle transition validation hook")
	}
}

func (pause *l8LifecyclePause) releaseNow() {
	if pause.released.CompareAndSwap(false, true) {
		close(pause.release)
	}
}

func l8StartLifecycleTransition(transition func() l8LifecycleTransitionResult) <-chan l8LifecycleTransitionResult {
	result := make(chan l8LifecycleTransitionResult, 1)
	go func() {
		result <- transition()
	}()
	return result
}

func l8AwaitLifecycleTransition(t *testing.T, result <-chan l8LifecycleTransitionResult) l8LifecycleTransitionResult {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case value := <-result:
		return value
	case <-timer.C:
		t.Fatal("timed out waiting for deterministic lifecycle transition")
		return l8LifecycleTransitionResult{}
	}
}

func l8AwaitLifecycleTransitionWithoutHook(t *testing.T, pause *l8LifecyclePause, result <-chan l8LifecycleTransitionResult) l8LifecycleTransitionResult {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case value := <-result:
		return value
	case <-pause.entered:
		pause.releaseNow()
		value := l8AwaitLifecycleTransition(t, result)
		t.Fatalf("invalid/noncommitting lifecycle path reached hook before returning %v", value.err)
		return l8LifecycleTransitionResult{}
	case <-timer.C:
		pause.releaseNow()
		t.Fatal("timed out waiting for lifecycle rejection/no-op")
		return l8LifecycleTransitionResult{}
	}
}

func l8HookedActiveLifecycle(t *testing.T, identity JobCredentialIdentity, revision uint64, now time.Time, beforeCommit func(jobCredentialLifecycleTransition)) *JobCredentialLifecycle {
	t.Helper()
	lifecycle, err := newJobCredentialLifecycleWithOptions(identity, jobCredentialLifecycleOptions{beforeCommit: beforeCommit})
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.BeginPrepare(identity); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(l8ActiveProof(t, identity, revision, now, now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	return lifecycle
}

func l8HookedCleanupIncompleteLifecycle(t *testing.T, identity JobCredentialIdentity, now time.Time, beforeCommit func(jobCredentialLifecycleTransition)) *JobCredentialLifecycle {
	t.Helper()
	lifecycle := l8HookedActiveLifecycle(t, identity, 1, now, beforeCommit)
	if err := lifecycle.BeginRevoke(); err != nil {
		t.Fatal(err)
	}
	inspectedAt := now.Add(time.Second)
	if err := l8RevokeError(lifecycle, l8CleanupProof(t, identity, 1, inspectedAt), inspectedAt); !errors.Is(err, ErrJobCredentialRevisionStale) {
		t.Fatalf("seed cleanup incomplete: %v", err)
	}
	if lifecycle.State() != JobCredentialStateCleanupIncomplete || lifecycle.HasActiveProof() || lifecycle.Revision() != 2 {
		t.Fatalf("cleanup-incomplete setup state=%q active=%t revision=%d", lifecycle.State(), lifecycle.HasActiveProof(), lifecycle.Revision())
	}
	return lifecycle
}

func l8AssertSafeLifecycleTransitionError(t *testing.T, err error, identity JobCredentialIdentity) {
	t.Helper()
	if err == nil {
		return
	}
	stable := false
	for _, allowed := range []error{
		ErrJobCredentialTransition, ErrJobCredentialExpired, ErrJobCredentialIdentityMismatch,
		ErrJobCredentialRevisionStale, ErrJobCredentialReplayRejected, ErrJobCredentialProofInvalid,
		ErrJobCredentialProofStale,
	} {
		if errors.Is(err, allowed) && err.Error() == allowed.Error() {
			stable = true
			break
		}
	}
	if !stable {
		t.Fatalf("concurrent lifecycle returned non-stable error %q", err)
	}
	for _, forbidden := range []string{
		identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.HostID,
		identity.RuntimeID, identity.WorkerJobID, identity.SubmissionID, identity.PrincipalID,
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("concurrent lifecycle error exposed identity %q", forbidden)
		}
	}
}

type l8FakeCredentialAuthorizer struct{}

type l8ForgedAuthenticatedWorkerPrincipal struct{}

func (l8ForgedAuthenticatedWorkerPrincipal) IsAuthenticatedWorkerPrincipal() {}
func (l8ForgedAuthenticatedWorkerPrincipal) ID() string                      { return "principal-owner" }
func (l8ForgedAuthenticatedWorkerPrincipal) UID() uint32                     { return 1001 }
func (l8ForgedAuthenticatedWorkerPrincipal) GID() uint32                     { return 1002 }
func (l8ForgedAuthenticatedWorkerPrincipal) AuthorityID() string             { return "peercred-authority" }
func (l8ForgedAuthenticatedWorkerPrincipal) AuthorityGeneration() string {
	return "daemon-generation-1"
}

func (*l8FakeCredentialAuthorizer) AuthorizeJobCredentials(context.Context, AuthenticatedWorkerPrincipal, JobCredentialAdmissionRequest) (CredentialAdmissionAuthorization, error) {
	return nil, nil
}

type l8FakeAuthorizedSourceRegistry struct{}

func (*l8FakeAuthorizedSourceRegistry) ResolveAuthorizedSource(context.Context, CredentialAdmissionAuthorization, string) (LiveSecretSource, error) {
	return nil, nil
}

type l8FakeJobCredentialRuntime struct{}

func (*l8FakeJobCredentialRuntime) PrepareJobCredentials(context.Context, JobCredentialPrepareRequest) (JobCredentialSession, error) {
	return nil, nil
}

func (*l8FakeJobCredentialRuntime) RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error) {
	return JobCredentialCleanupProof{}, nil
}
