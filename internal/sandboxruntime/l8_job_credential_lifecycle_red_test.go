package sandboxruntime

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
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
				func(l *JobCredentialLifecycle) error { return l.Revoke(cleanup) },
			},
			wantState: JobCredentialStateRevoked,
		},
		{
			name: "cleanup without begin revoke",
			steps: []func(*JobCredentialLifecycle) error{
				func(l *JobCredentialLifecycle) error { return l.BeginPrepare(identity) },
				func(l *JobCredentialLifecycle) error { return l.Activate(active) },
				func(l *JobCredentialLifecycle) error { return l.Revoke(cleanup) },
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
		name    string
		loss    JobCredentialLoss
		wantErr error
	}{
		{
			name: "same job current revision",
			loss: JobCredentialLoss{Identity: identity, Revision: 3, Code: JobCredentialFailureGuestHelperUnavailable},
		},
		{
			name: "neighbor job",
			loss: func() JobCredentialLoss {
				neighbor := identity
				neighbor.WorkerJobID = "job-neighbor"
				return JobCredentialLoss{Identity: neighbor, Revision: 3, Code: JobCredentialFailureGuestHelperUnavailable}
			}(),
			wantErr: ErrJobCredentialIdentityMismatch,
		},
		{
			name:    "stale watcher revision",
			loss:    JobCredentialLoss{Identity: identity, Revision: 2, Code: JobCredentialFailureGuestHelperUnavailable},
			wantErr: ErrJobCredentialRevisionStale,
		},
		{
			name: "stale runtime generation",
			loss: func() JobCredentialLoss {
				stale := identity
				stale.RuntimeGeneration = "runtime-generation-stale"
				return JobCredentialLoss{Identity: stale, Revision: 3, Code: JobCredentialFailureGuestHelperUnavailable}
			}(),
			wantErr: ErrJobCredentialIdentityMismatch,
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
			if err := lifecycle.Activate(l8ActiveProof(t, identity, 3, now, now.Add(time.Minute))); err != nil {
				t.Fatal(err)
			}
			err = lifecycle.ObserveLoss(tt.loss)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("loss error classification mismatch for %s", tt.name)
			}
			wantState := JobCredentialStateRevoking
			if got := lifecycle.State(); got != wantState {
				t.Fatalf("state = %q, want %q", got, wantState)
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
	if err := ValidateJobCredentialCleanupProof(cleanup, identity, 8); err != nil {
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
				if err := lifecycle.Revoke(tt.proof); !errors.Is(err, tt.want) {
					t.Fatalf("cleanup error = %v, want %v", err, tt.want)
				}
				if got := lifecycle.State(); got != JobCredentialStateCleanupIncomplete {
					t.Fatalf("state = %q, want cleanup_incomplete", got)
				}
				reinspected := l8CleanupProofWithID(t, identity, 2, now.Add(3*time.Second), "cleanup-proof-reinspected")
				if err := lifecycle.Revoke(reinspected); err != nil {
					t.Fatalf("cleanup retry: %v", err)
				}
				if got := lifecycle.State(); got != JobCredentialStateRevoked {
					t.Fatalf("state = %q, want revoked after reinspection", got)
				}
			})
		}
	})

	t.Run("exact repeat is idempotent but conflicting repeat is replay", func(t *testing.T) {
		lifecycle := l8ActiveLifecycle(t, identity, 1, now)
		if err := lifecycle.BeginRevoke(); err != nil {
			t.Fatal(err)
		}
		cleanup := l8CleanupProofWithID(t, identity, 2, now.Add(time.Second), "cleanup-proof-final")
		if err := lifecycle.Revoke(cleanup); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.Revoke(cleanup); err != nil {
			t.Fatalf("exact repeated cleanup is not idempotent: %v", err)
		}
		conflicting := l8CleanupProofWithID(t, identity, 2, now.Add(2*time.Second), "cleanup-proof-conflict")
		if err := lifecycle.Revoke(conflicting); !errors.Is(err, ErrJobCredentialReplayRejected) {
			t.Fatalf("conflicting repeated cleanup = %v, want replay rejected", err)
		}
		if got := lifecycle.State(); got != JobCredentialStateRevoked {
			t.Fatalf("conflicting repeat changed terminal state to %q", got)
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
	if err := lifecycle.Revoke(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Revoke(cleanup); err != nil {
		t.Fatalf("same revoke is not idempotent: %v", err)
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
		if err := lifecycle.Revoke(JobCredentialCleanupProof{}); err == nil {
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
			if err := ValidateJobCredentialCleanupProof(cleanup, mismatched, 2); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
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
	for label, value := range map[string]any{
		"lifecycle":     lifecycle,
		"active proof":  active,
		"cleanup proof": cleanup,
		"authority":     authority,
		"principal":     principal,
	} {
		l8AssertJobCredentialLiveValue(t, label, value, []string{
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

func l8AssertJobCredentialLiveValue(t *testing.T, label string, value any, forbidden []string) {
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
	stringer, ok := value.(fmt.Stringer)
	if !ok {
		t.Fatalf("%s lacks safe String formatting", label)
	}
	goStringer, ok := value.(fmt.GoStringer)
	if !ok {
		t.Fatalf("%s lacks safe GoString formatting", label)
	}
	for format, rendered := range map[string]string{
		"String":   stringer.String(),
		"GoString": goStringer.GoString(),
		"%v":       fmt.Sprintf("%v", value),
		"%+v":      fmt.Sprintf("%+v", value),
		"%#v":      fmt.Sprintf("%#v", value),
	} {
		if rendered == "" {
			t.Fatalf("%s %s formatting was empty", label, format)
		}
		for _, raw := range forbidden {
			if raw != "" && strings.Contains(rendered, raw) {
				t.Fatalf("%s %s formatting exposed %q", label, format, raw)
			}
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
	t.Helper()
	proof, err := NewJobCredentialCleanupProof(JobCredentialCleanupProofInput{
		ProofID:            proofID,
		Identity:           identity,
		Revision:           revision,
		RevokedAt:          inspectedAt.Add(-time.Nanosecond),
		AbsenceInspectedAt: inspectedAt,
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	})
	if err != nil {
		t.Fatalf("new cleanup proof: %v", err)
	}
	return proof
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
