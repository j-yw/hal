package sandboxruntime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Passing controls are separate from all missing-method REDs. No fake owner
// here runs a workload or returns a successful cleanup receipt.
func TestMinimalWorkerBindingOriginalControls(t *testing.T) {
	f := newMinimalWorkerBindingFixture(t)
	if f.authority.ValidateAuthenticatedWorkerPrincipal(f.principal) != nil || f.selection.Current(f.r.Context()) != nil {
		t.Fatal("original principal or selected input unavailable")
	}
	if f.journal.CheckMinimalLaunchReservation(f.r.Context(), f.r) != nil || f.journal.calls.Load() != 1 {
		t.Fatal("original neutral admission control was not reached")
	}
	f.arm(t)
	owner, err := f.binding.Start(f.r, f.selection, func() error { return nil })
	if err != nil || owner == nil || owner.owner != f.p.owner || owner.identity != f.r.Identity() || f.p.starts.Load() != 1 || f.p.claims.Load() != 1 {
		t.Fatal("actual unbound Start/Claim lost original owner")
	}
	if _, err := f.r.ClaimLaunch(f.r.Context()); !errors.Is(err, ErrMinimalLaunchUnavailable) {
		t.Fatal("actual Claim was reusable")
	}
	if receipt, err := owner.Finalize(context.Background()); receipt != (MinimalLaunchCleanupReceipt{}) || !errors.Is(err, ErrMinimalLaunchUnavailable) {
		t.Fatal("bookkeeping control manufactured cleanup success")
	}
}

func TestMinimalWorkerBindingCopiesOriginalInput(t *testing.T) {
	f := newMinimalWorkerBindingFixture(t)
	api := requireMinimalWorkerAPI(t, f.r) // First intended RED; later copies are unexercised today.
	if err := api.BindWorker(f.input, f.journal); err != nil {
		t.Fatalf("original binding rejected: %v", err)
	}
	f.input.Exec.Args[1], f.input.Exec.Env["TEST_MODE"] = "changed", "changed"
	f.input.Exec.Target.Runtime.Metadata.CapabilityLabels[0] = "changed"
	f.input.Credentials.SourceReferenceIDs[0], f.input.Credentials.Bindings[0].ID = "changed", "changed"
	f.p.register = true
	f.arm(t)
	owner, err := f.binding.Start(f.r, f.selection, func() error { return nil })
	got := f.p.received
	if err != nil || owner == nil || owner != api.RetainedWorkerOwner() || owner.owner != f.p.owner {
		t.Fatalf("bound Start did not return the original slot: %v", err)
	}
	if got.Principal != f.principal || got.RequestKey != f.r.Identity().RequestKey || got.Exec.Args[1] != "original-arg" || got.Exec.Env["TEST_MODE"] != "original-value" || got.Exec.Target.Runtime.Metadata.CapabilityLabels[0] != "original-label" || got.Credentials.SourceReferenceIDs[0] != "source-binding" || got.Credentials.Bindings[0].ID != "credential-binding" {
		t.Fatal("bound input aliases caller-owned data")
	}
	if got.Exec.Stdin != f.input.Exec.Stdin || got.Exec.Stdout != f.input.Exec.Stdout || got.Exec.Stderr != f.input.Exec.Stderr || got.Credentials.Identity != (JobCredentialAdmissionIdentity{}) {
		t.Fatal("original bounded I/O or unissued credential identity changed")
	}
	f.r.Revoke()
	if api.RetainedWorkerOwner() != owner || f.journal.calls.Load() < 2 {
		t.Fatal("loss erased slot or registration skipped original journal")
	}
}

func TestMinimalWorkerBindingRejectsUnissuedAndLateInputs(t *testing.T) {
	for _, name := range []string{"nil journal", "typed nil journal", "foreign journal", "copied journal", "foreign principal", "request mismatch", "credential identity", "after arm", "copied reservation"} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalWorkerBindingFixture(t)
			r, input := f.r, f.input
			var journal MinimalLaunchJournal = f.journal
			switch name {
			case "nil journal":
				journal = nil
			case "typed nil journal":
				journal = (*minimalWorkerAdmissionJournal)(nil)
			case "foreign journal":
				journal = newMinimalWorkerBindingFixture(t).journal
			case "copied journal":
				journal = &minimalWorkerAdmissionJournal{self: f.journal, r: f.r}
			case "foreign principal":
				input.Principal = newMinimalWorkerBindingFixture(t).principal
			case "request mismatch":
				input.RequestKey = "request-v2-" + strings.Repeat("c", 64)
			case "credential identity":
				input.Credentials.Identity.SandboxID = f.r.Identity().SandboxID
			case "after arm":
				f.arm(t)
			case "copied reservation":
				r = copyMinimalWorkerReservation(f.r)
			}
			api := requireMinimalWorkerAPI(t, r)
			if err := api.BindWorker(input, journal); !errors.Is(err, ErrMinimalLaunchUnavailable) || api.RetainedWorkerOwner() != nil || f.p.starts.Load() != 0 || f.p.claims.Load() != 0 {
				t.Fatal("invalid/late input issued worker ownership")
			}
		})
	}
}

func TestMinimalWorkerRegistrationWithoutBindingRejectsAfterRealClaim(t *testing.T) {
	f := newMinimalWorkerBindingFixture(t)
	f.p.register = true
	f.arm(t)
	owner, err := f.binding.Start(f.r, f.selection, func() error { return nil })
	if f.p.starts.Load() != 1 || f.p.claims.Load() != 1 || owner == nil || owner.owner != f.p.owner {
		t.Fatal("unbound control did not reach actual Claim/partial retention")
	}
	api := requireMinimalWorkerAPI(t, f.r)
	if !errors.Is(err, ErrMinimalLaunchUnavailable) || api.RetainedWorkerOwner() != nil {
		t.Fatal("missing worker binding permitted registration")
	}
}

func TestMinimalWorkerRegistrationRetainsBeforeBlockingCallback(t *testing.T) {
	for _, boundary := range []string{"identity", "mismatched identity", "journal", "provider", "provider panic"} {
		t.Run(boundary, func(t *testing.T) {
			f := newMinimalWorkerBindingFixture(t)
			api := requireMinimalWorkerAPI(t, f.r)
			if err := api.BindWorker(f.input, f.journal); err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			block := func() error {
				once.Do(func() { close(entered) })
				<-release
				return errors.New("sensitive callback error")
			}
			f.p.before = func(owner *minimalWorkerBindingOwner) {
				switch boundary {
				case "identity":
					owner.inspect = func() MinimalLaunchIdentity { _ = block(); panic("sensitive identity panic") }
				case "mismatched identity":
					owner.inspect = func() MinimalLaunchIdentity {
						_ = block()
						id := owner.identity
						id.JobGeneration = "foreign-generation"
						return id
					}
				case "journal":
					f.journal.check = func(*MinimalLaunchReservation) error { return block() }
				case "provider":
					f.p.after = block
				case "provider panic":
					f.p.after = func() error { _ = block(); panic("sensitive provider panic") }
				}
			}
			f.p.register = true
			f.arm(t)
			done := make(chan struct{})
			var returned *MinimalLaunchOwnerBinding
			var startErr error
			go func() {
				defer close(done)
				returned, startErr = f.binding.Start(f.r, f.selection, func() error { return nil })
			}()
			defer func() {
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("Start did not join after rescue")
				}
			}()
			select {
			case <-entered:
			case <-done:
				t.Fatal("Start returned before required blocked callback")
			case <-time.After(5 * time.Second):
				t.Fatal("callback was not reached")
			}
			observed := make(chan *MinimalLaunchOwnerBinding, 1)
			go func() { observed <- api.RetainedWorkerOwner() }()
			var slot *MinimalLaunchOwnerBinding
			select {
			case slot = <-observed:
			case <-time.After(5 * time.Second):
				unblock()
				slot = <-observed // Join the observation too; never discard a waiter.
				t.Error("retained-slot observation blocked behind callback")
			}
			if slot == nil || slot.owner != f.p.owner || slot.identity != f.r.Identity() || f.p.claims.Load() != 1 {
				t.Error("original partial owner was not retained before callback")
			}
			unblock()
			<-done
			if returned != slot || !errors.Is(startErr, ErrMinimalLaunchUnavailable) || strings.Contains(startErr.Error(), "sensitive") {
				t.Fatal("callback failure lost/reconstructed owner or leaked cause")
			}
			f.r.Revoke()
			if api.RetainedWorkerOwner() != slot || requireMinimalWorkerAPI(t, copyMinimalWorkerReservation(f.r)).RetainedWorkerOwner() != nil {
				t.Fatal("cleanup lookup lost original or accepted copied reservation")
			}
		})
	}
}
