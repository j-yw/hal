//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

type minimalInspectionVerifierFunc func(context.Context) (server.IsolationProofResult, error)

func (fn minimalInspectionVerifierFunc) VerifyWorkloadIsolation(ctx context.Context) (server.IsolationProofResult, error) {
	return fn(ctx)
}

// Forward faults are installed only at original guest construction, preserving
// both frozen RED files and the original host fixture. Callers wrap the concrete
// no-request verifier, never replace the host controller or synthesize its proof.
func minimalInspectionForwardGuest(t *testing.T, f *minimalSupervisorJointFixture,
	configure func(*server.Options, *minimalHostInspectionObservations)) (*minimalHostInspectionObservations, <-chan struct{}, func()) {
	t.Helper()
	listener := f.listener.Load()
	if listener == nil || !f.private.Load() {
		t.Fatal("original private listener missing")
	}
	fc, err := readMinimalControlFirecrackerConfig(f.admission.borrowed[6], f.admission.config.Config)
	if err != nil {
		t.Fatal("original retained boot missing")
	}
	boot, present, err := minimalcontrol.ParseBootCommandLine(fc.BootSource.BootArgs)
	if err != nil || !present {
		t.Fatal("actual selected boot invalid")
	}
	o := &minimalHostInspectionObservations{}
	o.backend = &minimalJointBackend{ready: func(context.Context) error { o.ready.Add(1); return nil }}
	verifier, err := server.NewLinuxWorkloadIsolationVerifier(server.LinuxIsolationVerifierOptions{ProcessBoundary: o, NetworkVerifier: o})
	if err != nil {
		t.Fatal("concrete verifier construction")
	}
	ctx, cancel := context.WithCancel(f.owned.minimalPreparation.ctx)
	transport, err := minimalcontrol.NewWorkloadTransport(minimalcontrol.BootstrapOptions{Listener: listener, Boot: boot,
		OwnerDone: ctx.Done(), Random: bytes.NewReader(bytes.Repeat([]byte{73}, 96))})
	if err != nil {
		cancel()
		t.Fatal("actual encrypted workload transport construction")
	}
	options := server.Options{Transport: transport, Backend: o.backend, WorkloadIsolationVerifier: verifier, EnvironmentResolver: o,
		RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true}
	configure(&options, o)
	guest, err := server.New(options)
	if err != nil {
		cancel()
		t.Fatal("actual Server construction")
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = guest.Serve(ctx) }()
	return o, done, func() {
		cancel()
		_ = listener.Close()
		minimalJointAwait(t, done, "forward guest joined")
		if o.backend.closes.Load() != 1 {
			t.Error("forward guest backend close not joined exactly once")
		}
	}
}
