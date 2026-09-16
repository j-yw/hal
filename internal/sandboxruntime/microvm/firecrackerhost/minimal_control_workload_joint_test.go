//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

// These tests join the real host Client, original authenticated controller and
// selected guest Server over ordinary Unix I/O. Backend and inspection are
// explicit fakes: neither prepared Linux execution nor VM isolation is claimed.
type minimalJointBackend struct {
	ready         func(context.Context) error
	exec          func(context.Context, server.ExecPlan) (server.ExecResult, error)
	copyIn        func(context.Context, server.CopyInPlan) (server.CopyResult, error)
	copyOut       func(context.Context, server.CopyOutPlan) (server.CopyResult, error)
	calls, closes atomic.Int32
}

func (b *minimalJointBackend) Ready(ctx context.Context) error {
	if b.ready != nil {
		return b.ready(ctx)
	}
	return nil
}
func (b *minimalJointBackend) Exec(ctx context.Context, plan server.ExecPlan) (server.ExecResult, error) {
	b.calls.Add(1)
	if b.exec != nil {
		return b.exec(ctx, plan)
	}
	return server.ExecResult{}, errors.New("unexpected exec")
}
func (b *minimalJointBackend) CopyIn(ctx context.Context, plan server.CopyInPlan) (server.CopyResult, error) {
	b.calls.Add(1)
	if b.copyIn != nil {
		return b.copyIn(ctx, plan)
	}
	return server.CopyResult{}, errors.New("unexpected copy")
}
func (b *minimalJointBackend) CopyOut(ctx context.Context, plan server.CopyOutPlan) (server.CopyResult, error) {
	b.calls.Add(1)
	if b.copyOut != nil {
		return b.copyOut(ctx, plan)
	}
	return server.CopyResult{}, errors.New("unexpected copy")
}
func (b *minimalJointBackend) Close(context.Context) error { b.closes.Add(1); return nil }

type minimalJointVerifier struct{ calls atomic.Int32 }

func (v *minimalJointVerifier) VerifyWorkloadIsolation(context.Context) (server.IsolationProofResult, error) {
	v.calls.Add(1)
	return server.IsolationProofResult{RestrictedIdentity: true, CapabilitiesCleared: true,
		NoNewPrivileges: true, SupplementaryGroupsCleared: true, RawPacketSocketDenied: true,
		Network: server.NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusVerified,
			SingleInterface: true, StaticRoutes: true, ProxyReachable: true}}, nil
}

func newMinimalJointFixture(t *testing.T, admission *minimalControlSupervisorAdmission, backend *minimalJointBackend, faults ...*minimalControllerPeerFault) (*minimalControllerFixture, *minimalJointVerifier, <-chan struct{}) {
	t.Helper()
	f := newMinimalControllerRetainedPeerFixture(t, admission)
	public, ok := minimalControlConfigBase64(admission.config.Control.ControllerPublicKey)
	if !ok {
		t.Fatal("invalid fixture public key")
	}
	line, err := minimalcontrol.RenderBootCommandLine("", f.identity, public[:], f.fields)
	if err != nil {
		t.Fatal(err)
	}
	boot, present, err := minimalcontrol.ParseBootCommandLine(line)
	if err != nil || !present {
		t.Fatal("invalid fixture boot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	var listener minimalcontrol.Listener = f.listener
	if len(faults) != 0 {
		listener = &minimalControllerPeerListener{base: f.listener, fault: faults[0]}
	}
	transport, err := minimalcontrol.NewWorkloadTransport(minimalcontrol.BootstrapOptions{Listener: listener, Boot: boot,
		OwnerDone: ctx.Done(), Random: bytes.NewReader(bytes.Repeat([]byte{73}, 96))})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	verifier := &minimalJointVerifier{}
	guest, err := server.New(server.Options{Transport: transport, Backend: backend, WorkloadIsolationVerifier: verifier,
		RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = guest.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = f.listener.Close()
		minimalJointAwait(t, done, "actual enclosing guest cleanup")
		if backend.closes.Load() != 1 {
			t.Error("backend cleanup not joined exactly once")
		}
	})
	return f, verifier, done
}

func minimalJointAwait(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal(label + " did not complete")
	}
}

func minimalJointClient(t *testing.T, c *minimalControlController) (*guestagent.Client, guestagent.Transport, *minimalControlReadiness) {
	t.Helper()
	r := minimalControllerRequireReady(t, c)
	transport, err := r.workloadTransport()
	if err != nil {
		t.Fatal(err)
	}
	client, err := guestagent.NewClient(guestagent.ClientOptions{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	return client, transport, r
}

func minimalJointExecRequest() guestagent.ExecRequest {
	return guestagent.ExecRequest{Args: []string{"hal", "--version"}, WorkDir: "/workspace",
		Stdout: guestagent.StreamMetadata{MaxBytes: 64}, Stderr: guestagent.StreamMetadata{MaxBytes: 64}}
}

func TestMinimalHostWorkloadJointSequentialExecAndMaximumCopy(t *testing.T) {
	data := bytes.Repeat([]byte{0, 1, 127, 255}, int(server.DefaultCopyBytes)/4)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	backend := &minimalJointBackend{
		exec: func(_ context.Context, plan server.ExecPlan) (server.ExecResult, error) {
			if !reflect.DeepEqual(plan.Args, []string{"hal", "--version"}) || plan.WorkDir != "/workspace" ||
				len(plan.Environment) != 0 || len(plan.Stdin) != 0 || plan.StdoutMaxBytes != 64 || plan.StderrMaxBytes != 64 {
				return server.ExecResult{}, errors.New("exec plan differs")
			}
			return server.ExecResult{ExitCode: 7, Stdout: []byte("exact output\n"), Stderr: []byte("exact error\n")}, nil
		},
		copyIn: func(_ context.Context, plan server.CopyInPlan) (server.CopyResult, error) {
			if plan.DestinationPath != "/workspace/payload.bin" || plan.Digest != digest || plan.MaxBytes != server.DefaultCopyBytes || !bytes.Equal(plan.Data, data) {
				return server.CopyResult{}, errors.New("copy-in plan differs")
			}
			return server.CopyResult{Published: true, SizeBytes: int64(len(data)), Digest: digest}, nil
		},
		copyOut: func(_ context.Context, plan server.CopyOutPlan) (server.CopyResult, error) {
			if plan.SourcePath != "/workspace/payload.bin" || plan.MaxBytes != server.DefaultCopyBytes {
				return server.CopyResult{}, errors.New("copy-out plan differs")
			}
			return server.CopyResult{Data: data, SizeBytes: int64(len(data)), Digest: digest}, nil
		},
	}
	a := newMinimalControlAdmissionFixture(t)
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		f, verifier, done := newMinimalJointFixture(t, admission, backend)
		return withMinimalWorkloadController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
			client, _, ready := minimalJointClient(t, c)
			for index := 0; index < 50; index++ {
				response, err := client.Exec(context.Background(), minimalJointExecRequest())
				if err != nil || response.ExitCode != 7 || response.Stdout.Data != base64.StdEncoding.EncodeToString([]byte("exact output\n")) ||
					response.Stderr.Data != base64.StdEncoding.EncodeToString([]byte("exact error\n")) {
					t.Fatalf("exact sequential response %d failed: %v", index, err)
				}
			}
			in, err := client.CopyIn(context.Background(), guestagent.CopyInRequest{DestinationPath: "/workspace/payload.bin",
				Payload: guestagent.PayloadMetadata{Data: base64.StdEncoding.EncodeToString(data), Encoding: guestagent.PayloadEncodingBase64,
					SizeBytes: int64(len(data)), MaxBytes: server.DefaultCopyBytes, Digest: digest}})
			if err != nil || in.Written.Digest != digest || in.Written.SizeBytes != int64(len(data)) {
				t.Fatal("copy-in acknowledgement differs", err)
			}
			out, err := client.CopyOut(context.Background(), guestagent.CopyOutRequest{SourcePath: "/workspace/payload.bin",
				Payload: guestagent.PayloadMetadata{MaxBytes: server.DefaultCopyBytes, Encoding: guestagent.PayloadEncodingBase64}})
			if err != nil || out.Payload.Digest != digest || out.Payload.Data != base64.StdEncoding.EncodeToString(data) {
				t.Fatal("copy-out bytes differ", err)
			}
			if backend.calls.Load() != 52 || verifier.calls.Load() != 53 || !ready.Current() || f.listener.connects.Load() != 1 {
				t.Fatal("work was duplicated, lacked a fresh inspection, retired or reconnected")
			}
			if c.Close() != nil {
				t.Fatal("host close failed")
			}
			minimalControllerRequireJoined(t, c, admission.controllerKey)
			minimalJointAwait(t, done, "guest joined after original host close")
			return nil
		})
	})
	if code != 0 {
		t.Fatal("joint success scope failed", code)
	}
}

func TestMinimalHostWorkloadJointCancellationAndBusy(t *testing.T) {
	for _, loss := range []string{"caller", "host-owner", "guest-owner", "host-close"} {
		t.Run(loss, func(t *testing.T) {
			entered, canceled := make(chan struct{}), make(chan struct{})
			backend := &minimalJointBackend{exec: func(ctx context.Context, _ server.ExecPlan) (server.ExecResult, error) {
				close(entered)
				<-ctx.Done()
				close(canceled)
				return server.ExecResult{}, ctx.Err()
			}}
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f, _, guestDone := newMinimalJointFixture(t, admission, backend)
				owner, cancelOwner := context.WithCancel(context.Background())
				defer cancelOwner()
				err := withMinimalWorkloadController(owner, f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
					client, transport, ready := minimalJointClient(t, c)
					caller, cancelCaller := context.WithCancel(context.Background())
					defer cancelCaller()
					result, finished := make(chan error, 1), make(chan struct{})
					go func() { defer close(finished); _, err := client.Exec(caller, minimalJointExecRequest()); result <- err }()
					minimalJointAwait(t, entered, "actual joint backend entry")
					_, busy := transport.RoundTrip(context.Background(), guestagent.TransportRequest{ProtocolVersion: guestagent.ProtocolVersionV1,
						Operation: guestagent.OperationExec, Encoded: []byte(`{}`), MaxResponseBytes: 512})
					var protocol *guestagent.ProtocolError
					if !errors.As(busy, &protocol) || protocol.Code != guestagent.ErrorCodeServerBusy || !ready.Current() || backend.calls.Load() != 1 {
						t.Fatal("concurrent call did not return bounded busy without disturbing original work", busy)
					}
					preCanceled, cancelBefore := context.WithCancel(context.Background())
					cancelBefore()
					if _, err := client.Exec(preCanceled, minimalJointExecRequest()); err == nil || !ready.Current() || backend.calls.Load() != 1 {
						t.Fatal("unadmitted canceled call disturbed the actual pending work")
					}
					switch loss {
					case "caller":
						cancelCaller()
					case "host-owner":
						cancelOwner()
					case "guest-owner":
						f.cancel()
					case "host-close":
						if c.Close() != nil {
							t.Fatal("close failed")
						}
					}
					minimalJointAwait(t, canceled, "actual backend cancellation without test release")
					minimalJointAwait(t, finished, "original host call joined")
					operationErr := <-result
					if operationErr == nil || ready.Current() {
						t.Fatal("lost operation succeeded or readiness survived")
					}
					if c.Close() != nil {
						t.Fatal("host did not join")
					}
					minimalControllerRequireJoined(t, c, admission.controllerKey)
					minimalJointAwait(t, guestDone, "enclosing guest joined on loss")
					if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err == nil || backend.calls.Load() != 1 || f.listener.connects.Load() != 1 {
						t.Fatal("retired transport retried or executed more work")
					}
					// The scope reports authentication/callback success, not an
					// implicit last-operation result. The actual consumer owns it.
					return operationErr
				})
				if err == nil {
					t.Fatal("owner loss became successful scope")
				}
				return nil
			})
			if code != 0 {
				t.Fatal("joint cancellation fixture failed", code)
			}
		})
	}
}

func TestMinimalHostWorkloadJointCorruptResponseRetiresWithoutRetry(t *testing.T) {
	for _, effect := range []string{"bad-magic", "ciphertext", "short-prefix", "short-body"} {
		t.Run(effect, func(t *testing.T) {
			backend := &minimalJointBackend{exec: func(context.Context, server.ExecPlan) (server.ExecResult, error) {
				return server.ExecResult{Stdout: []byte("untrusted result")}, nil
			}}
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				fault := &minimalControllerPeerFault{stage: 4, effect: effect, reached: make(chan struct{})}
				f, _, done := newMinimalJointFixture(t, admission, backend, fault)
				err := withMinimalWorkloadController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
					client, _, ready := minimalJointClient(t, c)
					response, operationErr := client.Exec(context.Background(), minimalJointExecRequest())
					minimalJointAwait(t, fault.reached, "actual post-backend response corruption")
					if operationErr == nil || response != nil || backend.calls.Load() != 1 || ready.Current() {
						t.Fatal("corrupt wire accepted, work repeated, or session retained")
					}
					if c.Close() != nil {
						t.Fatal("corrupt response owner failed to join")
					}
					minimalControllerRequireJoined(t, c, admission.controllerKey)
					minimalJointAwait(t, done, "guest after actual corrupt response")
					if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err == nil || backend.calls.Load() != 1 || f.listener.connects.Load() != 1 {
						t.Fatal("corrupt response triggered a retry/reconnect")
					}
					return operationErr
				})
				if err == nil {
					t.Fatal("corrupt operation callback became successful")
				}
				return nil
			})
			if code != 0 {
				t.Fatal("corrupt response fixture failed", code)
			}
		})
	}
}
