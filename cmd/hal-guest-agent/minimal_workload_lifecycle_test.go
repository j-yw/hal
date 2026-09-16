package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/vsock"
)

func TestMinimalGuestCommandPreparationFailureNeverReadies(t *testing.T) {
	for _, fault := range []string{"ready-error", "ready-panic", "proof-error", "proof-panic", "process-denied", "network-denied"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newMinimalCommandFixtureWithSetup(t, func(fixture *minimalCommandFixture) {
				fixture.backend.ready = func(context.Context) error {
					if fault == "ready-error" {
						return errors.New("private backend readiness canary")
					}
					if fault == "ready-panic" {
						panic("private backend readiness canary")
					}
					return nil
				}
				fixture.proof.verify = func(context.Context) (server.IsolationProofResult, error) {
					if fault == "proof-error" {
						return server.IsolationProofResult{}, errors.New("private proof canary")
					}
					if fault == "proof-panic" {
						panic("private proof canary")
					}
					result := minimalCommandVerifiedIsolation()
					if fault == "process-denied" {
						result.RestrictedIdentity = false
					}
					if fault == "network-denied" {
						result.Network.ProxyReachable = false
					}
					return result, nil
				}
			})
			state := fixture.establish(t)
			request, _ := minimalREDRequest(t, state, minimalREDBinding(fixture.identity))
			minimalREDWrite(t, fixture.peer, minimalREDSeal(t, state, request))
			minimalREDAssertClosed(t, fixture.peer)
			minimalCommandAwait(t, fixture.finished, "failed preparation cleanup")
			if fixture.result == nil || strings.Contains(fixture.result.Error(), "private") || fixture.backend.readyCalls.Load() != 1 || fixture.backend.execCalls.Load() != 0 {
				t.Errorf("preparation failure escaped or dispatched work: result=%v ready=%d exec=%d", fixture.result, fixture.backend.readyCalls.Load(), fixture.backend.execCalls.Load())
			}
		})
	}
}

func TestMinimalGuestCommandFreshProofCannotBeCached(t *testing.T) {
	for _, denied := range []string{"process", "network"} {
		t.Run(denied, func(t *testing.T) {
			fixture := newMinimalCommandFixtureWithSetup(t, func(fixture *minimalCommandFixture) {
				fixture.proof.verify = func(context.Context) (server.IsolationProofResult, error) {
					result := minimalCommandVerifiedIsolation()
					if fixture.proof.calls.Load() > 1 {
						if denied == "process" {
							result.RawPacketSocketDenied = false
						} else {
							result.Network.StaticRoutes = false
						}
					}
					return result, nil
				}
			})
			client := fixture.authenticate(t)
			if _, err := client.Exec(context.Background(), minimalCommandExecRequest()); err == nil || fixture.proof.calls.Load() != 2 || fixture.backend.execCalls.Load() != 0 {
				t.Errorf("selected command reused readiness proof: error=%v proof=%d exec=%d", err, fixture.proof.calls.Load(), fixture.backend.execCalls.Load())
			}
		})
	}
}

func TestMinimalGuestCommandBackendErrorAndPanicAreSanitized(t *testing.T) {
	for _, fault := range []string{"error", "panic"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newMinimalCommandFixtureWithSetup(t, func(fixture *minimalCommandFixture) {
				fixture.backend.exec = func(context.Context, server.ExecPlan) (server.ExecResult, error) {
					if fault == "panic" {
						panic("private backend execution canary")
					}
					return server.ExecResult{}, errors.New("private backend execution canary")
				}
			})
			client := fixture.authenticate(t)
			if _, err := client.Exec(context.Background(), minimalCommandExecRequest()); err == nil || strings.Contains(err.Error(), "private") || fixture.backend.execCalls.Load() != 1 || fixture.proof.calls.Load() != 2 {
				t.Errorf("backend failure escaped or skipped real admission: error=%v exec=%d proof=%d", err, fixture.backend.execCalls.Load(), fixture.proof.calls.Load())
			}
		})
	}
}

func TestMinimalGuestCommandRejectsRequestEnvironmentAuthority(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "TASK_SECRET"} {
		for _, source := range []guestagent.EnvironmentSource{guestagent.EnvironmentSourceLiteral, guestagent.EnvironmentSourceSecret, guestagent.EnvironmentSourceInherited, guestagent.EnvironmentSourceGenerated} {
			t.Run(name+"/"+string(source), func(t *testing.T) {
				fixture := newMinimalCommandFixture(t)
				fixture.authenticate(t)
				request := minimalCommandExecRequest()
				request.ProtocolVersion, request.Operation = guestagent.ProtocolVersionV1, guestagent.OperationExec
				request.Env = []guestagent.EnvironmentEntry{{Name: name, Source: source}}
				encoded, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				// Bypass only client prevalidation so lowercase proxy names reach
				// the actual server's existing strict environment-name rejection.
				response, err := fixture.transport.RoundTrip(context.Background(), guestagent.TransportRequest{Encoded: encoded, MaxResponseBytes: server.DefaultMaxResponseBytes})
				if err != nil {
					t.Fatal(err)
				}
				var decoded guestagent.ErrorResponse
				if err := json.Unmarshal(response.Encoded, &decoded); err != nil {
					t.Fatal(err)
				}
				wantCode, wantProof := guestagent.ErrorCodeEnvironmentUnavailable, int32(2)
				if name == "http_proxy" || name == "https_proxy" {
					wantCode, wantProof = guestagent.ErrorCodeInvalidMetadata, 1
				}
				if decoded.Error == nil || decoded.Error.Code != wantCode || fixture.backend.execCalls.Load() != 0 || fixture.proof.calls.Load() != wantProof {
					t.Errorf("request environment became authority or bypassed real server: error=%v exec=%d proof=%d", decoded.Error, fixture.backend.execCalls.Load(), fixture.proof.calls.Load())
				}
			})
		}
	}
}

func TestMinimalGuestCommandBlockedWorkCancelsAndJoins(t *testing.T) {
	for _, loss := range []string{"owner", "eof"} {
		t.Run(loss, func(t *testing.T) {
			entered, observed := make(chan struct{}), make(chan struct{})
			fixture := newMinimalCommandFixtureWithSetup(t, func(fixture *minimalCommandFixture) {
				fixture.backend.exec = func(ctx context.Context, _ server.ExecPlan) (server.ExecResult, error) {
					close(entered)
					<-ctx.Done()
					close(observed)
					return server.ExecResult{}, ctx.Err()
				}
				fixture.backend.close = func(ctx context.Context) error {
					select {
					case <-observed:
					default:
						return errors.New("backend closed before operation joined")
					}
					if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil {
						return errors.New("cleanup context lost independent bounded lifetime")
					}
					return nil
				}
			})
			client := fixture.authenticate(t)
			workDone := make(chan error, 1)
			go func() { _, err := client.Exec(context.Background(), minimalCommandExecRequest()); workDone <- err }()
			minimalCommandAwait(t, entered, "actual backend entry")
			if loss == "owner" {
				fixture.cancel()
			} else {
				_ = fixture.peer.Close()
			}
			minimalCommandAwait(t, observed, "backend cancellation without rescue release")
			minimalCommandAwait(t, fixture.finished, "command cleanup join")
			select {
			case err := <-workDone:
				if err == nil {
					t.Error("lost connection reported successful work")
				}
			case <-time.After(time.Second):
				t.Error("client did not join")
			}
			if fixture.backend.closeCalls.Load() != 1 || fixture.backend.execCalls.Load() != 1 {
				t.Error("blocked work cleanup ownership differs")
			}
		})
	}
}

func TestMinimalGuestCommandPartialCleanupIsBoundedAndSanitized(t *testing.T) {
	for _, fault := range []string{"error", "panic"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			backend := &minimalCommandBackend{close: func(ctx context.Context) error {
				deadline, bounded := ctx.Deadline()
				if !bounded || ctx.Err() != nil || time.Until(deadline) > server.DefaultMaxShutdownTime {
					t.Error("partial cleanup context is not independently bounded")
				}
				if fault == "panic" {
					panic("private cleanup panic canary")
				}
				return errors.New("private cleanup failure canary")
			}}
			dependencies := minimalCommandDependencies(t, backend, &minimalCommandVerifier{}, func() (vsock.Listener, error) { cancel(); return nil, nil })
			err := minimalCommandCapturePanic(t, func() error {
				return runMinimalGuestAgentWithDependencies(ctx, minimalBootstrapREDBootLine()+" "+minimalCommandL7Line, dependencies)
			})
			if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "private") || backend.closeCalls.Load() != 1 {
				t.Errorf("partial cleanup failure escaped or lost ownership: %v, closes=%d", err, backend.closeCalls.Load())
			}
		})
	}
}

func TestMinimalGuestCommandServeCleanupFailureRemainsFailure(t *testing.T) {
	fixture := newMinimalCommandFixtureWithSetup(t, func(fixture *minimalCommandFixture) {
		fixture.backend.close = func(context.Context) error { return errors.New("private backend cleanup canary") }
	})
	fixture.authenticate(t)
	fixture.cancel()
	minimalCommandAwait(t, fixture.finished, "failed cleanup return")
	if fixture.result == nil || !strings.Contains(fixture.result.Error(), "cleanup failed") || strings.Contains(fixture.result.Error(), "private") || fixture.backend.closeCalls.Load() != 1 {
		t.Errorf("server cleanup failure was hidden or leaked: result=%v closes=%d", fixture.result, fixture.backend.closeCalls.Load())
	}
}

func TestMinimalGuestCommandLookupPanicCannotConstruct(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &minimalCommandBackend{}
	proof := &minimalCommandVerifier{}
	listens := 0
	dependencies := minimalCommandDependencies(t, backend, proof, func() (vsock.Listener, error) { listens++; return nil, nil })
	dependencies.lookupEnvironment = func(string) (string, bool) { panic("private environment canary") }
	err := minimalCommandCapturePanic(t, func() error {
		return runMinimalGuestAgentWithDependencies(ctx, minimalBootstrapREDBootLine()+" "+minimalCommandL7Line, dependencies)
	})
	if err == nil || strings.Contains(err.Error(), "private") || listens != 0 || backend.constructors.Load() != 0 || proof.networkConstructors.Load() != 0 || proof.workloadConstructors.Load() != 0 {
		t.Errorf("lookup panic escaped or constructed authority: %v", err)
	}
}

func minimalCommandExecRequest() guestagent.ExecRequest {
	return guestagent.ExecRequest{Args: []string{"hal", "--version"}, WorkDir: "/workspace", Stdout: guestagent.StreamMetadata{MaxBytes: 64}, Stderr: guestagent.StreamMetadata{MaxBytes: 64}}
}

func minimalCommandAwait(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("did not observe %s", label)
	}
}
