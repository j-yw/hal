package minimalcontrol

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

type inspectionVerifierFunc func(context.Context) (server.IsolationProofResult, error)

func (verify inspectionVerifierFunc) VerifyWorkloadIsolation(ctx context.Context) (server.IsolationProofResult, error) {
	return verify(ctx)
}

func TestSelectedInspectionRetainsExactSecureBindingAndOrdinal(t *testing.T) {
	cases := append([]string{"session", "ordinal", "frame", "replay"}, bindingFields...)
	for _, changed := range cases {
		t.Run(changed, func(t *testing.T) {
			fixture, calls := inspectionLifecycleFixture(t, workloadTransportVerifier{}.VerifyWorkloadIsolation)
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			clear(fixture.readiness(t, peer, state, fixture.binding))
			id, ordinal, kind := state.SessionID(), uint64(1), session.FrameTypeControlRequest
			foreign := Binding{fields: maps.Clone(fixture.binding.fields)}
			switch changed {
			case "session":
				id[0]++
			case "ordinal":
				ordinal = 2
			case "frame":
				kind = session.FrameTypeControlPrivate
			case "replay":
			default:
				foreign.fields[changed] += "-changed"
			}
			payload, err := foreign.EncodeWorkload([]byte(inspectionRequest), ordinal, id)
			if err != nil {
				t.Fatal("negative envelope fixture encoding")
			}
			wire, err := state.SealApplication(kind, payload)
			clear(payload)
			if err != nil {
				t.Fatal("actual negative request authentication")
			}
			defer clear(wire)
			if changed == "replay" {
				write(t, peer, wire)
				clear(workloadResponse(t, fixture, peer, state, 1))
			}
			write(t, peer, wire)
			assertClosed(t, peer)
			if fixture.wait(t) == nil {
				t.Fatal("mismatched inspection remained current")
			}
			want := int32(1)
			if changed == "replay" {
				want = 2
			}
			if calls.Load() != want {
				t.Fatal("wrong original binding/session/ordinal crossed inspection boundary")
			}
		})
	}
}

func TestSelectedInspectionPendingNextWaitsForWriterAndCannotQueueMore(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(map[bool]string{false: "one next work", true: "second pending retires"}[extra], func(t *testing.T) {
			fixture, calls := inspectionLifecycleFixture(t, workloadTransportVerifier{}.VerifyWorkloadIsolation)
			peer, held := connectHeldWorkloadWriter(t, fixture, 4)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			clear(fixture.readiness(t, peer, state, fixture.binding))
			wire := workloadRecord(t, fixture, state, []byte(inspectionRequest), 1)
			write(t, peer, wire)
			clear(wire)
			clear(workloadResponse(t, fixture, peer, state, 1))
			await(t, held.held, "inspection reply consumed before writer return")
			wire = workloadRecord(t, fixture, state, workloadInnerExec(t), 2)
			write(t, peer, wire)
			clear(wire)
			peer.other.awaitIO(t, 13, 4)
			if calls.Load() != 2 {
				t.Fatal("pending next work ran before inspection writer joined")
			}
			if extra {
				wire = workloadRecord(t, fixture, state, []byte(inspectionRequest), 3)
				write(t, peer, wire)
				clear(wire)
				assertClosed(t, peer)
				fixture.wait(t)
				if calls.Load() != 2 {
					t.Fatal("second pending request was queued")
				}
			} else {
				close(held.release)
				inner := workloadResponse(t, fixture, peer, state, 2)
				if !bytes.Contains(inner, []byte(`"exitCode":7`)) || calls.Load() != 3 {
					t.Error("same-session work after inspection did not dispatch once")
				}
				clear(inner)
			}
		})
	}
}

type inspectionWithoutResultTransport struct{ server.Transport }
type inspectionWithoutResultHandler struct {
	server.Handler
	server.WorkloadHandler
}

func (transport inspectionWithoutResultTransport) Serve(ctx context.Context, limits server.Limits, handler server.Handler) error {
	return transport.Transport.Serve(ctx, limits, inspectionWithoutResultHandler{handler, handler.(server.WorkloadHandler)})
}

func TestSelectedInspectionMissingOptionalResultSupportNeverFallsBack(t *testing.T) {
	fixture := newWorkloadTransportFixture(t, &workloadTransportBackend{}, func(options *server.Options) {
		// Delegate all original algorithms; expose only the existing handler
		// interfaces so the new optional result method really is unavailable.
		options.Transport = inspectionWithoutResultTransport{options.Transport}
	})
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	clear(fixture.readiness(t, peer, state, fixture.binding))
	wire := workloadRecord(t, fixture, state, []byte(inspectionRequest), 1)
	write(t, peer, wire)
	clear(wire)
	inner := workloadResponse(t, fixture, peer, state, 1)
	if string(inner) != inspectionUnavailable {
		t.Error("missing support fell back or fabricated proof")
	}
	clear(inner)
	assertClosed(t, peer)
	if fixture.wait(t) == nil {
		t.Fatal("missing inspection support retained stream")
	}
}

func TestSelectedInspectionRecognitionDoesNotCaptureLegacyNestedValues(t *testing.T) {
	for _, request := range []string{
		`{"protocolVersion":"guest-agent-v1","operation":"exec","args":["inspect_isolation","guest-agent-minimal-v1"]}`,
		`{"operation":"exec","body":{"operation":"inspect_isolation"},"protocolVersion":"guest-agent-v1"}`,
		`{"operation":`, `null`,
	} {
		owned := []byte(request)
		if selectsInspection(owned) || string(owned) != request {
			t.Fatal("inspection selector captured or mutated unrelated v1 input")
		}
	}
}

func inspectionLifecycleFixture(t *testing.T, inspect func(context.Context) (server.IsolationProofResult, error)) (*bootstrapFixture, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	fixture := newWorkloadTransportFixture(t, &workloadTransportBackend{}, func(options *server.Options) {
		options.WorkloadIsolationVerifier = inspectionVerifierFunc(func(ctx context.Context) (server.IsolationProofResult, error) {
			if calls.Add(1) == 1 {
				return workloadTransportVerifier{}.VerifyWorkloadIsolation(ctx)
			}
			return inspect(ctx)
		})
	})
	return fixture, calls
}

func TestSelectedInspectionMalformedCanonicalRequestRetires(t *testing.T) {
	for name, payload := range map[string]string{
		"unknown":          strings.TrimSuffix(inspectionRequest, "}") + `,"extra":true}`,
		"duplicate":        `{"operation":"inspect_isolation","operation":"inspect_isolation","protocolVersion":"guest-agent-minimal-v1"}`,
		"duplicate hidden": `{"operation":"inspect\u005fisolation","operation":"exec","protocolVersion":"guest-agent-v1"}`,
		"reordered":        `{"protocolVersion":"guest-agent-minimal-v1","operation":"inspect_isolation"}`,
		"escaped key":      `{"\u006fperation":"inspect_isolation","protocolVersion":"guest-agent-minimal-v1"}`,
		"case aliases":     `{"Operation":"inspect_isolation","ProtocolVersion":"guest-agent-minimal-v1"}`,
		"escaped value":    `{"operation":"inspect\u005fisolation","protocolVersion":"guest-agent-minimal-v1"}`,
		"space":            " " + inspectionRequest,
		"newline":          inspectionRequest + "\n",
		"trailing":         inspectionRequest + `{}`,
		"truncated":        strings.TrimSuffix(inspectionRequest, "}"),
		"timing":           strings.TrimSuffix(inspectionRequest, "}") + `,"timing":{"timeoutMillis":1}}`,
		"generation":       strings.TrimSuffix(inspectionRequest, "}") + `,"generation":"request-authority"}`,
		"environment":      strings.TrimSuffix(inspectionRequest, "}") + `,"env":[]}`,
		"body":             strings.TrimSuffix(inspectionRequest, "}") + `,"body":null}`,
		"oversized":        strings.TrimSuffix(inspectionRequest, "}") + `,"args":"` + strings.Repeat("x", 2048) + `"}`,
		"wrong protocol":   `{"operation":"inspect_isolation","protocolVersion":"guest-agent-v1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			fixture, calls := inspectionLifecycleFixture(t, workloadTransportVerifier{}.VerifyWorkloadIsolation)
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			clear(fixture.readiness(t, peer, state, fixture.binding))
			wire := workloadRecord(t, fixture, state, []byte(payload), 1)
			write(t, peer, wire)
			clear(wire)
			assertClosed(t, peer)
			if fixture.wait(t) == nil || calls.Load() != 1 {
				t.Fatal("noncanonical inspection dispatched or retained stream")
			}
		})
	}
}

func TestSelectedInspectionFailureReplyIsFixedAndRetires(t *testing.T) {
	for name, change := range map[string]func(*server.IsolationProofResult) error{
		"error":        func(*server.IsolationProofResult) error { return errors.New("private-inspection-error") },
		"identity":     func(r *server.IsolationProofResult) error { r.RestrictedIdentity = false; return nil },
		"capabilities": func(r *server.IsolationProofResult) error { r.CapabilitiesCleared = false; return nil },
		"privileges":   func(r *server.IsolationProofResult) error { r.NoNewPrivileges = false; return nil },
		"groups":       func(r *server.IsolationProofResult) error { r.SupplementaryGroupsCleared = false; return nil },
		"raw":          func(r *server.IsolationProofResult) error { r.RawPacketSocketDenied = false; return nil },
		"network status": func(r *server.IsolationProofResult) error {
			r.Network.Status = guestagent.IsolationProofStatusFailed
			return nil
		},
		"interface": func(r *server.IsolationProofResult) error { r.Network.SingleInterface = false; return nil },
		"routes":    func(r *server.IsolationProofResult) error { r.Network.StaticRoutes = false; return nil },
		"proxy":     func(r *server.IsolationProofResult) error { r.Network.ProxyReachable = false; return nil },
	} {
		t.Run(name, func(t *testing.T) {
			fixture, calls := inspectionLifecycleFixture(t, func(ctx context.Context) (server.IsolationProofResult, error) {
				result, _ := workloadTransportVerifier{}.VerifyWorkloadIsolation(ctx)
				err := change(&result)
				return result, err
			})
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			clear(fixture.readiness(t, peer, state, fixture.binding))
			wire := workloadRecord(t, fixture, state, []byte(inspectionRequest), 1)
			write(t, peer, wire)
			clear(wire)
			inner := workloadResponse(t, fixture, peer, state, 1)
			defer clear(inner)
			if string(inner) != inspectionUnavailable {
				t.Error("failed proof was not the exact sanitized unavailable response")
			}
			assertClosed(t, peer)
			if fixture.wait(t) == nil || calls.Load() != 2 {
				t.Fatal("failed inspection retained stream or was not fresh")
			}
		})
	}
}

func TestSelectedInspectionBlockedVerifierObservesLoss(t *testing.T) {
	for _, loss := range []string{"eof", "owner", "cancel", "expiry", "extra request"} {
		t.Run(loss, func(t *testing.T) {
			entered, canceled := make(chan struct{}), make(chan struct{})
			fixture, calls := inspectionLifecycleFixture(t, func(ctx context.Context) (server.IsolationProofResult, error) {
				close(entered)
				<-ctx.Done()
				close(canceled)
				return workloadTransportVerifier{}.VerifyWorkloadIsolation(ctx)
			})
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			clear(fixture.readiness(t, peer, state, fixture.binding))
			wire := workloadRecord(t, fixture, state, []byte(inspectionRequest), 1)
			write(t, peer, wire)
			clear(wire)
			await(t, entered, "actual inspection entered")
			switch loss {
			case "eof":
				_ = peer.writer.Close()
			case "owner":
				close(fixture.owner)
			case "cancel":
				fixture.cancel()
			case "expiry":
				fixture.clock.advance(session.MaxGuestCredentialSessionLifetime)
			case "extra request":
				wire := workloadRecord(t, fixture, state, []byte(inspectionRequest), 2)
				write(t, peer, wire)
				clear(wire)
			}
			await(t, canceled, "blocked inspection canceled before rescue")
			assertClosed(t, peer)
			fixture.wait(t)
			if calls.Load() != 2 || peer.other.writes.Load() != 3 {
				t.Fatal("loss emitted late proof or dispatched extra inspection")
			}
		})
	}
}

func TestSelectedInspectionPanicAndLateObservationNeverReply(t *testing.T) {
	for _, loss := range []string{"panic", "owner", "cancel", "expiry without timer"} {
		t.Run(loss, func(t *testing.T) {
			var fixture *bootstrapFixture
			var calls *atomic.Int32
			fixture, calls = inspectionLifecycleFixture(t, func(ctx context.Context) (server.IsolationProofResult, error) {
				switch loss {
				case "panic":
					panic("private-inspection-panic")
				case "owner":
					close(fixture.owner)
					<-ctx.Done()
				case "cancel":
					fixture.cancel()
					<-ctx.Done()
				case "expiry without timer":
					fixture.clock.mu.Lock()
					fixture.clock.now = fixture.clock.now.Add(session.MaxGuestCredentialSessionLifetime)
					fixture.clock.mu.Unlock()
				}
				return workloadTransportVerifier{}.VerifyWorkloadIsolation(ctx)
			})
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			clear(fixture.readiness(t, peer, state, fixture.binding))
			wire := workloadRecord(t, fixture, state, []byte(inspectionRequest), 1)
			write(t, peer, wire)
			clear(wire)
			assertClosed(t, peer)
			err := fixture.wait(t)
			if (loss != "cancel" && err == nil) || (err != nil && strings.Contains(err.Error(), "private-")) || calls.Load() != 2 || peer.other.writes.Load() != 3 {
				t.Fatal("late/panicked inspection emitted proof or leaked")
			}
		})
	}
}

func TestSelectedInspectionBlockedWriterAndCompletedReplyLossJoin(t *testing.T) {
	for _, loss := range []string{"blocked writer EOF", "owner", "cancel", "expiry without timer"} {
		t.Run(loss, func(t *testing.T) {
			fixture, calls := inspectionLifecycleFixture(t, workloadTransportVerifier{}.VerifyWorkloadIsolation)
			peer, held := connectHeldWorkloadWriter(t, fixture, 4)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			clear(fixture.readiness(t, peer, state, fixture.binding))
			wire := workloadRecord(t, fixture, state, []byte(inspectionRequest), 1)
			write(t, peer, wire)
			clear(wire)
			if loss == "blocked writer EOF" {
				peer.other.awaitIO(t, 11, 4)
				_ = peer.writer.Close()
			} else {
				inner := workloadResponse(t, fixture, peer, state, 1)
				if !bytes.Contains(inner, []byte(`"isolationProof"`)) {
					t.Error("completed inspection prerequisite")
				}
				clear(inner)
				await(t, held.held, "consumed inspection with writer return held")
				switch loss {
				case "owner":
					close(fixture.owner)
				case "cancel":
					fixture.cancel()
				case "expiry without timer":
					fixture.clock.mu.Lock()
					fixture.clock.now = fixture.clock.now.Add(session.MaxGuestCredentialSessionLifetime)
					fixture.clock.mu.Unlock()
					close(held.release)
				}
			}
			await(t, fixture.server.Done(), "inspection writer joined after loss")
			assertClosed(t, peer)
			fixture.wait(t)
			if calls.Load() != 2 {
				t.Fatal("writer loss re-inspected")
			}
		})
	}
}
