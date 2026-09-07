//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// This peer is intentionally not the production guest Server. It uses the
// unchanged session cryptography so wrong plaintext/record kinds remain
// authenticated and cannot pass merely because a ciphertext tag was corrupted.
func runMinimalControllerSemanticPeer(parent context.Context, f *minimalControllerFixture, public ed25519.PublicKey, mutation string, sent chan<- struct{}) error {
	return runMinimalControllerObservedPeer(parent, f, public, mutation, sent, nil)
}

func runMinimalControllerObservedPeer(parent context.Context, f *minimalControllerFixture, public ed25519.PublicKey, mutation string, sent chan<- struct{}, afterFinished func() error) error {
	ctx, cancel := context.WithCancel(parent)
	var mu sync.Mutex
	var current io.ReadWriteCloser
	var state *session.State
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		<-ctx.Done()
		_ = f.listener.Close()
		mu.Lock()
		stream := current
		mu.Unlock()
		if stream != nil {
			_ = stream.Close()
		}
	}()
	defer func() {
		cancel()
		<-watchDone
		if state != nil {
			state.Revoke()
		}
	}()
	stream, err := f.listener.Accept(ctx)
	if err != nil {
		return err
	}
	mu.Lock()
	current = stream
	canceled := ctx.Err() != nil
	mu.Unlock()
	if canceled {
		_ = stream.Close()
		return ctx.Err()
	}
	prelude, err := frame.Read(stream, minimalcontrol.MaxMessageBytes)
	defer clear(prelude)
	if err != nil {
		return err
	}
	var candidate struct {
		Binding map[string]string `json:"binding"`
	}
	if json.Unmarshal(prelude, &candidate) != nil {
		return errors.New("fixture prelude decode")
	}
	identity := f.identity
	identity.FirecrackerProcessGeneration = candidate.Binding["processGeneration"]
	identity.VsockGeneration = candidate.Binding["vsockGeneration"]
	if identity.FirecrackerProcessGeneration != f.bridge.handle.ID {
		return errors.New("fixture process correlation")
	}
	fields := maps.Clone(f.fields)
	fields["processGeneration"], fields["vsockGeneration"] = identity.FirecrackerProcessGeneration, identity.VsockGeneration
	binding, err := minimalcontrol.NewBinding(identity, fields)
	if err != nil {
		return err
	}
	expectedPrelude, err := binding.BootstrapPrelude()
	defer clear(expectedPrelude)
	if err != nil || !bytes.Equal(prelude, expectedPrelude) {
		return errors.New("fixture prelaunch correlation")
	}
	handshake, hello, err := session.NewGuestHandshake(session.GuestHandshakeConfig{Identity: identity, PinnedControllerPublicKey: public, Dependencies: session.Dependencies{Random: bytes.NewReader(bytes.Repeat([]byte{73}, 96))}})
	defer clear(hello)
	if err != nil {
		return err
	}
	defer func() { _, _ = handshake.AcceptControllerAuth(nil) }()
	if n, err := stream.Write(hello); err != nil || n != len(hello) {
		return errors.New("fixture Hello write")
	}
	auth, err := l8D6ReadHandshakeWire(stream)
	defer clear(auth)
	if err != nil {
		return err
	}
	state, err = handshake.AcceptControllerAuth(auth)
	if err != nil {
		return err
	}
	finished, err := state.SealFinished()
	defer clear(finished)
	if err != nil {
		return err
	}
	if n, err := stream.Write(finished); err != nil || n != len(finished) {
		return errors.New("fixture Finished write")
	}
	controllerFinished, err := l8D6ReadSecureWire(stream)
	defer clear(controllerFinished)
	if err != nil || state.OpenFinished(controllerFinished) != nil || !state.Established() {
		return errors.New("fixture controller Finished")
	}
	if afterFinished != nil {
		if err := afterFinished(); err != nil {
			return err
		}
	}
	request, err := l8D6ReadSecureWire(stream)
	defer clear(request)
	if err != nil {
		return err
	}
	sessionID := state.SessionID()
	requestID := ""
	plaintext, err := state.OpenApplication(request, func(kind session.FrameType, payload []byte) error {
		var decoded struct {
			RequestID string `json:"requestId"`
		}
		if kind != session.FrameTypeControlRequest || json.Unmarshal(payload, &decoded) != nil {
			return errors.New("fixture readiness request")
		}
		expected, err := binding.EncodeReadinessRequest(decoded.RequestID, sessionID)
		defer clear(expected)
		if err != nil || !bytes.Equal(expected, payload) {
			return errors.New("fixture readiness binding")
		}
		requestID = decoded.RequestID
		return nil
	})
	defer clear(plaintext)
	if err != nil {
		return err
	}
	digest, err := binding.Digest(sessionID)
	if err != nil {
		return err
	}
	body := map[string]any{"bindingDigest": digest, "capabilities": []string{"authenticated_minimal_control"}, "guestSessionGeneration": base64.RawURLEncoding.EncodeToString(sessionID[:])}
	response := map[string]any{"body": body, "ok": true, "operation": "readiness", "protocolVersion": minimalcontrol.ProtocolVersion, "requestId": requestID}
	baseline, err := json.Marshal(response)
	defer clear(baseline)
	if err != nil || binding.ValidateReadinessResponse(baseline, requestID, sessionID) != nil {
		return errors.New("fixture canonical response prerequisite")
	}
	kind := session.FrameTypeControlResponse
	switch mutation {
	case "wrong-binding":
		body["bindingDigest"] = "sha256-" + strings.Repeat("ab", 32)
	case "wrong-capability":
		body["capabilities"] = []string{"exec"}
	case "extra-capability":
		body["capabilities"] = []string{"authenticated_minimal_control", "exec"}
	case "wrong-session":
		body["guestSessionGeneration"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{99}, 32))
	case "not-ok":
		response["ok"] = false
	case "wrong-operation":
		response["operation"] = "exec"
	case "wrong-protocol":
		response["protocolVersion"] = "guest-agent-v1"
	case "wrong-request":
		response["requestId"] = strings.Repeat("00", 16)
	case "missing-body":
		delete(response, "body")
	case "unknown-field":
		response["extra"] = true
	case "event-kind":
		kind = session.FrameTypeControlEvent
	}
	payload, err := json.Marshal(response)
	defer clear(payload)
	if err != nil {
		return err
	}
	if mutation != "matching" && mutation != "event-kind" && binding.ValidateReadinessResponse(payload, requestID, sessionID) == nil {
		return errors.New("fixture mutation did not change semantic validity")
	}
	if err := state.WriteApplication(stream, kind, payload); err != nil {
		return err
	}
	close(sent)
	var idle [1]byte
	defer clear(idle[:])
	_, _ = stream.Read(idle[:])
	return nil
}

func TestMinimalControlControllerAuthenticatedReadinessSemantics(t *testing.T) {
	for _, name := range []string{"matching", "wrong-binding", "wrong-capability", "extra-capability", "wrong-session", "not-ok", "wrong-operation", "wrong-protocol", "wrong-request", "missing-body", "unknown-field", "event-kind"} {
		t.Run(name, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerRetainedPeerFixture(t, admission)
				public, ok := minimalControlConfigBase64(admission.config.Control.ControllerPublicKey)
				if !ok {
					t.Fatal("fixture public key invalid")
				}
				peerCtx, peerCancel := context.WithCancel(context.Background())
				done, sent := make(chan struct{}), make(chan struct{})
				var peerErr error
				go func() {
					defer close(done)
					peerErr = runMinimalControllerSemanticPeer(peerCtx, f, public[:], name, sent)
				}()
				defer func() {
					peerCancel()
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Fatal("scripted peer not joined")
					}
				}()
				err := withMinimalControlController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					ready, err := c.WaitReady(ctx)
					if name == "matching" {
						if err != nil || !ready.Current() {
							t.Fatal("scripted authenticated positive failed", err)
						}
					} else {
						if err == nil || ready != nil {
							t.Fatal("authenticated wrong readiness accepted")
						}
						select {
						case <-c.Loss():
						default:
							t.Fatal("semantic rejection relied on admission expiry")
						}
					}
					if c.Close() != nil {
						t.Fatal("semantic peer scope close failed")
					}
					minimalControllerRequireJoined(t, c, admission.controllerKey)
					return nil
				})
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("scripted peer failed to observe controller close")
				}
				if peerErr != nil {
					t.Fatal("scripted transcript prerequisite failed", peerErr)
				}
				select {
				case <-sent:
				default:
					t.Fatal("authenticated response not sent")
				}
				if (err == nil) != (name == "matching") || f.listener.connects.Load() != 1 {
					t.Fatal("semantic result/retry changed")
				}
				return nil
			})
			if code != 0 {
				t.Fatal("semantic fixture failed")
			}
		})
	}
}
