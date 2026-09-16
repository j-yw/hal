package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/vsock"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

const minimalCommandL7Line = "hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
	"hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://198.18.0.1:18080"

func TestMinimalGuestCommandRejectsInvalidL7BeforeConstruction(t *testing.T) {
	for _, scenario := range []string{"absent-l7", "partial-l7", "duplicate-l7", "malformed-l7", "missing-environment", "partial-environment", "mismatch-environment", "different-boot-proxy", "canceled-before-read", "canceled-during-lookup"} {
		t.Run(scenario, func(t *testing.T) {
			line := minimalBootstrapREDBootLine() + " " + minimalCommandL7Line
			values := minimalCommandProxyEnvironment()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "absent-l7":
				line = minimalBootstrapREDBootLine()
			case "partial-l7":
				line = minimalBootstrapREDBootLine() + " hal_l7_net_if=eth0"
			case "duplicate-l7":
				line += " hal_l7_net_if=eth0"
			case "malformed-l7":
				line = strings.Replace(line, "hal_l7_proxy=http://198.18.0.1:18080", "hal_l7_proxy=private-invalid-canary", 1)
			case "missing-environment":
				values = nil
			case "partial-environment":
				delete(values, "https_proxy")
			case "mismatch-environment":
				values["http_proxy"] = "http://198.18.0.2:18080"
			case "different-boot-proxy":
				line = strings.Replace(line, "http://198.18.0.1:18080", "http://198.18.0.2:18080", 1)
			case "canceled-before-read":
				cancel()
			}
			backend := &minimalCommandBackend{}
			proof := &minimalCommandVerifier{}
			constructors, reads := 0, 0
			dependencies := minimalCommandDependencies(t, backend, proof, func() (vsock.Listener, error) {
				constructors++
				return nil, errors.New("private listener canary")
			})
			dependencies.newBackend = func(server.LinuxBackendOptions) (server.Backend, error) { constructors++; return backend, nil }
			dependencies.newNetworkVerifier = func(guestnetwork.LinuxNetworkIsolationVerifierOptions) (server.NetworkIsolationVerifier, error) {
				constructors++
				return proof, nil
			}
			dependencies.newWorkloadVerifier = func(server.LinuxIsolationVerifierOptions) (server.WorkloadIsolationVerifier, error) {
				constructors++
				return proof, nil
			}
			dependencies.lookupEnvironment = func(name string) (string, bool) {
				if scenario == "canceled-during-lookup" {
					cancel()
				}
				value, ok := values[name]
				return value, ok
			}
			err := runGuestAgentEntry(ctx, guestAgentEntryDependencies{
				readBootCommandLine: func(context.Context) (string, error) { reads++; return line, nil },
				runLegacy:           func() error { t.Error("selected config fell back to legacy"); return nil },
				runMinimal: func(ctx context.Context, retained string) error {
					if retained != line {
						t.Error("retained boot bytes changed")
					}
					return runMinimalGuestAgentWithDependencies(ctx, retained, dependencies)
				},
			})
			wantReads := 1
			if scenario == "canceled-before-read" {
				wantReads = 0
			}
			if err == nil || constructors != 0 || reads != wantReads {
				t.Errorf("invalid selected config crossed construction: constructors=%d bootReads=%d error=%v", constructors, reads, err)
			}
			if strings.HasPrefix(scenario, "canceled-") && !errors.Is(err, context.Canceled) {
				t.Errorf("cancellation identity lost: %v", err)
			}
			if err != nil && (strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "198.18.")) {
				t.Errorf("command error leaked input: %v", err)
			}
		})
	}
}

func TestMinimalGuestCommandAuthenticatedExecAndCopy(t *testing.T) {
	data := []byte("selected command copy payload")
	digest := sha256.Sum256(data)
	metadata := guestagent.PayloadMetadata{Encoding: "base64", Data: base64.StdEncoding.EncodeToString(data), SizeBytes: int64(len(data)), MaxBytes: 128, Digest: "sha256:" + hex.EncodeToString(digest[:])}
	inRequest := guestagent.CopyInRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationCopyIn, DestinationPath: "/workspace/output.txt", Payload: metadata}
	outRequest := guestagent.CopyOutRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationCopyOut, SourcePath: "/workspace/output.txt", Payload: guestagent.PayloadMetadata{MaxBytes: 128, Encoding: guestagent.PayloadEncodingBase64}}
	if err := guestagent.ValidateCopyInRequest(inRequest); err != nil {
		t.Fatalf("invalid copy-in fixture: %v", err)
	}
	if err := guestagent.ValidateCopyOutRequest(outRequest); err != nil {
		t.Fatalf("invalid copy-out fixture: %v", err)
	}
	fixture := newMinimalCommandFixture(t)
	client := fixture.authenticate(t)
	response, err := client.Exec(context.Background(), guestagent.ExecRequest{
		Args: []string{"hal", "--version"}, WorkDir: "/workspace",
		Stdout: guestagent.StreamMetadata{MaxBytes: 64}, Stderr: guestagent.StreamMetadata{MaxBytes: 64},
	})
	if err != nil || response == nil || response.Stdout.Data != base64.StdEncoding.EncodeToString([]byte("command-output")) {
		t.Fatalf("actual selected command did not dispatch authenticated exec: backendCalls=%d response=%v error=%v", fixture.backend.execCalls.Load(), response, err)
	}
	if plan := fixture.backend.execPlan; !reflect.DeepEqual(plan.Args, []string{"hal", "--version"}) || plan.WorkDir != "/workspace" || len(plan.Environment) != 0 || len(plan.Stdin) != 0 || plan.StdoutMaxBytes != 64 || plan.StderrMaxBytes != 64 {
		t.Fatal("selected command changed the actual decoded exec plan")
	}
	if _, err := client.CopyIn(context.Background(), inRequest); err != nil {
		t.Fatalf("actual selected command copy-in: %v", err)
	}
	out, err := client.CopyOut(context.Background(), outRequest)
	if err != nil || out.Payload.Data != metadata.Data || out.Payload.Digest != metadata.Digest {
		t.Fatalf("actual selected command copy-out: response=%v error=%v", out, err)
	}
	if fixture.backend.readyCalls.Load() != 1 || fixture.backend.execCalls.Load() != 1 || fixture.backend.copyCalls.Load() != 2 || fixture.proof.calls.Load() != 4 {
		t.Fatalf("missing actual readiness/fresh work proof: ready=%d exec=%d copy=%d proof=%d", fixture.backend.readyCalls.Load(), fixture.backend.execCalls.Load(), fixture.backend.copyCalls.Load(), fixture.proof.calls.Load())
	}
}

func minimalCommandProxyEnvironment() map[string]string {
	return map[string]string{"HTTP_PROXY": "http://198.18.0.1:18080", "HTTPS_PROXY": "http://198.18.0.1:18080", "http_proxy": "http://198.18.0.1:18080", "https_proxy": "http://198.18.0.1:18080"}
}

func minimalCommandDependencies(t *testing.T, backend *minimalCommandBackend, proof *minimalCommandVerifier, listen func() (vsock.Listener, error)) minimalGuestAgentDependencies {
	t.Helper()
	values := minimalCommandProxyEnvironment()
	return minimalGuestAgentDependencies{
		lookupEnvironment: func(name string) (string, bool) { value, ok := values[name]; return value, ok },
		listen:            listen,
		newBackend: func(options server.LinuxBackendOptions) (server.Backend, error) {
			want := l7GuestAgentConfiguration(t).backend
			if !reflect.DeepEqual(options, want) {
				t.Error("selected backend lost fixed workspace, executable roots, or narrow proxy environment")
			}
			backend.constructors.Add(1)
			return backend, nil
		},
		newNetworkVerifier: func(options guestnetwork.LinuxNetworkIsolationVerifierOptions) (server.NetworkIsolationVerifier, error) {
			if options.BootConfig != l7GuestBootConfig(t) {
				t.Error("network verifier did not receive the exact retained L7 boot config")
			}
			proof.networkConstructors.Add(1)
			return proof, nil
		},
		newWorkloadVerifier: func(options server.LinuxIsolationVerifierOptions) (server.WorkloadIsolationVerifier, error) {
			if options.ProcessBoundary != nil || options.NetworkVerifier != proof {
				t.Error("selected process verifier bypassed concrete process selection or retained network verifier")
			}
			proof.workloadConstructors.Add(1)
			return proof, nil
		},
	}
}

type minimalCommandFixture struct {
	peer     *minimalREDPipe
	identity session.Identity
	key      ed25519.PrivateKey
	binding  minimalcontrol.Binding
	backend  *minimalCommandBackend
	proof    *minimalCommandVerifier
}

func newMinimalCommandFixture(t *testing.T) *minimalCommandFixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	identity := session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		GuestBootNonce: [32]byte{1}, ControllerKeyGeneration: "controller-key-1", RuntimeID: "runtime-1", RuntimeGeneration: "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1", VsockGeneration: "vsock-generation-1", BootGeneration: "boot-generation-1", ImageGeneration: "image-generation-1", ImageSHA256: [32]byte{2}}
	fields := minimalREDBinding(identity)
	binding, err := minimalcontrol.NewBinding(identity, fields)
	if err != nil {
		t.Fatal(err)
	}
	prelaunch := identity
	prelaunch.FirecrackerProcessGeneration, prelaunch.VsockGeneration = "", ""
	prelaunchFields := maps.Clone(fields)
	delete(prelaunchFields, "processGeneration")
	delete(prelaunchFields, "vsockGeneration")
	line, err := minimalcontrol.RenderBootCommandLine(minimalCommandL7Line, prelaunch, key.Public().(ed25519.PublicKey), prelaunchFields)
	if err != nil {
		t.Fatal(err)
	}
	guestReader, peerWriter := io.Pipe()
	peerReader, guestWriter := io.Pipe()
	guest := &minimalREDPipe{reader: guestReader, writer: guestWriter}
	peer := &minimalREDPipe{reader: peerReader, writer: peerWriter}
	listener := &minimalCommandListener{minimalREDListener: minimalREDListener{connections: make(chan io.ReadWriteCloser, 1)}}
	listener.connections <- guest
	fixture := &minimalCommandFixture{peer: peer, identity: identity, key: key, binding: binding, backend: &minimalCommandBackend{}, proof: &minimalCommandVerifier{}}
	var listens, reads atomic.Int32
	dependencies := minimalCommandDependencies(t, fixture.backend, fixture.proof, func() (vsock.Listener, error) { listens.Add(1); return listener, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var timedOut atomic.Bool
	watchDone := make(chan struct{})
	watch := time.AfterFunc(3*time.Second, func() { defer close(watchDone); timedOut.Store(true); _ = guest.Close(); _ = peer.Close(); cancel() })
	go func() {
		done <- runGuestAgentEntry(ctx, guestAgentEntryDependencies{
			readBootCommandLine: func(context.Context) (string, error) { reads.Add(1); return line, nil },
			runLegacy:           func() error { return errors.New("unexpected legacy selection") },
			runMinimal: func(ctx context.Context, retained string) error {
				return runMinimalGuestAgentWithDependencies(ctx, retained, dependencies)
			},
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("actual command did not join after owner cancellation")
		}
		_ = peer.Close()
		_ = guest.Close()
		if !watch.Stop() {
			<-watchDone
		}
		if timedOut.Load() {
			t.Error("watchdog rescued a stuck command; not product cancellation evidence")
		}
		if reads.Load() != 1 || listens.Load() != 1 || fixture.backend.constructors.Load() != 1 || fixture.backend.closeCalls.Load() != 1 || fixture.proof.networkConstructors.Load() != 1 || fixture.proof.workloadConstructors.Load() != 1 || listener.closes.Load() != 1 {
			t.Errorf("command construction/cleanup ownership: reads=%d listens=%d backend=%d close=%d network=%d workload=%d listenerClose=%d", reads.Load(), listens.Load(), fixture.backend.constructors.Load(), fixture.backend.closeCalls.Load(), fixture.proof.networkConstructors.Load(), fixture.proof.workloadConstructors.Load(), listener.closes.Load())
		}
	})
	return fixture
}

func (fixture *minimalCommandFixture) authenticate(t *testing.T) *guestagent.Client {
	t.Helper()
	prelude, err := fixture.binding.BootstrapPrelude()
	if err != nil {
		t.Fatal(err)
	}
	if err := frame.Write(fixture.peer, prelude, minimalcontrol.MaxMessageBytes); err != nil {
		t.Fatal(err)
	}
	hello, err := frame.Read(fixture.peer, session.MaxHandshakeInnerBytes)
	if err != nil {
		t.Fatal(err)
	}
	var framed bytes.Buffer
	if err := frame.Write(&framed, hello, session.MaxHandshakeInnerBytes); err != nil {
		t.Fatal(err)
	}
	controller, err := session.NewControllerHandshake(session.ControllerHandshakeConfig{ExpectedIdentity: fixture.identity, SigningKey: fixture.key})
	if err != nil {
		t.Fatal(err)
	}
	state, auth, err := controller.AcceptGuestHello(framed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(state.Revoke)
	minimalREDWrite(t, fixture.peer, auth)
	if err := state.OpenFinished(minimalREDReadRecord(t, fixture.peer)); err != nil {
		t.Fatal(err)
	}
	finished, err := state.SealFinished()
	if err != nil {
		t.Fatal(err)
	}
	minimalREDWrite(t, fixture.peer, finished)
	request, digest := minimalREDRequest(t, state, minimalREDBinding(fixture.identity))
	minimalREDWrite(t, fixture.peer, minimalREDSeal(t, state, request))
	minimalREDAssertReadiness(t, fixture.peer, state, digest)
	var ordinal uint64
	client, err := guestagent.NewClient(guestagent.ClientOptions{Transport: guestagent.TransportFunc(func(ctx context.Context, request guestagent.TransportRequest) (guestagent.TransportResponse, error) {
		ordinal++
		payload, err := fixture.binding.EncodeWorkload(request.Encoded, ordinal, state.SessionID())
		if err != nil {
			return guestagent.TransportResponse{}, err
		}
		defer clear(payload)
		wire, err := state.SealApplication(session.FrameTypeControlRequest, payload)
		if err != nil {
			return guestagent.TransportResponse{}, err
		}
		defer clear(wire)
		if _, err := fixture.peer.Write(wire); err != nil {
			return guestagent.TransportResponse{}, err
		}
		header := make([]byte, session.SecureRecordHeaderBytes)
		if _, err := io.ReadFull(fixture.peer, header); err != nil {
			return guestagent.TransportResponse{}, err
		}
		size := binary.BigEndian.Uint32(header[16:20])
		if size < session.GCMTagBytes || size > minimalcontrol.MaxWorkloadMessageBytes+session.GCMTagBytes {
			return guestagent.TransportResponse{}, errors.New("invalid test response size")
		}
		reply := append(header, make([]byte, int(size))...)
		defer clear(reply)
		if _, err := io.ReadFull(fixture.peer, reply[len(header):]); err != nil {
			return guestagent.TransportResponse{}, err
		}
		var inner []byte
		id := state.SessionID()
		opened, err := state.OpenApplication(reply, func(kind session.FrameType, encoded []byte) error {
			var decodeErr error
			inner, decodeErr = fixture.binding.DecodeWorkloadResponse(kind, encoded, ordinal, id)
			return decodeErr
		})
		clear(opened)
		return guestagent.TransportResponse{Encoded: inner}, err
	})})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type minimalCommandListener struct {
	minimalREDListener
	closes atomic.Int32
}

func (listener *minimalCommandListener) Close() error { listener.closes.Add(1); return nil }

type minimalCommandVerifier struct{ networkConstructors, workloadConstructors, calls atomic.Int32 }

func (*minimalCommandVerifier) VerifyNetworkIsolation(context.Context) (server.NetworkIsolationProofResult, error) {
	return server.NetworkIsolationProofResult{}, errors.New("fake constructor marker must not be invoked directly")
}
func (proof *minimalCommandVerifier) VerifyWorkloadIsolation(context.Context) (server.IsolationProofResult, error) {
	proof.calls.Add(1)
	return server.IsolationProofResult{RestrictedIdentity: true, CapabilitiesCleared: true, NoNewPrivileges: true, SupplementaryGroupsCleared: true, RawPacketSocketDenied: true,
		Network: server.NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusVerified, SingleInterface: true, StaticRoutes: true, ProxyReachable: true}}, nil
}

type minimalCommandBackend struct {
	constructors, readyCalls, execCalls, copyCalls, closeCalls atomic.Int32
	execPlan                                                   server.ExecPlan
	data                                                       []byte
}

func (backend *minimalCommandBackend) Ready(context.Context) error {
	backend.readyCalls.Add(1)
	return nil
}
func (backend *minimalCommandBackend) Exec(_ context.Context, plan server.ExecPlan) (server.ExecResult, error) {
	backend.execPlan = plan
	backend.execCalls.Add(1)
	return server.ExecResult{Stdout: []byte("command-output")}, nil
}
func (backend *minimalCommandBackend) CopyIn(_ context.Context, plan server.CopyInPlan) (server.CopyResult, error) {
	backend.copyCalls.Add(1)
	backend.data = bytes.Clone(plan.Data)
	return server.CopyResult{Published: true, SizeBytes: int64(len(plan.Data)), Digest: plan.Digest}, nil
}
func (backend *minimalCommandBackend) CopyOut(context.Context, server.CopyOutPlan) (server.CopyResult, error) {
	backend.copyCalls.Add(1)
	digest := sha256.Sum256(backend.data)
	return server.CopyResult{Data: bytes.Clone(backend.data), SizeBytes: int64(len(backend.data)), Digest: "sha256:" + hex.EncodeToString(digest[:])}, nil
}
func (backend *minimalCommandBackend) Close(context.Context) error {
	backend.closeCalls.Add(1)
	return nil
}
