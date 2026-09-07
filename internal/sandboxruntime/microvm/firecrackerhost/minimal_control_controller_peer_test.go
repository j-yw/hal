//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

type minimalControllerPeerFault struct {
	stage   int
	effect  string
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

type minimalControllerPeerListener struct {
	base  *minimalControllerGuestListener
	fault *minimalControllerPeerFault
}

func (l *minimalControllerPeerListener) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	stream, err := l.base.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &minimalControllerPeerStream{ReadWriteCloser: stream, fault: l.fault, closed: make(chan struct{})}, nil
}
func (l *minimalControllerPeerListener) Close() error { return l.base.Close() }

type minimalControllerPeerStream struct {
	io.ReadWriteCloser
	fault  *minimalControllerPeerFault
	writes int
	closed chan struct{}
	once   sync.Once
}

func (s *minimalControllerPeerStream) Close() error {
	s.once.Do(func() { close(s.closed); _ = s.ReadWriteCloser.Close() })
	return nil
}

// These faults alter bytes emitted by the real shared guest. Ciphertext
// corruption is not evidence for authenticated semantic response validation.
func (s *minimalControllerPeerStream) Write(original []byte) (int, error) {
	s.writes++
	if s.writes != s.fault.stage {
		return s.ReadWriteCloser.Write(original)
	}
	s.fault.once.Do(func() { close(s.fault.reached) })
	if s.fault.effect == "cancel" {
		<-s.closed
		return 0, io.ErrClosedPipe
	}
	if s.fault.effect == "idle-byte" {
		n, err := s.ReadWriteCloser.Write(original)
		if err != nil || n != len(original) {
			return n, err
		}
		select {
		case <-s.closed:
			return n, io.ErrClosedPipe
		case <-s.fault.release:
		}
		_, err = s.ReadWriteCloser.Write([]byte{0x73})
		return n, err
	}
	payload := bytes.Clone(original)
	defer clear(payload)
	prefix := session.SecureRecordHeaderBytes
	if s.fault.stage == 1 {
		prefix = 4
	}
	switch s.fault.effect {
	case "bad-magic":
		index := 0
		if s.fault.stage == 1 {
			index = 4
		}
		payload[index] ^= 0xff
	case "oversized":
		if s.fault.stage == 1 {
			binary.BigEndian.PutUint32(payload[:4], session.MaxHandshakeInnerBytes+1)
		} else {
			binary.BigEndian.PutUint32(payload[16:20], minimalcontrol.MaxMessageBytes+session.GCMTagBytes+1)
		}
		payload = payload[:prefix] // Keep the peer open: reject before a body read.
	case "short-prefix":
		payload = payload[:prefix-1]
	case "short-body":
		payload = payload[:len(payload)-1]
	case "ciphertext":
		payload[len(payload)-1] ^= 1
	case "wrong-identity":
		hello, err := session.ParseGuestHello(original)
		if err != nil {
			return 0, err
		}
		hello.Identity.RuntimeGeneration += "-other"
		changed, err := session.MarshalGuestHello(hello)
		if err != nil {
			return 0, err
		}
		defer clear(changed)
		n, err := s.ReadWriteCloser.Write(changed)
		if err != nil || n != len(changed) {
			return 0, io.ErrShortWrite
		}
		return len(original), nil
	}
	n, err := s.ReadWriteCloser.Write(payload)
	if s.fault.effect == "short-prefix" || s.fault.effect == "short-body" {
		_ = s.Close()
		return 0, io.ErrUnexpectedEOF
	}
	if err != nil || n != len(payload) {
		return 0, io.ErrShortWrite
	}
	return len(original), nil
}

func newMinimalControllerPeerFixture(t *testing.T, admission *minimalControlSupervisorAdmission, fault *minimalControllerPeerFault) *minimalControllerFixture {
	t.Helper()
	f := newMinimalControllerFixture(t, admission)
	manager := f.transport.manager
	before, err := manager.resolveLiveProcessIdentity(f.bridge.handle)
	if err != nil || f.transport.claimed.Load() || f.listener.connects.Load() != 0 {
		t.Fatal("original fixture already claimed or lost")
	}
	parent, err := statPrivateFirecrackerStateDir(f.bridge.paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	f.close(t)
	select {
	case <-f.guest.Done():
	default:
		t.Fatal("original guest not joined")
	}
	f.listener.mu.Lock()
	quiesced := f.listener.closed && f.listener.pending == nil
	f.listener.mu.Unlock()
	if !quiesced || f.transport.claimed.Load() {
		t.Fatal("original listener/transport not quiescent and unused")
	}
	path := f.bridge.paths.VsockSocketPath
	original, err := os.Lstat(path)
	if err != nil || original.Mode()&os.ModeSocket == 0 {
		t.Fatal("missing original fixture socket")
	}
	displaced := path + ".before-peer"
	if _, err := os.Lstat(displaced); !os.IsNotExist(err) {
		t.Fatal("displaced fixture name occupied")
	}
	if err := os.Rename(path, displaced); err != nil {
		t.Fatal(err)
	}
	f.listener = &minimalControllerGuestListener{listener: l5ListenBridgeSocket(t, path)}
	f.listener.listener.(*net.UnixListener).SetUnlinkOnClose(false)
	current, err := os.Lstat(path)
	old, oldErr := os.Lstat(displaced)
	after, afterErr := manager.resolveLiveProcessIdentity(f.bridge.handle)
	parentAfter, parentErr := statPrivateFirecrackerStateDir(f.bridge.paths.StateDir)
	if err != nil || oldErr != nil || os.SameFile(current, original) || !os.SameFile(old, original) || afterErr != nil ||
		before.pid != after.pid || before.done != after.done || before.handle != after.handle || before.paths != after.paths || !sameVsockProcessOwner(before.owner, after.owner) ||
		parentErr != nil || parent != parentAfter || manager != f.transport.manager || f.transport.claimed.Load() {
		t.Fatal("test peer replacement changed retained ownership")
	}
	t.Cleanup(func() {
		info, err := os.Lstat(displaced)
		if err != nil || !os.SameFile(info, original) {
			t.Error("displaced fixture socket was consumed")
		}
	})
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
	f.guest, err = minimalcontrol.NewBootstrap(minimalcontrol.BootstrapOptions{Listener: &minimalControllerPeerListener{base: f.listener, fault: fault}, Boot: boot, OwnerDone: ctx.Done(), Random: bytes.NewReader(bytes.Repeat([]byte{73}, 96))})
	if err != nil {
		cancel()
		_ = f.listener.Close()
		t.Fatal(err)
	}
	go func() { _ = f.guest.Serve(ctx) }()
	return f
}

func TestMinimalControlControllerPeerFixtureCompletes(t *testing.T) {
	a := newMinimalControlAdmissionFixture(t)
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		f := newMinimalControllerPeerFixture(t, admission, &minimalControllerPeerFault{})
		defer f.close(t)
		return withMinimalControlController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
			ready := minimalControllerRequireReady(t, c)
			if c.Close() != nil || ready.Current() || f.listener.connects.Load() != 1 {
				t.Fatal("replacement fixture transcript did not join")
			}
			minimalControllerRequireJoined(t, c, admission.controllerKey)
			return nil
		})
	})
	if code != 0 {
		t.Fatal("replacement peer positive control failed")
	}
}

func TestMinimalControlControllerRejectsCorruptPeerTranscript(t *testing.T) {
	for stage, name := range []string{"hello", "finished", "readiness"} {
		effects := []string{"bad-magic", "oversized", "short-prefix", "short-body"}
		if stage == 0 {
			effects = append(effects, "wrong-identity")
		} else {
			effects = append(effects, "ciphertext")
		}
		for _, effect := range effects {
			t.Run(name+"/"+effect, func(t *testing.T) {
				a := newMinimalControlAdmissionFixture(t)
				code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
					fault := &minimalControllerPeerFault{stage: stage + 1, effect: effect, reached: make(chan struct{})}
					f := newMinimalControllerPeerFixture(t, admission, fault)
					defer f.close(t)
					err := withMinimalControlController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						defer cancel()
						if ready, err := c.WaitReady(ctx); err == nil || ready != nil {
							t.Fatal("corrupt transcript reached readiness")
						}
						select {
						case <-fault.reached:
						default:
							t.Fatal("guest fault not reached")
						}
						select {
						case <-c.Loss():
						default:
							t.Fatal("fault waited for admission expiry instead of rejecting")
						}
						if c.Close() != nil {
							t.Fatal("fault scope did not close")
						}
						minimalControllerRequireJoined(t, c, admission.controllerKey)
						return nil
					})
					if err == nil || f.listener.connects.Load() != 1 {
						t.Fatal("fault retried or returned successful transcript")
					}
					return nil
				})
				if code != 0 {
					t.Fatal("fault fixture failed")
				}
			})
		}
	}
}

func TestMinimalControlControllerPeerStageCancellationAndIdleByte(t *testing.T) {
	for _, test := range []struct {
		name   string
		stage  int
		effect string
	}{
		{"hello-cancel", 1, "cancel"}, {"finished-cancel", 2, "cancel"}, {"readiness-cancel", 3, "cancel"}, {"idle-byte", 3, "idle-byte"},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				fault := &minimalControllerPeerFault{stage: test.stage, effect: test.effect, reached: make(chan struct{}), release: make(chan struct{})}
				f := newMinimalControllerPeerFixture(t, admission, fault)
				defer f.close(t)
				owner, cancel := context.WithCancel(context.Background())
				defer cancel()
				err := withMinimalControlController(owner, f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
					select {
					case <-fault.reached:
					case <-time.After(time.Second):
						t.Fatal("guest stage not reached")
					}
					var ready *minimalControlReadiness
					if test.effect == "idle-byte" {
						ready = minimalControllerRequireReady(t, c)
						close(fault.release)
					} else {
						cancel()
					}
					select {
					case <-c.Loss():
					case <-time.After(time.Second):
						t.Fatal("peer-stage loss did not retire")
					}
					if c.Close() != nil || ready.Current() {
						t.Fatal("peer-stage loss retained readiness")
					}
					minimalControllerRequireJoined(t, c, admission.controllerKey)
					return nil
				})
				if (err == nil) != (test.effect == "idle-byte") || f.listener.connects.Load() != 1 {
					t.Fatal("peer-stage result or retry changed")
				}
				return nil
			})
			if code != 0 {
				t.Fatal("peer-stage fixture failed")
			}
		})
	}
}
