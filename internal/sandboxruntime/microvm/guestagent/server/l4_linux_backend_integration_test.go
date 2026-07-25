//go:build l4_guest_agent_server_integration

package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

const l4AmbientCanary = "HAL_L4_AMBIENT_CANARY"

func TestL4PreparedLinuxLocalServerE2E(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatalf("L4 prepared integration requires Linux; got %s", runtime.GOOS)
	}
	t.Setenv(l4AmbientCanary, "must-not-reach-child")

	workspace := t.TempDir()
	backend, err := NewLinuxBackend(LinuxBackendOptions{
		WorkspaceRoot:   workspace,
		GuestRoot:       "/workspace",
		ExecutablePaths: []string{filepath.Dir(os.Args[0])},
		TermGrace:       25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewLinuxBackend() prerequisite failure: %v", err)
	}

	transport := newL4MemoryTransport()
	server, err := New(Options{
		Transport:        transport,
		Backend:          backend,
		MaxConcurrent:    2,
		MaxOperationTime: 5 * time.Second,
		MaxShutdownTime:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(context.Background()) }()
	select {
	case <-transport.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("transport did not begin serving")
	}

	t.Run("exec stdin binary nonzero truncation and ambient env", func(t *testing.T) {
		stdin := []byte{0x00, 'h', 'a', 'l', 0xff}
		response := l4Exec(t, transport, context.Background(), []string{
			os.Args[0], "-test.run=^TestL4PreparedLinuxHelperProcess$", "--", "io",
		}, stdin, 64, 64)
		if response.ExitCode != 7 {
			t.Fatalf("exit code = %d, want 7", response.ExitCode)
		}
		stdout := decodeL4Data(t, response.Stdout.Data)
		if string(stdout) != string(append(append([]byte(nil), stdin...), 0xfe)) {
			t.Fatalf("stdout = %v, want stdin plus binary suffix", stdout)
		}
		stderr := decodeL4Data(t, response.Stderr.Data)
		if strings.Contains(string(stderr), "must-not-reach-child") {
			t.Fatalf("ambient environment leaked to child: %q", stderr)
		}

		truncated := l4Exec(t, transport, context.Background(), []string{
			os.Args[0], "-test.run=^TestL4PreparedLinuxHelperProcess$", "--", "output",
		}, nil, 3, 5)
		if !truncated.Stdout.Truncated || !truncated.Stderr.Truncated {
			t.Fatalf("truncation = stdout:%t stderr:%t, want both true", truncated.Stdout.Truncated, truncated.Stderr.Truncated)
		}
		if got := decodeL4Data(t, truncated.Stdout.Data); string(got) != "abc" {
			t.Fatalf("truncated stdout = %q, want %q", got, "abc")
		}
		if got := decodeL4Data(t, truncated.Stderr.Data); string(got) != "12345" {
			t.Fatalf("truncated stderr = %q, want %q", got, "12345")
		}
	})

	t.Run("cancel kills and reaps process leader", func(t *testing.T) {
		pidPath := filepath.Join(workspace, "cancel.pid")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan []byte, 1)
		go func() {
			done <- transport.roundTrip(ctx, mustL4JSON(t, l4ExecRequest([]string{
				os.Args[0], "-test.run=^TestL4PreparedLinuxHelperProcess$", "--", "sleep", pidPath,
			}, nil, 64, 64)))
		}()
		pid := waitL4PID(t, pidPath)
		cancel()
		assertL4ErrorCode(t, <-done, "request_canceled")
		waitL4ProcessGone(t, pid)
	})

	t.Run("copy digest atomic mode preservation and containment", func(t *testing.T) {
		old := []byte("old")
		path := filepath.Join(workspace, "artifact.bin")
		if err := os.WriteFile(path, old, 0o644); err != nil {
			t.Fatalf("seed destination: %v", err)
		}
		payload := []byte{0x00, 'c', 'o', 'p', 'y', 0xff}
		digest := l4Digest(payload)
		copyIn := guestagent.CopyInRequest{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationCopyIn,
			DestinationPath: "/workspace/artifact.bin",
			Payload: guestagent.PayloadMetadata{
				SizeBytes: int64(len(payload)),
				MaxBytes:  1024,
				Digest:    digest,
				Encoding:  guestagent.PayloadEncodingBase64,
				Data:      base64.StdEncoding.EncodeToString(payload),
			},
		}
		var written guestagent.CopyInResponse
		mustL4Decode(t, transport.roundTrip(context.Background(), mustL4JSON(t, copyIn)), &written)
		if written.Error != nil || written.Written.SizeBytes != int64(len(payload)) || written.Written.Digest != digest {
			t.Fatalf("copy-in response = %#v", written)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat copied file: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("copied mode = %o, want 600", info.Mode().Perm())
		}

		copyOut := guestagent.CopyOutRequest{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationCopyOut,
			SourcePath:      "/workspace/artifact.bin",
			Payload: guestagent.PayloadMetadata{
				MaxBytes: 1024,
				Encoding: guestagent.PayloadEncodingBase64,
			},
		}
		var read guestagent.CopyOutResponse
		mustL4Decode(t, transport.roundTrip(context.Background(), mustL4JSON(t, copyOut)), &read)
		if read.Error != nil || read.Payload.Digest != digest || string(decodeL4Data(t, read.Payload.Data)) != string(payload) {
			t.Fatalf("copy-out response = %#v", read)
		}

		copyIn.Payload.Digest = l4Digest([]byte("wrong"))
		assertL4ErrorCode(t, transport.roundTrip(context.Background(), mustL4JSON(t, copyIn)), "digest_mismatch")
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(payload) {
			t.Fatalf("destination after rejected copy = %v, %v", got, err)
		}

		copyOut.SourcePath = "/workspace/../escape"
		assertL4Error(t, transport.roundTrip(context.Background(), mustL4JSON(t, copyOut)))
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("outside-canary"), 0o600); err != nil {
			t.Fatalf("write outside canary: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(workspace, "link")); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		copyOut.SourcePath = "/workspace/link"
		assertL4Error(t, transport.roundTrip(context.Background(), mustL4JSON(t, copyOut)))
		if err := os.Link(path, filepath.Join(workspace, "hardlink")); err != nil {
			t.Fatalf("create hard link: %v", err)
		}
		copyOut.SourcePath = "/workspace/hardlink"
		assertL4Error(t, transport.roundTrip(context.Background(), mustL4JSON(t, copyOut)))
	})

	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if got := server.State(); got != StateStopped {
		t.Fatalf("server state = %q, want %q", got, StateStopped)
	}
	entries, err := os.ReadDir(workspace)
	if err != nil {
		t.Fatalf("read workspace after shutdown: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temporary file remained after shutdown: %s", entry.Name())
		}
	}
}

func TestL4PreparedLinuxHelperProcess(t *testing.T) {
	mode, args, ok := l4HelperArgs(os.Args)
	if !ok {
		return
	}
	switch mode {
	case "io":
		data, _ := io.ReadAll(os.Stdin)
		_, _ = os.Stdout.Write(append(data, 0xfe))
		_, _ = fmt.Fprintf(os.Stderr, "env=%s", os.Getenv(l4AmbientCanary))
		os.Exit(7)
	case "output":
		_, _ = io.WriteString(os.Stdout, "abcdef")
		_, _ = io.WriteString(os.Stderr, "123456789")
		os.Exit(0)
	case "sleep":
		if len(args) != 1 {
			os.Exit(2)
		}
		_ = os.WriteFile(args[0], []byte(fmt.Sprintf("%d", os.Getpid())), 0o600)
		select {}
	default:
		os.Exit(2)
	}
}

type l4MemoryTransport struct {
	ready chan struct{}
	mu    sync.RWMutex
	h     Handler
}

func newL4MemoryTransport() *l4MemoryTransport {
	return &l4MemoryTransport{ready: make(chan struct{})}
}

func (transport *l4MemoryTransport) Serve(ctx context.Context, _ Limits, handler Handler) error {
	transport.mu.Lock()
	transport.h = handler
	transport.mu.Unlock()
	close(transport.ready)
	<-ctx.Done()
	return nil
}

func (transport *l4MemoryTransport) roundTrip(ctx context.Context, encoded []byte) []byte {
	transport.mu.RLock()
	handler := transport.h
	transport.mu.RUnlock()
	return handler.Handle(ctx, Request{Encoded: encoded}).Encoded
}

func l4Exec(t *testing.T, transport *l4MemoryTransport, ctx context.Context, args []string, stdin []byte, stdoutMax, stderrMax int64) guestagent.ExecResponse {
	t.Helper()
	var response guestagent.ExecResponse
	mustL4Decode(t, transport.roundTrip(ctx, mustL4JSON(t, l4ExecRequest(args, stdin, stdoutMax, stderrMax))), &response)
	if response.Error != nil {
		t.Fatalf("exec response error = %#v", response.Error)
	}
	return response
}

func l4ExecRequest(args []string, stdin []byte, stdoutMax, stderrMax int64) guestagent.ExecRequest {
	request := guestagent.ExecRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		Args:            args,
		WorkDir:         "/workspace",
		Stdout:          guestagent.StreamMetadata{MaxBytes: stdoutMax},
		Stderr:          guestagent.StreamMetadata{MaxBytes: stderrMax},
	}
	if stdin != nil {
		request.Stdin = &guestagent.StreamMetadata{
			SizeBytes: int64(len(stdin)),
			MaxBytes:  1024,
			Encoding:  guestagent.PayloadEncodingBase64,
			Data:      base64.StdEncoding.EncodeToString(stdin),
		}
	}
	return request
}

func l4Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeL4Data(t *testing.T, encoded string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return data
}

func mustL4JSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return encoded
}

func mustL4Decode(t *testing.T, encoded []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(encoded, destination); err != nil {
		t.Fatalf("decode JSON %q: %v", encoded, err)
	}
}

func assertL4Error(t *testing.T, encoded []byte) {
	t.Helper()
	var envelope struct {
		Error *guestagent.ProtocolError `json:"error"`
	}
	mustL4Decode(t, encoded, &envelope)
	if envelope.Error == nil {
		t.Fatalf("response = %s, want protocol error", encoded)
	}
}

func assertL4ErrorCode(t *testing.T, encoded []byte, code string) {
	t.Helper()
	var envelope struct {
		Error *guestagent.ProtocolError `json:"error"`
	}
	mustL4Decode(t, encoded, &envelope)
	if envelope.Error == nil || string(envelope.Error.Code) != code {
		t.Fatalf("response = %s, want error code %q", encoded, code)
	}
}

func l4HelperArgs(args []string) (string, []string, bool) {
	for index, arg := range args {
		if arg == "--" && index+1 < len(args) {
			return args[index+1], args[index+2:], true
		}
	}
	return "", nil, false
}

func waitL4PID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var pid int
			if _, err := fmt.Sscanf(string(data), "%d", &pid); err == nil {
				return pid
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for pid file %s", path)
	return 0
}

func waitL4ProcessGone(t *testing.T, pid int) {
	t.Helper()
	process, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := process.Signal(syscall.Signal(0)); err != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("process %d still exists after cancellation", pid)
}
