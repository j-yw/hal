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
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

const l4AmbientCanary = "L4_PREPARED_AMBIENT_CANARY"

func TestL4PreparedLinuxLocalServerE2E(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatalf("L4 prepared integration requires Linux; got %s", runtime.GOOS)
	}
	t.Setenv(l4AmbientCanary, "must-not-reach-child")

	workspace := t.TempDir()
	scriptRoot := t.TempDir()
	t.Run("executable root rejects proc descriptor magic link", func(t *testing.T) {
		rootFD, err := unix.Open(scriptRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open executable root: %v", err)
		}
		defer unix.Close(rootFD)

		magicLink := filepath.Join("/proc/self/fd", strconv.Itoa(rootFD))
		roots, err := openLinuxExecutableRoots([]string{magicLink})
		for _, root := range roots {
			_ = unix.Close(root.fd)
		}
		if err == nil {
			t.Fatal("openLinuxExecutableRoots() accepted proc descriptor magic link")
		}
	})
	t.Run("executable root follows ordinary symlink once and stays pinned", func(t *testing.T) {
		parent := t.TempDir()
		original := filepath.Join(parent, "original")
		replacement := filepath.Join(parent, "replacement")
		for _, directory := range []string{original, replacement} {
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatalf("create executable directory: %v", err)
			}
		}
		configured := filepath.Join(parent, "configured")
		if err := os.Symlink(original, configured); err != nil {
			t.Fatalf("create executable-root symlink: %v", err)
		}

		roots, err := openLinuxExecutableRoots([]string{configured})
		if err != nil {
			t.Fatalf("openLinuxExecutableRoots() error: %v", err)
		}
		defer unix.Close(roots[0].fd)
		if err := os.Remove(configured); err != nil {
			t.Fatalf("remove executable-root symlink: %v", err)
		}
		if err := os.Symlink(replacement, configured); err != nil {
			t.Fatalf("replace executable-root symlink: %v", err)
		}

		var pinned, originalStat, replacementStat unix.Stat_t
		if err := unix.Fstat(roots[0].fd, &pinned); err != nil {
			t.Fatalf("stat pinned executable root: %v", err)
		}
		if err := unix.Stat(original, &originalStat); err != nil {
			t.Fatalf("stat original executable root: %v", err)
		}
		if err := unix.Stat(replacement, &replacementStat); err != nil {
			t.Fatalf("stat replacement executable root: %v", err)
		}
		if pinned.Dev != originalStat.Dev || pinned.Ino != originalStat.Ino {
			t.Fatal("executable root descriptor did not pin the original symlink target")
		}
		if pinned.Dev == replacementStat.Dev && pinned.Ino == replacementStat.Ino {
			t.Fatal("executable root descriptor followed the replacement symlink target")
		}
	})

	backend, err := NewLinuxBackend(LinuxBackendOptions{
		WorkspaceRoot:   workspace,
		GuestRoot:       "/workspace",
		ExecutablePaths: []string{filepath.Dir(os.Args[0]), scriptRoot},
		TermGrace:       250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewLinuxBackend() prerequisite failure: %v", err)
	}
	hooks, ok := backend.(interface {
		setBeforeExecStartTestHook(func())
		setAfterCopyTempOpenTestHook(func())
	})
	if !ok {
		t.Fatal("production Linux backend does not expose package-private acceptance hooks")
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

	t.Run("exec keeps a pinned interpreter script available", func(t *testing.T) {
		scriptPath := filepath.Join(scriptRoot, "entrypoint")
		pinnedPath := filepath.Join(scriptRoot, "entrypoint-pinned")
		if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nprintf 'script:%s' \"$1\"\n"), 0o700); err != nil {
			t.Fatalf("write interpreter script: %v", err)
		}

		var hookErr error
		hooks.setBeforeExecStartTestHook(func() {
			if err := os.Rename(scriptPath, pinnedPath); err != nil {
				hookErr = fmt.Errorf("pin interpreter script: %w", err)
				return
			}
			if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nprintf 'replacement:%s' \"$1\"\n"), 0o700); err != nil {
				hookErr = fmt.Errorf("write replacement interpreter script: %w", err)
			}
		})
		defer hooks.setBeforeExecStartTestHook(nil)
		response := l4Exec(t, transport, context.Background(), []string{scriptPath, "ok"}, nil, 64, 64)
		if hookErr != nil {
			t.Fatal(hookErr)
		}
		if response.ExitCode != 0 {
			t.Fatalf("interpreter script exit code = %d, stderr=%q", response.ExitCode, decodeL4Data(t, response.Stderr.Data))
		}
		if got := string(decodeL4Data(t, response.Stdout.Data)); got != "script:ok" {
			t.Fatalf("interpreter script stdout = %q, want %q", got, "script:ok")
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

	t.Run("cancel terminates and reaps process group descendant", func(t *testing.T) {
		childPIDPath := filepath.Join(workspace, "descendant.pid")
		reapedPath := filepath.Join(workspace, "descendant.reaped")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan []byte, 1)
		go func() {
			done <- transport.roundTrip(ctx, mustL4JSON(t, l4ExecRequest([]string{
				os.Args[0], "-test.run=^TestL4PreparedLinuxHelperProcess$", "--", "group-leader", childPIDPath, reapedPath,
			}, nil, 64, 64)))
		}()
		childPID := waitL4PID(t, childPIDPath)
		cancel()
		assertL4ErrorCode(t, <-done, "request_canceled")
		if got, err := os.ReadFile(reapedPath); err != nil || string(got) != "reaped" {
			t.Fatalf("descendant reap marker = %q, %v", got, err)
		}
		waitL4ProcessGone(t, childPID)
	})

	t.Run("exec and environment fail closed", func(t *testing.T) {
		for _, executable := range []string{"/bin/sh", "sh"} {
			request := l4ExecRequest([]string{executable, "-c", "exit 0"}, nil, 64, 64)
			assertL4ErrorCode(t, transport.roundTrip(context.Background(), mustL4JSON(t, request)), "execution_failed")
		}

		request := l4ExecRequest([]string{
			os.Args[0], "-test.run=^TestL4PreparedLinuxHelperProcess$", "--", "output",
		}, nil, 64, 64)
		request.Env = []guestagent.EnvironmentEntry{{
			Name:   "REQUESTED_VALUE",
			Source: guestagent.EnvironmentSourceGenerated,
		}}
		assertL4ErrorCode(t, transport.roundTrip(context.Background(), mustL4JSON(t, request)), "environment_unavailable")
	})

	t.Run("work directory remains pinned across path replacement", func(t *testing.T) {
		workDir := filepath.Join(workspace, "pinned-workdir")
		renamedDir := filepath.Join(workspace, "pinned-workdir-original")
		if err := os.Mkdir(workDir, 0o700); err != nil {
			t.Fatalf("create pinned work directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(workDir, "identity"), []byte("original"), 0o600); err != nil {
			t.Fatalf("write original work-directory identity: %v", err)
		}

		var hookErr error
		hooks.setBeforeExecStartTestHook(func() {
			if err := os.Rename(workDir, renamedDir); err != nil {
				hookErr = fmt.Errorf("rename pinned work directory: %w", err)
				return
			}
			if err := os.Mkdir(workDir, 0o700); err != nil {
				hookErr = fmt.Errorf("create replacement work directory: %w", err)
				return
			}
			if err := os.WriteFile(filepath.Join(workDir, "identity"), []byte("replacement"), 0o600); err != nil {
				hookErr = fmt.Errorf("write replacement work-directory identity: %w", err)
			}
		})

		request := l4ExecRequest([]string{
			os.Args[0], "-test.run=^TestL4PreparedLinuxHelperProcess$", "--", "cwd-identity",
		}, nil, 64, 64)
		request.WorkDir = "/workspace/pinned-workdir"
		response := l4ExecRequestRoundTrip(t, transport, context.Background(), request)
		if hookErr != nil {
			t.Fatal(hookErr)
		}
		if got := string(decodeL4Data(t, response.Stdout.Data)); got != "original" {
			t.Fatalf("pinned work-directory identity = %q, want original", got)
		}
	})

	t.Run("copy descriptors are not inherited by concurrent exec", func(t *testing.T) {
		workDir := filepath.Join(workspace, "fd-workdir")
		if err := os.Mkdir(workDir, 0o700); err != nil {
			t.Fatalf("create descriptor work directory: %v", err)
		}
		copyOpened := make(chan struct{})
		releaseCopy := make(chan struct{})
		hooks.setAfterCopyTempOpenTestHook(func() {
			close(copyOpened)
			<-releaseCopy
		})

		copyDone := make(chan []byte, 1)
		go func() {
			copyDone <- transport.roundTrip(context.Background(), mustL4JSON(t,
				l4CopyInRequest("/workspace/concurrent-copy.bin", []byte("copy-data"), 1024)))
		}()
		select {
		case <-copyOpened:
		case <-time.After(5 * time.Second):
			t.Fatal("copy-in did not reach the open-descriptor hook")
		}

		request := l4ExecRequest([]string{
			os.Args[0], "-test.run=^TestL4PreparedLinuxHelperProcess$", "--", "fd-list",
		}, nil, 4096, 64)
		request.WorkDir = "/workspace/fd-workdir"
		response := l4ExecRequestRoundTrip(t, transport, context.Background(), request)
		output := string(decodeL4Data(t, response.Stdout.Data))
		if strings.Contains(output, ".hal-copy-") {
			t.Fatalf("copy descriptor leaked to child: %q", output)
		}
		for _, forbidden := range []string{workspace, filepath.Dir(os.Args[0]), os.Args[0]} {
			for _, target := range strings.Split(strings.TrimSpace(output), "\n") {
				if target == forbidden {
					t.Fatalf("server descriptor target %q leaked to child: %q", forbidden, output)
				}
			}
		}
		if !strings.Contains(output, workDir) {
			t.Fatalf("deliberate work-directory descriptor missing from child: %q", output)
		}

		close(releaseCopy)
		var copied guestagent.CopyInResponse
		mustL4Decode(t, <-copyDone, &copied)
		if copied.Error != nil {
			t.Fatalf("concurrent copy-in response = %#v", copied)
		}
	})

	t.Run("copy digest atomic mode preservation and containment", func(t *testing.T) {
		old := []byte("old")
		path := filepath.Join(workspace, "artifact.bin")
		if err := os.WriteFile(path, old, 0o644); err != nil {
			t.Fatalf("seed destination: %v", err)
		}
		payload := []byte{0x00, 'c', 'o', 'p', 'y', 0xff}
		digest := l4IntegrationDigest(payload)
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

		copyIn.Payload.Digest = l4IntegrationDigest([]byte("wrong"))
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
	})

	t.Run("copy-out rejects directory fifo socket and hard link", func(t *testing.T) {
		directoryPath := filepath.Join(workspace, "copy-out-directory")
		if err := os.Mkdir(directoryPath, 0o700); err != nil {
			t.Fatalf("create copy-out directory: %v", err)
		}
		fifoPath := filepath.Join(workspace, "copy-out.fifo")
		if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
			t.Fatalf("create copy-out FIFO: %v", err)
		}
		socketPath := filepath.Join(workspace, "copy-out.sock")
		socketFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("create copy-out socket: %v", err)
		}
		defer unix.Close(socketFD)
		if err := unix.Bind(socketFD, &unix.SockaddrUnix{Name: socketPath}); err != nil {
			t.Fatalf("bind copy-out socket: %v", err)
		}
		originalPath := filepath.Join(workspace, "copy-out-original")
		hardLinkPath := filepath.Join(workspace, "copy-out-hardlink")
		if err := os.WriteFile(originalPath, []byte("linked"), 0o600); err != nil {
			t.Fatalf("create copy-out original: %v", err)
		}
		if err := os.Link(originalPath, hardLinkPath); err != nil {
			t.Fatalf("create copy-out hard link: %v", err)
		}

		for _, sourcePath := range []string{
			"/workspace/copy-out-directory",
			"/workspace/copy-out.fifo",
			"/workspace/copy-out.sock",
			"/workspace/copy-out-hardlink",
		} {
			request := l4CopyOutRequest(sourcePath, 1024)
			assertL4ErrorCode(t, transport.roundTrip(context.Background(), mustL4JSON(t, request)), "copy_failed")
		}
	})

	t.Run("rejected copy-in preserves destination and removes temporary file", func(t *testing.T) {
		destinationPath := filepath.Join(workspace, "preserved-directory")
		if err := os.Mkdir(destinationPath, 0o700); err != nil {
			t.Fatalf("create preserved destination: %v", err)
		}
		sentinelPath := filepath.Join(destinationPath, "sentinel")
		if err := os.WriteFile(sentinelPath, []byte("preserve-me"), 0o600); err != nil {
			t.Fatalf("create preserved sentinel: %v", err)
		}
		assertNoL4CopyTemps(t, workspace)

		payload := []byte("replacement")
		request := l4CopyInRequest("/workspace/preserved-directory", payload, 1024)
		assertL4ErrorCode(t, transport.roundTrip(context.Background(), mustL4JSON(t, request)), "copy_failed")

		got, err := os.ReadFile(sentinelPath)
		if err != nil || string(got) != "preserve-me" {
			t.Fatalf("preserved destination sentinel = %q, %v", got, err)
		}
		assertNoL4CopyTemps(t, workspace)
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

func TestL4RejectedLinuxBackendConstructionClosesWorkspaceDescriptor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatalf("L4 prepared integration requires Linux; got %s", runtime.GOOS)
	}
	workspace := t.TempDir()
	before := l4DescriptorTargetCount(t, workspace)
	for attempt := 0; attempt < 16; attempt++ {
		backend, err := NewLinuxBackend(LinuxBackendOptions{
			WorkspaceRoot: workspace,
			GuestRoot:     "/workspace",
			TermGrace:     -time.Millisecond,
		})
		if err == nil || backend != nil {
			t.Fatalf("NewLinuxBackend() = %#v, %v, want negative termGrace error", backend, err)
		}
	}
	if after := l4DescriptorTargetCount(t, workspace); after != before {
		t.Fatalf("workspace descriptor count = %d after rejected construction, want %d", after, before)
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
	case "group-leader":
		if len(args) != 2 {
			os.Exit(2)
		}
		termination := make(chan os.Signal, 1)
		signal.Notify(termination, syscall.SIGTERM)
		defer signal.Stop(termination)
		child := exec.Command(os.Args[0], "-test.run=^TestL4PreparedLinuxHelperProcess$", "--", "group-child", args[0])
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		<-termination
		_ = child.Wait()
		if err := os.WriteFile(args[1], []byte("reaped"), 0o600); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	case "group-child":
		if len(args) != 1 {
			os.Exit(2)
		}
		_ = os.WriteFile(args[0], []byte(fmt.Sprintf("%d", os.Getpid())), 0o600)
		select {}
	case "cwd-identity":
		data, err := os.ReadFile("identity")
		if err != nil {
			os.Exit(3)
		}
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	case "fd-list":
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			os.Exit(3)
		}
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if err == nil {
				_, _ = fmt.Fprintln(os.Stdout, target)
			}
		}
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func l4DescriptorTargetCount(t *testing.T, target string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read process descriptors: %v", err)
	}
	count := 0
	for _, entry := range entries {
		resolved, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && resolved == target {
			count++
		}
	}
	return count
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
	return l4ExecRequestRoundTrip(t, transport, ctx, l4ExecRequest(args, stdin, stdoutMax, stderrMax))
}

func l4ExecRequestRoundTrip(t *testing.T, transport *l4MemoryTransport, ctx context.Context, request guestagent.ExecRequest) guestagent.ExecResponse {
	t.Helper()
	var response guestagent.ExecResponse
	mustL4Decode(t, transport.roundTrip(ctx, mustL4JSON(t, request)), &response)
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

func l4CopyInRequest(destinationPath string, data []byte, maxBytes int64) guestagent.CopyInRequest {
	return guestagent.CopyInRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyIn,
		DestinationPath: destinationPath,
		Payload: guestagent.PayloadMetadata{
			SizeBytes: int64(len(data)),
			MaxBytes:  maxBytes,
			Digest:    l4IntegrationDigest(data),
			Encoding:  guestagent.PayloadEncodingBase64,
			Data:      base64.StdEncoding.EncodeToString(data),
		},
	}
}

func l4CopyOutRequest(sourcePath string, maxBytes int64) guestagent.CopyOutRequest {
	return guestagent.CopyOutRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyOut,
		SourcePath:      sourcePath,
		Payload: guestagent.PayloadMetadata{
			MaxBytes: maxBytes,
			Encoding: guestagent.PayloadEncodingBase64,
		},
	}
}

func l4IntegrationDigest(data []byte) string {
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

func assertNoL4CopyTemps(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read copy destination directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".hal-copy-") && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("copy temporary file remained after rejection: %s", entry.Name())
		}
	}
}
