package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/vsock"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "hal guest agent failed")
		os.Exit(1)
	}
}

func run() error {
	listener, err := vsock.ListenLinux()
	if err != nil {
		return err
	}
	transport, err := vsock.NewTransport(vsock.Options{Listener: listener})
	if err != nil {
		_ = listener.Close()
		return err
	}
	backend, err := server.NewLinuxBackend(server.LinuxBackendOptions{
		WorkspaceRoot: "/workspace",
		GuestRoot:     "/",
		BaseEnvironment: []string{
			"HOME=/workspace",
			"PATH=/usr/bin:/bin",
			"TMPDIR=/tmp",
		},
		ExecutablePaths: []string{"/usr/bin", "/bin"},
	})
	if err != nil {
		_ = listener.Close()
		return err
	}
	agent, err := server.New(server.Options{
		Transport: transport,
		Backend:   backend,
	})
	if err != nil {
		_ = listener.Close()
		_ = backend.Close(context.Background())
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return agent.Serve(ctx)
}
