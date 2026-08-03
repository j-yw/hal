//go:build linux

package l7network

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

type osNamespaceCommand struct{ nsenterPath string }

func newPlatformNamespaceCommand(nsenterPath string) (NamespaceCommandBoundary, bool) {
	return &osNamespaceCommand{nsenterPath: nsenterPath}, true
}

func tapPlatformSupported() bool { return true }

func (r *osNamespaceCommand) Run(ctx context.Context, namespace NamespaceLease, request NamespaceCommandRequest, limit int64) ([]byte, error) {
	provider, ok := namespace.(interface {
		commandFiles() *linuxtopology.NamespaceFiles
	})
	if !ok || provider.commandFiles() == nil || !validToolPath(request.Path) || limit <= 0 || limit > maxTAPOutputLimit {
		return nil, ErrTopologyPrepareFailed
	}
	for _, arg := range request.Args {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return nil, ErrTopologyPrepareFailed
		}
	}
	user, network, err := provider.commandFiles().DuplicateForCommand()
	if err != nil {
		return nil, ErrTopologyPrepareFailed
	}
	defer user.Close()
	defer network.Close()
	args := []string{"--preserve-credentials", "--keep-caps", "--user=/proc/self/fd/3", "--net=/proc/self/fd/4", "--", request.Path}
	args = append(args, request.Args...)
	command := exec.CommandContext(ctx, r.nsenterPath, args...)
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{user, network}
	buffer := &boundedCommandBuffer{limit: limit}
	command.Stdout, command.Stderr = buffer, buffer
	if err := command.Run(); err != nil {
		return nil, ErrTopologyPrepareFailed
	}
	if buffer.overflow {
		return nil, ErrTopologyPrepareFailed
	}
	return append([]byte(nil), buffer.payload...), nil
}

type boundedCommandBuffer struct {
	mu       sync.Mutex
	limit    int64
	payload  []byte
	overflow bool
}

func (b *boundedCommandBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - int64(len(b.payload))
	if remaining <= 0 || int64(len(payload)) > remaining {
		if remaining > 0 {
			b.payload = append(b.payload, payload[:int(remaining)]...)
		}
		b.overflow = true
		return len(payload), nil
	}
	b.payload = append(b.payload, payload...)
	return len(payload), nil
}
