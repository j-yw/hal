package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
)

func TestL7LiveDriverConstructionIsExplicitAndFailsBeforeMutation(t *testing.T) {
	intent := &l7CompositionIntentResolver{}
	assets := &l7CompositionAssetResolver{}
	starter := &l7CompositionNamespaceStarter{}

	driver, err := NewL7LiveDriver(L7LiveDriverOptions{
		Live:             LiveDriverOptions{},
		Intent:           intent,
		Assets:           assets,
		NamespaceStarter: starter,
		NSenterPath:      filepath.Join(string(filepath.Separator), "usr", "bin", "nsenter"),
	})
	if driver != nil || err == nil {
		t.Fatalf("NewL7LiveDriver(incomplete) = %#v, %v, want fail-closed construction", driver, err)
	}
	if intent.calls != 0 || assets.calls != 0 || starter.calls != 0 {
		t.Fatalf("construction crossed live boundary: intent=%d assets=%d starts=%d", intent.calls, assets.calls, starter.calls)
	}
	assertL7CompositionSanitizedError(t, err)
}

func TestL7LiveDriverDefaultPathsRemainInert(t *testing.T) {
	files := []string{
		filepath.Join("..", "..", "..", "..", "cmd"),
		filepath.Join("..", "..", "..", "sandboxworker"),
		filepath.Join("..", "..", "..", "sandboxexec"),
	}
	for _, root := range files {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			payload, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(payload), "NewL7LiveDriver(") {
				t.Fatalf("default production path %s enabled explicit L7 live construction", filepath.Base(path))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Existing generic construction remains planning-only unless its own
	// explicit LiveStart dependencies are supplied.
	options, err := NewLiveBackendOptions(LiveDriverOptions{})
	if err == nil || options.LiveStart {
		t.Fatalf("NewLiveBackendOptions(zero) = %#v, %v, want inert rejection", options, err)
	}
}

func TestL7LiveDriverRejectsNonLinuxBeforeLiveResolution(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux fail-closed construction is covered by cross-compile")
	}
	intent := &l7CompositionIntentResolver{}
	assets := &l7CompositionAssetResolver{}
	driver, err := NewL7LiveDriver(L7LiveDriverOptions{Intent: intent, Assets: assets})
	if driver != nil || err == nil {
		t.Fatalf("NewL7LiveDriver(non-Linux) = %#v, %v, want unsupported", driver, err)
	}
	if intent.calls != 0 || assets.calls != 0 {
		t.Fatal("non-Linux construction resolved live intent or assets")
	}
}

type l7CompositionIntentResolver struct{ calls int }

func (resolver *l7CompositionIntentResolver) ResolveL7RuntimeIntent(context.Context, string) (l7network.PrepareRequest, error) {
	resolver.calls++
	return l7network.PrepareRequest{}, errors.New("private endpoint=/run/private")
}

type l7CompositionAssetResolver struct{ calls int }

func (resolver *l7CompositionAssetResolver) AcquireL7RuntimeAssets(context.Context, l7network.Identity) (L7RuntimeAssets, error) {
	resolver.calls++
	return L7RuntimeAssets{}, errors.New("private asset=/home/private/rootfs")
}

type l7CompositionNamespaceStarter struct{ calls int }

func (starter *l7CompositionNamespaceStarter) StartNamespaceProcess(context.Context, NamespaceProcessStartRequest) (HostProcess, error) {
	starter.calls++
	return nil, errors.New("pid=4242 socket=/run/private.sock")
}

func assertL7CompositionSanitizedError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil")
	}
	for _, forbidden := range []string{"/run/", "/home/", "4242", "private.sock", "endpoint="} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked %q: %v", forbidden, err)
		}
	}
	var operation *microvm.OperationError
	if !errors.As(err, &operation) && !errors.Is(err, ErrL7LiveCompositionInvalid) {
		t.Fatalf("error = %T %v, want structured or stable L7 construction error", err, err)
	}
}
