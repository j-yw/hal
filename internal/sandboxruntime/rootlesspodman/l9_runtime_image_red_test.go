package rootlesspodman_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

func TestL9CreateUsesRequestedDigestPinnedRuntimeImage(t *testing.T) {
	const (
		configuredImage = "registry.test/hal/default:configured"
		selectedImage   = "registry.test/hal/runtime:stable@sha256:abababababababababababababababababababababababababababababababab"
	)
	runner := &fakeCommandRunner{
		resultByOperation: map[string]rootlesspodman.CommandResult{
			rootlesspodman.OperationCreate: {Stdout: "runtime-l9\n"},
		},
	}
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner: runner,
		Image:           configuredImage,
	})
	req := sandboxruntime.CreateRequest{Name: "runtime-l9"}
	setL9CreateRequestImage(t, &req, selectedImage)

	created, err := driver.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if len(runner.lifecycleRequests) != 1 {
		t.Fatalf("create requests = %d, want 1", len(runner.lifecycleRequests))
	}
	args := runner.lifecycleRequests[0].Args
	if !containsExactL9Arg(args, selectedImage) || containsExactL9Arg(args, configuredImage) {
		t.Fatalf("create image args = %#v, want only selected digest-pinned image", args)
	}
	if created.Runtime.Image != selectedImage {
		t.Fatalf("created runtime image = %q, want selected digest-pinned image", created.Runtime.Image)
	}
}

func TestL9CreateFailureRedactsExplicitRuntimeImage(t *testing.T) {
	const selectedImage = "registry.test/private/runtime:stable@sha256:1212121212121212121212121212121212121212121212121212121212121212"
	runnerErr := errors.New("runtime image unavailable")
	runner := &fakeCommandRunner{
		resultByOperation: map[string]rootlesspodman.CommandResult{
			rootlesspodman.OperationCreate: {
				ExitCode: 125,
				Stderr:   "image " + selectedImage + " is unavailable",
			},
		},
		errByOperation: map[string]error{rootlesspodman.OperationCreate: runnerErr},
	}
	driver := rootlesspodman.New(rootlesspodman.Options{LifecycleRunner: runner})
	req := sandboxruntime.CreateRequest{Name: "runtime-l9", Image: selectedImage}

	_, err := driver.Create(context.Background(), req)
	if err == nil || !errors.Is(err, runnerErr) {
		t.Fatalf("Create() error = %v, want wrapped runner error", err)
	}
	if strings.Contains(err.Error(), selectedImage) || strings.Contains(err.Error(), "registry.test") || strings.Contains(err.Error(), "private/runtime") {
		t.Fatalf("Create() error leaked explicit runtime image: %q", err)
	}
}

func setL9CreateRequestImage(t *testing.T, req *sandboxruntime.CreateRequest, image string) {
	t.Helper()
	field := reflect.ValueOf(req).Elem().FieldByName("Image")
	if !field.IsValid() || field.Kind() != reflect.String || !field.CanSet() {
		t.Fatal("sandboxruntime.CreateRequest.Image string field is required for selected runtime construction")
	}
	field.SetString(image)
}

func containsExactL9Arg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
