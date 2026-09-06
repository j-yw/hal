//go:build !linux

package linuxtopology

import (
	"context"
	"errors"
	"testing"
)

func TestL7LinuxTopologyNonLinuxFailsClosed(t *testing.T) {
	lifecycle, err := New(Config{Enabled: true, Tools: testTools()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = lifecycle.Start(context.Background(), testRequest("topology-gen-nonlinux"))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Start error = %v, want ErrUnsupported", err)
	}
}
