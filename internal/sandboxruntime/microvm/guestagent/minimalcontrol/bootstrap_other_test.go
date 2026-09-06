//go:build !linux

package minimalcontrol

import (
	"bytes"
	"context"
	"testing"
)

func TestBootstrapOtherPlatformFailsClosed(t *testing.T) {
	if line, err := ReadLinuxBootCommandLine(context.Background()); line != "" || err != ErrUnavailable {
		t.Fatal("non-Linux boot reader supplied a fallback")
	}
	value := bytes.Repeat([]byte{1}, 32)
	if n, err := (bootstrapEntropy{}).Read(value); n != 0 || err != ErrUnavailable || !bytes.Equal(value, make([]byte, 32)) {
		t.Fatal("non-Linux entropy supplied a fallback")
	}
}
