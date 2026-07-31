//go:build !linux

package firecracker

import (
	"errors"
	"io"
	"os"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

func newSealedL7LaunchMaterial(string) (*sealedL7LaunchMaterial, error) {
	return nil, errors.New("sealed L7 launch material requires Linux")
}

type sealedL7LaunchMaterial struct{}

func (*sealedL7LaunchMaterial) WriteAsset(assets.AssetRole, io.Reader) (string, error) {
	return "", errors.New("sealed L7 launch material requires Linux")
}

func (*sealedL7LaunchMaterial) Validate() error {
	return errors.New("sealed L7 launch material requires Linux")
}

func (*sealedL7LaunchMaterial) inheritedFiles() ([]*os.File, error) {
	return nil, errors.New("sealed L7 launch material requires Linux")
}

func (*sealedL7LaunchMaterial) Close() error { return nil }
