//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

func defaultSandboxdRuntimePaths() sandboxdRuntimePaths {
	socketPath := filepath.Join(os.TempDir(), sandboxdDefaultSocketName)
	return sandboxdRuntimePaths{
		socketPath:  socketPath,
		jobStateDir: socketPath + ".jobs",
	}
}

func prepareSandboxdDefaultRuntime(string) error {
	return fmt.Errorf("sandboxd private runtime directory is unsupported")
}
