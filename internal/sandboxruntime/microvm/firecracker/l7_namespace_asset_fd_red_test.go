package firecracker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL7NamespaceRenderMovesOnlyTwoAssetsToChildFDsFiveAndSix(t *testing.T) {
	config := validL7NetworkBackendConfig(t)
	config.RuntimeID = "runtime-l7-namespace-assets"
	stateDir := filepath.Join(t.TempDir(), "state")
	config.Paths = PathPlan{
		StateDir:        stateDir,
		APISocketPath:   stateDir + "/api.sock",
		ConfigPath:      stateDir + "/config.json",
		LogPath:         stateDir + "/firecracker.log",
		MetricsPath:     stateDir + "/firecracker.metrics",
		VsockSocketPath: stateDir + "/guest.vsock",
	}
	config.AssetChildFDStart = 5

	files, err := renderLiveBootFilesForStart(config)
	if err != nil {
		t.Fatalf("renderLiveBootFilesForStart() error = %v", err)
	}
	defer func() {
		if closeErr := closeProcessInheritedFiles(files); closeErr != nil {
			t.Errorf("closeProcessInheritedFiles() error = %v", closeErr)
		}
	}()
	if len(files) != 2 {
		t.Fatalf("inherited files = %d, want exactly two assets", len(files))
	}
	payload, err := os.ReadFile(config.Paths.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, want := range []string{"/proc/self/fd/5", "/proc/self/fd/6"} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered config missing %q: %s", want, payload)
		}
	}
	for _, forbidden := range []string{"/proc/self/fd/3", "/proc/self/fd/4"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("namespace-wrapped config retained old asset fd %q", forbidden)
		}
	}

	four := []*os.File{files[0], files[1], files[0], files[1]}
	if err := validateProcessInheritedFiles(four); err == nil {
		t.Fatal("generic ProcessStartRequest accepted four inherited files")
	}
}

func TestL7NamespaceAssetFDOffsetRejectsUnsupportedOrNonL7Use(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*BackendConfig)
	}{
		{name: "unsupported offset", mutate: func(config *BackendConfig) { config.AssetChildFDStart = 7 }},
		{name: "non-L7", mutate: func(config *BackendConfig) {
			config.NetworkMode = "no_live_networking"
			config.NetworkInterfaces = nil
			config.StaticNetwork = nil
			config.AssetChildFDStart = 5
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validL7NetworkBackendConfig(t)
			test.mutate(&config)
			if _, err := liveBootConfig(config); err == nil {
				t.Fatal("liveBootConfig() error = nil")
			}
		})
	}
}
