package sandbox

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestProviderFromConfig_Daytona(t *testing.T) {
	cfg := ProviderConfig{DaytonaAPIKey: "test-key"}
	p, err := ProviderFromConfig("daytona", cfg)
	if err != nil {
		t.Fatalf("ProviderFromConfig(daytona) unexpected error: %v", err)
	}
	dp, ok := p.(*DaytonaProvider)
	if !ok {
		t.Fatalf("expected *DaytonaProvider, got %T", p)
	}
	if dp.APIKey != "test-key" {
		t.Errorf("APIKey = %q, want %q", dp.APIKey, "test-key")
	}
}

func TestProviderFromConfig_Hetzner(t *testing.T) {
	cfg := ProviderConfig{
		HetznerSSHKey:     "my-key",
		HetznerServerType: "cx22",
		HetznerImage:      "ubuntu-24.04",
		StateDir:          "/tmp/test-hal",
	}
	p, err := ProviderFromConfig("hetzner", cfg)
	if err != nil {
		t.Fatalf("ProviderFromConfig(hetzner) unexpected error: %v", err)
	}
	hp, ok := p.(*HetznerProvider)
	if !ok {
		t.Fatalf("expected *HetznerProvider, got %T", p)
	}
	if hp.SSHKey != "my-key" {
		t.Errorf("SSHKey = %q, want %q", hp.SSHKey, "my-key")
	}
	if hp.ServerType != "cx22" {
		t.Errorf("ServerType = %q, want %q", hp.ServerType, "cx22")
	}
	if hp.Image != "ubuntu-24.04" {
		t.Errorf("Image = %q, want %q", hp.Image, "ubuntu-24.04")
	}
	if hp.StateDir != "/tmp/test-hal" {
		t.Errorf("StateDir = %q, want %q", hp.StateDir, "/tmp/test-hal")
	}
}

func TestProviderFromConfig_Unknown(t *testing.T) {
	cfg := ProviderConfig{}
	_, err := ProviderFromConfig("digitalocean", cfg)
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
	if !strings.Contains(err.Error(), "unknown sandbox provider") {
		t.Errorf("error %q does not contain %q", err.Error(), "unknown sandbox provider")
	}
	if !strings.Contains(err.Error(), "digitalocean") {
		t.Errorf("error %q does not mention the unknown provider name", err.Error())
	}
}

func TestProviderFromConfig_AllKnown(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantType string
	}{
		{"daytona", "daytona", "*sandbox.DaytonaProvider"},
		{"hetzner", "hetzner", "*sandbox.HetznerProvider"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ProviderFromConfig(tt.provider, ProviderConfig{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := fmt.Sprintf("%T", p)
			if got != tt.wantType {
				t.Errorf("type = %s, want %s", got, tt.wantType)
			}
		})
	}
}

func TestRunCmd_Success(t *testing.T) {
	cmd := exec.Command("echo", "hello world")
	var buf bytes.Buffer
	err := RunCmd(cmd, &buf)
	if err != nil {
		t.Fatalf("RunCmd() unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "hello world") {
		t.Errorf("output = %q, want to contain %q", buf.String(), "hello world")
	}
}

func TestRunCmd_Failure(t *testing.T) {
	cmd := exec.Command("false")
	var buf bytes.Buffer
	err := RunCmd(cmd, &buf)
	if err == nil {
		t.Fatal("RunCmd() expected error for failing command, got nil")
	}
}

func TestRunCmd_StderrCaptured(t *testing.T) {
	// sh -c writes to stderr
	cmd := exec.Command("sh", "-c", "echo error-output >&2")
	var buf bytes.Buffer
	err := RunCmd(cmd, &buf)
	if err != nil {
		t.Fatalf("RunCmd() unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "error-output") {
		t.Errorf("output = %q, want to contain stderr %q", buf.String(), "error-output")
	}
}

func TestSandboxResult_Fields(t *testing.T) {
	r := &SandboxResult{
		ID:   "sb-123",
		Name: "my-sandbox",
		IP:   "10.0.0.1",
	}
	if r.ID != "sb-123" {
		t.Errorf("ID = %q, want %q", r.ID, "sb-123")
	}
	if r.Name != "my-sandbox" {
		t.Errorf("Name = %q, want %q", r.Name, "my-sandbox")
	}
	if r.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want %q", r.IP, "10.0.0.1")
	}
}
