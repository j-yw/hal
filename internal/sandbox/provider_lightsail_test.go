package sandbox

import (
	"strings"
	"testing"
)

func TestGenerateLightsailCloudInit_WithEnvVars(t *testing.T) {
	env := map[string]string{
		"GIT_TOKEN": "ghp_abc",
		"API_KEY":   "sk-123",
	}

	yaml := generateLightsailCloudInit(env)

	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}
	if !strings.Contains(yaml, "encoding: b64") {
		t.Error("cloud-init should use base64 encoding")
	}
	if !strings.Contains(yaml, "runcmd:") {
		t.Error("cloud-init should have runcmd section")
	}
	if !strings.Contains(yaml, "setup.sh") {
		t.Error("cloud-init runcmd should run setup.sh")
	}

	// Verify env file content
	content := buildLightsailEnvFileContent(env)
	if !strings.Contains(content, "API_KEY='sk-123'") {
		t.Errorf("env content should contain API_KEY, got: %s", content)
	}
	if !strings.Contains(content, "GIT_TOKEN='ghp_abc'") {
		t.Errorf("env content should contain GIT_TOKEN, got: %s", content)
	}
	apiIdx := strings.Index(content, "API_KEY=")
	gitIdx := strings.Index(content, "GIT_TOKEN=")
	if apiIdx > gitIdx {
		t.Error("env vars should be sorted: API_KEY before GIT_TOKEN")
	}
}

func TestGenerateLightsailCloudInit_EmptyEnv(t *testing.T) {
	yaml := generateLightsailCloudInit(nil)
	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}
	if !strings.Contains(yaml, "runcmd:") {
		t.Error("cloud-init should have runcmd section")
	}
}

func TestBuildLightsailCreateArgs(t *testing.T) {
	args := buildLightsailCreateArgs("my-instance", "us-east-1a", "small_3_0", "my-key", "/tmp/cloud-init.yaml")
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "lightsail create-instances") {
		t.Errorf("args should contain 'lightsail create-instances', got: %s", joined)
	}
	if !strings.Contains(joined, "--instance-names my-instance") {
		t.Errorf("args should contain '--instance-names my-instance', got: %s", joined)
	}
	if !strings.Contains(joined, "--availability-zone us-east-1a") {
		t.Errorf("args should contain '--availability-zone us-east-1a', got: %s", joined)
	}
	if !strings.Contains(joined, "--blueprint-id ubuntu_22_04") {
		t.Errorf("args should contain '--blueprint-id ubuntu_22_04', got: %s", joined)
	}
	if !strings.Contains(joined, "--bundle-id small_3_0") {
		t.Errorf("args should contain '--bundle-id small_3_0', got: %s", joined)
	}
	if !strings.Contains(joined, "--key-pair-name my-key") {
		t.Errorf("args should contain '--key-pair-name my-key', got: %s", joined)
	}
	if !strings.Contains(joined, "--user-data-file /tmp/cloud-init.yaml") {
		t.Errorf("args should contain '--user-data-file /tmp/cloud-init.yaml', got: %s", joined)
	}
}

func TestLightsailProvider_SSH(t *testing.T) {
	dir := t.TempDir()
	state := &SandboxState{
		Name:     "test-dev",
		Provider: "lightsail",
		IP:       "44.203.78.182",
	}
	if err := SaveState(dir, state); err != nil {
		t.Fatal(err)
	}

	p := &LightsailProvider{StateDir: dir}
	cmd, err := p.SSH("test-dev")
	if err != nil {
		t.Fatalf("SSH() error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "ubuntu@44.203.78.182") {
		t.Errorf("SSH cmd should contain ubuntu@44.203.78.182, got: %s", args)
	}
	if !strings.Contains(args, "StrictHostKeyChecking=no") {
		t.Errorf("SSH cmd should contain StrictHostKeyChecking=no, got: %s", args)
	}
}

func TestLightsailProvider_Exec(t *testing.T) {
	dir := t.TempDir()
	state := &SandboxState{
		Name:     "test-dev",
		Provider: "lightsail",
		IP:       "44.203.78.182",
	}
	if err := SaveState(dir, state); err != nil {
		t.Fatal(err)
	}

	p := &LightsailProvider{StateDir: dir}
	cmd, err := p.Exec("test-dev", []string{"ls", "-la"})
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "ubuntu@44.203.78.182") {
		t.Errorf("Exec cmd should contain ubuntu@44.203.78.182, got: %s", args)
	}
	if !strings.Contains(args, "-- ls -la") {
		t.Errorf("Exec cmd should contain '-- ls -la', got: %s", args)
	}
}

func TestLightsailProvider_SSH_NoIP(t *testing.T) {
	dir := t.TempDir()
	state := &SandboxState{
		Name:     "test-dev",
		Provider: "lightsail",
		IP:       "",
	}
	if err := SaveState(dir, state); err != nil {
		t.Fatal(err)
	}

	p := &LightsailProvider{StateDir: dir}
	_, err := p.SSH("test-dev")
	if err == nil {
		t.Fatal("SSH() should error when IP is empty")
	}
	if !strings.Contains(err.Error(), "no IP address") {
		t.Errorf("error should mention missing IP, got: %v", err)
	}
}
