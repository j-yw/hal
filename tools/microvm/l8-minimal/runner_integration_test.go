//go:build linux && microvm_assets_integration

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests execute the real entry scripts with fake Git/cache/runtime CLIs.
// They never contact a registry, launch a container or compile a guest image.
func TestMinimalParentBuildersSelectExplicitRootlessRuntime(t *testing.T) {
	for _, lane := range []string{"l5", "l7"} {
		for _, scenario := range []string{"default_docker", "explicit_docker", "podman", "rootful", "wrong_digest", "unsupported", "excess_jobs"} {
			t.Run(lane+"/"+scenario, func(t *testing.T) {
				root := t.TempDir()
				mustRunnerWrite := func(name, data string) {
					t.Helper()
					if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(name, []byte(data), 0700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Chmod(root, 0700); err != nil {
					t.Fatal(err)
				}
				repo := filepath.Join(root, "repo")
				bin := filepath.Join(root, "bin")
				cache := filepath.Join(root, "cache")
				if err := os.Mkdir(cache, 0700); err != nil {
					t.Fatal(err)
				}
				source, err := os.ReadFile("../" + lane + "/build.sh")
				if err != nil {
					t.Fatal(err)
				}
				script := filepath.Join(repo, "tools", "microvm", lane, "build.sh")
				mustRunnerWrite(script, string(source))
				mustRunnerWrite(filepath.Join(repo, "tools", "microvm", "l5", "verify-cache.sh"), "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RUNNER_TEST_CACHE_LOG\"\n")
				mustRunnerWrite(filepath.Join(bin, "git"), `#!/bin/sh
shift 2
case "$1:$2" in
rev-parse:--show-toplevel) printf '%s\n' "$RUNNER_TEST_REPO" ;;
rev-parse:HEAD) printf '%040d\n' 1 ;;
rev-parse:*) printf '%040d\n' 2 ;;
status:*) exit 0 ;;
show:*) printf '1780000000\n' ;;
*) exit 90 ;;
esac
`)
				for _, runtime := range []string{"docker", "podman"} {
					mustRunnerWrite(filepath.Join(bin, runtime), `#!/bin/sh
printf '%s\n' "$0 $*" >> "$RUNNER_TEST_CALL_LOG"
case "$1" in
info) printf '%s\n' "$RUNNER_TEST_ROOTLESS" ;;
image) printf '%s\n' "$RUNNER_TEST_DIGEST" ;;
run) printf '%s\n' "$@" > "$RUNNER_TEST_RUN_LOG" ;;
*) exit 91 ;;
esac
`)
				}
				const digest = "registry.gitlab.com/buildroot.org/buildroot/base@sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6"
				rootless, image, jobs := "true", digest, "3"
				runtime := "podman"
				switch scenario {
				case "default_docker":
					runtime = ""
				case "explicit_docker":
					runtime = "docker"
				case "rootful":
					rootless = "false"
				case "wrong_digest":
					image = "unrelated@sha256:" + strings.Repeat("a", 64)
				case "unsupported":
					runtime = "arbitrary-runtime"
				case "excess_jobs":
					jobs = "4"
				}
				args := []string{script, "--cache", cache, "--output", filepath.Join(root, "output")}
				if runtime != "" {
					args = append(args, "--runtime", runtime)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, "/bin/bash", args...)
				runLog, callLog, cacheLog := filepath.Join(root, "run"), filepath.Join(root, "calls"), filepath.Join(root, "cache-args")
				command.Env = []string{
					"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + root,
					"RUNNER_TEST_REPO=" + repo, "RUNNER_TEST_RUN_LOG=" + runLog, "RUNNER_TEST_CALL_LOG=" + callLog,
					"RUNNER_TEST_CACHE_LOG=" + cacheLog, "RUNNER_TEST_ROOTLESS=" + rootless, "RUNNER_TEST_DIGEST=" + image,
					"HAL_" + strings.ToUpper(lane) + "_JOBS=" + jobs, "UNRELATED_SECRET=runner-seeded-secret",
				}
				output, runErr := command.CombinedOutput()
				valid := scenario == "default_docker" || scenario == "explicit_docker" || scenario == "podman"
				if !valid {
					if runErr == nil {
						t.Fatalf("unsafe runner accepted: %s", output)
					}
					if _, err := os.Stat(runLog); !os.IsNotExist(err) {
						t.Fatal("unsafe runner reached container launch")
					}
					return
				}
				if runErr != nil {
					t.Fatalf("valid runner rejected: %v: %s", runErr, output)
				}
				argv, err := os.ReadFile(runLog)
				if err != nil {
					t.Fatal(err)
				}
				text := string(argv)
				for _, required := range []string{"--pull=never\n", "--network=none\n", "--user=", digest + "\n", "/src/tools/microvm/" + lane + "/build-in-container.sh\n"} {
					if !strings.Contains(text, required) {
						t.Errorf("run argv missing %q", required)
					}
				}
				if strings.Contains(text, "runner-seeded-secret") || strings.Contains(text, "docker.sock") {
					t.Fatal("host credentials or runtime socket included")
				}
				calls, err := os.ReadFile(callLog)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "podman" {
					for _, required := range []string{"--userns=keep-id\n", "--cpus=3\n", "--memory=12g\n", "--pids-limit=512\n", "--security-opt=no-new-privileges\n"} {
						if !strings.Contains(text, required) {
							t.Errorf("rootless run missing %q", required)
						}
					}
					if !strings.Contains(string(calls), "/podman info ") || strings.Contains(string(calls), "/docker ") {
						t.Fatal("missing rootless proof or implicit Docker fallback")
					}
				} else if strings.Contains(text, "--userns") || strings.Contains(string(calls), "/podman ") || strings.Contains(string(calls), " info ") {
					t.Fatal("legacy Docker path changed")
				}
				verified, err := os.ReadFile(cacheLog)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(verified), "/l5/cache.manifest\n") {
					t.Fatal("exact L5 cache authority replaced")
				}
			})
		}
	}
}
