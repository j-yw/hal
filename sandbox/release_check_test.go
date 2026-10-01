package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSandboxReleaseCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release wrapper requires POSIX sh")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("release wrapper JSON verification requires jq")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	script, err := os.ReadFile(filepath.Join(filepath.Dir(source), "release-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		fail bool
	}{
		{"pass", false}, {"skip", true}, {"package-skip", true},
		{"fail", true}, {"exit", true}, {"empty", true}, {"malformed", true},
		{"prepare-fail", true}, {"destroy-fail", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(filepath.Join(root, "sandbox"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			write := func(path, content string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(root, "sandbox", "release-check.sh"), string(script))
			write(filepath.Join(root, "sandbox", "podman-lab.sh"), `#!/bin/sh
printf 'lab %s\n' "$1" >> "$RELEASE_TEST_LOG"
case "$1" in
prepare) [ "$RELEASE_TEST_CASE" != prepare-fail ] ;;
destroy) [ "$RELEASE_TEST_CASE" != destroy-fail ] ;;
run) shift; shift; exec "$@" ;;
esac
`)
			write(filepath.Join(bin, "go"), `#!/bin/sh
printf 'go %s\n' "$*" >> "$RELEASE_TEST_LOG"
case "$1" in
env) printf '%s\n' "$RELEASE_TEST_ROOT"; exit 0 ;;
esac
case " $* " in
*' -json '*)
case " $* " in
*' -race '*)
case "$RELEASE_TEST_CASE" in
skip) echo '{"Action":"skip","Test":"TestPodmanIntegrationLifecycleExecAndCopy"}'; exit 0 ;;
package-skip) echo '{"Action":"skip","Package":"example"}'; exit 0 ;;
fail) echo '{"Action":"fail","Package":"example"}'; exit 0 ;;
exit) exit 1 ;;
empty) exit 0 ;;
malformed) echo 'not json'; exit 0 ;;
esac
;;
esac
for test in TestPodmanIntegrationLifecycleExecAndCopy TestWorkerJobPodmanIntegrationSurvivesClientDisconnect TestL3PreparedLinuxRecoveryE2E TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver TestFactoryRootlessBundleRealGitPreservesSourceBaseAndRun TestFactoryFinalizationRecoveryRealGit TestFactoryFinalizationRecoveryWorkerRoundTrip; do
printf '{"Action":"pass","Test":"%s"}\n' "$test"
done
;;
esac
`)
			for _, name := range []string{"make", "git", "gofmt"} {
				write(filepath.Join(bin, name), "#!/bin/sh\nexit 0\n")
			}
			write(filepath.Join(bin, "uname"), "#!/bin/sh\necho Linux\n")
			write(filepath.Join(bin, "id"), "#!/bin/sh\necho 1000\n")
			write(filepath.Join(bin, "podman"), "#!/bin/sh\necho true\n")
			logPath := filepath.Join(root, "commands.log")
			cmd := exec.Command("sh", filepath.Join(root, "sandbox", "release-check.sh"))
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"RELEASE_TEST_CASE="+tc.name, "RELEASE_TEST_ROOT="+root, "RELEASE_TEST_LOG="+logPath)
			output, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail {
				t.Fatalf("error = %v, want failure = %v; output: %s", err, tc.fail, output)
			}
			log, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(log), "lab destroy\n") != 1 {
				t.Fatalf("destroy must run exactly once, including on failure: %s", log)
			}
			if tc.name == "pass" {
				for _, want := range []string{
					"-race -count=1 -json -tags=podman_integration,l3_recovery_e2e",
					"./internal/sandboxruntime/rootlesspodman ./internal/sandboxworker ./cmd -run ^(TestPodmanIntegration|TestWorkerJobPodmanIntegration|TestL3PreparedLinuxRecoveryE2E)",
					"-tags=worker_integration,integration", "TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver",
					"TestFactoryRootlessBundleRealGit", "TestFactoryFinalizationRecovery",
				} {
					if !strings.Contains(string(log), want) {
						t.Errorf("missing required selection %q: %s", want, log)
					}
				}
			}
		})
	}
}
