package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestSandboxdImageJobAttestationReachesDriverAndJobAdmission(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want bool
	}{
		{"default image", nil, true},
		{"custom image without attestation", []string{"--image", "localhost/hal-agent:custom"}, false},
		{"custom image explicitly attested", []string{"--image", "localhost/hal-agent:custom", "--image-job-execution-supported"}, true},
		{"custom image explicit false", []string{"--image", "localhost/hal-agent:custom", "--image-job-execution-supported=false"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var service *sandboxworker.Service
			cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
				rootlessPodmanAvailable: func(context.Context, sandboxdRootlessPodmanConfig) error { return nil },
				newRootlessPodmanDriver: func(config sandboxdRootlessPodmanConfig) sandboxruntime.Driver {
					driver := defaultSandboxdRootlessPodmanDriver(config).(*rootlesspodman.Driver)
					if driver.SupportsJobExecution() != test.want {
						t.Fatalf("constructed driver job support = %v, want %v", driver.SupportsJobExecution(), test.want)
					}
					// Keep production image capability selection, but never execute
					// Podman or a real agent in this command-to-service test.
					return sandboxdImageJobDriver{Driver: driver}
				},
				newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
					var err error
					service, err = sandboxworker.NewService(options)
					return service, err
				},
				newServer: func(sandboxworker.ServerOptions) (sandboxdServer, error) {
					return sandboxdServerFunc(func(ctx context.Context) error {
						capabilities := service.Capabilities()
						if err := capabilities.Validate(); err != nil {
							t.Fatal(err)
						}
						assertSandboxdDefaultCapabilitySecurity(t, "worker", capabilities.Security)
						if len(capabilities.RuntimeDrivers) != 1 {
							t.Fatalf("runtime drivers = %#v", capabilities.RuntimeDrivers)
						}
						descriptor := capabilities.RuntimeDrivers[0]
						assertSandboxdDefaultCapabilitySecurity(t, "driver", descriptor.Security)
						if descriptor.IsolationLevel != sandboxworker.IsolationLevelContainer || descriptor.Security.Enforced.CredentialProxyMode ||
							!reflect.DeepEqual(descriptor.Security.Enforced.CredentialModes, []string{"env", "legacy_auth_sync"}) ||
							descriptor.Security.Enforced.CredentialDelivery != nil || descriptor.NetworkEnforcement != nil {
							t.Fatalf("image attestation inflated security: %#v", descriptor)
						}
						for _, operations := range [][]string{capabilities.SupportedOperations, descriptor.Operations} {
							if containsSandboxdTestString(operations, sandboxworker.OperationJobStart) != test.want {
								t.Fatalf("job_start capability = %#v, want supported=%v", operations, test.want)
							}
						}
						response := service.JobStartResponse(ctx, "image-job-request", sandboxruntime.DriverRootlessPodman, sandboxworker.JobStartRequest{
							ContractVersion: sandboxworker.JobContractVersion,
							SubmissionID:    "image-job-submission",
							Exec: sandboxworker.ExecRequest{
								OperationID: "image-job-exec",
								Target:      sandboxworker.Target{Name: "image-job-box", Runtime: sandboxworker.RuntimeTarget{Driver: sandboxruntime.DriverRootlessPodman, RuntimeID: "image-job-runtime"}},
								Args:        []string{"sh", "-c", "true"}, StdoutLimitBytes: 1024, StderrLimitBytes: 1024,
							},
						})
						if response.OK != test.want {
							t.Fatalf("job admission = %#v, error=%+v, want accepted=%v", response, response.Error, test.want)
						}
						if !test.want {
							if response.Error == nil || response.Error.Code != sandboxworker.ErrorCodeUnsupportedOp {
								t.Fatalf("custom image without attestation was not denied: %#v", response)
							}
							return nil
						}
						deadline := time.Now().Add(time.Second)
						for time.Now().Before(deadline) {
							status := service.JobStatusResponse("image-job-status", sandboxworker.JobStatusRequest{ContractVersion: sandboxworker.JobContractVersion, JobID: response.Job.ID})
							if status.Job != nil && status.Job.State == sandboxworker.JobStateSucceeded {
								return nil
							}
							time.Sleep(time.Millisecond)
						}
						t.Fatal("admitted fake job did not complete")
						return nil
					}), nil
				},
			})
			args := []string{"--socket", "/tmp/image-job-test.sock", "--job-state-dir", filepath.Join(t.TempDir(), "jobs"), "--worker-id", "image-job-worker", "--podman", "unused-fake-podman"}
			cmd.SetArgs(append(args, test.args...))
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSandboxdImageJobAttestationRejectsWrongDriver(t *testing.T) {
	for _, flag := range []string{"--image-job-execution-supported", "--image-job-execution-supported=false"} {
		cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
			newService: func(sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
				t.Fatal("invalid attestation reached service construction")
				return nil, nil
			},
		})
		cmd.SetArgs([]string{"--driver", "microvm", flag})
		err := cmd.Execute()
		var exitErr *ExitCodeError
		if !errors.As(err, &exitErr) || exitErr.Code != ExitCodeValidation || !strings.Contains(err.Error(), "--image-job-execution-supported requires --driver rootless_podman") {
			t.Fatalf("wrong-driver attestation error = %v", err)
		}
	}
}

func TestSandboxdImageJobAttestationFlagContract(t *testing.T) {
	cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{})
	flag := cmd.Flags().Lookup("image-job-execution-supported")
	if flag == nil || flag.Value.Type() != "bool" || flag.DefValue != "false" {
		t.Fatalf("image attestation flag = %#v, want default-off boolean", flag)
	}
	for _, want := range []string{"operator attestation", "does not verify", "strengthen security"} {
		if !strings.Contains(flag.Usage, want) {
			t.Errorf("flag help does not explain %q: %s", want, flag.Usage)
		}
	}
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--image-job-execution-supported=invalid"}, "invalid argument"},
		{[]string{"--image-job-execution-supported", "--image", " "}, "--image is required"},
	} {
		cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
			rootlessPodmanAvailable: func(context.Context, sandboxdRootlessPodmanConfig) error {
				t.Fatal("invalid image attestation reached runtime availability check")
				return nil
			},
		})
		cmd.SetArgs(test.args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("Execute(%q) = %v, want %q", test.args, err, test.want)
		}
	}
}

type sandboxdImageJobDriver struct{ *rootlesspodman.Driver }

func (sandboxdImageJobDriver) Exec(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	return &sandboxruntime.ExecResult{ExitCode: 0}, nil
}
