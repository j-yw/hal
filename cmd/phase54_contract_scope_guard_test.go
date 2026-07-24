package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/status"
)

func TestPhase54NoSchemaOrContractExpansionRequired(t *testing.T) {
	cases := []struct {
		label string
		typ   reflect.Type
		want  []string
	}{
		{
			label: "status.StatusResult",
			typ:   reflect.TypeOf(status.StatusResult{}),
			want: []string{
				"contractVersion", "workflowTrack", "state", "artifacts", "nextAction", "summary",
				"manual,omitempty", "compound,omitempty", "reviewLoop,omitempty", "paths,omitempty",
			},
		},
		{
			label: "doctor.DoctorResult",
			typ:   reflect.TypeOf(doctor.DoctorResult{}),
			want: []string{
				"contractVersion", "overallStatus", "engine", "checks", "totalChecks", "passedChecks",
				"failures", "warnings", "primaryRemediation,omitempty", "summary",
			},
		},
		{
			label: "ContinueResult",
			typ:   reflect.TypeOf(ContinueResult{}),
			want: []string{
				"contractVersion", "ready", "status", "doctor", "nextCommand", "nextDescription", "summary",
			},
		},
		{
			label: "sandboxexecution.Manifest",
			typ:   reflect.TypeOf(sandboxexecution.Manifest{}),
			want: []string{
				"id", "purpose", "sandboxName,omitempty", "projectDir,omitempty", "command,omitempty",
				"workDir,omitempty", "status", "startedAt", "finishedAt,omitempty", "workspace,omitempty",
				"host,omitempty", "runtime,omitempty", "security,omitempty", "networkProxySession,omitempty",
				"networkPolicyDecisionLogs,omitempty", "credentialProxyPlan,omitempty", "credentialProxySession,omitempty",
				"credentialProxyBindings,omitempty", "credentialDelivery,omitempty", "lease,omitempty",
				"workerRouting,omitempty", "workerJob,omitempty", "finalization,omitempty", "templateLock,omitempty", "artifacts,omitempty", "artifactMetadata,omitempty",
				"syncOut,omitempty", "syncOutApply,omitempty",
			},
		},
		{
			label: "sandboxexecution.Artifact",
			typ:   reflect.TypeOf(sandboxexecution.Artifact{}),
			want:  []string{"id,omitempty", "name", "type", "path,omitempty", "storedPath,omitempty", "sizeBytes,omitempty", "createdAt,omitempty"},
		},
		{
			label: "sandboxexecution.ArtifactMetadata",
			typ:   reflect.TypeOf(sandboxexecution.ArtifactMetadata{}),
			want:  []string{"collected,omitempty", "partial,omitempty", "warnings,omitempty"},
		},
		{
			label: "sandboxexecution.ArtifactMetadataEntry",
			typ:   reflect.TypeOf(sandboxexecution.ArtifactMetadataEntry{}),
			want:  []string{"id,omitempty", "name,omitempty", "type,omitempty", "path,omitempty", "storedPath,omitempty", "sizeBytes,omitempty", "createdAt,omitempty"},
		},
		{
			label: "factory.RunRecord",
			typ:   reflect.TypeOf(factory.RunRecord{}),
			want: []string{
				"runId", "status", "executorMode", "engine,omitempty", "source", "repoPath", "repoRemote",
				"branchName", "baseBranch", "policy,omitempty", "sandboxName,omitempty", "sandbox,omitempty",
				"currentStep", "createdAt", "updatedAt", "finishedAt,omitempty", "artifacts,omitempty",
				"verification,omitempty", "telemetry,omitempty", "failure,omitempty", "secrets,omitempty",
				"postRun,omitempty",
			},
		},
		{
			label: "factory.SandboxMetadata",
			typ:   reflect.TypeOf(factory.SandboxMetadata{}),
			want: []string{
				"name", "provider", "size,omitempty", "status", "connection,omitempty", "sshCommand,omitempty",
				"cleanupCommand,omitempty", "handoff,omitempty", "host,omitempty", "runtime,omitempty",
				"workspace,omitempty", "security,omitempty", "networkProxySession,omitempty",
				"credentialProxyPlan,omitempty", "credentialProxySession,omitempty", "credentialProxyBindings,omitempty",
				"credentialDelivery,omitempty", "lease,omitempty", "workerRouting,omitempty", "templateLock,omitempty",
			},
		},
		{
			label: "factory.SandboxConnectionMetadata",
			typ:   reflect.TypeOf(factory.SandboxConnectionMetadata{}),
			want:  []string{"address,omitempty", "publicIp,omitempty", "tailscaleIp,omitempty", "tailscaleHostname,omitempty", "tailscaleLockdown,omitempty"},
		},
		{
			label: "factory.SandboxRuntimeMetadata",
			typ:   reflect.TypeOf(factory.SandboxRuntimeMetadata{}),
			want:  []string{"driver", "isolationLevel", "runtimeId", "image", "workerId"},
		},
		{
			label: "factory.SandboxWorkspaceMetadata",
			typ:   reflect.TypeOf(factory.SandboxWorkspaceMetadata{}),
			want:  []string{"mode", "inputSource", "branch", "syncRef"},
		},
		{
			label: "factory.SandboxSecurityMetadata",
			typ:   reflect.TypeOf(factory.SandboxSecurityMetadata{}),
			want: []string{
				"network,omitempty", "secrets,omitempty", "capabilityReadiness,omitempty",
				"capabilityReadinessDiagnostics,omitempty", "securityReadinessGate,omitempty",
			},
		},
		{
			label: "factory.SandboxNetworkSecurityMetadata",
			typ:   reflect.TypeOf(factory.SandboxNetworkSecurityMetadata{}),
			want:  []string{"policyRequested,omitempty", "policyEnforced,omitempty", "enforcementMode,omitempty", "policyResult,omitempty"},
		},
		{
			label: "factory.SandboxSecretSecurityMetadata",
			typ:   reflect.TypeOf(factory.SandboxSecretSecurityMetadata{}),
			want:  []string{"requestedModes,omitempty", "activeModes,omitempty"},
		},
		{
			label: "factory.SandboxLeaseMetadata",
			typ:   reflect.TypeOf(factory.SandboxLeaseMetadata{}),
			want:  []string{"id", "hostId", "hostName", "runtimeDriver", "resourceKey", "purpose", "runId", "acquiredAt", "expiresAt"},
		},
		{
			label: "factory.RunSecretMetadata",
			typ:   reflect.TypeOf(factory.RunSecretMetadata{}),
			want:  []string{"name", "source", "required", "present"},
		},
		{
			label: "factory.ArtifactReference",
			typ:   reflect.TypeOf(factory.ArtifactReference{}),
			want: []string{
				"id,omitempty", "name", "type", "sourcePath,omitempty", "storedPath,omitempty", "path,omitempty",
				"url,omitempty", "sizeBytes,omitempty", "createdAt,omitempty", "summary,omitempty",
				"warnings,omitempty", "partial,omitempty",
			},
		},
		{
			label: "factory.EventRecord",
			typ:   reflect.TypeOf(factory.EventRecord{}),
			want:  []string{"sequence", "runId", "eventType", "timestamp", "message,omitempty", "summary,omitempty", "metadata,omitempty", "networkPolicyDecisionLogs,omitempty"},
		},
		{
			label: "factory.PolicyDecisionMetadata",
			typ:   reflect.TypeOf(factory.PolicyDecisionMetadata{}),
			want:  []string{"policyField", "decision", "outcome", "reason", "policyMode,omitempty", "code,omitempty", "counts,omitempty"},
		},
		{
			label: "FactoryRunResponse",
			typ:   reflect.TypeOf(FactoryRunResponse{}),
			want:  []string{"contractVersion", "version", "runId", "status", "executorMode", "baseBranch", "nextAction", "artifacts", "telemetry,omitempty", "eventSummary", "failure"},
		},
		{
			label: "FactoryListResponse",
			typ:   reflect.TypeOf(FactoryListResponse{}),
			want:  []string{"contractVersion", "runs"},
		},
		{
			label: "FactoryStatusResponse",
			typ:   reflect.TypeOf(FactoryStatusResponse{}),
			want:  []string{"contractVersion", "run", "timeline"},
		},
		{
			label: "FactoryArtifactsResponse",
			typ:   reflect.TypeOf(FactoryArtifactsResponse{}),
			want:  []string{"contractVersion", "runId", "artifacts", "warnings", "summary"},
		},
		{
			label: "FactoryLogsResponse",
			typ:   reflect.TypeOf(FactoryLogsResponse{}),
			want:  []string{"contractVersion", "runId", "chunks"},
		},
		{
			label: "FactoryOpenResponse",
			typ:   reflect.TypeOf(FactoryOpenResponse{}),
			want:  []string{"contractVersion", "runId", "handoff,omitempty", "error,omitempty", "summary"},
		},
		{
			label: "FactoryTriggerResponse",
			typ:   reflect.TypeOf(FactoryTriggerResponse{}),
			want:  []string{"contractVersion", "runId", "run", "entry,omitempty", "summary"},
		},
		{
			label: "FactoryQueueAddResponse",
			typ:   reflect.TypeOf(FactoryQueueAddResponse{}),
			want:  []string{"contractVersion", "entry", "summary"},
		},
		{
			label: "FactoryQueueListResponse",
			typ:   reflect.TypeOf(FactoryQueueListResponse{}),
			want:  []string{"contractVersion", "entries", "summary"},
		},
		{
			label: "FactoryQueueWorkResponse",
			typ:   reflect.TypeOf(FactoryQueueWorkResponse{}),
			want:  []string{"contractVersion", "claimed", "entry", "summary"},
		},
		{
			label: "SandboxRuntimeListResponse",
			typ:   reflect.TypeOf(SandboxRuntimeListResponse{}),
			want:  []string{"contractType", "contractVersion", "host", "source", "runtimes", "capacity", "security", "diagnostics", "errors"},
		},
		{
			label: "SandboxRuntimeStatusResponse",
			typ:   reflect.TypeOf(SandboxRuntimeStatusResponse{}),
			want:  []string{"contractType", "contractVersion", "host", "runtime", "selectedTemplate", "source", "supportedOperations", "capacity", "readiness", "security", "diagnostics", "errors"},
		},
		{
			label: "SandboxRuntimeSecuritySummary",
			typ:   reflect.TypeOf(SandboxRuntimeSecuritySummary{}),
			want: []string{
				"requested", "enforced", "networkEnforcementProof,omitempty", "networkPolicyResult,omitempty", "capabilityReadiness,omitempty",
				"capabilityReadinessDiagnostics,omitempty", "securityReadinessGate,omitempty",
			},
		},
		{
			label: "SandboxRuntimeSecurityControls",
			typ:   reflect.TypeOf(SandboxRuntimeSecurityControls{}),
			want:  []string{"networkPolicy,omitempty", "networkEnforcement,omitempty", "credentialModes,omitempty", "credentialProxyMode,omitempty", "isolationLevel,omitempty"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := phase54JSONTags(tc.typ)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("%s JSON fields changed:\n got: %#v\nwant: %#v", tc.label, got, tc.want)
			}
		})
	}
}

func TestPhase54DefaultDocsDoNotRequireLiveRuntimePrerequisites(t *testing.T) {
	for _, path := range phase54DesignDocPaths(t) {
		doc := phase50ReadFile(t, path)
		normalized := strings.Join(strings.Fields(strings.ToLower(doc)), " ")
		for _, claim := range phase54ForbiddenDefaultRequirementClaims() {
			if strings.Contains(normalized, claim) {
				t.Fatalf("%s makes default verification require live prerequisite claim %q", phase50SafeDisplayPath(path), claim)
			}
		}
		for _, command := range phase54DefaultDocumentedCommands(doc) {
			if marker := phase54ForbiddenDefaultCommandMarker(command); marker != "" {
				t.Fatalf("%s default command %q contains live prerequisite marker %q", phase50SafeDisplayPath(path), command, marker)
			}
		}
	}
}

func TestPhase54ReleasePackageDocumentationIdentifiesBuildCommand(t *testing.T) {
	for _, path := range phase54ReleasePackageDocPaths() {
		doc := phase50ReadFile(t, path)
		for _, want := range []string{
			"make build",
			"./hal",
		} {
			if !strings.Contains(doc, want) {
				t.Fatalf("%s must document %q for the Phase 54 release package surface", phase50SafeDisplayPath(path), want)
			}
		}
	}
}

func TestPhase54DefaultChecksDocumentationDefinesFakeOnlyMatrix(t *testing.T) {
	doc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, want := range []string{
		"The GitHub Actions `checks` job and the local release verification path are fake-only.",
		"must not require live runtime prerequisites",
		"tagged live test suites",
		"This boundary is intentionally narrower than the entire GitHub Actions workflow.",
		"`sandbox-test` and `integration-test` jobs",
		"outside the Phase 54 fake-only checks/package verification boundary",
		"must not be described as fake-only default verification",
		"Phase 54 planning workflow references use plain `hal convert`",
		"do not require `hal convert --granular`",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("%s must document default fake-only checks matrix requirement %q", phase50SafeDisplayPath(phase54ReleasePackageDesignDocPath()), want)
		}
	}

	commands := phase34DocumentedShellCommands(doc)
	for _, want := range phase54DefaultCICommands() {
		if !commands[want] {
			t.Fatalf("%s default checks matrix missing command line %q", phase50SafeDisplayPath(phase54ReleasePackageDesignDocPath()), want)
		}
	}
	for _, command := range phase54DefaultDocumentedCommands(doc) {
		if marker := phase54ForbiddenDefaultCommandMarker(command); marker != "" {
			t.Fatalf("%s default checks command %q contains live or tagged-suite marker %q", phase50SafeDisplayPath(phase54ReleasePackageDesignDocPath()), command, marker)
		}
	}
}

func TestPhase54GitHubChecksJobMatchesDefaultCIMatrix(t *testing.T) {
	body := phase54GitHubWorkflowJobBody(t, "checks")
	for _, want := range phase54DefaultCICommands() {
		if !strings.Contains(body, "run: "+want) {
			t.Fatalf(".github/workflows/ci.yml checks job must run %q; body:\n%s", want, body)
		}
	}
	for _, marker := range phase54ForbiddenDefaultCommandMarkers() {
		if strings.Contains(body, marker) {
			t.Fatalf(".github/workflows/ci.yml checks job must stay fake-only; found marker %q in:\n%s", marker, body)
		}
	}
}

func TestPhase54ReleaseDocsDiscloseConditionalWorkflowJobsOutsideFakeOnlyBoundary(t *testing.T) {
	workflow := phase50ReadFile(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	for _, want := range []string{
		"  sandbox-test:",
		"  integration-test:",
		"docker/build-push-action",
		"go test -tags=integration",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf(".github/workflows/ci.yml missing conditional workflow marker %q", want)
		}
	}

	for _, path := range []string{
		phase54ReleasePackageDesignDocPath(),
		phase54OperatorReleaseHandoffDocPath(),
	} {
		doc := phase50ReadFile(t, path)
		normalized := strings.Join(strings.Fields(doc), " ")
		for _, want := range []string{
			"conditional `sandbox-test` and `integration-test` jobs",
			"outside the Phase 54 fake-only checks/package verification boundary",
			"must not",
		} {
			if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
				t.Fatalf("%s must disclose conditional workflow boundary %q", phase50SafeDisplayPath(path), want)
			}
		}
	}
}

func TestPhase54ReleasePackageDocumentationStaysDefaultSafe(t *testing.T) {
	doc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, want := range []string{
		"root",
		"KVM",
		"Firecracker",
		"Docker/Podman",
		"sandboxd",
		"cloud provider",
		"registry credentials",
		"proxy listeners",
		"firewall mutation",
		"real API secrets",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("%s must name default-safe package/build prerequisite %q", phase50SafeDisplayPath(phase54ReleasePackageDesignDocPath()), want)
		}
	}
}

func TestPhase54ReleaseMakefileBuildSurfaceStaysLocalHalBinaryOnly(t *testing.T) {
	body := phase54MakefileTargetBody(t, "build")
	for _, want := range []string{
		"go build $(LDFLAGS) -o $(BINARY_NAME) .",
		"Built ./$(BINARY_NAME)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Makefile build target must contain %q; body:\n%s", want, body)
		}
	}
	if marker := phase54ForbiddenReleasePackageMakefileMarker(body); marker != "" {
		t.Fatalf("Makefile build target must stay local and fake-only; found marker %q in:\n%s", marker, body)
	}
}

func TestPhase54ReleaseCheckSurfaceDoesNotPublishOrReadCredentials(t *testing.T) {
	body := phase54MakefileTargetBody(t, "release-check")
	if !strings.Contains(body, "goreleaser check") {
		t.Fatalf("Makefile release-check target must validate GoReleaser config with goreleaser check; body:\n%s", body)
	}
	for _, forbidden := range []string{
		"release --clean",
		"release --snapshot",
		"HOMEBREW_TAP_TOKEN",
		"GITHUB_TOKEN",
		"docker",
		"podman",
		"firecracker",
		"/dev/" + "kvm",
		"sandboxd",
		"iptables",
		"pfctl",
		"curl ",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("Makefile release-check target must not publish, read credentials, or invoke live prerequisites; found %q in:\n%s", forbidden, body)
		}
	}
}

func TestPhase54PackageGuardsStayFakeOnlyByDefault(t *testing.T) {
	for _, path := range phase54CommandGuardFiles(t) {
		source := phase50ReadFile(t, path)
		if phase50HasOptionalLiveBuildTag(source) {
			continue
		}
		file := phase50ParseGoSource(t, path, source)
		if message := phase50DefaultLivePrerequisiteBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func phase54JSONTags(typ reflect.Type) []string {
	var tags []string
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		tags = append(tags, tag)
	}
	return tags
}

func phase54DesignDocPaths(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "docs", "design", "*phase54*.md"))
	if err != nil {
		t.Fatalf("Glob(phase54 design docs) error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("Phase 54 docs guard matched no docs/design/*phase54*.md files")
	}
	sort.Strings(paths)
	return paths
}

func phase54ReleasePackageDocPaths() []string {
	return []string{
		filepath.Join("..", "README.md"),
		phase54ReleasePackageDesignDocPath(),
	}
}

func phase54ReleasePackageDesignDocPath() string {
	return filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase54-release-package-verification.md")
}

func phase54CommandGuardFiles(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "cmd", "phase54*.go"))
	if err != nil {
		t.Fatalf("Glob(phase54 command guards) error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("Phase 54 package guard matched no cmd/phase54*.go files")
	}
	sort.Strings(paths)
	return paths
}

func phase54DefaultDocumentedCommands(doc string) []string {
	var commands []string
	inOptionalLiveSection := false
	optionalLiveHeadingDepth := 0
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			depth := phase54MarkdownHeadingDepth(line)
			lower := strings.ToLower(line)
			if inOptionalLiveSection && depth <= optionalLiveHeadingDepth {
				inOptionalLiveSection = false
				optionalLiveHeadingDepth = 0
			}
			if strings.Contains(lower, "optional") && strings.Contains(lower, "live") {
				inOptionalLiveSection = true
				optionalLiveHeadingDepth = depth
			}
			continue
		}
		if inOptionalLiveSection {
			continue
		}
		if phase54IsShellCommandLine(line) {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase54MarkdownHeadingDepth(line string) int {
	depth := 0
	for _, r := range line {
		if r != '#' {
			break
		}
		depth++
	}
	return depth
}

func phase54IsShellCommandLine(line string) bool {
	for _, prefix := range []string{
		"env ", "go test ", "go vet ", "make ", "git diff ", "hal ", "docker ", "podman ", "firecracker ", "curl ",
	} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func phase54ForbiddenDefaultRequirementClaims() []string {
	liveRuntime := "live runtime"
	return []string{
		"default verification requires kvm",
		"default verification requires a firecracker binary",
		"default verification requires root privileges",
		"default verification requires docker",
		"default verification requires podman",
		"default verification requires cloud credentials",
		"default verification requires registry credentials",
		"default verification requires proxy listeners",
		"default verification requires firewall mutation",
		"default verification requires real api secrets",
		"default verification requires " + liveRuntime,
		"default ci requires kvm",
		"default ci requires firecracker",
		"default ci requires docker",
		"default ci requires podman",
		"default ci requires cloud credentials",
		"default ci requires real credentials",
		"default ci requires " + liveRuntime,
		"default package verification requires " + liveRuntime,
	}
}

func phase54ForbiddenDefaultCommandMarker(command string) string {
	for _, marker := range phase54ForbiddenDefaultCommandMarkers() {
		if strings.Contains(command, marker) {
			return marker
		}
	}
	return ""
}

func phase54ForbiddenDefaultCommandMarkers() []string {
	return []string{
		"-tags=" + "integration",
		"-tags=" + "worker_" + "integration",
		"-tags=" + "podman_" + "integration",
		"-tags=" + "microvm_e2e_" + "live",
		"-tags=" + "firecracker_" + "live",
		"-tags=" + "network_enforcement_" + "live",
		"-tags=" + "credential_delivery_" + "live",
		"HAL_" + "FIRECRACKER_LIVE",
		"HAL_" + "NETWORK_ENFORCEMENT_LIVE",
		"HAL_" + "CREDENTIAL_DELIVERY_LIVE",
		"HAL_" + "TEMPLATE_TRUST_LIVE",
		"HAL_" + "WORKER_INTEGRATION_",
		"HAL_" + "PODMAN_",
		"DOCKER_HOST",
		"SSH_AUTH_SOCK",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"docker ",
		"podman ",
		"firecracker ",
		"make sandbox-build",
		"make sandbox-test",
		"make sandbox-shell",
		"/dev/" + "kvm",
		"curl ",
		"sudo ",
		"hal sandboxd",
		"--live",
	}
}

func phase54DefaultCICommands() []string {
	return []string{
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
}

func phase54GitHubWorkflowJobBody(t *testing.T, job string) string {
	t.Helper()
	source := phase50ReadFile(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	lines := strings.Split(source, "\n")
	jobPrefix := "  " + job + ":"
	var body []string
	inJob := false
	for _, line := range lines {
		if !inJob {
			if line == jobPrefix {
				inJob = true
			}
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.TrimSpace(line) != "" {
			break
		}
		body = append(body, line)
	}
	if !inJob {
		t.Fatalf(".github/workflows/ci.yml job %q not found", job)
	}
	return strings.Join(body, "\n")
}

func phase54MakefileTargetBody(t *testing.T, target string) string {
	t.Helper()
	source := phase50ReadFile(t, filepath.Join("..", "Makefile"))
	lines := strings.Split(source, "\n")
	var body []string
	inTarget := false
	targetPrefix := target + ":"
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inTarget {
			if strings.HasPrefix(line, targetPrefix) {
				inTarget = true
			}
			continue
		}
		if trimmed == "" {
			body = append(body, line)
			continue
		}
		if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			break
		}
		body = append(body, line)
	}
	if !inTarget {
		t.Fatalf("Makefile target %q not found", target)
	}
	return strings.Join(body, "\n")
}

func phase54ForbiddenReleasePackageMakefileMarker(body string) string {
	normalized := strings.ToLower(body)
	for _, marker := range []string{
		"docker",
		"podman",
		"firecracker",
		"/dev/" + "kvm",
		"sandboxd",
		"iptables",
		"pfctl",
		"nft ",
		"curl ",
		"http://",
		"https://",
		"registry",
		"token",
		"secret",
	} {
		if strings.Contains(normalized, marker) {
			return marker
		}
	}
	return ""
}

func TestPhase54ContractScopeGuardRejectsUnsafeFixtures(t *testing.T) {
	liveDoc := "## Default Verification\n\n" + "env " + "HAL_" + "FIRECRACKER_LIVE=<set> go test -tags=" + "firecracker_" + "live ./internal/sandboxruntime/microvm\n"
	commands := phase54DefaultDocumentedCommands(liveDoc)
	if len(commands) != 1 {
		t.Fatalf("fixture default commands = %#v, want one command", commands)
	}
	if marker := phase54ForbiddenDefaultCommandMarker(commands[0]); marker == "" {
		t.Fatal("fixture command should fail the Phase 54 live prerequisite marker guard")
	}

	optionalLiveDoc := "## Optional Live Verification\n\n" + "env " + "HAL_" + "FIRECRACKER_LIVE=<set> go test -tags=" + "firecracker_" + "live ./internal/sandboxruntime/microvm\n"
	if commands := phase54DefaultDocumentedCommands(optionalLiveDoc); len(commands) != 0 {
		t.Fatalf("optional live fixture commands = %#v, want none in default command scan", commands)
	}

	tempDir := t.TempDir()
	fixture := filepath.Join(tempDir, "phase54_fixture.go")
	if err := os.WriteFile(fixture, []byte(`package fixture
import "os/exec"
func run() {
	_ = exec.Command("firecracker")
}
`), 0o600); err != nil {
		t.Fatalf("WriteFile(fixture) error: %v", err)
	}
	source := phase50ReadFile(t, fixture)
	file := phase50ParseGoSource(t, fixture, source)
	if message := phase50DefaultLivePrerequisiteBoundaryMessage(fixture, file); !strings.Contains(message, "Firecracker process") {
		t.Fatalf("fixture boundary message = %q, want Firecracker process", message)
	}

	unsafeMakefileBody := "\n\t@docker build -t hal-sandbox .\n"
	if marker := phase54ForbiddenReleasePackageMakefileMarker(unsafeMakefileBody); marker != "docker" {
		t.Fatalf("unsafe Makefile fixture marker = %q, want docker", marker)
	}
}
