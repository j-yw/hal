package cmd

import (
	"go/ast"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestUS010LiveE2EEnvironmentMarkersStayInApprovedSources(t *testing.T) {
	for _, path := range phase50RepositoryGoFiles(t) {
		source := phase50ReadFile(t, path)
		message := us010LiveE2EEnvMarkerBoundaryMessage(path, source)
		if message == "" {
			continue
		}
		rel := phase50RepositoryRelativePath(t, path)
		if us010ApprovedLiveE2EEnvMarkerSource(rel, source) {
			continue
		}
		t.Fatal(message)
	}
}

func TestUS010LiveE2EMarkersStayInApprovedSources(t *testing.T) {
	for _, path := range phase50RepositoryGoFiles(t) {
		source := phase50ReadFile(t, path)
		message := us010LiveE2EPlacementMarkerBoundaryMessage(path, source)
		if message == "" {
			continue
		}
		rel := phase50RepositoryRelativePath(t, path)
		if us010ApprovedLiveE2EPlacementMarkerSource(rel, source) {
			continue
		}
		t.Fatal(message)
	}
}

func TestUS010DefaultPathsDoNotTriggerLiveMicroVME2E(t *testing.T) {
	for _, path := range us010DefaultPathProductionFiles(t) {
		source := phase50ReadFile(t, path)
		file := phase50ParseGoSource(t, path, source)
		if message := us010DefaultPathTriggerBoundaryMessage(path, file, source); message != "" {
			t.Fatal(message)
		}
	}
}

func TestUS010PureLiveE2EContractsStayMetadataOnly(t *testing.T) {
	for _, path := range us010PureLiveE2EContractFiles(t) {
		source := phase50ReadFile(t, path)
		file := phase50ParseGoSource(t, path, source)
		if message := us010PureLiveE2EContractBoundaryMessage(path, file, source); message != "" {
			t.Fatal(message)
		}
	}
}

func TestUS010LiveMarkerGuardRejectsUnsafeFixtures(t *testing.T) {
	envMessage := us010LiveE2EEnvMarkerBoundaryMessage("fixture.go", `package fixture
import "os"
func run() {
	_ = os.Getenv("HAL_FIRECRACKER_LIVE=/Users/alice/secret.sock")
}
`)
	if !strings.Contains(envMessage, "fixture.go") || !strings.Contains(envMessage, "live E2E env marker") {
		t.Fatalf("env guard message = %q, want file and category", envMessage)
	}
	us010AssertGuardMessageRedactionSafe(t, envMessage)

	triggerSource := `package fixture
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm"
func run() {
	_ = microvm.PreflightLiveE2EFirecrackerRuntime(microvm.LiveE2EFirecrackerPreflightInput{})
}
`
	triggerFile := phase50ParseGoSource(t, "trigger.go", triggerSource)
	triggerMessage := us010DefaultPathTriggerBoundaryMessage("trigger.go", triggerFile, triggerSource)
	if !strings.Contains(triggerMessage, "trigger.go") || !strings.Contains(triggerMessage, "live E2E preflight trigger") {
		t.Fatalf("trigger guard message = %q, want file and category", triggerMessage)
	}
	us010AssertGuardMessageRedactionSafe(t, triggerMessage)

	pureSource := `package fixture
import "os/exec"
func run() {
	_ = exec.Command("firecracker", "--api-sock", "/tmp/private.sock")
}
`
	pureFile := phase50ParseGoSource(t, "pure.go", pureSource)
	pureMessage := us010PureLiveE2EContractBoundaryMessage("pure.go", pureFile, pureSource)
	if !strings.Contains(pureMessage, "pure.go") || !strings.Contains(pureMessage, "process execution import") {
		t.Fatalf("pure contract guard message = %q, want file and category", pureMessage)
	}
	us010AssertGuardMessageRedactionSafe(t, pureMessage)
}

func us010LiveE2EEnvMarkerBoundaryMessage(path, source string) string {
	for _, marker := range us010LiveE2EEnvMarkerPrefixes() {
		if strings.Contains(source, marker) {
			return us010GuardMessage(path, "live E2E env marker")
		}
	}
	return ""
}

func us010LiveE2EPlacementMarkerBoundaryMessage(path, source string) string {
	for _, marker := range us010LiveE2EPlacementMarkerTokens() {
		if strings.Contains(source, marker.token) {
			return us010GuardMessage(path, marker.category)
		}
	}
	return ""
}

func us010DefaultPathTriggerBoundaryMessage(path string, file *ast.File, source string) string {
	if strings.Contains(source, "TestMicroVMLiveE2EComposedLiveExecutionPath") ||
		strings.Contains(source, "microVMLiveE2E") {
		return us010GuardMessage(path, "live E2E harness trigger")
	}
	return us010CallTriggerBoundaryMessage(path, file)
}

func us010PureLiveE2EContractBoundaryMessage(path string, file *ast.File, source string) string {
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return us010GuardMessage(path, "unreadable import")
		}
		if category := us010PureContractForbiddenImportCategory(importPath); category != "" {
			return us010GuardMessage(path, category)
		}
	}
	if strings.Contains(source, "NewOSExecProcessRunner") {
		return us010GuardMessage(path, "Firecracker process runner trigger")
	}
	if strings.Contains(source, "NewLiveDriver(") {
		return us010GuardMessage(path, "Firecracker live driver trigger")
	}
	return us010CallTriggerBoundaryMessage(path, file)
}

func us010CallTriggerBoundaryMessage(path string, file *ast.File) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := phase50CallSelectorName(call.Fun)
		switch {
		case us010CallReadsLiveE2EEnv(selector) && us010CallHasLiveE2EEnvArg(call):
			message = us010GuardMessage(path, "live E2E env read")
		case us010CallSetsLiveE2EEnv(selector) && us010CallHasLiveE2EEnvArg(call):
			message = us010GuardMessage(path, "live E2E env setup")
		case us010SelectorMatches(selector, "PreflightLiveE2EFirecrackerRuntime"):
			message = us010GuardMessage(path, "live E2E preflight trigger")
		case us010SelectorMatches(selector, "ProjectLiveE2ECredentialDeliveryMetadata"),
			us010SelectorMatches(selector, "ProjectLiveE2ETemplateTrustMetadata"),
			us010SelectorMatches(selector, "ProjectLiveE2ENetworkEnforcementReadiness"):
			message = us010GuardMessage(path, "live E2E readiness trigger")
		case us010SelectorMatches(selector, "RequireLiveGate") && us010CallHasMicroVME2EGateArg(call):
			message = us010GuardMessage(path, "live E2E gate trigger")
		}
		return message == ""
	})
	return message
}

func us010ApprovedLiveE2EEnvMarkerSource(rel, source string) bool {
	return us010ApprovedLiveE2EGuardFile(rel) ||
		us010LiveGateHelperFile(rel) ||
		us010ApprovedLiveTaggedTest(source, rel)
}

func us010ApprovedLiveE2EPlacementMarkerSource(rel, source string) bool {
	return us010ApprovedLiveE2EGuardFile(rel) ||
		us010LiveGateHelperFile(rel) ||
		us010PureLiveE2EContractFile(rel) ||
		us010PureLiveE2EContractTest(rel) ||
		us010ApprovedLiveTaggedTest(source, rel)
}

func us010ApprovedLiveTaggedTest(source, rel string) bool {
	if !strings.HasSuffix(rel, "_test.go") {
		return false
	}
	for _, tag := range []string{
		"microvm_e2e_live",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
	} {
		if phase50HasBuildTag(source, tag) {
			return true
		}
	}
	return false
}

func us010ApprovedLiveE2EGuardFile(rel string) bool {
	return us010ApprovedLiveE2EGuardFiles()[filepath.ToSlash(filepath.Clean(rel))]
}

func us010ApprovedLiveE2EGuardFiles() map[string]bool {
	return map[string]bool{
		"cmd/phase34_firecracker_docs_test.go":                                                 true,
		"cmd/phase35_firecracker_host_adapter_docs_test.go":                                    true,
		"cmd/phase36_firecracker_live_driver_docs_test.go":                                     true,
		"cmd/phase37_firecracker_guest_readiness_docs_test.go":                                 true,
		"cmd/phase45_final_fake_only_verification_test.go":                                     true,
		"cmd/phase45_network_enforcement_live_guard_test.go":                                   true,
		"cmd/phase46_final_fake_only_verification_test.go":                                     true,
		"cmd/phase46_runtime_worker_docs_test.go":                                              true,
		"cmd/phase48_final_fake_only_verification_test.go":                                     true,
		"cmd/phase49_final_code_verification_test.go":                                          true,
		"cmd/phase49_live_provider_gates_test.go":                                              true,
		"cmd/phase50_default_live_gate_guard_test.go":                                          true,
		"cmd/phase50_manual_live_opt_in_docs_test.go":                                          true,
		"cmd/phase50_optional_live_placeholders_test.go":                                       true,
		"cmd/phase53_final_verification_test.go":                                               true,
		"cmd/phase53_live_e2e_docs_test.go":                                                    true,
		"cmd/phase53_live_marker_guard_test.go":                                                true,
		"cmd/phase54_optional_live_matrix_docs_test.go":                                        true,
		"cmd/phase56_live_gate_docs_test.go":                                                   true,
		"cmd/sandbox_default_fake_only_guard_test.go":                                          true,
		"cmd/secure_default_runtime_docs_red_test.go":                                          true,
		"cmd/us004_default_harness_guard_test.go":                                              true,
		"internal/credentialdelivery/activation_diagnostics_test.go":                           true,
		"internal/credentialdelivery/import_boundary_test.go":                                  true,
		"internal/sandboxruntime/microvm/firecrackerhost/real_process_runner_boundary_test.go": true,
	}
}

func us010LiveGateHelperFile(rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(rel))
	return rel == "internal/livegate/contracts.go" ||
		rel == "internal/livegate/composed.go" ||
		strings.HasPrefix(rel, "internal/livegate/") && strings.HasSuffix(rel, "_test.go")
}

func us010LiveE2EEnvMarkerPrefixes() []string {
	return []string{
		"HAL_FIRECRACKER_LIVE",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"HAL_TEMPLATE_TRUST_LIVE",
	}
}

func us010LiveE2EPlacementMarkerTokens() []struct {
	token    string
	category string
} {
	return []struct {
		token    string
		category string
	}{
		{token: "microvm_e2e_live", category: "live E2E build tag marker"},
		{token: "MicroVME2E", category: "live E2E gate marker"},
		{token: "LiveE2E", category: "live E2E contract marker"},
		{token: "microVMLiveE2E", category: "live E2E harness marker"},
		{token: "TestMicroVMLiveE2EComposedLiveExecutionPath", category: "live E2E execution marker"},
		{token: "PreflightLiveE2EFirecrackerRuntime", category: "live E2E preflight marker"},
		{token: "ProjectLiveE2E", category: "live E2E readiness marker"},
	}
}

func us010DefaultPathProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := map[string]bool{}
	for _, root := range []string{
		filepath.Join("..", "cmd"),
		filepath.Join("..", "internal", "factory"),
		filepath.Join("..", "internal", "sandboxtarget"),
		filepath.Join("..", "internal", "sandboxexec"),
		filepath.Join("..", "internal", "sandboxworker"),
	} {
		for _, path := range us010ProductionGoFilesUnder(t, root) {
			paths[path] = true
		}
	}
	return us010SortedPaths(paths)
}

func us010PureLiveE2EContractFile(rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(rel))
	for _, path := range us010PureLiveE2EContractRelPaths() {
		if rel == path {
			return true
		}
	}
	return false
}

func us010PureLiveE2EContractTest(rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(rel))
	for _, path := range []string{
		"internal/sandboxruntime/microvm/credential_metadata_test.go",
		"internal/sandboxruntime/microvm/metadata_contract_test.go",
		"internal/sandboxruntime/microvm/network_enforcement_readiness_test.go",
		"internal/sandboxruntime/microvm/preflight_test.go",
		"internal/sandboxruntime/microvm/prerequisite_diagnostics_test.go",
		"internal/sandboxruntime/microvm/template_trust_test.go",
	} {
		if rel == path {
			return true
		}
	}
	return false
}

func us010PureLiveE2EContractFiles(t *testing.T) []string {
	t.Helper()
	paths := map[string]bool{}
	for _, path := range us010ProductionGoFilesUnder(t, filepath.Join("..", "internal", "livegate")) {
		paths[path] = true
	}
	for _, rel := range us010PureLiveE2EContractRelPaths() {
		paths[filepath.Join("..", filepath.FromSlash(rel))] = true
	}
	return us010SortedPaths(paths)
}

func us010PureLiveE2EContractRelPaths() []string {
	var paths []string
	for _, name := range []string{
		"credential_delivery.go",
		"live_e2e_diagnostics.go",
		"live_e2e_metadata.go",
		"live_e2e_network_enforcement.go",
		"live_e2e_preflight.go",
		"template_trust.go",
	} {
		paths = append(paths, filepath.ToSlash(filepath.Join("internal", "sandboxruntime", "microvm", name)))
	}
	return paths
}

func us010ProductionGoFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".hal", "vendor", "node_modules":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkDir(%s) error: %v", phase50SafeDisplayPath(root), err)
	}
	if len(paths) == 0 {
		t.Fatalf("US-010 guard matched no production files under %s", phase50SafeDisplayPath(root))
	}
	sort.Strings(paths)
	return paths
}

func us010SortedPaths(paths map[string]bool) []string {
	out := make([]string, 0, len(paths))
	for path := range paths {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func us010PureContractForbiddenImportCategory(importPath string) string {
	switch {
	case importPath == "os", importPath == "syscall", strings.HasPrefix(importPath, "golang.org/x/sys"):
		return "host process import"
	case importPath == "os/exec":
		return "process execution import"
	case importPath == "net", importPath == "net/http", strings.HasPrefix(importPath, "net/http/"), strings.HasPrefix(importPath, "google.golang.org/grpc"):
		return "network import"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"),
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"),
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialdelivery"),
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxworker"):
		return "live implementation import"
	case strings.HasPrefix(importPath, "github.com/docker/docker"), strings.HasPrefix(importPath, "github.com/containers/podman"):
		return "container API import"
	case strings.HasPrefix(importPath, "github.com/firecracker-microvm"), strings.Contains(strings.ToLower(importPath), "kvm"):
		return "Firecracker or KVM import"
	default:
		return ""
	}
}

func us010CallReadsLiveE2EEnv(selector string) bool {
	return selector == "os.Getenv" || selector == "os.LookupEnv"
}

func us010CallSetsLiveE2EEnv(selector string) bool {
	return selector == "Setenv" || selector == "t.Setenv"
}

func us010CallHasLiveE2EEnvArg(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if us010ExprContainsLiveE2EEnvMarker(arg) {
			return true
		}
	}
	return false
}

func us010CallHasMicroVME2EGateArg(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if strings.Contains(us010ExprText(arg), "MicroVME2E") {
			return true
		}
	}
	return false
}

func us010ExprContainsLiveE2EEnvMarker(expr ast.Expr) bool {
	text := us010ExprText(expr)
	for _, marker := range us010LiveE2EEnvMarkerPrefixes() {
		if strings.Contains(text, marker) {
			return true
		}
	}
	for _, marker := range []string{
		"EnvVarFirecrackerLive",
		"EnvVarNetworkEnforcementLive",
		"EnvVarCredentialDeliveryLive",
		"EnvVarTemplateTrustLive",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func us010ExprText(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind == token.STRING {
			unquoted, err := strconv.Unquote(value.Value)
			if err == nil {
				return unquoted
			}
		}
		return value.Value
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return us010ExprText(value.X) + "." + value.Sel.Name
	case *ast.CallExpr:
		var parts []string
		parts = append(parts, us010ExprText(value.Fun))
		for _, arg := range value.Args {
			parts = append(parts, us010ExprText(arg))
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

func us010SelectorMatches(selector, name string) bool {
	return selector == name || strings.HasSuffix(selector, "."+name)
}

func us010GuardMessage(path, category string) string {
	return "US-010 live marker guard: " + phase50SafeDisplayPath(path) + " contains " + category + " outside approved live E2E boundaries"
}

func us010AssertGuardMessageRedactionSafe(t *testing.T, message string) {
	t.Helper()
	phase50AssertGuardMessageRedactionSafe(t, message)
	for _, unsafe := range []string{
		"HAL_FIRECRACKER_LIVE=/Users/alice/secret.sock",
		"/Users/alice/secret.sock",
		"secret.sock",
		"/tmp/private.sock",
		"--api-sock",
	} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("US-010 guard message leaked unsafe fragment %q: %s", unsafe, message)
		}
	}
}
