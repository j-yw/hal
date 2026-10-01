package cmd

import (
	fmt "fmt"
	ast "go/ast"
	parser "go/parser"
	token "go/token"
	os "os"
	filepath "path/filepath"
	regexp "regexp"
	strconv "strconv"
	strings "strings"
	testing "testing"
)

func phase19SourceHeader(source string) string {
	lines := strings.Split(source, "\n")
	var header []string
	for _, line := range lines {
		if strings.HasPrefix(line, "package ") {
			break
		}
		header = append(header, line)
	}
	return strings.Join(header, "\n")
}

func phase34AllGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase34AssertDefaultTestFileAvoidsLiveImports(t *testing.T, path string) {
	t.Helper()
	file := phase34ParseGoFile(t, path, parser.ImportsOnly)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
		}
		if forbidden := phase34ForbiddenDefaultTestImport(importPath); forbidden != "" {
			t.Fatalf("%s imports %q; Phase 34 fake-only guard avoids %s", phase34FirecrackerDisplayPath(t, path), importPath, forbidden)
		}
	}
}

func phase34DocumentedShellCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "go test "):
			commands[line] = true
		case strings.HasPrefix(line, "go vet "):
			commands[line] = true
		case strings.HasPrefix(line, "make "):
			commands[line] = true
		case strings.HasPrefix(line, "git diff "):
			commands[line] = true
		}
	}
	return commands
}

func phase34FirecrackerDisplayPath(t *testing.T, path string) string {
	t.Helper()
	if !strings.HasPrefix(filepath.ToSlash(path), "../") {
		return filepath.ToSlash(filepath.Join("cmd", path))
	}
	rel, err := filepath.Rel(filepath.Join(".."), path)
	if err != nil {
		t.Fatalf("Rel(%s, %s) error: %v", filepath.Join(".."), path, err)
	}
	return filepath.ToSlash(rel)
}

func phase34FocusedCommandCoveringTest(t *testing.T, commands []string, pkg, testName string) string {
	t.Helper()
	for _, command := range commands {
		if !phase34FocusedCommandTargetsPackage(command, pkg) {
			continue
		}
		selector, ok := phase34FocusedCommandRunSelector(t, command)
		if !ok {
			return command
		}
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 34 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if compiled.MatchString(testName) {
			return command
		}
	}
	return ""
}

func phase34FocusedCommandRunSelector(t *testing.T, command string) (string, bool) {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 34 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\""), true
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\""), true
		}
	}
	return "", false
}

func phase34FocusedCommandTargetsPackage(command, pkg string) bool {
	for _, field := range strings.Fields(command) {
		if strings.Trim(field, "'\"") == pkg {
			return true
		}
	}
	return false
}

type phase34FocusedTest struct {
	pkg      string
	file     string
	testName string
}

func phase34ForbiddenDefaultTestImport(importPath string) string {
	switch importPath {
	case "net", "net/http", "net/http/httputil", "net/rpc", "net/smtp":
		return "network sockets or live proxy servers"
	case "os/exec":
		return "process launch"
	case "syscall":
		return "host privilege or KVM access"
	}
	for _, forbidden := range []struct {
		prefix string
		label  string
	}{
		{prefix: "github.com/docker/docker", label: "Docker clients"},
		{prefix: "github.com/containers/podman", label: "Podman clients"},
		{prefix: "github.com/containers/image", label: "container image clients"},
		{prefix: "github.com/containers/storage", label: "container storage clients"},
		{prefix: "github.com/firecracker-microvm", label: "Firecracker SDKs"},
		{prefix: "libvirt.org/go/libvirt", label: "KVM or microVM integrations"},
		{prefix: "golang.org/x/sys", label: "host privilege or KVM access"},
		{prefix: "github.com/digitalocean/godo", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go-v2", label: "cloud SDKs"},
		{prefix: "github.com/Azure/azure-sdk-for-go", label: "cloud SDKs"},
		{prefix: "github.com/hetznercloud/hcloud-go", label: "cloud SDKs"},
		{prefix: "cloud.google.com/go", label: "cloud SDKs"},
		{prefix: "google.golang.org/api", label: "cloud SDKs"},
		{prefix: "google.golang.org/grpc", label: "network clients"},
	} {
		if strings.HasPrefix(importPath, forbidden.prefix) {
			return forbidden.label
		}
	}
	return ""
}

func phase34ParseGoFile(t *testing.T, path string, mode parser.Mode) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, mode)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	return file
}

func phase34TestFileDefinesFunction(t *testing.T, path, testName string) bool {
	t.Helper()
	file := phase34ParseGoFile(t, path, parser.ParseComments)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == testName {
			return true
		}
	}
	return false
}

func phase49FinalReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func phase50CallHasAnyLiteralArg(call *ast.CallExpr, wants []string) bool {
	for _, value := range phase50StringLiteralArgs(call) {
		for _, want := range wants {
			if value == want || strings.HasSuffix(value, "/"+want) || strings.Contains(value, want+" ") {
				return true
			}
		}
	}
	return false
}

func phase50CallHasOptionalLiveEnvArg(call *ast.CallExpr) bool {
	return phase50FirstOptionalLiveEnvArg(call) != ""
}

func phase50CallLaunchesLiveProcess(selector string, call *ast.CallExpr) bool {
	switch selector {
	case "exec.Command", "exec.CommandContext", "exec.LookPath", "os.StartProcess", "syscall.Exec":
		return phase50CallHasAnyLiteralArg(call, []string{"docker", "podman"})
	default:
		return false
	}
}

func phase50CallOpensDefaultNetwork(selector string, call *ast.CallExpr) bool {
	switch selector {
	case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
		network := phase50FirstStringLiteralArg(call)
		return network != "" && network != "unix" && network != "unixpacket"
	case "http.Get", "http.Head", "http.Post", "http.PostForm", "http.ListenAndServe", "http.ListenAndServeTLS":
		return true
	default:
		return false
	}
}

func phase50CallReadsLiveEnv(selector string) bool {
	switch selector {
	case "os.Getenv", "os.LookupEnv":
		return true
	default:
		return false
	}
}

func phase50CallSelectorName(expr ast.Expr) string {
	switch fn := expr.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	default:
		return ""
	}
}

func phase50CallSetsLiveEnv(selector string) bool {
	return selector == "Setenv" || selector == "t.Setenv"
}

func phase50DefaultForbiddenLiveImport(importPath string) string {
	switch {
	case strings.HasPrefix(importPath, "github.com/docker/docker"),
		strings.HasPrefix(importPath, "github.com/containers/podman"):
		return "Docker or Podman API import"
	case strings.HasPrefix(importPath, "github.com/digitalocean/godo"),
		strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go"),
		strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2"),
		strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go"),
		strings.HasPrefix(importPath, "cloud.google.com/go"),
		strings.HasPrefix(importPath, "google.golang.org/api"):
		return "provider API import"
	default:
		return ""
	}
}

func phase50DefaultGuardMessage(fileName, category, marker string) string {
	return fmt.Sprintf("Phase 50 default fake-only guard: %s contains %s marker %q outside optional live build tags or approved helper files", phase50SafeDisplayPath(fileName), category, marker)
}

func phase50DefaultLivePrerequisiteBoundaryMessage(fileName string, file *ast.File) string {
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return phase50DefaultGuardMessage(fileName, "unreadable import", "import")
		}
		if forbidden := phase50DefaultForbiddenLiveImport(importPath); forbidden != "" {
			return phase50DefaultGuardMessage(fileName, forbidden, phase50ImportMarker(importPath))
		}
	}

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
		case phase50CallReadsLiveEnv(selector) && phase50CallHasOptionalLiveEnvArg(call):
			message = phase50DefaultGuardMessage(fileName, "optional live env lookup", phase50FirstOptionalLiveEnvArg(call))
		case phase50CallSetsLiveEnv(selector) && phase50CallHasOptionalLiveEnvArg(call):
			message = phase50DefaultGuardMessage(fileName, "optional live env setup", phase50FirstOptionalLiveEnvArg(call))
		case phase50CallLaunchesLiveProcess(selector, call):
			message = phase50DefaultGuardMessage(fileName, phase50LiveProcessLabel(call), phase50LiveProcessMarker(call))
		case phase50CallOpensDefaultNetwork(selector, call):
			message = phase50DefaultGuardMessage(fileName, "default network access", phase50NetworkMarker(selector))
		}
		return message == ""
	})
	return message
}

func phase50FirstOptionalLiveEnvArg(call *ast.CallExpr) string {
	for _, value := range phase50StringLiteralArgs(call) {
		if phase50OptionalLiveEnvMarker(value) {
			return phase50SafeEnvMarker(value)
		}
	}
	return ""
}

func phase50FirstStringLiteralArg(call *ast.CallExpr) string {
	for _, value := range phase50StringLiteralArgs(call) {
		return value
	}
	return ""
}

func phase50HasBuildTag(source, tag string) bool {
	header := phase19SourceHeader(source)
	for _, line := range strings.Split(header, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//go:build") || strings.HasPrefix(line, "// +build") {
			if strings.Contains(line, tag) {
				return true
			}
		}
	}
	return false
}

func phase50HasOptionalLiveBuildTag(source string) bool {
	for _, tag := range []string{
		"integration",
		"worker_integration",
		"podman_integration",
	} {
		if phase50HasBuildTag(source, tag) {
			return true
		}
	}
	return false
}

func phase50ImportMarker(importPath string) string {
	switch {
	case strings.HasPrefix(importPath, "github.com/docker/docker"):
		return "docker-api"
	case strings.HasPrefix(importPath, "github.com/containers/podman"):
		return "podman-api"
	case strings.HasPrefix(importPath, "github.com/digitalocean/godo"):
		return "provider-api"
	case strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2"):
		return "provider-api"
	case strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go"):
		return "provider-api"
	case strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go"):
		return "provider-api"
	case strings.HasPrefix(importPath, "cloud.google.com/go"):
		return "provider-api"
	case strings.HasPrefix(importPath, "google.golang.org/api"):
		return "provider-api"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/cmd"):
		return "cmd-package"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/cmdtest"):
		return "command-test-helper"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandbox/provider"):
		return "provider-adapter"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxworker"):
		return "worker-daemon"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime"):
		return "live-runtime"
	default:
		return "dependency"
	}
}

func phase50LiveProcessLabel(call *ast.CallExpr) string {
	switch {
	case phase50CallHasAnyLiteralArg(call, []string{"docker"}):
		return "Docker process"
	case phase50CallHasAnyLiteralArg(call, []string{"podman"}):
		return "Podman process"
	default:
		return "live process"
	}
}

func phase50LiveProcessMarker(call *ast.CallExpr) string {
	switch {
	case phase50CallHasAnyLiteralArg(call, []string{"docker"}):
		return "docker"
	case phase50CallHasAnyLiteralArg(call, []string{"podman"}):
		return "podman"
	default:
		return "process"
	}
}

func phase50NetworkMarker(selector string) string {
	if strings.HasPrefix(selector, "http.") {
		return "http client/server"
	}
	return "network socket"
}

func phase50OptionalLiveEnvMarker(value string) bool {
	return strings.HasPrefix(value, phase50WorkerIntegrationEnvPrefix) ||
		strings.HasPrefix(value, phase50PodmanEnvPrefix)
}

func phase50ParseGoSource(t *testing.T, path, source string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", phase50SafeDisplayPath(path), err)
	}
	return file
}

const phase50PodmanEnvPrefix = "HAL_PODMAN_"

func phase50ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", phase50SafeDisplayPath(path), err)
	}
	return string(data)
}

func phase50SafeDisplayPath(path string) string {
	clean := filepath.ToSlash(filepath.Clean(path))
	if strings.HasPrefix(clean, "../") {
		return strings.TrimPrefix(clean, "../")
	}
	return clean
}

func phase50SafeEnvMarker(value string) string {
	if idx := strings.IndexAny(value, " ="); idx >= 0 {
		return value[:idx]
	}
	return value
}

func phase50StringLiteralArgs(call *ast.CallExpr) []string {
	var values []string
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(lit.Value)
		if err == nil {
			values = append(values, value)
		}
	}
	return values
}

const phase50WorkerIntegrationEnvPrefix = "HAL_WORKER_" + "INTEGRATION_"

func phase54AssertPackageSelectorExists(t *testing.T, packageSelector, command string) {
	t.Helper()
	dir := phase54PackageSelectorDir(t, packageSelector)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Phase 54 optional live command %q uses missing package selector %q: %v", command, packageSelector, err)
	}
	if !info.IsDir() {
		t.Fatalf("Phase 54 optional live command %q uses non-directory package selector %q", command, packageSelector)
	}
}

func phase54AssertRunSelectorMatchesPackageTests(t *testing.T, runSelector, packageSelector, command string) {
	t.Helper()
	re, err := regexp.Compile(runSelector)
	if err != nil {
		t.Fatalf("Phase 54 optional live command %q has invalid -run selector %q: %v", command, runSelector, err)
	}
	for _, testName := range phase54PackageTestNames(t, packageSelector) {
		if re.MatchString(testName) {
			return
		}
	}
	t.Fatalf("Phase 54 optional live command %q -run selector %q matched no tests in %s", command, runSelector, packageSelector)
}

func phase54CommandPackageSelectors(command string) []string {
	var packages []string
	for _, field := range strings.Fields(command) {
		field = strings.Trim(field, "'\"")
		if strings.HasPrefix(field, "./") {
			packages = append(packages, field)
		}
	}
	return packages
}

func phase54CommandRunSelector(command string) (string, bool) {
	fields := strings.Fields(command)
	for i, field := range fields {
		field = strings.Trim(field, "\"")
		if strings.HasPrefix(field, "-run=") {
			return phase54TrimShellQuotes(strings.TrimPrefix(field, "-run=")), true
		}
		if field == "-run" && i+1 < len(fields) {
			return phase54TrimShellQuotes(fields[i+1]), true
		}
	}
	return "", false
}

func phase54OptionalLiveDocumentedCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
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
			if strings.Contains(lower, "optional") && strings.Contains(lower, "live") && strings.Contains(lower, "verification") {
				inOptionalLiveSection = true
				optionalLiveHeadingDepth = depth
			}
			continue
		}
		if inOptionalLiveSection && phase54IsShellCommandLine(line) {
			commands[line] = true
		}
	}
	return commands
}

func phase54PackageSelectorDir(t *testing.T, packageSelector string) string {
	t.Helper()
	if !strings.HasPrefix(packageSelector, "./") || strings.Contains(packageSelector, "...") {
		t.Fatalf("Phase 54 optional live command uses unsupported package selector %q", packageSelector)
	}
	return filepath.Join("..", filepath.FromSlash(strings.TrimPrefix(packageSelector, "./")))
}

func phase54PackageTestNames(t *testing.T, packageSelector string) []string {
	t.Helper()
	dir := phase54PackageSelectorDir(t, packageSelector)
	paths, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		t.Fatalf("Glob(%s/*_test.go) error: %v", phase50SafeDisplayPath(dir), err)
	}
	if len(paths) == 0 {
		t.Fatalf("Phase 54 optional live package selector %s contains no test files", packageSelector)
	}

	var names []string
	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", phase50SafeDisplayPath(path), err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", phase50SafeDisplayPath(path), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			names = append(names, fn.Name.Name)
		}
	}
	if len(names) == 0 {
		t.Fatalf("Phase 54 optional live package selector %s contains no Test functions", packageSelector)
	}
	return names
}

func phase54TrimShellQuotes(value string) string {
	return strings.Trim(value, "'\"")
}
