package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const l4GuestAgentProtocolImport = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"

func TestL4GuestAgentServerProductionImportsStayBounded(t *testing.T) {
	for _, path := range l4GuestAgentServerProductionFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("Unquote(%s in %s) error: %v", spec.Path.Value, path, err)
			}
			if reason := l4GuestAgentServerForbiddenImport(importPath); reason != "" {
				t.Fatalf("%s imports forbidden %s %q", path, reason, importPath)
			}
			if !l4GuestAgentServerAllowedImport(importPath) {
				t.Fatalf("%s imports unapproved dependency %q", path, importPath)
			}
		}
	}
}

func TestL4GuestAgentServerProductionSourceOmitsForbiddenSideEffects(t *testing.T) {
	for _, path := range l4GuestAgentServerProductionFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if message := l4GuestAgentServerForbiddenCall(path, file); message != "" {
			t.Fatal(message)
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		for _, forbidden := range []string{
			"/var/run/docker.sock",
			"/run/docker.sock",
			"DOCKER_HOST",
			"Message: err.Error()",
			"Message: cause.Error()",
		} {
			if strings.Contains(string(source), forbidden) {
				t.Fatalf("%s contains forbidden L4 server source marker %q", path, forbidden)
			}
		}
	}
}

func TestL4GuestAgentServerForbiddenImportGuardCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		importPath string
		want       string
	}{
		{importPath: "github.com/jywlabs/hal/cmd", want: "command package"},
		{importPath: "github.com/jywlabs/hal/internal/factory", want: "factory package"},
		{importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "worker package"},
		{importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost", want: "Firecracker package"},
		{importPath: "github.com/containers/podman/v5/pkg/bindings", want: "container runtime package"},
		{importPath: "github.com/docker/docker/client", want: "container runtime package"},
		{importPath: "net", want: "network listener or dialer package"},
		{importPath: "net/http", want: "HTTP or RPC package"},
		{importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
	} {
		if got := l4GuestAgentServerForbiddenImport(tt.importPath); !strings.Contains(got, tt.want) {
			t.Fatalf("forbidden import %q reason = %q, want %q", tt.importPath, got, tt.want)
		}
	}
	for _, allowed := range []string{
		"context",
		"os",
		"os/exec",
		"path/filepath",
		"syscall",
		"golang.org/x/sys/unix",
		l4GuestAgentProtocolImport,
	} {
		if reason := l4GuestAgentServerForbiddenImport(allowed); reason != "" {
			t.Fatalf("allowed import %q rejected as %s", allowed, reason)
		}
		if !l4GuestAgentServerAllowedImport(allowed) {
			t.Fatalf("allowed import %q was not approved", allowed)
		}
	}
}

func TestL4GuestAgentServerForbiddenSourceGuardCoversRequiredBoundaries(t *testing.T) {
	source := `package fixture
import ("os"; "os/exec"; "net")
func f() {
	os.Environ()
	os.LookupEnv("TOKEN")
	exec.Command("sh", "-c", "echo unsafe")
	net.Listen("tcp", ":0")
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatalf("ParseFile(fixture) error: %v", err)
	}
	message := l4GuestAgentServerForbiddenCall("fixture.go", file)
	if message == "" {
		t.Fatal("forbidden source guard accepted side-effect fixture")
	}
}

func l4GuestAgentServerProductionFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.) error: %v", err)
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		paths = append(paths, filepath.Join(".", name))
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("no L4 guest-agent server production files matched import/source guards")
	}
	return paths
}

func l4GuestAgentServerAllowedImport(importPath string) bool {
	if importPath == l4GuestAgentProtocolImport || importPath == "golang.org/x/sys/unix" {
		return true
	}
	first := strings.Split(importPath, "/")[0]
	return !strings.Contains(first, ".")
}

func l4GuestAgentServerForbiddenImport(importPath string) string {
	for _, forbidden := range []struct {
		prefix string
		reason string
	}{
		{prefix: "github.com/jywlabs/hal/cmd", reason: "command package"},
		{prefix: "github.com/jywlabs/hal/internal/factory", reason: "factory package"},
		{prefix: "github.com/jywlabs/hal/internal/sandboxworker", reason: "worker package"},
		{prefix: "github.com/jywlabs/hal/internal/sandboxexec", reason: "execution package"},
		{prefix: "github.com/jywlabs/hal/internal/sandboxexecution", reason: "execution package"},
		{prefix: "github.com/jywlabs/hal/internal/sandboxworkspace", reason: "workspace package"},
		{prefix: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", reason: "Firecracker package"},
		{prefix: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost", reason: "Firecracker package"},
		{prefix: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", reason: "container runtime package"},
		{prefix: "github.com/docker/docker", reason: "container runtime package"},
		{prefix: "github.com/containers/podman", reason: "container runtime package"},
		{prefix: "github.com/containers/image", reason: "container runtime package"},
		{prefix: "github.com/digitalocean/godo", reason: "cloud SDK package"},
		{prefix: "github.com/aws/aws-sdk-go", reason: "cloud SDK package"},
		{prefix: "github.com/aws/aws-sdk-go-v2", reason: "cloud SDK package"},
		{prefix: "github.com/hetznercloud/hcloud-go", reason: "cloud SDK package"},
		{prefix: "cloud.google.com/go", reason: "cloud SDK package"},
		{prefix: "google.golang.org/api", reason: "cloud SDK package"},
		{prefix: "github.com/spf13/cobra", reason: "Cobra package"},
		{prefix: "google.golang.org/grpc", reason: "HTTP or RPC package"},
	} {
		if importPath == forbidden.prefix || strings.HasPrefix(importPath, forbidden.prefix+"/") {
			return forbidden.reason
		}
	}
	switch importPath {
	case "net":
		return "network listener or dialer package"
	case "net/http", "net/rpc":
		return "HTTP or RPC package"
	default:
		return ""
	}
}

func l4GuestAgentServerForbiddenCall(path string, file *ast.File) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := l4GuestAgentServerCallSelector(call)
		switch selector {
		case "os.Environ", "os.Getenv", "os.LookupEnv":
			message = fmt.Sprintf("%s calls %s; L4 server must not use ambient environment", path, selector)
		case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
			message = fmt.Sprintf("%s calls %s; L4 server transport is injected", path, selector)
		case "http.Get", "http.Post", "http.ListenAndServe", "rpc.ServeConn":
			message = fmt.Sprintf("%s calls %s; L4 server must not use HTTP/RPC", path, selector)
		case "exec.Command", "exec.CommandContext":
			if l4GuestAgentServerImplicitShell(call) {
				message = fmt.Sprintf("%s calls %s with an implicit shell", path, selector)
			}
		}
		return message == ""
	})
	return message
}

func l4GuestAgentServerCallSelector(call *ast.CallExpr) string {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	ident, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name + "." + selector.Sel.Name
}

func l4GuestAgentServerImplicitShell(call *ast.CallExpr) bool {
	start := 0
	if l4GuestAgentServerCallSelector(call) == "exec.CommandContext" {
		start = 1
	}
	if len(call.Args) <= start {
		return false
	}
	executable, ok := call.Args[start].(*ast.BasicLit)
	if !ok || executable.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(executable.Value)
	if err != nil {
		return false
	}
	switch filepath.Base(value) {
	case "sh", "bash", "dash", "zsh":
		return true
	default:
		return false
	}
}
