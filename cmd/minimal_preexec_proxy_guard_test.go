package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalPreexecProxyGuard(t *testing.T) {
	const parent = "internal/sandboxruntime/microvm/firecrackerhost/"
	for _, name := range []string{"minimal_preexec_host_linux.go", "minimal_preexec_assembler_linux.go"} {
		t.Run(name, func(t *testing.T) {
			path := parent + name
			payload, err := os.ReadFile(filepath.Join("..", path))
			if err != nil {
				t.Fatal(err)
			}
			source := string(payload)
			t.Run("reviewed composition", func(t *testing.T) {
				if err := validateL6ProductionProxySource(path, payload); err != nil {
					t.Fatal(err)
				}
			})
			for label, suffix := range map[string]string{
				"unreviewed constructor":   "\nfunc hidden() { policyproxy.New(policyproxy.Config{}) }",
				"global constructor alias": "\nvar hidden = policyproxy.New",
				"direct lifecycle":         "\nfunc hidden(a *policyproxy.Adapter) { a.StartProxyListener(nil, networkenforcement.ProxyListenerLifecycleRequest{}) }",
				"init constructor":         "\nfunc init() { policyproxy.New(policyproxy.Config{}) }",
			} {
				t.Run(label, func(t *testing.T) {
					err := validateL6ProductionProxySource(path, []byte(source+suffix))
					if err == nil || !strings.Contains(err.Error(), "selected proxy") {
						t.Fatalf("mutation was not rejected at the selected proxy boundary: %v", err)
					}
				})
			}
			t.Run("third file still forbidden", func(t *testing.T) {
				if err := validateL6ProductionProxySource(parent+"unreviewed.go", payload); err == nil {
					t.Fatal("new filename acquired proxy construction authority")
				}
			})
		})
	}
}
