package l7network_test

import (
	"maps"
	"strings"
	"testing"
)

func TestMinimalPreexecCompositionGuardForward(t *testing.T) {
	sources := readFirecrackerHostTopologySources(t)
	for _, change := range []struct {
		name, file, before, after string
		valid                     bool
	}{
		{"comments are not authority", "minimal_preexec_host_linux.go", "os.Geteuid() != 0", "false /* os.Geteuid() != 0 */", false},
		{"incapable dependency replaced", "minimal_preexec_assembler_linux.go", "GuestIsolation: minimalPreexecNoGuest{}", "GuestIsolation: supplied", false},
		{"lower host activation", "minimal_preexec_host_linux.go", "host.self = host", "input.proxy.ApplicationRoutes.Start(ctx); host.self = host", false},
		{"L7 constructor value escape", "minimal_preexec_assembler_linux.go", "proxyConfig := input.proxy", "construct := l7network.New; _ = construct; proxyConfig := input.proxy", false},
		{"comments and whitespace", "minimal_preexec_host_linux.go", "os.Geteuid() != 0", "os.Geteuid() /* actual observation */ != 0", true},
	} {
		t.Run(change.name, func(t *testing.T) {
			candidate := maps.Clone(sources)
			source := string(candidate[change.file])
			if strings.Count(source, change.before) != 1 {
				t.Fatal("forward mutation prerequisite changed")
			}
			candidate[change.file] = []byte(strings.Replace(source, change.before, change.after, 1))
			err := validateFirecrackerHostTopologySources(candidate)
			if change.valid && err != nil || !change.valid && (err == nil || !strings.Contains(err.Error(), "selected preexec")) {
				t.Fatalf("source-boundary result differs from intended semantic mutation: %v", err)
			}
		})
	}
}
