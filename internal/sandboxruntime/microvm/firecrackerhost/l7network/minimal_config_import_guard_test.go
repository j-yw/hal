package l7network_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalL7ConfigSourceGuardAcceptsOnlyPureDescriptorMapping(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "minimal_l7_config.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	const networkPath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	for name, candidate := range map[string]string{
		"actual mapper": source,
		"aliased descriptor import": strings.ReplaceAll(
			strings.Replace(source, `"`+networkPath+`"`, `network "`+networkPath+`"`, 1), "l7network.", "network."),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateMinimalL7ConfigSource([]byte(candidate)); err != nil {
				t.Fatalf("pure descriptor mapping rejected: %v", err)
			}
		})
	}
	mutations := map[string]string{
		"constructor call":        source + "\nfunc hidden() { l7network.New(nil) }",
		"constructor value alias": source + "\nvar hidden = l7network.New",
		"aliased constructor": strings.Replace(source, `"`+networkPath+`"`, `network "`+networkPath+`"`, 1) +
			"\nvar hidden = network.New",
		"session type":              source + "\ntype hidden = l7network.Session",
		"factory access":            source + "\nvar hidden = l7network.Factory",
		"prepare access":            source + "\nvar hidden = l7network.Prepare",
		"descriptor value":          source + "\nvar hidden = l7network.LaunchDescriptor",
		"descriptor construction":   source + "\nvar hidden = l7network.LaunchDescriptor{}",
		"dot import":                strings.Replace(source, `"`+networkPath+`"`, `. "`+networkPath+`"`, 1),
		"blank import":              strings.Replace(source, `"`+networkPath+`"`, `_ "`+networkPath+`"`, 1),
		"hidden namespace call":     source + "\nfunc hidden() { owner.ProcessNamespace() }",
		"hidden prepare alias":      source + "\nvar hidden = owner.Prepare",
		"hidden release closure":    source + "\nvar hidden = func() { owner.Release() }",
		"hidden quarantine":         source + "\nfunc hidden() { owner.Quarantine() }",
		"unqualified constructor":   source + "\nfunc hidden() { NewL7LiveDriver(nil) }",
		"unqualified factory alias": source + "\nfunc hidden() { create := NewL7LiveDriver; create(nil) }",
		"shadowed allowed closure":  source + "\nfunc hidden() { invalid := NewL7LiveDriver; invalid(nil) }",
		"shadowed builtin":          source + "\nfunc hidden() { len := NewL7LiveDriver; len(nil) }",
		"shadowed package":          source + "\nfunc hidden() { bytes := owner; bytes.NewReader(nil) }",
		"indirect function":         source + "\nfunc hidden() { (func() {})() }",
		"goroutine":                 source + "\nfunc hidden() { go minimalL7Mapping(nil) }",
		"deferred work":             source + "\nfunc hidden() { defer minimalL7Mapping(nil) }",
		"malformed source":          source + "\nfunc",
	}
	for _, path := range []string{"net", "net/http", "os", "os/exec", "reflect", "syscall", "unsafe", "golang.org/x/sys/unix"} {
		mutations["forbidden import "+path] = strings.Replace(source, "import (", "import (\n\t\""+path+"\"", 1)
	}
	for name, candidate := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := validateMinimalL7ConfigSource([]byte(candidate)); err == nil {
				t.Fatal("guard accepted a mapper with an unapproved authority or callable surface")
			}
		})
	}
}
