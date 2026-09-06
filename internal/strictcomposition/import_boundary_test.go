package strictcomposition

import (
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestL10StrictCompositionImportBoundary(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "composition.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("ParseFile(composition.go) error = %v", err)
	}
	allowed := map[string]bool{
		"context": true, "crypto/rand": true, "crypto/sha256": true,
		"crypto/subtle": true, "encoding/binary": true, "encoding/hex": true,
		"errors": true, "reflect": true, "strings": true, "sync": true, "time": true,
		"github.com/jywlabs/hal/internal/sandbox":                                          true,
		"github.com/jywlabs/hal/internal/sandboxruntime":                                   true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network": true,
		"github.com/jywlabs/hal/internal/sandboxtemplate/selection":                        true,
		"github.com/jywlabs/hal/internal/sandboxworkspace":                                 true,
	}
	for _, imported := range file.Imports {
		path, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			t.Fatalf("invalid import %q: %v", imported.Path.Value, unquoteErr)
		}
		if !allowed[path] {
			t.Errorf("composition.go imports forbidden dependency %q", path)
		}
	}
}
