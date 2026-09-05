package sandboxtemplate

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Format identifies a structured local template encoding.
type Format string

const (
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
)

// DecodeBytes decodes a caller-provided local sandbox template document.
//
// displayName is used only for user-facing diagnostics. Callers that load from
// paths should pass a redaction-safe label if full local paths are sensitive.
func DecodeBytes(data []byte, format Format, displayName string) (Template, error) {
	var template Template
	var err error

	switch format {
	case FormatJSON:
		err = json.Unmarshal(data, &template)
	case FormatYAML:
		err = yaml.Unmarshal(data, &template)
	default:
		return Template{}, fmt.Errorf("decode sandbox template %q: unsupported format %q", displayName, format)
	}
	if err != nil {
		return Template{}, fmt.Errorf("decode sandbox template %q as %s: %w", displayName, format, err)
	}

	return template, nil
}
