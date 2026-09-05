package sandboxtemplate

import (
	"reflect"
	"strings"
	"testing"
)

func TestDecodeBytesYAML(t *testing.T) {
	got, err := DecodeBytes([]byte(validTemplateYAML), FormatYAML, "fixture.yaml")
	if err != nil {
		t.Fatalf("DecodeBytes() error = %v", err)
	}
	assertDecodedTemplate(t, got)
}

func TestDecodeBytesJSON(t *testing.T) {
	got, err := DecodeBytes([]byte(validTemplateJSON), FormatJSON, "fixture.json")
	if err != nil {
		t.Fatalf("DecodeBytes() error = %v", err)
	}
	assertDecodedTemplate(t, got)
}

func TestDecodeBytesJSONEquivalentToYAML(t *testing.T) {
	fromYAML, err := DecodeBytes([]byte(validTemplateYAML), FormatYAML, "fixture.yaml")
	if err != nil {
		t.Fatalf("DecodeBytes(yaml) error = %v", err)
	}
	fromJSON, err := DecodeBytes([]byte(validTemplateJSON), FormatJSON, "fixture.json")
	if err != nil {
		t.Fatalf("DecodeBytes(json) error = %v", err)
	}
	if !reflect.DeepEqual(fromJSON, fromYAML) {
		t.Fatalf("JSON template = %#v, want YAML equivalent %#v", fromJSON, fromYAML)
	}
}

func TestDecodeBytesMalformedTopLevelYAMLReturnsSanitizedError(t *testing.T) {
	_, err := DecodeBytes([]byte("- not\n- an\n- object\n"), FormatYAML, "provided-template.yaml")
	if err == nil {
		t.Fatal("DecodeBytes() error = nil, want malformed top-level YAML error")
	}
	assertSanitizedDecodeError(t, err, "provided-template.yaml")
}

func TestDecodeBytesMalformedTopLevelJSONReturnsSanitizedError(t *testing.T) {
	_, err := DecodeBytes([]byte(`["not","an","object"]`), FormatJSON, "provided-template.json")
	if err == nil {
		t.Fatal("DecodeBytes() error = nil, want malformed top-level JSON error")
	}
	assertSanitizedDecodeError(t, err, "provided-template.json")
}

func assertDecodedTemplate(t *testing.T, got Template) {
	t.Helper()
	if got.APIVersion != TemplateAPIVersionV1 {
		t.Fatalf("APIVersion = %q, want %q", got.APIVersion, TemplateAPIVersionV1)
	}
	if got.Kind != TemplateKindSandbox {
		t.Fatalf("Kind = %q, want %q", got.Kind, TemplateKindSandbox)
	}
	if got.Metadata.ID != "codex-go" {
		t.Fatalf("Metadata.ID = %q, want codex-go", got.Metadata.ID)
	}
	if got.Runtime == nil || got.Runtime.Driver != RuntimeDriverMicroVM {
		t.Fatalf("Runtime = %#v, want microvm runtime", got.Runtime)
	}
	if got.Runtime.Resources == nil || got.Runtime.Resources.CPUCores != 4 || got.Runtime.Resources.MemoryMB != 8192 {
		t.Fatalf("Runtime.Resources = %#v, want cpu and memory hints", got.Runtime.Resources)
	}
	if got.Workspace == nil || got.Workspace.Mode != WorkspaceModeClone || !got.Workspace.ReadOnly {
		t.Fatalf("Workspace = %#v, want read-only clone workspace", got.Workspace)
	}
	if got.Network == nil || got.Network.Profile != NetworkProfileDenyByDefault {
		t.Fatalf("Network = %#v, want deny-by-default network", got.Network)
	}
	if len(got.Network.Allow) != 1 || got.Network.Allow[0].Value != "api.github.com" {
		t.Fatalf("Network.Allow = %#v, want github API rule", got.Network.Allow)
	}
	if got.Credentials == nil || len(got.Credentials.Services) != 1 || got.Credentials.Services[0].ID != "openai" {
		t.Fatalf("Credentials = %#v, want openai service", got.Credentials)
	}
	if len(got.Setup) != 1 || got.Setup[0].ID != "go-version" {
		t.Fatalf("Setup = %#v, want go-version setup command", got.Setup)
	}
}

func assertSanitizedDecodeError(t *testing.T, err error, displayName string) {
	t.Helper()
	message := err.Error()
	if !strings.Contains(message, displayName) {
		t.Fatalf("error = %q, want display name %q", message, displayName)
	}
	if strings.Contains(message, "/Users/") || strings.Contains(message, "\\Users\\") {
		t.Fatalf("error = %q, want no local filesystem path", message)
	}
}

const validTemplateYAML = `
apiVersion: sandbox-template.hal.dev/v1
kind: SandboxTemplate
metadata:
  id: codex-go
  name: Codex Go
  version: 1.2.0
  labels:
    language: go
runtime:
  driver: microvm
  isolationLevel: vm
  image:
    kind: oci_image
    ref: ghcr.io/acme/go-agent:1.2.0
  resources:
    cpuCores: 4
    memoryMb: 8192
    diskGb: 20
workspace:
  mode: clone
  inputSource: remote_ref
  readOnly: true
network:
  profile: deny_by_default
  blockPrivateNetworks: true
  allow:
    - id: github-api
      kind: domain
      value: api.github.com
credentials:
  deliveryModes:
    - http_proxy
  services:
    - id: openai
      domains:
        - api.openai.com
      deliveryModes:
        - http_proxy
      required: true
setup:
  - id: go-version
    command:
      - go
      - version
    requiresNetwork: false
    timeoutSeconds: 30
`

const validTemplateJSON = `{
  "apiVersion": "sandbox-template.hal.dev/v1",
  "kind": "SandboxTemplate",
  "metadata": {
    "id": "codex-go",
    "name": "Codex Go",
    "version": "1.2.0",
    "labels": {
      "language": "go"
    }
  },
  "runtime": {
    "driver": "microvm",
    "isolationLevel": "vm",
    "image": {
      "kind": "oci_image",
      "ref": "ghcr.io/acme/go-agent:1.2.0"
    },
    "resources": {
      "cpuCores": 4,
      "memoryMb": 8192,
      "diskGb": 20
    }
  },
  "workspace": {
    "mode": "clone",
    "inputSource": "remote_ref",
    "readOnly": true
  },
  "network": {
    "profile": "deny_by_default",
    "blockPrivateNetworks": true,
    "allow": [
      {
        "id": "github-api",
        "kind": "domain",
        "value": "api.github.com"
      }
    ]
  },
  "credentials": {
    "deliveryModes": [
      "http_proxy"
    ],
    "services": [
      {
        "id": "openai",
        "domains": [
          "api.openai.com"
        ],
        "deliveryModes": [
          "http_proxy"
        ],
        "required": true
      }
    ]
  },
  "setup": [
    {
      "id": "go-version",
      "command": [
        "go",
        "version"
      ],
      "requiresNetwork": false,
      "timeoutSeconds": 30
    }
  ]
}`
