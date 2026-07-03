# Sandbox Runtime Templates

Sandbox runtime templates describe sandbox requirements. They are separate from
Hal project templates in `.hal/`: project templates guide Hal prompts,
standards, and local workflow files, while sandbox runtime templates describe
runtime metadata such as isolation, workspace mode, network policy intent,
credential planning, and setup expectations.

Phase 44 templates are contracts only. Hal does not build images, pull
artifacts, fetch Git repositories, execute runtimes, enforce network policy, or
deliver credentials from these files.

## YAML Example

```yaml
apiVersion: sandbox-template.hal.dev/v1
kind: SandboxTemplate
metadata:
  id: codex-go
  name: Codex Go
  version: 1.2.0
  reference:
    kind: oci_artifact
    ref: ghcr.io/acme/hal-template-go-codex:1.2.0
    digest:
      algorithm: sha256
      value: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
runtime:
  driver: microvm
  isolationLevel: vm
  image:
    kind: oci_image
    ref: ghcr.io/acme/go-agent:1.2.0
workspace:
  mode: clone
  inputSource: remote_ref
  readOnly: true
network:
  profile: deny_by_default
  blockPrivateNetworks: true
  blockMetadataEndpoints: true
  routeHttpsThroughProxy: true
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
    displayName: Go version
    tools:
      - go
    command:
      - go
      - version
    timeoutSeconds: 30
```

## JSON Example

```json
{
  "apiVersion": "sandbox-template.hal.dev/v1",
  "kind": "SandboxTemplate",
  "metadata": {
    "id": "codex-go",
    "version": "1.2.0",
    "reference": {
      "kind": "oci_artifact",
      "ref": "ghcr.io/acme/hal-template-go-codex:1.2.0"
    }
  },
  "runtime": {
    "driver": "microvm",
    "isolationLevel": "vm",
    "image": {
      "kind": "oci_image",
      "ref": "ghcr.io/acme/go-agent:1.2.0"
    }
  },
  "workspace": {
    "mode": "copy",
    "inputSource": "copy"
  },
  "network": {
    "profile": "allow_listed",
    "allow": [
      {
        "id": "github-api",
        "kind": "domain",
        "value": "api.github.com"
      }
    ]
  },
  "credentials": {
    "deliveryModes": ["http_proxy"]
  }
}
```

## Reference Semantics

A reference with valid digest metadata is digest-pinned. Hal preserves that
digest in normalized, sanitized, and projected metadata, but Phase 44 does not
verify the remote object behind it.

A reference without digest metadata is unresolved mutable metadata. Hal may
project the reference as an unresolved requirement, but it must not claim the
reference is immutable or locked.

## Workspace Modes

`clone` and `copy` are not unsafe by default. `direct` means the sandbox may
operate against a directly shared workspace and must be treated as trusted-only
or unsafe. Phase 44 represents that intent as metadata only; it does not mount,
clone, copy, sync, or mutate workspace files.

## Security Semantics

Network requirements are requested policy metadata. They do not prove proxy,
firewall, runtime, or deny-by-default enforcement.

Credential requirements are requested delivery metadata. They do not deliver
credentials, open secret broker sessions, inspect credential providers, write
temporary files, forward SSH agents, or inject environment variables.

Setup commands are descriptors only. Phase 44 does not spawn shells, execute
commands, inspect tool availability, or read the host environment.
