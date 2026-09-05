# Sandbox Runtime Templates

Sandbox runtime templates describe sandbox requirements. They are separate from
Hal project templates in `.hal/`: project templates guide Hal prompts,
standards, and local workflow files, while sandbox runtime templates describe
runtime metadata such as isolation, workspace mode, network policy intent,
credential planning, and setup expectations.

Phase 44 templates are contracts only. Hal does not build images, pull
artifacts, fetch Git repositories, execute runtimes, enforce network policy, or
deliver credentials from these files.

Phase 47 adds fake-safe acquisition metadata for local files and injected
OCI-like fixtures. Acquisition resolves a template document into normalized,
sanitized template metadata plus redaction-safe lock metadata; it still does
not perform live pulls, contact registries, clone repositories, start runtimes,
or deliver credentials.

Phase 59 selected-template semantics carry the acquired template through
durable runtime, worker, and command status metadata. The `selectedTemplate`
status is a sanitized projection of the template lock, digest, provenance, and
`trustPolicy` decision; it can be `trusted`, `unresolved`, `rejected`, or
`absent`. This status explains why a runtime may be blocked for strict
secure-default readiness, but it is not a global runtime or template selector.

Phase 59 accepts local paths, Git URLs, and OCI/artifact references through the
same safe source/reference vocabulary. Local input is represented as
`local_file`, Git input is represented as `git`, and OCI/artifact input is
represented as `oci_artifact`. Public lock, provenance, worker, runtime, and
status output keeps only safe source kind, reference kind, digest, status,
warning/error code, reason code, and trust-policy metadata.

## Fake-only acquisition

Git and OCI acquisition use injected adapters/fakes in default verification.
Default acquisition may read local fixture documents, classify Git and OCI
references, and resolve injected fixture metadata, but it does not clone Git
repositories, fetch Git remotes, contact live OCI registries, use Docker or
Podman, read cloud credentials, start worker daemons, start `hal sandboxd`, or
run `hal run` as part of template acquisition.

Templates alone do not prove deny-by-default network enforcement, credential
delivery, live runtime isolation proof, or strict secure-default readiness.
They provide selected-template trust and provenance input that other explicit
proof surfaces must combine with before any strict secure-default claim is
allowed.

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

## Local YAML/JSON acquisition

Local acquisition uses the `local_file` source kind to read a YAML or JSON
sandbox template document from a caller-provided path such as `codex-go.yaml`
or `codex-go.json`.

```go
resolver := acquisition.NewLocalResolver()
result, err := resolver.Resolve(ctx, acquisition.ResolveRequest{
	Source: acquisition.TemplateSource{
		Kind:      acquisition.SourceKindLocalFile,
		LocalPath: "codex-go.yaml",
		Format:    sandboxtemplate.FormatYAML,
	},
})
```

The local resolver decodes the document, runs the Phase 44 normalization,
validation, sanitization, and immutable-reference preservation path, and then
records a locked `document` entry with reason code `document_digest`. That
entry is a deterministic SHA-256 document digest over the template document
bytes, plus the byte size and optional lock timestamp. Local paths are caller
input and are not copied into durable lock metadata or public error strings.

## Fake OCI acquisition

Fake OCI acquisition uses the `oci_artifact` source kind with an injected
resolver. The default implementation is fixture-driven
`NewInMemoryOCIArtifactResolver`, also available as
`NewFakeOCIArtifactResolver`, and does not require a live registry.

```go
fake := acquisition.NewInMemoryOCIArtifactResolver(map[string]acquisition.OCIArtifactResolveResult{
	"ghcr.io/acme/templates/codex-go:1.2.0": {
		TemplateBytes:          []byte(templateYAML),
		Format:                 sandboxtemplate.FormatYAML,
		TemplateArtifactDigest: digest,
		ReferenceDigests: []acquisition.ReferenceDigestProof{
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage, Digest: imageDigest},
		},
	},
})
resolver := acquisition.NewOCIResolver(fake)
```

Fixture metadata may provide `documentDigest`, `templateArtifactDigest`, and
per-reference digest proofs. When fixture metadata proves immutable identity,
the acquisition lock records `immutable_digest`; otherwise it falls back to a
deterministic document digest for the template document and unresolved mutable
metadata for unproven references.

## Reference Semantics

A reference with valid digest metadata is digest-pinned. Hal preserves that
digest in normalized, sanitized, and projected metadata, but Phase 44 does not
verify the remote object behind it. Phase 47 preserves pinned `ImmutableRef`
values and treats those as digest-locked references in acquisition metadata
with reason code `immutable_digest`.

A reference without digest metadata is unresolved mutable metadata. Hal may
project the reference as an unresolved requirement, but it must not claim the
reference is immutable or locked.

Acquisition records the field that was evaluated, such as
`metadata.reference`, `runtime.image`, or `workspace.ref`. Mutable runtime
image and source references without a digest proof are preserved as unresolved
mutable references with reason code `mutable_reference`; they are not upgraded
to locked runtime image or source artifact digests.

## Durable `templateLock` surfaces

Resolved acquisition metadata is projected into the additive `templateLock`
JSON field only on these durable surfaces:

- `internal/sandbox.SandboxRuntimeState.TemplateLock`
- `internal/sandboxexecution.Manifest.TemplateLock`
- `internal/factory.SandboxMetadata.TemplateLock`
- `internal/sandboxruntime.RuntimeMetadata.TemplateLock`

The durable lock categories are `document`, `templateReference`,
`runtimeImage`, and `sourceArtifact`. Each entry keeps only bounded
redaction-safe fields: `sourceKind`, `referenceKind`, `status`,
`digestAlgorithm`, `digestValue`, optional `sizeBytes`, optional `lockedAt`,
bounded `warningCodes`, and `reasonCode`.

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
