# Sandbox Runtime v2 L9 Production OCI Acquisition

## Authority and phase boundary

This note implements issue #49 phase L9 from the locked Linux-completion
architecture. The exact phase base is
`762ee1a61d2efc5bb9241a6e87409ca20d68f976`.

L9 owns production OCI Distribution acquisition, immutable selection, cache
publication, and selected-template evidence. It does not implement signature
verification, transparency-log verification, Firecracker guest/vsock work,
network proxy or firewall enforcement, credential delivery, or strict default
composition. Those remain L5-L8 and L10 concerns.

## 1. Inputs, outputs, states, and failure codes

The explicit CLI inputs are `--sandbox-template REFERENCE` and
`--sandbox-template-trust strict|advisory` on sandbox-backed `hal run`,
`hal auto`, and `hal factory run`. They require `--sandbox`. `REFERENCE` is
transient caller input classified by the existing template source intake. It
is never copied into a manifest, runtime status, error, or evidence record.
The default trust mode is `strict`.

Registry authentication is a transient adapter dependency. Production command
wiring may read a username and token from the process environment, but the
values, environment keys, registry endpoint, and authentication challenge are
never durable or public. Plain HTTP is disabled in production command wiring;
the tagged local-registry test injects a loopback-only HTTP transport.

Selection returns:

- the normalized and sanitized template;
- the verified manifest digest and template-layer digest;
- the existing `TemplateLock`, provenance, and strict/advisory policy result;
- a sanitized `RuntimeTemplateLockMetadata` projection; and
- runtime driver/isolation intent used before provider or runtime construction.

The production adapter accepts only:

- manifest media type `application/vnd.oci.image.manifest.v1+json`;
- artifact type `application/vnd.hal.sandbox-template.v1`;
- layer media types `application/vnd.hal.sandbox-template.v1+yaml` and
  `application/vnd.hal.sandbox-template.v1+json`; and
- digest algorithm `sha256`.

The default bounds are 1 MiB for a manifest, 4 MiB for a template layer,
8 KiB for a `WWW-Authenticate` challenge, and 64 KiB for a token response.
Bounds apply to bytes actually read, independent of `Content-Length`.

Stable safe failure codes are:

- `invalid_reference`;
- `registry_unavailable`;
- `authentication_failed`;
- `authentication_challenge_invalid`;
- `authentication_response_oversize`;
- `redirect_rejected`;
- `manifest_oversize`;
- `manifest_media_type_unsupported`;
- `manifest_invalid`;
- `manifest_digest_mismatch`;
- `tag_mutated`;
- `artifact_type_unsupported`;
- `layer_count_invalid`;
- `layer_media_type_unsupported`;
- `layer_oversize`;
- `layer_digest_mismatch`;
- `cache_invalid`;
- `cache_publish_failed`; and
- `selection_rejected`.

Errors expose only the operation and one of these codes. They never include a
registry endpoint, repository, tag, credential, token, challenge, hostname,
socket, response body, or cache path.

## 2. Package ownership and import boundaries

`internal/sandboxtemplate/acquisition` remains the transport-free contract,
normalization, locking, provenance, trust-policy, and selection package. Its
existing fake-safe import boundary remains intact.

`internal/sandboxtemplate/acquisition/registry` owns the concrete standard
library HTTP Distribution client, bounded authentication exchange, redirect
policy, digest verification, tag-stability check, and verified cache. It
implements `acquisition.OCIArtifactResolver` but imports no command, factory,
worker, provider, runtime adapter, cloud SDK, Docker/Podman client, process
runner, or credential-delivery package.

`cmd` owns flag parsing and dependency wiring only. It calls the acquisition
selection boundary before target provisioning, provider construction, worker
client construction, or runtime driver construction. Status/rendering paths
consume the sanitized selected-template projection and never perform
acquisition.

## 3. Durable and machine-contract schema changes

L9 adds no raw registry or authentication fields to durable schemas. It reuses
the additive `templateLock` fields on sandbox state, execution manifests,
factory sandbox metadata, and runtime metadata, plus the existing
`selectedTemplate` status projections.

Successful selection pins the template source to the verified manifest digest
before strict trust evaluation. The durable projection contains only bounded
source/reference kinds, lock/trust states, sha256 digest values, sizes,
timestamps, and safe reason codes. Legacy records without `templateLock`
remain valid.

No new machine response may contain the caller reference. JSON failure output
uses the existing command envelope with a sanitized stable error.

## 4. Redaction and containment rules

Requests may contain a registry-qualified reference and credentials only in
live memory. The HTTP client disables automatic authorization forwarding and
rejects redirects whose destination is not the original origin. The client
never forwards `Authorization` to a different host.

Bearer authentication permits one bounded challenge, one bounded token
request, and one retry of the original registry request. Basic authentication
permits one retry. Multiple challenges, unsupported schemes, malformed quoted
parameters, oversized headers/bodies, redirect chains, or a second
unauthorized response fail closed.

The cache key is the verified manifest sha256 digest, never a tag, endpoint,
repository, or credential. Cache paths are derived only from validated hex
digests beneath an owned mode-0700 root. Files are mode 0600. Reads reverify
length and digest. Publication writes a private temporary entry, syncs files,
and atomically renames it; incomplete entries are never hits.

## 5. Crash, retry, cancellation, and cleanup semantics

Context cancellation stops network and token requests and returns a sanitized
failure without publishing cache state or selection evidence.

A mutable tag is resolved to manifest bytes, verified against the response
digest when present, and captured as an immutable digest. The template blob is
then requested by descriptor digest and verified from its bytes. Immediately
before cache/selection publication, the tag is resolved again. Any changed
manifest digest fails with `tag_mutated`; neither result is cached or selected.
A digest-pinned request never trusts the digest header and verifies the
response bytes against the requested digest.

HTTP retries are limited to the single authentication retry. L9 does not add
general network retries. A failed request, digest mismatch, unsupported media
type, oversize response, corrupt cache entry, tag mutation, or publication
failure has no local-file, in-memory-fixture, mutable-tag, advisory, or stale
cache fallback.

Tagged integration tests close the in-process loopback registry, remove the
private temporary cache root, and assert no listener, cache entry, credential,
or goroutine-owned request remains. Production cache cleanup may remove only
entries whose digest ownership and containment have been revalidated.

## 6. Red-first fake and live acceptance tests

Red commits precede implementation and cover:

- requested and captured manifest digest verification from response bytes;
- `Docker-Content-Digest` mismatch and manifest `Content-Type`/`mediaType`
  disagreement;
- body bounds independent of missing or false `Content-Length`;
- digest-pinned success and mismatch;
- unsupported manifest/artifact/layer media, layer count, and size;
- bounded Basic/Bearer challenge and token behavior;
- challenge/token header/body limits and safe errors;
- same-origin redirects only and no cross-host authorization forwarding;
- tag mutation between resolution and publication;
- blob digest mismatch;
- cache identity by manifest digest, revalidation, atomic publication,
  concurrent fetch coalescing, and corrupt/incomplete-entry rejection;
- strict selection pinning and propagation before construction;
- advisory selection remaining non-strict;
- no unverified/local/fake fallback; and
- redaction canaries across errors, JSON, durable metadata, and cache names.

The tagged test
`TestOCIRegistryIntegrationStrictTrust` uses a disposable loopback registry,
pushes one non-secret HAL template artifact, selects it through a mutable tag
captured to an immutable digest, proves a cache hit avoids a second blob pull,
exercises mutation/auth/digest/media/size failures, and proves cleanup. It has
no external or billed-cloud dependency. Any skip is a blocker, not a pass.

Focused commands:

```text
go test -count=1 ./internal/sandboxtemplate/acquisition ./internal/sandboxtemplate/acquisition/registry
go test -race -count=1 ./internal/sandboxtemplate/acquisition ./internal/sandboxtemplate/acquisition/registry
go test -tags=template_oci_integration -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition/registry -run '^TestOCIRegistryIntegrationStrictTrust$'
go test -count=1 ./cmd -run 'TestL9'
```

Broad gates follow the Linux-completion architecture, including full tests,
typecheck-only tests, vet, docs-check, build, diff/gofmt checks, and
base-relative lint when `golangci-lint` is installed.

## 7. Non-goals and next-phase handoff

L9 does not verify signatures, transparency logs, attestations, or key
policies. It does not pull a runtime image, start a sandbox, claim guest
readiness, create proxy/firewall proof, deliver runtime credentials, choose a
global default, or upgrade advisory/rootless execution to strict.

L10 receives only the sanitized, immutable selected-template evidence produced
here. L10 must correlate it with the same sandbox/run and the independent L5,
L7, L8, and workspace proofs. Missing, stale, warning-bearing, rejected, or
mismatched template evidence must continue to fail closed.
