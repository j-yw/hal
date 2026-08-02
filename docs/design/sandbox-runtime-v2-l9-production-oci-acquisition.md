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

`--sandbox-template-trust` without `--sandbox-template`, either template flag
without `--sandbox`, an empty reference, an unsupported trust mode, or a
template runtime that conflicts with explicit `--sandbox-runtime` fails
validation before acquisition. No-template compatibility makes zero
acquisition calls.

Dry-run with template flags remains L1-pure: it classifies only static source,
trust, and requested runtime intent, renders that intent as unresolved and
inactive, and returns before credential environment access, resolver/cache/HTTP
construction, acquisition, durable IDs, stores, targets, providers, workers,
or runtimes. Panic fakes lock every forbidden boundary.

Registry authentication is a transient adapter dependency. Production command
wiring reads credentials only when an exact normalized registry origin is
present in an explicit credential allowlist. The credential provider is keyed
by that exact origin; a user-controlled reference or challenge cannot select
generic environment credentials. Values, environment keys, origins, and
authentication challenges are never durable or public. Plain HTTP is disabled
in production command wiring; the tagged local-registry test injects an exact
loopback-origin exception.

Production registry, redirect, and token transport uses a dedicated client
with ambient proxy discovery disabled and TLS 1.2 as the minimum. A normalized
HTTPS origin is accepted only when each fresh DNS resolution and each dial
produces a public unicast address. Loopback, private, link-local, metadata,
unspecified, and multicast destinations fail before a request is sent. Trusted
internal deployments require an exact configured origin-and-address exception;
the tagged test injects the same kind of exact exception for its loopback
origin. DNS is resolved and the selected IP is revalidated on every registry
dial, redirect dial, and token dial, so redirects and rebinding cannot reuse
an earlier public-address decision. Current IANA non-ordinary IPv6 ranges are
also denied, including discard-only, benchmarking, documentation, 6to4, local
translation, and deprecated/special allocation blocks. The globally reachable
`2001:3::/32`, `2001:4:112::/48`, `2001:20::/28`, and `2001:30::/28`
exceptions remain usable. IPv4-translation prefixes are conservatively denied
because they can encode non-public IPv4 destinations.

Selection returns:

- the normalized and sanitized template;
- the verified manifest digest and template-layer digest;
- the existing `TemplateLock`, provenance, and strict/advisory policy result;
- a sanitized `RuntimeTemplateLockMetadata` projection; and
- runtime driver/isolation intent plus an optional digest-pinned runtime-image
  identity used before provider or runtime construction.

The production adapter accepts only:

- manifest media type `application/vnd.oci.image.manifest.v1+json`;
- artifact type `application/vnd.hal.sandbox-template.v1`;
- layer media types `application/vnd.hal.sandbox-template.v1+yaml` and
  `application/vnd.hal.sandbox-template.v1+json`; and
- digest algorithm `sha256`.

The default bounds are 1 MiB for a manifest, 4 MiB for a template layer,
8 KiB for a `WWW-Authenticate` challenge, and 64 KiB for a token response.
Bounds apply to bytes actually read, independent of `Content-Length`.
Compressed HTTP content is rejected (`Content-Encoding` must be absent or
`identity`) so transport decompression cannot bypass byte limits. Header bytes,
request deadlines, redirect count, response status, and `Accept` handling are
also bounded and explicit.

References accept only a normalized registry authority plus repository and tag
or standard `@sha256:<64 lowercase hex>` digest. Inline digest input is
normalized into the existing split immutable reference/digest model before
selection. Parsing rejects tag-plus-digest ambiguity, dual/conflicting digest
representations, userinfo, query, fragment, encoded or literal dot segments,
backslashes, controls, whitespace, ambiguous percent encoding, empty path
segments, invalid repository components, missing tag or digest, and
unsupported or uppercase digest algorithms/values.

Stable safe failure codes are:

- `invalid_reference`;
- `request_canceled`;
- `request_timeout`;
- `registry_unavailable`;
- `address_rejected`;
- `authentication_failed`;
- `authentication_challenge_invalid`;
- `authentication_response_oversize`;
- `response_headers_oversize`;
- `response_headers_invalid`;
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

`internal/sandboxtemplate/selection` owns the acquire, digest-canonicalize,
strict/advisory policy-evaluate, runtime-intent, and identity-binding workflow.
It depends on the transport-free acquisition interface and root runtime/data
contracts only. `internal/sandboxtarget` does not import acquisition,
selection, or the registry adapter and performs no trust decision.

`cmd` owns flag parsing and dependency wiring only. It calls the acquisition
selection boundary before target provisioning, provider construction, worker
client construction, or runtime driver construction. Status/rendering paths
consume the sanitized selected-template projection and never perform
acquisition.

Run, auto, and factory share one ordering contract: parse/validate; perform
strict static OCI reference validation before credential, cache, HTTP, or
workflow construction; perform the pure dry-run return when requested; acquire
and strictly select; then resolve or provision the target with the selected
runtime requirements and immutable lock already present; correlate the
returned target with the execution, sandbox, and runtime identities; persist
the same sanitized lock in those containing records; and only then construct a
provider, worker client, or runtime driver.

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
Requested dry runs expose only a redaction-safe static template intent:
`sourceKind`, trust mode, and requested/resolved/active booleans. They do not
resolve the reference or expose its authority, repository, tag, digest, or raw
text.

Selection binding is not a status-only attachment. Before construction,
command wiring verifies that one selected manifest digest and trust result is
carried unchanged into the selected runtime target. The same sanitized lock is
then persisted under the exact execution manifest and sandbox/runtime state
that already carry the execution, sandbox, runtime, and worker identities. A
missing or different digest at any handoff returns `selection_rejected`; it is
never repaired by status projection.
When the template selects a runtime image, command wiring also provisions and
constructs with its digest-pinned reference. Binding compares that selection
with the independently observed target/runtime image identity after lifecycle
operations. A missing or different observed image fails before provider
preparation, readiness persistence, or trusted-template projection. L9 does
not itself pull the runtime-image blob.

## 4. Redaction and containment rules

Requests may contain a registry-qualified reference and credentials only in
live memory. Registry manifest requests permit bounded same-origin redirects.
Blob redirects are same-origin by default; explicitly configured exact HTTPS
blob origins may be allowed for object storage. Every cross-origin hop strips
`Authorization`. Redirects reject userinfo, query credentials, fragments, TLS
downgrade, non-allowlisted origins, ambiguous encodings, and more than three
hops. The client never forwards `Authorization` to a different host.

Bearer authentication permits one bounded challenge, one bounded token
request, and one retry of the original registry request. Basic authentication
permits one retry. Multiple challenges, unsupported schemes, malformed quoted
parameters, oversized headers/bodies, redirect chains, or a second
unauthorized response fail closed.
Every intermediate response passes the same bounded header-name/value
validation before a `WWW-Authenticate` challenge or `Location` is inspected;
duplicate redirect locations are rejected before another request is made.

Bearer `realm` may be cross-origin only when it is an exact configured HTTPS
token origin for the selected registry origin; the loopback integration
exception is exact and test-only. The requested `service` must equal the
configured service or the challenged registry authority, and `scope` must
equal the canonical `repository:<normalized-repository>:pull` scope. Unknown,
broader, repeated, or conflicting service/scope parameters fail. Registry
credentials are sent to a token realm only when the credential provider
explicitly authorizes that exact `(registry origin, token origin)` pair. Token
requests cannot reach arbitrary challenge-selected origins, private/link-local
destinations, or redirects.

The cache key is the verified manifest sha256 digest, never a tag, endpoint,
repository, or credential. Cache paths are derived only from validated hex
digests beneath an owned mode-0700 root. Cache roots, entries, and files are
opened descriptor-relatively with no-follow semantics, reject symlinks,
non-directories, wrong owner, or permissive modes, and remain pinned while an
operation runs. Files are mode 0600. Reads reverify
length and digest. Publication writes a private temporary entry in the same
directory, syncs each file and the temporary directory, atomically renames it,
and syncs the parent directory; incomplete entries are never hits.

## 5. Crash, retry, cancellation, and cleanup semantics

Context cancellation stops network and token requests and returns
`request_canceled`; an adapter deadline returns `request_timeout`. Both are
sanitized failures and publish neither cache state nor selection evidence.

A mutable tag is resolved to manifest bytes, verified against the response
digest when present, and captured as an immutable digest. The template blob is
then requested by descriptor digest and verified from its bytes. Immediately
before cache/selection publication, the tag is resolved again using the same
bounded authentication policy. Any changed manifest digest fails with
`tag_mutated`; neither result is cached or selected. The immutable evidence is
the first verified manifest digest only after the second resolution agrees. A
digest-pinned request never trusts the digest header and verifies the response
bytes against the requested digest.

The manifest must be schema version 2. Its HTTP `Content-Type` must equal its
JSON `mediaType`. `artifactType` must be the HAL template artifact type. The
config descriptor must use `application/vnd.oci.empty.v1+json`, be no larger
than two bytes, and carry a valid sha256 digest; it is validated but not
fetched. Exactly one template layer is allowed. Its descriptor media type,
size, and sha256 digest are validated before I/O. The adapter fetches and
verifies exactly that one layer blob and no runtime-image, subject, config, or
unrelated blob.

Manifest decoding uses an exact field allowlist:
`schemaVersion`, `mediaType`, `artifactType`, `config`, and `layers`.
Both the config descriptor and layer descriptor allow exactly `mediaType`,
`digest`, and `size`. Thus indexes, `subject`, annotations, foreign descriptor
`urls`, platform data, alternate-data maps, extension fields, and count/byte
overflow are rejected rather than ignored. There are exactly two descriptors
(config plus one layer), at most 4 MiB of fetched blob data, and at most 5 MiB
across bounded manifest plus fetched blob bytes.
Root acquisition remeasures every supplied document or reference proof against
the corresponding bytes; injected digest labels alone never create a lock.
Mutable tags are intake aliases only: selection replaces them with a
digest-canonical reference before calling the unchanged strict evaluator.

HTTP retries are limited to the single authentication retry. L9 does not add
general network retries. A failed request, digest mismatch, unsupported media
type, oversize response, corrupt cache entry, tag mutation, or publication
failure has no local-file, in-memory-fixture, mutable-tag, advisory, or stale
cache fallback.

Cache is an optimization for the already-identified immutable template layer,
not offline trust. Every selection performs a live manifest resolution (and
tag re-resolution when applicable), so an unavailable registry fails closed
even when verified bytes exist in cache. A hit may avoid only the layer-blob
download after live manifest identity is established.

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
- cross-origin blob redirects strip authorization and reject TLS downgrade,
  userinfo, non-allowlisted origins, and excess hops;
- strict reference parsing, response status/Accept, header/deadline, and
  `Content-Encoding` limits;
- distinct cancellation/timeout errors plus public-address revalidation on
  every registry, redirect, and token dial;
- ambient-proxy disablement, TLS minimum enforcement, DNS-rebinding defense,
  and exact trusted-internal/loopback exceptions;
- exact manifest and descriptor field allowlists, including rejection of
  subject, annotations, foreign URLs, platforms, and extension fields;
- tag mutation between resolution and publication;
- blob digest mismatch;
- cache identity by manifest digest, revalidation, atomic publication,
  concurrent fetch coalescing, symlink/change-during-read defense, and
  corrupt/incomplete-entry rejection;
- strict selection pinning and propagation before construction;
- advisory selection remaining non-strict;
- no unverified/local/fake fallback;
- dry-run/no-template zero-call compatibility, strict static reference
  classification before any credential/cache/HTTP dependency, redaction-safe
  preview intent, flag conflicts, and run/auto/factory pre-construction
  ordering;
- exact execution/sandbox/runtime selection binding rather than status-only
  projection; and
- provider/runtime constructor panic fakes for every acquisition/policy
  failure, with durable digest equality to the bytes that derived runtime
  intent; and
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
