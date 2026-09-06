# Selected minimal source assembly

This is the B2 source-build workstream, not a boot, credential, or strict
readiness claim. The current staged-input publisher and B1 bundle API remain
unchanged. The legacy L8 builder, profile and unissued HL8E gates remain intact.

## First boundary: reconstruct the exact cache

`tools/microvm/l8/fetch.sh --cache ABSENT_ABSOLUTE_DIRECTORY` reuses the L5
fetcher in a private temporary directory, including its pinned Buildroot
signer, signed digest, tag object and commit checks. A bounded helper then
copies the verified L5 files and acquires the L8 extension. It reads the
checked-in L5/L8 manifests; it never changes a source pin or runs npm resolution.

Node22.22.0 and Pi0.82.1 have fixed HTTPS source URLs. The Pi tarball must match
its size and SHA-256 before the helper extracts exactly one regular
`package/npm-shrinkwrap.json`. Extraction is streaming and bounded, does not
extract filesystem entries, and rejects unsafe paths, links and duplicate
records. The extracted shrinkwrap must independently match its manifest pin.
Only then can its package names, versions and registry URLs identify the
remaining locked archives. Exact npm URL paths and manifest filenames must
agree; ambiguous, missing, extra and duplicate-source mappings fail closed.

Each request has an explicit timeout, bounded redirect count and fixed HTTPS
origin/path policy, without environment proxies, cookies, credentials or npm
configuration. Bodies are copied with a locked-size-plus-one bound, hashed,
synced and closed before becoming cache entries. All 194 files must match the
two exact manifests before a Linux no-replace directory rename. An existing
cache is verified read-only; it is never repaired or overwritten implicitly.
Errors expose operation categories, not remote bodies or arbitrary URLs.

Cancellation and failure remove only newly owned temporary staging paths.
No-replace rename is the publication commit point: cancellation observed before
it aborts; cancellation racing after the final check does not roll back a
committed cache. A directory-sync error may leave complete output present and
requires explicit verification before reuse. The CLI's overall time budget
also bounds the reused L5 fetcher; its legacy implementation is not rewritten.

Default tests use synthetic tar/manifest fixtures and fake HTTP transports,
with no network, npm or process calls. They cover path/link/duplicate attacks,
bad pins, exact sets, bounded reads, wrong origins, cancellation and preservation
of existing files. Any actual fetch is separately selected and its measured
results recorded; an unavailable upstream archive is not a successful cache.

## Assembly boundary and later gates

The next slice uses the existing immutable Buildroot image digest with an
explicit rootless Podman runner, `--pull=never`, `--network=none`, preserved
caller UID/GID and output ownership. Existing Docker builder defaults remain
compatible. Cache and source inputs are read-only, fresh staging/output roots
are private, and no host home, credential directory or runtime socket is mounted.

The selected filesystem installs only untagged hal-init and hal-guest-agent,
Node22.22.0 and Pi0.82.1 plus the exact shrinkwrap closure. The guest bootstrap
retains L7 configuration and UID1000 capability-dropping semantics; the three
historical guest roles and native role bootstrap are not installed. No guest
seccomp claim is made. Root-owned executable and dependency bytes, traversable
parents, coherent locked accounts, UID1000 workspace/run ownership and canonical
tar metadata must satisfy the existing measured ext4 inspector.

Independently measured archive, executable, init-script and installed-tree pins
from that trusted build feed `minimalprofile.PublishRequest`; candidate JSON
does not supply provenance. Genuine L7 parent verification and the exact
seven-file B1 publication remain mandatory. Two separately clean source builds
must produce identical documented outputs before B2 artifact acceptance.

Locked compressed input budget is 513,011,551 bytes (52 L5 +142 L8 files),
excluding signing metadata and the pinned builder image. Plan one build at a
time, three compiler jobs, 12GiB RAM, 512 PIDs and a 60GiB disk reservation under
a new task directory on the /home filesystem, not tmpfs. Actual download,
builder acquisition, disk use, build duration, reproducibility and boot remain
unverified until separately executed. No privileged setup or billed resources.
