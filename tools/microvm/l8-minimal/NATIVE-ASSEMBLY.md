# Native source assembly: implementation and trust boundary

This is the B2 offline producer, not final L8 acceptance. `assemble.sh` now
implements the selected-source route. Its tests use real local Git and fake
Podman; neither those tests nor the acquired archives constitute a native build.

## Independently selected source authority

The entrypoint is `assemble.sh --source-repo ABS_REPO
--source-revision EXACT_COMMIT --cache ABS_L5_L8_CACHE
--native-cache ABS_NATIVE_CACHE --output ABSENT_DIR --runtime podman`.
The trusted operator selects the full commit ID independently of all candidate
output. Branch names, caller-supplied tree labels, candidate receipts and
adjacent checksum files are not selection authority. There is no receipt-import
or source-tree-override option.

Before launch, resolve that commit to its actual Git tree, reject a changed
selected checkout, and snapshot the selected objects into private owned staging.
Read `native-sources.lock.json`, the existing L5/L8 manifests, builder pin and
assembly recipe from this same tree. Recheck source identity before launch;
build only from the retained snapshot, never a validated then blindly reopened
worktree. Missing lock blobs, substituted trees and modified lock bytes fail.
Git subprocesses use a bounded, clean environment and local object access only.
Raw commit/tree/blob object hashes are verified; the three source-lock documents
are decoded from those same retained blob bytes, not reopened metadata. Git
archive export substitutions are not used. The host assembler itself must also
come from a reviewed revision selected by the trusted supervisor; selecting a
candidate's self-authored commit does not establish source provenance.

The minimal-only native lock is distinct from the unchanged L5/L8 manifests and
legacy `PiDependencyTreeSHA256` source archive inventory. It records exactly the
eleven additional archives selected by the pinned Buildroot configuration,
including original HTTPS URL, trusted package hash-file path/algorithm/digest,
download cap and measured size/SHA-256. Strict decoding rejects unknown fields,
duplicates, unsafe names, extra or missing records and invalid pins. Verify all
52 L5, 142 L8 and 11 native cache entries before any container execution. Exact
entry sets, retained no-follow reads and byte rechecks prevent a changed cache
from being accepted by metadata alone. Copy only verified bytes into private
read-only build inputs. Native files do not relax the L5 exact-52-file contract.

## Actual assembly and receipt boundary

Only the explicit rootless Podman path is selected. Reuse the accepted pinned,
bounded runner: no pull, no network, no host home/auth/runtime socket, preserved
host UID/GID, three jobs, 12GiB memory, 512 PIDs and task-owned scoped cleanup.
The host runner also receives a clean environment, not inherited HOME/auth or
XDG values. For an isolated image store, the supervisor selects a self-contained
task-owned `podman` wrapper via PATH that restores only its explicit local lab
context; that context is not added to the guest environment or bind mounts.
The selected Buildroot configuration uses dynamic libraries, C++, target and
source-built host Node, ICU and OpenSSL. Host QEMU is a build dependency only.
Buildroot receives only the verified offline cache, a nonexistent download site
and primary-site-only mode; neither npm resolution nor any download target is
an accepted build step. A missing archive fails instead of fetching.
The committed `buildroot-downloads.lock.json` records all 55 package-directory /
archive pairs derived by no-download `defconfig` and `show-info` from the genuine
Buildroot archive. Each assembly repeats that evaluation and compares the exact
layout before preseeding `DL_DIR/<package>/<archive>`. The final target is
`rootfs-tar`, not the legacy 64MiB ext4 image target. The host's existing bounded
ext4 producer creates and inspects the actual minimal image afterward.

The owned build installs untagged hal-init, hal-guest-agent, Node and the exact
Pi closure; no HL8E, native role bootstrap, historical guest helper roles or
guest seccomp claim is introduced. The assembled canonical tar must preserve
the existing ownership, UID1000 traversal and locked-account contracts. Actual
output measurement must derive the archive, executable, init-script and
installed-Pi-tree pins; a runner exit of zero or runner-printed JSON is not
sufficient. No archive/receipt is published on failed or unmeasured output.
The existing untagged L7 PID1 and v1 guest agent are built from the selected tree;
they do not implement the later authenticated credential-control contract.
That later change requires new selected source and rebuilt release artifacts.
Pi's published JavaScript is installed byte-for-byte from the pinned archives,
not independently rebuilt from TypeScript. No npm lifecycle scripts are run.
Host QEMU is used only for Buildroot's build-time V8 snapshot, not guest boot.

The trusted host assembler retains the selected revision, actual tree and
native-lock SHA-256 together with its verified input handles throughout owned
execution and measurement. A fresh host-generated receipt/request is emitted
only after successful build and byte measurement. Candidate JSON cannot restore
that in-process authority. The supervisor must retain the command's independently
observed receipt/request digest for later `minimalprofile.Publish`, rather than
recovering expected pins from files adjacent to the candidate. The actual tree
contains the native lock, so existing B1 `ProvenanceSHA256` binds that tree and
thus the selected native lock. A free-form `SourceTree` passed directly to the
staged-input publisher is still only trusted-caller metadata, not build proof.
The producer publishes exactly `rootfs.tar`, `rootfs.ext4` and `assembly.json`
with no-replace directory rename. It emits the host-generated receipt on stdout
only after inspection and publication; runner logs are bounded and go to stderr.
The receipt supplies `SourceRevision`, `SourceTree`, `SourceDateEpoch`, archive
SHA-256 and actual `Pins` for the later trusted `PublishRequest`. That handoff
must separately supply the genuine L7 parent, unchanged L5/L8 source inventory,
and pinned builder image. The producer does not call the seven-file publisher,
mint a parent receipt, or restore receipt authority from adjacent JSON.

The output parent and both exact cache directories must be canonical, owned,
private 0700 paths outside the source repository. Output must be absent. Input
copies and output entry creation use retained no-follow directory authority;
replacement fails without writing into the foreign replacement. Build and
inspection scratch remain below that output parent, not `/tmp`. Failed owned
staging is deliberately retained, especially when scoped container cleanup is
uncertain. A signal to the public entrypoint reaches the controller and bounded
CID/label cleanup. The no-replace rename is the commit point: later cancellation
or stdout failure does not retroactively delete committed measured output.

The existing B1 seven-file publication, genuine resolver-issued L7 parent
authority and source inventory meanings do not change. The measured ext4
logical-byte cap remains 512MiB. Two independently clean builds must agree on
the canonical archive hash, rootfs hash, executable/init pins and installed Pi
tree before artifact acceptance. Build twice into distinct absent output names
using the same independently selected commit and verified caches, then compare
those measured receipt fields. No real native build, reproducibility, KVM boot
or strict readiness is claimed by this implementation submission.

## Acquisition evidence and test boundary

The eleven archives were acquired through one separately authorized bounded
HTTPS operation on 2026-09-06. Total measured bytes: 237,662,404, below the
448,790,528-byte reviewed aggregate cap. Every archive passed its hash from the
signer-verified Buildroot 2026.05.1 source archive before its size/SHA-256 was
recorded. Pixman was first verified against upstream SHA-512, then measured as
660,536 bytes with SHA-256
`a098c33924754ad43f981b740f6d576c70f9ed1006e12221b1845431ebce1239`.
No archive was extracted or executed during acquisition. Exact URLs and pins
are in the lock; task-local evidence additionally retains redirect observations.

Tagged real-Git/fake-runtime tests exercise the actual assembler CLI:
valid selected inputs must reach only the offline runner; missing/altered/extra
native inputs, missing or changed committed lock and forged authority must not.
A fake runtime success without measured output must be rejected, not issued a
receipt. The committed RED checkpoint failed at the missing entrypoint before
its 15 fixture cases ran; GREEN executes those cases plus entrypoint-only TERM.
These tests use synthetic archives and deliberately selected fixture commits;
they do not verify an upstream package, run a container or compile guest code.
Default lock tests have no network, process or external-cache dependency.

Default checks: `go test -p 2 ./tools/microvm/l8-minimal/...`.
Explicit CLI-backed checks: `go test -p 2 -tags=microvm_assets_integration
./tools/microvm/l8-minimal/...`; add `-race -count=3` for the focused race gate.
They require local Git, Bash, the pinned offline Go toolchain/cache and Python 3,
not a live container, downloads or KVM. Existing L5/L7 Docker-default runner
regressions remain in that tagged suite. Missing prerequisites are failures,
not evidence of a passing build. Real image production additionally needs the
locally present pinned Podman builder and e2fsprogs 1.47.4.

## Measured npm archive compatibility

A bounded read-only audit first verified all 140 npm archive sizes/SHA-256,
then visited 18,868 tar headers (28,228,089 compressed bytes). No links or devices
were present. The default extractor still accepts only canonical `package/`
paths, ordinary directories/files, no PAX and no duplicate canonical names.
Seven exceptions in `stage-native.py` require both exact archive name and the
unchanged L8 SHA-256; changing a pin requires another explicit audit.

| Archive | Measured format |
| --- | --- |
| `types-retry-0.12.0.tgz` | Exact `retry/` prefix |
| `types-node-22.19.19.tgz` | Exact `node v22.19/` prefix |
| `http-proxy-agent-7.0.2.tgz` | Ordered duplicate pair below |
| `agent-base-7.1.4.tgz` | Ordered duplicate pair below |
| `https-proxy-agent-7.0.6.tgz` | Ordered duplicate pair below |
| `buffer-equal-constant-time-1.0.1.tgz` | Seven regular members with the exact metadata-key allowlist below |
| `mistralai-mistralai-2.2.6.tgz` | Three long-name members with PAX `mtime`, `path`, `size` |

The three duplicate pairs are `package/./dist/index.js` followed by
`package/dist/index.js`, canonical `dist/index.js`. Each member is regular type
`0`, mode 0644, UID/GID 0, mtime 499162500, without PAX. Both must match the same
measured size and SHA-256 before the second is skipped:

| Archive | Bytes | Member SHA-256 |
| --- | ---: | --- |
| http-proxy-agent | 6088 | `fd33b43da34da60d4914780e13fae5d52a7faaa996d687eea5335128de148627` |
| agent-base | 7324 | `c6503bd5e007db8b73fedf07b6eaaf4a94d5541953f0d06c8a17d1644c29a0c5` |
| https-proxy-agent | 7451 | `30165586fac3becbc9dbf2b7b5bdaa802a77ac34af9926208f6e94a3bd87ef31` |

Changed content, metadata, order or count fails; other duplicate names still
fail. The buffer package's exact PAX-key set is:

```text
NODETAR.blksize NODETAR.blocks NODETAR.depth NODETAR.follow
NODETAR.ignoreFiles.0 NODETAR.ignoreFiles.1 NODETAR.ignoreFiles.2
NODETAR.package.author NODETAR.package.description
NODETAR.package.devDependencies.mocha
NODETAR.package.keywords.0 NODETAR.package.keywords.1
NODETAR.package.keywords.2 NODETAR.package.keywords.3
NODETAR.package.license NODETAR.package.main NODETAR.package.name
NODETAR.package.repository NODETAR.package.scripts.test NODETAR.package.version
NODETAR.type SCHILY.dev SCHILY.ino SCHILY.nlink gid path size uid
```

These are ignored archive metadata, not executable instructions, source
authority or installed ownership. PAX path/size must match the effective tar
record. Mistral's three measured basenames are
`getchatcompletionfieldoptionscountsv1observabilitychatcompletionfieldsfieldnameoptionscountspost`
with `.d.ts.map`, `.js.map`, and `.d.ts` under `package/esm/models/operations/`.
Canonical output uses deterministic GNU long-name records, with no PAX, to
preserve those bytes without truncation. No general prefix, path, link or PAX
relaxation is available through the assembler CLI.
