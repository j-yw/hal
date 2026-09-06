# Native source assembly: design and RED boundary

This is the next B2 implementation boundary. The assembler entrypoint does not
exist at this checkpoint. Tagged tests deliberately fail on that missing route;
neither the test runner nor the acquired source archives constitute a build.

## Independently selected source authority

The proposed entrypoint is `assemble.sh --source-repo ABS_REPO
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
The selected Buildroot configuration uses dynamic libraries, C++, target and
source-built host Node, ICU and OpenSSL. Host QEMU is a build dependency only.
Buildroot receives only the verified offline cache, a nonexistent download site
and primary-site-only mode; neither npm resolution nor any download target is
an accepted build step. A missing archive fails instead of fetching.

The owned build installs untagged hal-init, hal-guest-agent, Node and the exact
Pi closure; no HL8E, native role bootstrap, historical guest helper roles or
guest seccomp claim is introduced. The assembled canonical tar must preserve
the existing ownership, UID1000 traversal and locked-account contracts. Actual
output measurement must derive the archive, executable, init-script and
installed-Pi-tree pins; a runner exit of zero or runner-printed JSON is not
sufficient. No archive/receipt is published on failed or unmeasured output.

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

The existing B1 seven-file publication, genuine resolver-issued L7 parent
authority and source inventory meanings do not change. The measured ext4
logical-byte cap remains 512MiB. Two independently clean builds must agree on
documented measured outputs before artifact acceptance. No build, publication,
reproducibility, KVM boot or strict readiness is claimed by this checkpoint.

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

Tagged real-Git/fake-runtime tests specify the proposed actual assembler CLI:
valid selected inputs must reach only the offline runner; missing/altered/extra
native inputs, missing or changed committed lock and forged authority must not.
A fake runtime success without measured output must be rejected, not issued a
receipt. At this RED checkpoint the entrypoint assertion fails before these
individual fixture cases execute; they are not passing behavioral evidence yet.
These tests use synthetic archives and deliberately selected fixture commits;
they do not verify an upstream package, run a container or compile guest code.
Default lock tests have no network, process or external-cache dependency.
