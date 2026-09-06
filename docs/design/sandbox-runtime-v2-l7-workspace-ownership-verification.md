# L7 workspace ownership before and inside fakeroot

The L7 builder intentionally runs as the caller's numeric UID/GID; those IDs
need not be the guest agent's fixed `1000:1000`. Post-build must not attempt
to chown the host build tree to that foreign identity.

The trusted Buildroot **2026.05.1** sources establish this order:

1. `Makefile:827-832` runs `BR2_ROOTFS_POST_BUILD_SCRIPT` during
   `target-finalize`, outside fakeroot. A failed script stops the build.
2. `fs/common.mk:75-88` depends on `target-finalize` and collects users and
   permissions tables, including this profile's existing configured tables.
3. `fs/common.mk:164-195` copies the target tree into each filesystem's private
   image tree and generates a fakeroot script: root ownership normalization,
   generated `mkusers` commands, `makedevs` permissions, then image generation.
4. `support/scripts/mkusers:388-392` creates the home directory if absent and
   **prints** its recursive chown for execution inside that fakeroot script.
   `docs/manual/makedev-syntax.adoc` defines a `d` entry's directory mode and
   numeric owner/group. `makedevs` applies it after the generated user commands.

The minimal correction keeps pre-fakeroot `/workspace` creation at mode `0700`
without ownership flags, and records `/workspace d 0700 1000 1000 - - - - -`
in the existing permissions table. This is image ownership metadata, not a
request for host privileges. The existing agent user entry remains unchanged.
The BusyBox root-owned `0755` permission entry is unchanged.

The mandatory final image verifier still requires `/workspace` to be a
directory with mode `0700` and UID/GID `1000:1000`; its root-owned executable
checks remain intact. A successful post-build command is not final-image proof.

## Red-first verification

`TestL7PostBuildWorkspaceDoesNotRequireGuestOwnership` executes the actual
post-build script against private fixture files. Its install shim refuses any
owner/group request for a simulated nonmatching builder `2001:3001`, without
changing real UIDs/GIDs. Both new and existing workspace cases must complete,
retain mode `0700`, and preserve existing contents. The separate table/config
test locks the fakeroot ownership inputs and mandatory final verifier checks.

```sh
go test -p 2 ./tools/microvm/l7 -run '^TestL7(PostBuildWorkspace|WorkspaceFinalOwnership)' -count=1
go test -p 2 -race ./tools/microvm/l7 -count=3
go vet -p 2 ./tools/microvm/l7
sh -n tools/microvm/l7/post-build.sh
git diff --check
```

These are command-harness and source-contract tests. They do not execute a
container, privileged operation, namespace, full Buildroot build or guest.
Fresh real-image acceptance remains a separate required build gate; these tests
do not claim that an ext4 image was generated or verified.
