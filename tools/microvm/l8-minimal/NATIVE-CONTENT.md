# Minimal native content predicate: bounded DESIGN/RED

## Evidence and scope

The native build 3 archive from selected source `99b58782` remains unchanged:
SHA-256 `920d4709395af20e7fa5856f241b805392b59b742b3d32d4058d34d523501f13`.
A separate read-only scan of all 18,809 regular files reproduced the current
minimal inspector's `secretContent` predicate. Exactly three files matched:

- Pi `docs/providers.md` contains `export AWS_SECRET_ACCESS_KEY=...`, an exact
  three-dot documentation placeholder.
- AWS credential-provider-ini `dist-cjs/index.js` and
  `dist-es/resolveStaticCredentials.js` each contain
  `typeof arg.aws_secret_access_key === "string"`, a type comparison.

These are syntax false positives, not evidence of an installed actual key.
The original native attempt stopped earlier at archive metadata validation;
this read-only audit identified a later inspection blocker, not a successfully
reached native image gate. Neither the audit nor these tests attests the full
image. The separate bracket-applet/recipe metadata correction is not a dependency
of this slice: all fixtures use the already accepted ordinary names and metadata.

This checkpoint adds only tests and this design, based on `38e16732`. No scanner,
recipe, source lock, cache, stage, receipt or publication behavior changes yet.
The proposed GREEN scope is the private content predicate and its one existing
call in `minimalprofile/inspect_linux.go`, with any helper in the same package.
No path, package, source hash, candidate pin or build-success exception is allowed.

## Proposed precise grammar

Retain unconditional case-insensitive private-key-header and `HAL_*CANARY`
checks across the complete file. Continue examining every occurrence of the
existing `_authToken` and `aws_secret_access_key` assignment markers. An empty,
unknown or malformed value is rejected, not presumed harmless. A matched marker
may be ignored only when it belongs to one of these complete lexical forms:

1. A complete physical line:

   ```text
   H* ("export" H+)? KEY H* "=" H* "..." H* (LF | CR LF | EOF)
   ```

   `H` is ASCII space or tab. `KEY` is exactly either existing marker,
   case-insensitively; `export` is lowercase. The left boundary is line start,
   not any earlier substring. Exactly three unquoted ASCII dots are the entire
   value. Bare CR, controls, comments, punctuation, quotes, suffixes, continuations
   and other tokens on that line are not allowed. Newline between `=` and dots
   is not allowed. Two independent valid lines are harmless; a second actual
   assignment anywhere still rejects the file.

2. A narrowly recognizable JavaScript type-test expression:

   ```text
   "typeof" H+ IDENT ("." IDENT)* "." KEY H* ("==" | "===") H* STRING
   ```

   `IDENT` is ASCII `[A-Za-z_$][A-Za-z0-9_$]*`; `KEY` uses the rule above.
   `STRING` is exactly `"string"` or `'string'`, with matching unescaped quotes.
   `typeof` and `string` are case-sensitive. The expression begins at file start
   or after ASCII space/tab/LF/CR or one of `(!&|?:={[,;`, never inside an
   identifier or property. It ends at file end or before ASCII space/tab/LF/CR
   or one of `),;:&|?!}]`.
   No newline is accepted inside the expression. Missing/extra/split equals,
   missing or unknown RHS, malformed quotes or adjacent identifier/assignment
   suffixes do not qualify. This is not a general JavaScript parser or blanket
   equality exemption. In particular `KEY==value` remains rejected: in a shell
   that is still an assignment whose value begins with `=`.

The predicate must not return harmless merely because one permitted occurrence
was found, skip a whole matching file/line, rewrite content before hashing, or
stop scanning later occurrences. Private-key headers and canaries still reject
even alongside valid examples. All files retain the existing content/inode/record
bounds, complete-read requirement and numeric-inode query boundary. Keep analysis
bounded and linear over already bounded bytes; no subprocess, language runtime,
path-aware parser or unbounded regex-result allocation is needed.

## Behavioral RED and later verification

`TestMinimalNativeContentHarmlessSyntax` feeds an actual canonical test archive
through the existing numeric-inode transcript into the real `inspect` function.
It replaces a dependency file and independently recomputes the fixture's Pi-tree
pin from the test's known entry map; it never takes pins from inspector output.
Every scenario asserts that the actual content read occurs exactly once. The
unrelated-name dependency fixture prevents a package/path exemption from passing.
Passing requires the complete executable and installed-tree measurement, not
merely a scanner return value.

`TestMinimalNativeContentRejectsAssignmentsAndLookalikes` uses the same real
inspector boundary and recomputed pins for synthetic assignments, empty/malformed
values, placeholder/equality lookalikes, mixed occurrences, private-key headers
and canaries. No actual secret is used or logged. Failure must return the existing
sanitized error and zero measurement. The independent baseline, deliberately
wrong tree pin and wrong executable pin execute in separate controls.

`TestMinimalNativeContentRealExt4`, explicitly tagged
`microvm_assets_integration`, uses local e2fsprogs 1.47.4, ordinary private files
and a 30-second per-case context. It constructs small real ext4 images with a
baseline, both harmless forms and two mixed negative canaries. Rejection must
occur at actual ext4 inspection and leave no published output. Missing tools are
a failure, not a skipped acceptance. No guest file is executed and no mount,
container, network or privileged operation is required.

Focused commands (pinned Go, task-owned temporary/cache directories):

```sh
go test -p 2 -race -count=1 ./internal/sandboxruntime/microvm/assets/minimalprofile -run '^TestMinimalNativeContent'
go test -p 2 -race -count=1 -tags=microvm_assets_integration ./internal/sandboxruntime/microvm/assets/minimalprofile -run '^TestMinimalNativeContentRealExt4$'
go test -p 2 ./internal/sandboxruntime/microvm/assets/minimalprofile -run '^TestMinimalDefault(TestsDoNotUseImageTools|ToolGuardRejectsSeededCalls)$'
```

Freeze compiling RED and actual failing/control results before GREEN review.
At RED the existing marker regex rejects harmless examples at the content gate;
their later successful-measurement assertions are necessarily unreached. The
negative and independent baseline controls execute independently. After approved
GREEN, rerun these exact assertions plus adjacent default/tagged race, vet and
source guards. Existing metadata, source/provenance and publication gates remain.

The initial focused race reproduction has 12 intended failing leaves (13 events
including the parent), 70 passing test/subtest events and no skips or race report.
The real-ext4 reproduction has two intended failing leaves (three events including
the parent), three passing controls and no skips or race report. Both benign cases
reach `ext4 inspection`; the independent baseline publishes a measured fixture,
and both unsafe-content controls leave their destinations absent. Tagged package
vet passes. These are deliberately failing RED gates, not a passing feature.

No full retained-tar transformation/probe, native rebuild, B1 issuance or receipt
recovery is authorized here. A future explicitly diagnostic copy may reveal other
image mismatches, but cannot replace two fresh builds of the same reviewed final
source or count as native source/build acceptance.
