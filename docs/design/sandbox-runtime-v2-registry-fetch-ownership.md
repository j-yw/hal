# Registry fetch ownership hardening

## Scope and authority

Review of the selected template provider at `56b6e490` exposed two inherited registry
prerequisites: last-owner cancellation returned before borrowed fetch cleanup
finished, and a background layer callback panic escaped synchronous provider
recovery. Neither problem was introduced by that provider change.

This slice owns only registry fetch-group lifetime, focused fake-only tests, and
this note. It does not activate the provider, alter template trust or digest
validation, add a cache/mode, modify host or guest lifecycle, or claim live L9,
credential, strict, image, or prepared-Linux acceptance.

## Selected behavior

Each coalesced fetch generation retains its own completion channel and live
owner count. Canceling a nonlast owner returns promptly; remaining owners still
own the callback. Canceling the last live owner cancels and removes that exact
generation under the group mutex, then waits for that generation's completion
outside all group locks before returning its original cancellation/deadline
classification. Replacement generations and unrelated keys can progress while
the old callback completes its cleanup. Stale release/completion must not remove
or cancel a replacement generation.

This explicitly strengthens last-owner cancellation from cancel delivery to
joined callback completion. Borrowed HTTP/cache/auth callbacks must respond to
cancellation and finish their own cleanup. The resolver cannot forcibly interrupt
arbitrary callbacks or syscalls, and no provider-wide wait is introduced.

The background fetch callback has a narrow panic boundary. Its ordinary stack
cleanup unwinds before completion is signaled. A panic produces no bytes and
only the fixed `registry_unavailable` error, without retaining the recovered
value as an error cause. Every waiting owner is released; subsequent requests
can acquire a new generation. Unix and Windows use equivalent behavior, without
changing Windows file-cache fail-closed semantics. Public APIs, durable schemas,
and machine contracts are unchanged.

## RED checkpoint and verification

Before production edits, real `Resolver.ResolveOCIArtifact` tests use injected
HTTPDoers to acquire and verify synthetic manifests and exercise real layer
coalescing. Cancellation/deadline tests hold a context-responsive callback's
cleanup tail and require Resolve to remain pending until that tail joins.
Another generation must progress while cleanup is held. Layer Do/Read/Close
panic tests run in isolated copies of the test binary, requiring a sanitized
returned failure, no leaked panic payload, completed cleanup, and later retry.
They do not use real HTTP, services, credentials, native images, or privileges.

Existing coalescing, nonlast prompt cancellation, all-owner cancellation, and
stale-release assertions remain unchanged. Freeze the compiling RED version for
independent reproduction before GREEN. Then run whole affected acquisition
packages, focused repeated race tests, unchanged L9 guards, vet, and Windows and
Darwin cross-compilation. Compilation is not runtime or live-security evidence.

## Implemented checkpoint

The design and compiling behavior RED at `0da2313b` were independently reproduced
before GREEN: twelve control passes, twenty-one expected failures, no skips in
three race repetitions. The original 282-line RED remains unchanged.

The two existing platform fetch-group implementations now join only the canceled
last owner's retained call outside the mutex. A deferred callback panic boundary
discards the recovered value, returns nil bytes with `registry_unavailable`, and
retires failed exact generations before signaling completion. A further real
resolver control holds the replacement live across old completion, then proves
a third caller coalesces with that replacement rather than refetching it.

Whole template default tests, affected acquisition/selection race tests repeated
three times, unchanged L9 command/runtime guards, and template vet pass without
failures or skips. Unix and Windows fetch-group sections are byte-identical;
Windows/amd64 and Darwin/arm64 registry test compilation pass. These are component
checks, not full-repository, live registry, native sandbox, or Windows runtime
acceptance. Callback cancellation responsiveness remains a trusted prerequisite.
