# Rootless factory post-run verification

The worker-backed rootless factory path uses the image-provided `hal` for
post-run verification and the existing optional sandbox publish helper, just as
its auto execution does. A non-login shell preserves the image's PATH. The
legacy SSH/default helpers retain `$HOME/.local/bin/hal` and their login shell.
Command arguments, secret delivery, verification JSON, and publication policy
remain unchanged; this change neither publishes anything nor adds authority.

Recovery generation retains the existing script and exact durable runtime
identity. A missing execution result, nonzero exit, or driver error cannot emit
the successful generation event. Generation remains best effort: script success
does not prove every optional artifact exists. Collection continues through the
existing worker runtime copier and workspace projection; absent optional
recovery files remain warning-only records without stored payloads.

The observed pre-dispatch recovery failure is a separate worker JSON decoder
bug: globally rewriting escaped slashes corrupts literal backslash/slash pairs
in the script's `sed` expression. The actual-script wire regression below
requires the independently reviewed escape-aware decoder fix. Do not change the
script, relax request validation, or replace runtime identity to hide that bug.

Default tests use fakes and no external CLI:

```sh
go test -p 2 ./cmd -run '^(TestFactoryFinalization|TestRunFactorySandboxRemoteVerification|TestPublishFactoryRunWithSandboxRunner)'
go test -p 2 -race ./cmd -run '^TestFactoryFinalization'
```

Explicit local fixture gates (no container, credentials, or remote network):

```sh
go test -p 2 -tags=integration ./cmd -run '^TestFactoryFinalizationRecovery(ScriptParses|RealGit)$'
go test -p 2 -tags=worker_integration -race ./cmd -run '^TestFactoryFinalizationRecoveryWorkerRoundTrip$'
```

The first gate requires Linux, Git, and a POSIX shell and generates/verifies a
real recovery bundle plus committed/dirty patches in a temporary repository.
Unavailable tools fail that gate. The second uses a private Unix socket and the
actual worker client/strict decoder with a byte-recording fake handler; it does
not execute the transmitted command. It checks exact script bytes and runtime
identity across the wire.

Broad gates are `go test -p 2 ./cmd ./internal/factory ./internal/sandboxexec
./internal/sandboxworkspace ./internal/sandboxworker` and `go vet` over those
same packages. These tests do not establish live factory acceptance, publication,
VM readiness, or strict sandbox enforcement. Factory recover JSON exit status
and host dirty-worktree preflight are separately tracked, outside this slice.
