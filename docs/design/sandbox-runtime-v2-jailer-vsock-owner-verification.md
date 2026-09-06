# Jailer-derived vsock owner correlation

This slice consumes the existing lifecycle manager's strict runtime UID and
captured state-directory identity. Neither a readiness request nor public bridge
options can supply an expected UID. A private owner value carries the exact
parent device/inode/UID and process lifetime through activation, transport,
session currentness, and the existing v2 control connector. Legacy processes
retain caller-EUID ownership semantics.

Linux observes the socket relative to a nofollow-opened parent, rechecks the
parent pathname, and requires exact parent identity, directory mode 0700, socket
mode 0600, and matching UID. Each connection also checks the tracked PID and,
for strict processes, UID via peer credentials. Changed or absent authority,
socket replacement, process exit, and cancellation cannot publish readiness.
Private per-instance observation callbacks permit deterministic tests with fake
UID observations and ordinary local Unix sockets; they are not public options.
The default observer remains authoritative and the strict peer check requires
both PID and UID. An incomplete strict launch record yields an invalid non-nil
owner, never a legacy fallback; ordinary process-liveness inspection remains
separate. Admitted strict handshakes join a process-exit watcher and close their
connection on revocation. Publication rechecks cancellation and authority; an
exit or cancellation after the final check can still race publication, and
process exit then invalidates the session through the existing generation owner.

Default tests do not chown, change identity, start Jailer, or use KVM. They prove
owner correlation, not dedicated-UID allocation, boot, cgroups, network policy,
credential activation, daemon restart recovery, or post-drop containment.
Strict admission and prepared-host failure gates remain unchanged.

Verification commands (Go 1.25.7, `GOMAXPROCS=3`):

```sh
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestJailerVsockOwner'
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^(TestL5.*Vsock|TestL7ProductionVsock|TestL8D6V2Control|TestStrictJailerLifecycle)'
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost
go vet ./internal/sandboxruntime/microvm/firecrackerhost
GOOS=darwin GOARCH=arm64 go test -p 2 -c -o /dev/null ./internal/sandboxruntime/microvm/firecrackerhost
```

Cross-compilation for Darwin is a compile gate only, not execution evidence.
