# L8 D7 JobCredential proof mint after helper success; HL8E remains unissued

This slice binds default-off Firecracker host JobCredential active and cleanup
proof minting to admitted helper-success identities. HL8E remains unissued.
This slice does not change live D7 stub fatals. It does not claim D7 live,
does not claim L8 complete, does not claim L10, and does not claim L11. D7
prepared-Linux acceptance remains unaccepted. Live D7 remains unaccepted.

Guest `credentialclient` maps helper prepare/renew/revoke success onto v2
control success and installs the helper-response ledger. It does not mint
`sandboxruntime` JobCredential proofs and must not import `firecrackerhost`.
Minting belongs on the host `L8JobCredentialRuntime` that already owns
`sandboxruntime.NewJobCredentialActiveProof` and
`NewJobCredentialCleanupProof`.

## Real operations

After honest guest helper success already admitted by the host guest session:

- Prepare mints `NewJobCredentialActiveProof` with the helper
  `ActiveProofID`, the preflight `JobCredentialIdentity`, revision `1`, and
  the issued/expiry times already computed for that prepare.
- Renew mints a replacement active proof with the helper replacement proof
  ID and revision `n+1`.
- Revoke mints `NewJobCredentialCleanupProof` with the helper cleanup proof
  ID after guest revoke, resource absence, and close succeed.

Missing helper-success proof IDs stay fail-closed as `dependency_unaccepted`.
Identity mismatch stays `ErrJobCredentialIdentityMismatch`. Revision `0` stays
`ErrJobCredentialRevisionStale`. Constructors and validators re-check the
admitted identity and revision before the proof is retained. Errors,
`String`/`GoString`/`Format`, and JSON/text encodings never include live
secret bodies.

Preflight abort before transfer and `RecoverJobCredentials` store-metadata
cleanup remain the prior host-absence paths. They do not consume helper
cleanup IDs and do not make D7 live accepted.

Default command paths stay unwired. There is no sandboxd, `hal run`,
`hal auto`, or factory JobCredential proof-mint wiring.
`NewProductionL8JobCredentialRuntime` stays explicit injection only.

## Focused fake-only commands

```
go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'JobCredentialRuntime|ProofMint|RecoverMints|RecoverFailsClosed' -count=1
go test ./internal/sandboxruntime/microvm/guestagent/server/credentialclient -run '^TestL8D7GuestHelper' -count=1
go test ./cmd -run '^TestL8D7JobCredentialProofMint' -count=1
go vet ./internal/sandboxruntime/microvm/firecrackerhost ./internal/sandboxruntime/microvm/guestagent/server/credentialclient ./cmd
```

These commands are fake-only. They do not boot a VM, call billed APIs, or
select live tags.

## Broad verification

```
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint` is reported only when `command -v golangci-lint` succeeds.

## Non-goals

This slice does not:

- accept D7 prepared-Linux live proof;
- treat live D7 as an accepted proof;
- issue HL8E or enable `generateEvidence` success;
- generate `verified-pinned-callsites.hl8e` from a fixture;
- mint JobCredential proofs inside guest `credentialclient`;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- claim L8, L10, or L11 complete;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- treat L5 images as L8 proof / L5-as-L8;
- change live D7 stub fatals.
