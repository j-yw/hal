# Worker JSON slash escape verification

The worker JSON preflight must preserve literal backslashes immediately before
slashes in command arguments, map keys/values, and response text. The factory
recovery script's JSON-escaping `sed` expression exposed a transport rejection:
global replacement of `\/` also consumed the second byte of an escaped
backslash, leaving a string that `strconv.Unquote` rejected before dispatch.

The narrow correction walks escape pairs and normalizes only genuine JSON slash
escapes before the existing unquoting step. It does not replace the JSON decoder
or change size/depth limits, unknown-field rejection, canonical typed-key rules,
case-fold duplicate checks, credential proof flags, or state validation.
Previously rejected malformed escapes and surrogate escape sequences remain
rejected. No execution policy, credential handling, command construction, or
runtime driver implementation changes here.

Pure regressions cover backslash runs of length zero through eight with both
literal and escaped slashes, Unicode/quotes/newlines, and the exact recovery
`json_escape` line. Request and response decoding must preserve values exactly.
Private V2 state decoding uses deliberately invalid slash-bearing request keys
to exercise the same parser, then verifies that state validation still rejects
them; successful decoding is not authority to load or execute that state.

Checks (new regressions are pure; the full worker suite also covers local Unix
transport with fake drivers, without external CLIs or live runtimes):

```sh
go test -p 2 ./internal/sandboxworker -run '^TestWorkerJSONSlashEscapes' -count=1
go test -p 2 -race ./internal/sandboxworker -run '^TestWorkerJSONSlashEscapes' -count=10
go test -p 2 ./internal/sandboxworker
go test -p 2 -race ./internal/sandboxworker
go vet ./internal/sandboxworker
```

The command-owned full recovery-script worker round trip and real runtime
checks are separate integration gates. This pure slice does not claim that
factory finalization or end-to-end execution has completed.
