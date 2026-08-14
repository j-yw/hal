package cmd

import (
	stdcontext "context"
	"encoding/json"
	"go/ast"
	"go/build"
	"go/constant"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestL8D2HelperServiceReadinessDocsAreNormative(t *testing.T) {
	seam := readL8D2ReadinessFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	architecture := readL8D2ReadinessFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-production-credential-delivery-architecture.md"))

	for _, required := range []string{
		"type HelperExecPrivateObservation struct",
		"type HelperExecStreamObservation struct",
		"func NewHelperExecPrivateObservation(",
		"func NewHelperExecStreamObservation(",
		"ProposeObservedPrivate(",
		"ProposeObservedStdin(",
		"view credentialmemory.BorrowedView",
		"helperExecConfiguredDependencyNil(any) bool",
		"plain nil context returns `ErrHelperExecTransactionStream`",
		"typed-nil context returns the same stream error",
		"opaque, copy-safe, one-use safe-metadata handle",
		"helperExecProposalSourceLegacy   helperExecProposalSource = 1",
		"helperExecProposalSourceObserved helperExecProposalSource = 2",
		"candidateStdinEOF       bool",
		"observedReady           bool",
		"func cloneHelperExecSHA256(*helperExecSHA256) *helperExecSHA256",
		"func newHelperExecObservedStdinSink(",
		"configured Service sequencing and the Core return matrix own that assurance",
		"No second FSM, transcript implementation, payload slot, or",
		"nil or typed-nil view before",
		"No transaction mutex is held across",
		"sole atomic installation point",
		"current hashes and counters remain byte-for-byte",
		"calls must join before `WriteTo` returns",
		"not claimed to be retroactively detectable",
		"narrow recovery boundary",
		"raw error and",
		"fully wipes the superseded current stdin and transcript",
		"nils the proposal pointers without wiping the transferred",
		"does not itself claim that Core ran",
		"same outer `ReceivedBodyCapability.Borrow` callback",
		"Every observation scalar, revision, and digest is rebound",
		"The unique EOF hashes",
		"forbidden from decoding or constructing a",
		"type ReceivedExecPrivate struct",
		"observation credentialprotocol.HelperExecPrivateObservation",
		"observation credentialprotocol.HelperExecStreamObservation",
		"func ComputeCanonicalHelperBootstrapSHA256(",
		"func cloneHelperExecSHA256(",
		"func newHelperExecObservedStdinSink(",
		"ErrHelperBootstrapCanonicalDigest",
		"l8composition.ComputeHelperBootstrapSHA256` remains public and byte-compatible",
		"bootstrapSHA256     [32]byte",
		"no caller-supplied digest argument is added",
		"claimed       bool",
		"A losing concurrent claim",
		"`ReceiveRequest`, body, and right unconsumed",
		"full-capacity wipes the claimed plan",
		"destroys it exactly once on every dispatch path",
		"type ReceivedPrepareBegin struct",
		"transaction *credentialprotocol.HelperPrepareTransaction",
		"transactionSeed credentialprotocol.HelperExecTransactionSeed",
		"`PrivateBindingLength`, `PrivateBindingSHA256`, `Plan`",
		"first rejects a plain nil context with",
		"`ErrContractInvalidArgument` or a typed-nil context with",
		"`context`, `internal/credentialmemory`, and `reflect`",
		"reflect.TypeOf",
		"TypeSpec.TypeParams",
		"call elsewhere cannot satisfy the guard",
		"The guard binds every helper operand",
		"type Service struct",
		"extensions []extensionEntry",
		"state      *serviceState",
		"serveCalled bool",
		"configured-dependency storage",
		"snapshotServiceExtensionEntries",
		"credentialprotocol.CloneExtensionDescriptor",
		"execution CoreExecution",
		"fresh empty `&serviceState{}` literal",
		"returns that exact classification error",
		"receiver/state-alias reset or replacement",
		"privately takes each exec-private or exec-stream arm",
		"exact handler context",
		"cannot be reassigned or shadowed",
		"direct lexical statements",
		"canonical rejection condition",
		"as the entire",
		"discarded Commit result or omitted/non-direct Wipe",
		"a disconnected helper or marker cannot",
		"outer `Borrow` is one direct reachable call",
		"Each static callback",
		"contains exactly one matching Propose call",
		"Package-level `ValueSpec` variables are retention roots",
		"later assignment to a package function",
		"type serviceExecDispatch struct",
		"Every reachable private Service handler",
		"Counts include every executable nested closure",
		"unique top-level exact `func TestX(t *testing.T)` AST declaration",
		"one combined topology",
		"exact Service `state.mu` is held",
		"general state-field or helper exemption",
		"literal untyped `nil` third argument",
		"immediate recovery owned by the enclosing handler",
		"control-flow-complete critical section",
		"assigned exactly once under `state.mu`",
		"exact typed `ReceivedExec` arm carried by that dispatch",
		"exact outer recovery is installed before",
		"private `corePlan.destroy()` call",
		"zero result with nil error",
		"body `Destroy(ctx)` result is bound and checked",
		"Every lock-acquired path unlocks",
		"Assignment to a global or another owner",
		"includes helpers, method values, aliases",
		"ordinary calls in both",
		"Constant-time acceptance is bound through issuance",
	} {
		if !strings.Contains(seam, required) {
			t.Errorf("L8 D2 extension seam omits readiness contract %q", required)
		}
	}
	for _, required := range []string{
		"D2 Service-readiness payload closure",
		"observation proves canonical metadata/digest",
		"ProposeObservedStdin(context.Context",
		"no transaction lock",
		"current hashes and counters remain unchanged",
		"synchronous scoped TCB values",
		"same outer body-borrow callback",
		"Every observation field is rebound",
		"Proposal source is explicit and private",
		"fully wipes the superseded current stdin/transcript hash owners",
		"After observation consumption",
		"D2 Service-readiness bootstrap closure",
		"ComputeCanonicalHelperBootstrapSHA256(header",
		"ReceivedBootstrap.bootstrapSHA256",
		"destroys the claimed plan exactly once on every dispatch path",
		"Implementation merge ordering is satisfied",
		"transport-context correction is already present",
		"AST guards bind the constant-time requirement",
		"Each call's operands are exact too",
		"TypeSpec.TypeParams",
		"private Service topology is also closed",
		"never-reset",
		"fresh empty `&serviceState{}`",
		"returns that exact classification error",
		"receiver alias, or a state alias",
		"production AST requirements",
		"privately takes the matching received arm",
		"background-context substitution",
		"Reassignment or shadowing",
		"direct callback statements",
		"no-result Wipe as the statement immediately",
		"entire branch condition",
		"concrete Borrow-callback orders",
		"The outer Borrow is one",
		"direct reachable call",
		"exact transaction correlation and exact",
		"Across each callback there is exactly one",
		"package-level `ValueSpec` variable as a retention root",
		"Later package-variable assignment",
		"serviceExecDispatch",
		"Handler reachability from `Serve` follows only actual returned",
		"The total includes executable nested/IIFE closures",
		"top-level exact `func TestX(t *testing.T)` AST declaration",
		"one combined construction, one-shot",
		"sole state-copy allowance",
		"literal untyped `nil` view",
		"immediately enclosing handler recovery",
		"control-flow-complete critical section",
		"sole state execution install",
		"exact typed `ReceivedExec` arm carried by that dispatch",
		"The outer recovery is installed before",
		"private `corePlan.destroy()` call",
		"zero result/nil error is forbidden",
		"Body `Destroy(ctx)`",
		"is bound and checked",
		"Every path which acquired the lock unlocks",
		"global/other-owner assignment",
		"including through helpers, method",
		"includes ordinary call dataflow",
		"constant-time gate also dominates the exact issued authority",
	} {
		if !strings.Contains(architecture, required) {
			t.Errorf("L8 D2 architecture omits readiness contract %q", required)
		}
	}
}

func TestL8D2HelperServiceReadinessProductGuard(t *testing.T) {
	protocolDir := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "credentialprotocol")
	helperDir := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "credentialhelper")
	compositionDir := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "l8composition")

	protocolProduction := readL8D2ReadinessGoFiles(t, protocolDir, false)
	helperProduction := readL8D2ReadinessGoFiles(t, helperDir, false)
	compositionProduction := readL8D2ReadinessGoFiles(t, compositionDir, false)
	execImportGuard := readL8D2ReadinessFile(t, filepath.Join(protocolDir, "helper_exec_transaction_state_import_boundary_test.go"))
	for _, path := range []string{
		filepath.Join(protocolDir, "helper_exec_transaction_observation.go"),
		filepath.Join(protocolDir, "helper_bootstrap_digest.go"),
	} {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			t.Errorf("missing exact readiness production file %s", filepath.Base(path))
		}
	}

	for _, required := range []string{
		"type HelperExecPrivateObservation struct",
		"type HelperExecStreamObservation struct",
		"func NewHelperExecPrivateObservation(",
		"func NewHelperExecStreamObservation(",
		") ProposeObservedPrivate(",
		") ProposeObservedStdin(",
		"helperExecConfiguredDependencyNil",
		"type helperExecProposalSource uint8",
		"helperExecProposalSourceLegacy",
		"helperExecProposalSourceObserved",
		"observedReady",
		"func ComputeCanonicalHelperBootstrapSHA256(",
		"ErrHelperBootstrapCanonicalDigest",
		"subtle.ConstantTimeCompare",
	} {
		if !strings.Contains(protocolProduction, required) {
			t.Errorf("credentialprotocol production omits readiness marker %q", required)
		}
	}

	assertL8D2ReadinessStructFields(t, protocolDir, "HelperExecPrivateObservation", []string{"owner"})
	assertL8D2ReadinessStructFields(t, protocolDir, "helperExecPrivateObservationOwner", []string{"mu", "revision", "privateLength", "privateSHA256", "used"})
	assertL8D2ReadinessStructFields(t, protocolDir, "HelperExecStreamObservation", []string{"owner"})
	assertL8D2ReadinessStructFields(t, protocolDir, "helperExecStreamObservationOwner", []string{"mu", "revision", "streamKind", "flags", "offset", "payloadLength", "payloadSHA256", "used"})
	assertL8D2ReadinessStructFieldTypes(t, protocolDir, "HelperExecPrivateObservation", map[string]string{"owner": "*helperExecPrivateObservationOwner"})
	assertL8D2ReadinessStructFieldTypes(t, protocolDir, "helperExecPrivateObservationOwner", map[string]string{"mu": "sync.Mutex", "revision": "uint64", "privateLength": "uint32", "privateSHA256": "[32]byte", "used": "bool"})
	assertL8D2ReadinessStructFieldTypes(t, protocolDir, "HelperExecStreamObservation", map[string]string{"owner": "*helperExecStreamObservationOwner"})
	assertL8D2ReadinessStructFieldTypes(t, protocolDir, "helperExecStreamObservationOwner", map[string]string{"mu": "sync.Mutex", "revision": "uint64", "streamKind": "HelperExecStreamKind", "flags": "HelperExecStreamFlags", "offset": "uint64", "payloadLength": "uint32", "payloadSHA256": "[32]byte", "used": "bool"})
	assertL8D2ReadinessStructFields(t, protocolDir, "helperExecPayloadProposalOwner", []string{"transaction", "source", "kind", "flags", "offset", "length", "sha256", "slot", "candidateStdinHash", "candidateTranscriptHash", "candidateStdinOffset", "candidateStdinBytes", "candidateStdinRecords", "candidateStdinEOF", "observedReady", "hashed", "copied", "committed", "wiped"})
	assertL8D2ReadinessStructFieldTypes(t, protocolDir, "helperExecPayloadProposalOwner", map[string]string{
		"transaction": "*helperExecTransactionOwner", "source": "helperExecProposalSource", "kind": "helperExecProposalKind", "flags": "HelperExecStreamFlags",
		"offset": "uint64", "length": "uint32", "sha256": "[32]byte", "slot": "[]byte",
		"candidateStdinHash": "*helperExecSHA256", "candidateTranscriptHash": "*helperExecSHA256", "candidateStdinOffset": "uint64",
		"candidateStdinBytes": "uint64", "candidateStdinRecords": "uint32", "candidateStdinEOF": "bool", "observedReady": "bool",
		"hashed": "bool", "copied": "bool", "committed": "bool", "wiped": "bool",
	})
	assertL8D2ReadinessTypedConstValues(t, protocolDir, "helperExecProposalSource", map[string]string{
		"helperExecProposalSourceLegacy": "1", "helperExecProposalSourceObserved": "2",
	})
	assertL8D2ReadinessStructFields(t, helperDir, "ReceivedBootstrap", []string{"liveValue", "agentIdentitySHA256", "bootGeneration", "helperGeneration", "bootstrapSHA256"})
	assertL8D2ReadinessStructFields(t, helperDir, "ReceivedPrepareBegin", []string{"liveValue", "revision", "expiryUnixNano", "manifest", "transaction"})
	assertL8D2ReadinessStructFields(t, helperDir, "ReceivedExec", []string{"liveValue", "revision", "execBindingID", "privateLength", "privateSHA256", "plan", "transactionSeed"})
	assertL8D2ReadinessStructFieldTypes(t, helperDir, "ReceivedPrepareBegin", map[string]string{"liveValue": "liveValue", "revision": "uint64", "expiryUnixNano": "int64", "manifest": "ManifestCapability", "transaction": "*credentialprotocol.HelperPrepareTransaction"})
	assertL8D2ReadinessStructFieldTypes(t, helperDir, "ReceivedBootstrap", map[string]string{"liveValue": "liveValue", "agentIdentitySHA256": "[32]byte", "bootGeneration": "credentialprotocol.SafeID", "helperGeneration": "credentialprotocol.SafeID", "bootstrapSHA256": "[32]byte"})
	assertL8D2ReadinessStructFieldTypes(t, helperDir, "ReceivedExec", map[string]string{"liveValue": "liveValue", "revision": "uint64", "execBindingID": "credentialprotocol.SafeID", "privateLength": "uint32", "privateSHA256": "[32]byte", "plan": "ExecPlanCapability", "transactionSeed": "credentialprotocol.HelperExecTransactionSeed"})
	assertL8D2ReadinessStructFields(t, helperDir, "ReceivedExecPrivate", []string{"liveValue", "revision", "privateBindingLength", "privateBindingSHA256", "observation"})
	assertL8D2ReadinessStructFields(t, helperDir, "ReceivedExecStream", []string{"liveValue", "revision", "streamKind", "flags", "offset", "payloadLength", "payloadSHA256", "observation"})
	assertL8D2ReadinessStructFieldTypes(t, helperDir, "ReceivedExecPrivate", map[string]string{"liveValue": "liveValue", "revision": "uint64", "privateBindingLength": "uint32", "privateBindingSHA256": "[32]byte", "observation": "credentialprotocol.HelperExecPrivateObservation"})
	assertL8D2ReadinessStructFieldTypes(t, helperDir, "ReceivedExecStream", map[string]string{"liveValue": "liveValue", "revision": "uint64", "streamKind": "credentialprotocol.HelperExecStreamKind", "flags": "credentialprotocol.HelperExecStreamFlags", "offset": "uint64", "payloadLength": "uint32", "payloadSHA256": "[32]byte", "observation": "credentialprotocol.HelperExecStreamObservation"})
	assertL8D2ReadinessStructFields(t, helperDir, "execPlanCapabilityState", []string{"mu", "encodedLength", "sha256", "canonical", "claimed", "destroyed"})
	assertL8D2ReadinessStructFieldTypes(t, helperDir, "execPlanCapabilityState", map[string]string{"mu": "sync.Mutex", "encodedLength": "uint32", "sha256": "[32]byte", "canonical": "[credentialprotocol.MaxHelperExecPlanBytes]byte", "claimed": "bool", "destroyed": "bool"})
	assertL8D2ReadinessTypedConstValues(t, helperDir, "ContractErrorCode", map[string]string{
		"ContractInvalidArgument": "1", "ContractTypedNil": "2", "ContractCorrelation": "3", "ContractTransition": "4", "ContractCapability": "5",
		"ContractOwnership": "6", "ContractResultMatrix": "7", "ContractDependency": "8", "ContractDestroyed": "9",
	})
	assertL8D2ReadinessErrorCatalog(t, protocolDir, map[string]string{
		"ErrHelperExecPrivateObservation":       `errors.New("credential protocol helper exec private observation is invalid")`,
		"ErrHelperExecPrivateObservationUsed":   `errors.New("credential protocol helper exec private observation is already used")`,
		"ErrHelperExecStreamObservation":        `errors.New("credential protocol helper exec stream observation is invalid")`,
		"ErrHelperExecStreamObservationUsed":    `errors.New("credential protocol helper exec stream observation is already used")`,
		"ErrHelperExecObservationSerialization": `errors.New("credential protocol helper exec observation serialization is denied")`,
	})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "", "NewHelperExecPrivateObservation", []string{"uint64", "uint32", "[32]byte", "[32]byte"}, []string{"HelperExecPrivateObservation", "error"})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "", "NewHelperExecStreamObservation", []string{"uint64", "HelperExecStreamKind", "HelperExecStreamFlags", "uint64", "uint32", "[32]byte", "[32]byte"}, []string{"HelperExecStreamObservation", "error"})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "*HelperExecTransaction", "ProposeObservedPrivate", []string{"HelperExecTransactionCorrelation", "HelperExecPrivateObservation"}, []string{"*HelperExecPayloadProposal", "error"})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "*HelperExecTransaction", "ProposeObservedStdin", []string{"context.Context", "HelperExecTransactionCorrelation", "HelperExecStreamObservation", "credentialmemory.BorrowedView"}, []string{"*HelperExecPayloadProposal", "error"})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "", "helperExecTransactionCorrelationEqual", []string{"HelperExecTransactionCorrelation", "HelperExecTransactionCorrelation"}, []string{"bool"})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "", "helperExecDigestsEqual", []string{"[32]byte", "[32]byte"}, []string{"bool"})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "", "helperExecConfiguredDependencyNil", []string{"any"}, []string{"bool"})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "", "cloneHelperExecSHA256", []string{"*helperExecSHA256"}, []string{"*helperExecSHA256"})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "", "newHelperExecObservedStdinSink", []string{"*helperExecSHA256", "*helperExecSHA256"}, []string{"*helperExecObservedStdinSink"})
	assertL8D2ReadinessFunctionSignature(t, protocolDir, "", "ComputeCanonicalHelperBootstrapSHA256", []string{"HelperPacketHeader", "[]byte"}, []string{"[32]byte", "error"})
	assertL8D2ReadinessFunctionSignature(t, compositionDir, "", "ComputeHelperBootstrapSHA256", []string{"credentialprotocol.HelperPacketHeader", "HelperBootstrapBody", "HelperBootstrapExpected"}, []string{"[sha256.Size]byte", "error"})
	assertL8D2ReadinessFunctionSignature(t, helperDir, "", "NewReceivedBootstrapPacket", []string{"context.Context", "ReceiveRequest", "credentialprotocol.HelperPacketHeader", "ReceivedKernelCredential", "uint32", "ReceivedBodyCapability", "uint32", "uint32", "uint32", "uint32", "credentialprotocol.SafeID", "credentialprotocol.SafeID", "ReceivedCapability"}, []string{"ReceivedPacket", "error"})
	assertL8D2ReadinessFunctionSignature(t, helperDir, "", "NewReceivedPrepareBeginPacket", []string{"context.Context", "ReceiveRequest", "credentialprotocol.HelperPacketHeader", "ReceivedKernelCredential", "uint32", "ReceivedBodyCapability", "uint32", "credentialprotocol.HelperPrepareBeginBody", "ManifestCapability"}, []string{"ReceivedPacket", "error"})
	assertL8D2ReadinessFunctionSignature(t, helperDir, "", "NewReceivedExecPacket", []string{"context.Context", "ReceiveRequest", "credentialprotocol.HelperPacketHeader", "ReceivedKernelCredential", "uint32", "ReceivedBodyCapability", "uint32", "credentialprotocol.HelperExecBody", "ExecPlanCapability"}, []string{"ReceivedPacket", "error"})
	assertL8D2ReadinessStructFields(t, helperDir, "Service", []string{"core", "transport", "policy", "extensions", "host", "runtime", "state"})
	assertL8D2ReadinessStructFieldTypes(t, helperDir, "Service", map[string]string{
		"core": "Core", "transport": "Transport", "policy": "Policy", "extensions": "[]extensionEntry",
		"host": "ExtensionHost", "runtime": "ServiceRuntime", "state": "*serviceState",
	})
	assertL8D2ReadinessStructFieldTypes(t, helperDir, "serviceState", map[string]string{"mu": "sync.Mutex", "serveCalled": "bool", "execution": "CoreExecution"})
	assertL8D2ReadinessStructFields(t, helperDir, "serviceExecDispatch", []string{"transaction", "correlation", "comparison"})
	assertL8D2ReadinessStructFieldTypes(t, helperDir, "serviceExecDispatch", map[string]string{"transaction": "*credentialprotocol.HelperExecTransaction", "correlation": "credentialprotocol.HelperExecTransactionCorrelation", "comparison": "bool"})
	assertL8D2ReadinessFunctionSignature(t, helperDir, "", "NewService", []string{"ServiceOptions"}, []string{"*Service", "error"})
	assertL8D2ReadinessFunctionSignature(t, helperDir, "", "snapshotServiceExtensionEntries", []string{"*ExtensionRegistry"}, []string{"[]extensionEntry"})
	assertL8D2ReadinessFunctionSignature(t, helperDir, "*Service", "Serve", []string{"context.Context"}, []string{"ServiceResult", "error"})
	assertL8D2ReadinessFunctionSignature(t, helperDir, "*Service", "takeExecDispatch", []string{"uint64"}, []string{"serviceExecDispatch", "error"})
	assertL8D2ReadinessExportedMethods(t, helperDir, "Service", []string{"Serve"})
	assertL8D2ReadinessExportedMethods(t, protocolDir, "HelperExecPrivateObservation", []string{"Format", "GoString", "MarshalBinary", "MarshalJSON", "MarshalText", "String", "UnmarshalBinary", "UnmarshalJSON", "UnmarshalText"})
	assertL8D2ReadinessExportedMethods(t, protocolDir, "HelperExecStreamObservation", []string{"Format", "GoString", "MarshalBinary", "MarshalJSON", "MarshalText", "String", "UnmarshalBinary", "UnmarshalJSON", "UnmarshalText"})
	for _, observationType := range []string{"HelperExecPrivateObservation", "HelperExecStreamObservation"} {
		assertL8D2ReadinessFunctionSignature(t, protocolDir, observationType, "String", nil, []string{"string"})
		assertL8D2ReadinessFunctionSignature(t, protocolDir, observationType, "GoString", nil, []string{"string"})
		assertL8D2ReadinessFunctionSignature(t, protocolDir, observationType, "Format", []string{"fmt.State", "rune"}, nil)
		for _, method := range []string{"MarshalJSON", "MarshalText", "MarshalBinary"} {
			assertL8D2ReadinessFunctionSignature(t, protocolDir, observationType, method, nil, []string{"[]byte", "error"})
		}
		for _, method := range []string{"UnmarshalJSON", "UnmarshalText", "UnmarshalBinary"} {
			assertL8D2ReadinessFunctionSignature(t, protocolDir, "*"+observationType, method, []string{"[]byte"}, []string{"error"})
		}
	}
	assertL8D2ReadinessExportedMethods(t, helperDir, "ReceivedExec", []string{"ExecBindingID", "Plan", "PrivateBindingLength", "PrivateBindingSHA256", "Revision"})
	assertL8D2ReadinessExportedMethods(t, helperDir, "ReceivedExecPrivate", []string{"PrivateBindingLength", "PrivateBindingSHA256", "Revision"})
	assertL8D2ReadinessExportedMethods(t, helperDir, "ReceivedExecStream", []string{"Flags", "Offset", "PayloadLength", "PayloadSHA256", "Revision", "StreamKind"})
	assertL8D2ReadinessExactImports(t, filepath.Join(protocolDir, "helper_bootstrap_digest.go"), []string{"crypto/sha256", "encoding/binary", "errors"})
	assertL8D2ReadinessNoRetainedScopedTypes(t, protocolDir)
	assertL8D2ReadinessNoDynamicScopedEscapes(t, helperDir)
	assertL8D2ReadinessObservationReflectBoundary(t, protocolDir)
	assertL8D2ReadinessObservationConstantTimeBoundary(t, protocolDir)
	assertL8D2ReadinessExecClaimTransferBoundary(t, filepath.Join(helperDir, "transport_receive.go"))
	assertL8D2ReadinessServiceStructuralBoundaries(t, helperDir)

	for _, required := range []string{
		"credentialprotocol.ComputeCanonicalHelperBootstrapSHA256(",
		"credentialprotocol.NewHelperExecPrivateObservation(",
		"credentialprotocol.NewHelperExecStreamObservation(",
		"credentialprotocol.NewHelperPrepareTransaction(",
		"credentialprotocol.NewHelperExecTransactionSeed(",
		"claimed",
		"type Service struct",
		"func NewService(",
		") Serve(",
	} {
		if !strings.Contains(helperProduction, required) {
			t.Errorf("credentialhelper production omits readiness marker %q", required)
		}
	}
	for _, constructor := range []string{
		"NewReceivedBootstrapPacket",
		"NewReceivedPrepareBeginPacket",
		"NewReceivedExecPacket",
	} {
		assertL8D2ReadinessLeadingContextConstructor(t, helperDir, constructor)
	}
	for _, forbidden := range []string{
		"helperExecBorrowedViewNil",
		"credentialprotocol.DecodeHelperExecPrivateBody(",
		"credentialprotocol.DecodeHelperExecStreamBody(",
		"credentialprotocol.NewHelperExecPrivateBody(",
		"credentialprotocol.NewHelperExecStreamBody(",
	} {
		if strings.Contains(helperProduction, forbidden) {
			t.Errorf("credentialhelper production contains forbidden second-owner path %q", forbidden)
		}
	}
	if !strings.Contains(compositionProduction, "credentialprotocol.ComputeCanonicalHelperBootstrapSHA256(") {
		t.Error("l8composition bootstrap compatibility wrapper does not delegate to the shared digest primitive")
	}
	for _, source := range []struct {
		name string
		text string
	}{
		{name: "credentialprotocol", text: protocolProduction},
		{name: "credentialhelper", text: helperProduction},
	} {
		if strings.Contains(source.text, "/guestagent/l8composition") {
			t.Errorf("%s imports forbidden higher-level l8composition package", source.name)
		}
	}
	for _, required := range []string{
		`"context":`,
		`"github.com/jywlabs/hal/internal/credentialmemory":`,
		`"reflect":`,
		`"net."`,
		`"syscall."`,
		`*ast.GoStmt`,
		`*ast.MapType`,
	} {
		if !strings.Contains(execImportGuard, required) {
			t.Errorf("exec transaction import/live-boundary guard omits %q", required)
		}
	}
	if strings.Contains(execImportGuard, `"context.",`) {
		t.Error("exec transaction import/live-boundary guard still rejects the approved scoped context dependency")
	}
	if strings.Contains(execImportGuard, `"reflect.",`) {
		t.Error("exec transaction import/live-boundary guard still rejects the confined observation reflect dependency")
	}

	requiredTests := []string{
		"TestComputeCanonicalHelperBootstrapSHA256ExactVectorAndMutationMatrix",
		"TestCanonicalHelperBootstrapDigestPureImportBoundary",
		"TestComputeHelperBootstrapSHA256DelegatesWithoutVectorDrift",
		"TestReceivedBootstrapStoresSharedCanonicalDigest",
		"TestHelperExecObservationsOneUseOpaqueAndConcurrent",
		"TestHelperExecObservedAdmissionNormalComparisonEOFAndFailureMatrix",
		"TestHelperExecObservedAdmissionRaceAndNoPayloadRetention",
		"TestHelperExecObservedAdmissionNoViewOrSinkRetention",
		"TestHelperExecObservedTypedNilPreTouchMatrix",
		"TestHelperExecObservedCommitWipesSupersededHashOwnersBeforeTransfer",
		"TestHelperExecObservedProposalSourceCommitMatrix",
		"TestHelperExecObservedExternalFailureAndPanicSanitization",
		"TestHelperExecObservedTransactionBindingAndPrecedence",
		"TestHelperExecConfiguredDependencyTypedNilPreTouch",
		"TestHelperExecObservedStdinCoreSequentialBorrowScope",
		"TestReceivedExecObservationsMintOnlyAfterCanonicalValidation",
		"TestReceivedExecPlanClaimOwnershipMatrix",
		"TestServiceDestroysClaimedExecPlanOnEveryDispatchPath",
		"TestServiceConstructorDependenciesSnapshotAndServeOneShot",
		"TestServiceServeContextPreconditionBeforeOneShotLatch",
		"TestServiceObservedInputsTakenOnceBeforeDispatch",
		"TestServiceObservedPrivateCoreCommitCleanupMatrix",
		"TestServiceObservedPrivateCommitRequiresValidCoreExecution",
		"TestServiceObservedStdinCoreCommitCleanupMatrix",
		"TestServiceObservedStdinCommitRequiresNilCoreError",
		"TestServiceObservedComparisonNeverCallsCore",
		"TestServiceObservedBodiesDestroyedExactlyOnce",
		"TestServiceObservedFailureAndPanicCleanupIsExhaustive",
		"TestTransactionStartConstructorsCleanOwnedStateOnDependencyPanic",
		"TestTransportTypedNilContextIsPreTransferEverywhere",
		"TestReceivedExecCleanupFailureOverridesConstructorError",
		"TestReceivedExecPublicMethodSetIsExact",
		"TestHelperExecObservedConstantTimeBindingFunctions",
		"TestHelperExecReadinessExactAPIAndOpacity",
	}
	counts, err := l8D2ReadinessExactTopLevelTests(filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent"))
	if err != nil {
		t.Fatal(err)
	}
	serviceTestRequirements := l8D2ReadinessServiceTestRequirements()
	serviceTestResults, err := l8D2ReadinessExactServiceBehavioralTests(filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent"), serviceTestRequirements)
	if err != nil {
		t.Fatal(err)
	}
	for _, requiredTest := range requiredTests {
		if counts[requiredTest] != 1 {
			t.Errorf("guestagent exact top-level test %s count = %d, want 1", requiredTest, counts[requiredTest])
			continue
		}
		if _, serviceTest := serviceTestRequirements[requiredTest]; serviceTest && !serviceTestResults[requiredTest] {
			t.Errorf("guestagent exact top-level test %s does not live-drive its exact Service boundary and assert every promised observable", requiredTest)
		}
	}
}

func TestL8D2HelperServiceReadinessRequiredTestGuardSelfTest(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		source string
		want   int
	}{
		{name: "exact", source: "package fixture\nimport \"testing\"\nfunc TestRequired(t *testing.T) {}\n", want: 1},
		{name: "comment and string", source: "package fixture\nconst marker = `func TestRequired(t *testing.T)`\n// func TestRequired(t *testing.T)\n"},
		{name: "function literal", source: "package fixture\nimport \"testing\"\nvar marker = func(t *testing.T) {}\n"},
		{name: "wrong signature", source: "package fixture\nfunc TestRequired() {}\n"},
		{name: "lookalike testing import", source: "package fixture\nimport testing \"example.invalid/testing\"\nfunc TestRequired(t *testing.T) {}\n"},
		{name: "wrong parameter name", source: "package fixture\nimport \"testing\"\nfunc TestRequired(other *testing.T) {}\n"},
		{name: "receiver method lookalike", source: "package fixture\nimport \"testing\"\ntype suite struct{}\nfunc (suite) TestRequired(t *testing.T) {}\n"},
		{name: "extra parameter", source: "package fixture\nimport \"testing\"\nfunc TestRequired(t *testing.T, extra int) {}\n"},
		{name: "duplicate exact declarations", source: "package fixture\nimport \"testing\"\nfunc TestRequired(t *testing.T) {}\nfunc TestRequired(t *testing.T) {}\n", want: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			counts := l8D2ReadinessExactTestDeclarations(map[string]*ast.File{"fixture_test.go": file})
			if counts["TestRequired"] != test.want {
				t.Fatalf("count = %d, want %d", counts["TestRequired"], test.want)
			}
		})
	}
	for _, test := range []struct {
		name, source string
		wantType     bool
	}{
		{name: "if init binding", source: `package fixture
type wrapperMap map[int64]int
func target() { if wrapperMap := map[float64]int{}; ready { marker(wrapperMap) } }`},
		{name: "for init binding", source: `package fixture
type wrapperMap map[int64]int
func target() { for wrapperMap := map[float64]int{}; ready; { marker(wrapperMap) } }`},
		{name: "range key binding", source: `package fixture
type wrapperMap map[int64]int
func target() { for wrapperMap := range values { marker(wrapperMap) } }`},
		{name: "range value binding", source: `package fixture
type wrapperMap map[int64]int
func target() { for _, wrapperMap := range values { marker(wrapperMap) } }`},
		{name: "switch init binding", source: `package fixture
type wrapperMap map[int64]int
func target() { switch wrapperMap := map[float64]int{}; ready { default: marker(wrapperMap) } }`},
		{name: "type switch binding", source: `package fixture
type wrapperMap map[int64]int
func target() { switch wrapperMap := raw.(type) { case map[float64]int: marker(wrapperMap) } }`},
		{name: "select receive bindings", source: `package fixture
type wrapperMap map[int64]int
func target() { select { case wrapperMap, ok := <-values: marker(wrapperMap); marker(ok) } }`},
		{name: "case local binding", source: `package fixture
type wrapperMap map[int64]int
func target() { switch { default: wrapperMap := map[float64]int{}; marker(wrapperMap) } }`},
		{name: "closure parameter binding", source: `package fixture
type wrapperMap map[int64]int
func target() { func(wrapperMap map[float64]int) { marker(wrapperMap) }(nil) }`},
		{name: "closure result binding", source: `package fixture
type wrapperMap map[int64]int
func target() { _ = func() (wrapperMap map[float64]int) { marker(wrapperMap); return }() }`},
		{name: "function result binding", source: `package fixture
type wrapperMap map[int64]int
func target() (wrapperMap map[float64]int) { marker(wrapperMap); return }`},
		{name: "nested type declaration reestablishes type name", wantType: true, source: `package fixture
type wrapperMap map[int64]int
func target() { if wrapperMap := map[float64]int{}; ready { _ = wrapperMap; { type wrapperMap map[string]int; marker(wrapperMap{}) } } }`},
		{name: "expired if init restores package type", wantType: true, source: `package fixture
type wrapperMap map[int64]int
func target() { if wrapperMap := map[float64]int{}; ready { _ = wrapperMap }; marker(wrapperMap{}) }`},
		{name: "sibling block binding does not hide package type", wantType: true, source: `package fixture
type wrapperMap map[int64]int
func target() { { wrapperMap := map[float64]int{}; _ = wrapperMap }; { marker(wrapperMap{}) } }`},
	} {
		t.Run("named type scope "+test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "scope_fixture.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			var function *ast.FuncDecl
			var marker token.Pos
			for _, declaration := range file.Decls {
				candidate, ok := declaration.(*ast.FuncDecl)
				if ok && candidate.Name.Name == "target" {
					function = candidate
				}
			}
			ast.Inspect(function, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				called, direct := call.Fun.(*ast.Ident)
				if ok && direct && called.Name == "marker" && marker == token.NoPos {
					marker = call.Pos()
				}
				return true
			})
			if function == nil || marker == token.NoPos {
				t.Fatal("fixture omits target marker")
			}
			environment := l8D2ReadinessTerminalEnvironment{namedTypes: l8D2ReadinessDeclaredNamedTypes(file.Decls)}
			_, got := l8D2ReadinessWrapperNamedTypes(function, marker, environment)["wrapperMap"]
			if got != test.wantType {
				t.Fatalf("package wrapperMap visible = %t, want %t", got, test.wantType)
			}
		})
	}
	t.Run("resolver does not retain stale package name across analyses", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "credentialhelper")
		dependency := filepath.Join(root, "replacement")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dependency, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/main\n\ngo 1.25\nrequire example.test/dependency v0.0.0\nreplace example.test/dependency => ./replacement\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dependency, "go.mod"), []byte("module example.test/dependency\n\ngo 1.25\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		packageFile := filepath.Join(dependency, "package.go")
		if err := os.WriteFile(packageFile, []byte("package mathx\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		source := "package fixture\nimport \"example.test/dependency\"\n"
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, "fixture.go"), source, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := l8D2ReadinessResolvedImportPackageNames(build.Default, dir, file)["example.test/dependency"]; got != "mathx" {
			t.Fatalf("initial resolved package = %q", got)
		}
		if err := os.WriteFile(packageFile, []byte("package int\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := l8D2ReadinessResolvedImportPackageNames(build.Default, dir, file)["example.test/dependency"]; got != "int" {
			t.Fatalf("resolved package after source mutation = %q, want int", got)
		}
	})
	t.Run("offline environment seals hostile module and vanity resolution controls", func(t *testing.T) {
		values := make(map[string]string)
		counts := make(map[string]int)
		for _, item := range l8D2ReadinessOfflineGoEnvironmentFrom(build.Default, []string{
			"CGO_ENABLED=1",
			"GO111MODULE=off",
			"GOARCH=hostile",
			"GOENV=/tmp/hostile-goenv",
			"GOFLAGS=-mod=mod",
			"GOWORK=/tmp/foreign.work",
			"GOPRIVATE=*.private.invalid",
			"GOPRIVATE=*.second.invalid",
			"GONOPROXY=*.direct.invalid",
			"GOINSECURE=*.insecure.invalid",
			"GONOSUMDB=*.unchecked.invalid",
			"GOOS=hostile",
			"GOPROXY=direct",
			"GOSUMDB=sum.invalid",
			"GOTOOLCHAIN=auto",
			"GOVCS=private.invalid:all",
		}) {
			name, value, _ := strings.Cut(item, "=")
			values[name] = value
			counts[name]++
		}
		for name, want := range map[string]string{
			"CGO_ENABLED": "0",
			"GO111MODULE": "on",
			"GOENV":       "off",
			"GOFLAGS":     "",
			"GOARCH":      build.Default.GOARCH,
			"GOINSECURE":  "",
			"GONOPROXY":   "none",
			"GONOSUMDB":   "none",
			"GOOS":        build.Default.GOOS,
			"GOPRIVATE":   "",
			"GOPROXY":     "off",
			"GOSUMDB":     "off",
			"GOTOOLCHAIN": "local",
			"GOVCS":       "*:off",
			"GOWORK":      "off",
		} {
			if got := values[name]; got != want {
				t.Fatalf("%s = %q, want %q", name, got, want)
			}
			if got := counts[name]; got != 1 {
				t.Fatalf("%s count = %d, want 1", name, got)
			}
		}
	})
	t.Run("module roots canonicalize symlinks and reject broken chains", func(t *testing.T) {
		realRoot := t.TempDir()
		nested := filepath.Join(realRoot, "credentialhelper", "nested")
		if err := os.MkdirAll(nested, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realRoot, "go.mod"), []byte("module example.test/main\n\ngo 1.25\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		links := t.TempDir()
		linkedRoot := filepath.Join(links, "module")
		if err := os.Symlink(realRoot, linkedRoot); err != nil {
			t.Fatal(err)
		}
		got, ok := l8D2ReadinessModuleRoot(filepath.Join(linkedRoot, "credentialhelper", "nested"))
		if !ok || got != realRoot {
			t.Fatalf("symlinked module root = %q, %t, want %q", got, ok, realRoot)
		}
		broken := filepath.Join(links, "broken")
		if err := os.Symlink(filepath.Join(links, "missing"), broken); err != nil {
			t.Fatal(err)
		}
		if got, ok := l8D2ReadinessModuleRoot(broken); ok || got != "" {
			t.Fatalf("broken module root = %q, %t", got, ok)
		}
		cycleA := filepath.Join(links, "cycle-a")
		cycleB := filepath.Join(links, "cycle-b")
		if err := os.Symlink(cycleB, cycleA); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(cycleA, cycleB); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if got, ok := l8D2ReadinessModuleRoot(cycleA); ok || got != "" {
			t.Fatalf("cyclic module root = %q, %t", got, ok)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("cyclic module root resolution took %s", elapsed)
		}
	})
	t.Run("readonly invocation and failures are not cached", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/main\n\ngo 1.25\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		goSum := filepath.Join(root, "go.sum")
		if err := os.WriteFile(goSum, []byte("sentinel\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		fakeGo := filepath.Join(root, "fake-go")
		arguments := filepath.Join(root, "arguments")
		writeScript := func(body string) {
			t.Helper()
			if err := os.WriteFile(fakeGo, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		writeScript("exit 1")
		resolver := l8D2ReadinessNewImportResolver()
		resolver.goCommand = fakeGo
		resolver.timeout = 100 * time.Millisecond
		resolver.environment = []string{"GO111MODULE=off", "GOFLAGS=-mod=mod"}
		if name, ok := resolver.goListPackageName(build.Default, root, "example.test/dependency"); ok || name != "" {
			t.Fatalf("failed command resolved %q", name)
		}
		writeScript("printf '%s\\n' \"$*\" > " + strconv.Quote(arguments) + "\nprintf '%s\\n' '{\"ImportPath\":\"example.test/dependency\",\"Name\":\"int\",\"Dir\":\"/safe\"}'")
		if name, ok := resolver.goListPackageName(build.Default, root, "example.test/dependency"); !ok || name != "int" {
			t.Fatalf("success after failure = %q, %t", name, ok)
		}
		called, err := os.ReadFile(arguments)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(called), "-mod=readonly") || strings.Contains(string(called), "-mod=mod") {
			t.Fatalf("go list arguments = %q", called)
		}
		if content, err := os.ReadFile(filepath.Join(root, "go.mod")); err != nil || string(content) != "module example.test/main\n\ngo 1.25\n" {
			t.Fatalf("go.mod changed: %q, %v", content, err)
		}
		if content, err := os.ReadFile(goSum); err != nil || string(content) != "sentinel\n" {
			t.Fatalf("go.sum changed: %q, %v", content, err)
		}
	})
	t.Run("timeout is bounded and not negatively cached", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/main\n\ngo 1.25\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		fakeGo := filepath.Join(root, "fake-go")
		if err := os.WriteFile(fakeGo, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		resolver := l8D2ReadinessNewImportResolver()
		resolver.goCommand = fakeGo
		resolver.timeout = 10 * time.Millisecond
		started := time.Now()
		if name, ok := resolver.goListPackageName(build.Default, root, "example.test/timeout"); ok || name != "" {
			t.Fatalf("timeout resolved %q", name)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("timeout took %s", elapsed)
		}
		if err := os.WriteFile(fakeGo, []byte("#!/bin/sh\nprintf '%s\\n' '{\"ImportPath\":\"example.test/timeout\",\"Name\":\"mathx\",\"Dir\":\"/safe\"}'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		resolver.timeout = time.Second
		if name, ok := resolver.goListPackageName(build.Default, root, "example.test/timeout"); !ok || name != "mathx" {
			t.Fatalf("success after timeout = %q, %t", name, ok)
		}
	})
}

func TestL8D2HelperServiceReadinessReducerGuardSelfTest(t *testing.T) {
	t.Parallel()
	canonical := l8D2ReadinessCanonicalReducerFixture()
	for _, test := range []struct {
		name, source string
		want         bool
	}{
		{name: "canonical", source: canonical, want: true},
		{name: "package variable alias", source: strings.Replace(canonical, "func newServiceResult", "var newServiceResult = evilResult\nfunc ignoredServiceResult", 1)},
		{name: "wrong function body", source: strings.Replace(canonical, "return ServiceResult{disposition: disposition, closeReason: closeReason}, nil", "return ServiceResult{}, nil", 1)},
		{name: "duplicate declaration", source: canonical + "\nfunc newServiceResult(disposition ServiceDisposition, closeReason credentialprotocol.CloseReason) (ServiceResult, error) { return ServiceResult{}, nil }"},
		{name: "lookalike protocol import", source: strings.Replace(canonical, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol", "example.invalid/credentialprotocol", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := l8D2ReadinessExactServiceResultReducer(map[string]*ast.File{"fixture.go": file}); got != test.want {
				t.Fatalf("exact reducer = %t, want %t", got, test.want)
			}
		})
	}
}

func l8D2ReadinessCanonicalReducerFixture() string {
	return `package fixture
import credentialprotocol "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
type ServiceDisposition uint8
const ( ServiceClosed ServiceDisposition = 1; ServiceStopVMRequired ServiceDisposition = 2 )
type ServiceResult struct { disposition ServiceDisposition; closeReason credentialprotocol.CloseReason }
var ErrContractInvalidArgument, ErrContractResultMatrix error
func ValidateServiceDisposition(ServiceDisposition) error { return nil }
func newServiceResult(disposition ServiceDisposition, closeReason credentialprotocol.CloseReason) (ServiceResult, error) {
	if ValidateServiceDisposition(disposition) != nil || credentialprotocol.ValidateCloseReason(closeReason) != nil { return ServiceResult{}, ErrContractInvalidArgument }
	clean := disposition == ServiceClosed && (closeReason == credentialprotocol.CloseReasonNormal || closeReason == credentialprotocol.CloseReasonShutdown)
	stop := disposition == ServiceStopVMRequired && (closeReason == credentialprotocol.CloseReasonProtocolError || closeReason == credentialprotocol.CloseReasonIdentityDrift || closeReason == credentialprotocol.CloseReasonExpired || closeReason == credentialprotocol.CloseReasonHelperLoss)
	if !clean && !stop { return ServiceResult{}, ErrContractResultMatrix }
	return ServiceResult{disposition: disposition, closeReason: closeReason}, nil
}`
}

func TestL8D2HelperServiceReadinessBuildContextGuardSelfTest(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{name: "canonical all supported builds", want: true, files: map[string]string{"service.go": "package credentialhelper\ntype Service struct{}\n", "service_values.go": l8D2ReadinessCanonicalReducerFixture()}},
		{name: "windows only reducer does not satisfy linux", files: map[string]string{"service.go": "package credentialhelper\ntype Service struct{}\n", "service_values_windows.go": l8D2ReadinessCanonicalReducerFixture()}},
		{name: "duplicate alternate build reducer rejected", files: map[string]string{"service.go": "package credentialhelper\ntype Service struct{}\n", "service_values_linux.go": l8D2ReadinessCanonicalReducerFixture(), "service_values_windows.go": l8D2ReadinessCanonicalReducerFixture()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			files := make(map[string]*ast.File)
			for name, source := range test.files {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
				file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
				if err != nil {
					t.Fatal(err)
				}
				files[path] = file
			}
			if got := l8D2ReadinessExactServiceResultReducerAcrossBuilds(dir, files); got != test.want {
				t.Fatalf("build reducer = %t, want %t", got, test.want)
			}
		})
	}
	behavioralSource := `package credentialhelper
import "testing"
type fakeRuntime struct{ serveCalls int }
type ServiceOptions struct{ Runtime *fakeRuntime }
const expectedCalls int = 1
func TestRequired(t *testing.T) { runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; result, err := service.Serve(ctx); if err != nil || result.Disposition() != ServiceClosed || runtime.serveCalls != expectedCalls { t.Fatalf("unexpected result") } }
`
	for _, test := range []struct {
		name, testFile         string
		extraFile, extraSource string
		want                   bool
	}{
		{name: "behavioral test selected in every supported build", testFile: "service_test.go", want: true},
		{name: "windows only behavioral test does not satisfy linux", testFile: "service_windows_test.go"},
		{name: "active build package int shadow rejects", testFile: "service_test.go", extraFile: "shadow_linux.go", extraSource: "package credentialhelper\ntype int = int64\n"},
		{name: "inactive build package int shadow ignored", testFile: "service_test.go", extraFile: "shadow_aix.go", extraSource: "package credentialhelper\ntype int = int64\n", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "credentialhelper")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, source := range map[string]string{
				"service.go":        "package credentialhelper\ntype Service struct{}\n",
				"service_values.go": strings.Replace(l8D2ReadinessCanonicalReducerFixture(), "package fixture", "package credentialhelper", 1),
				test.testFile:       behavioralSource,
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test.extraFile != "" {
				if err := os.WriteFile(filepath.Join(dir, test.extraFile), []byte(test.extraSource), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			results, err := l8D2ReadinessExactServiceBehavioralTests(root, map[string]l8D2ReadinessServiceTestRequirement{
				"TestRequired": {exercise: []string{"NewService", "Serve"}, evidence: []string{"serveCalls"}, dependencyFields: map[string][]string{"serveCalls": {"Runtime"}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := results["TestRequired"]; got != test.want {
				t.Fatalf("behavioral build selection = %t, want %t", got, test.want)
			}
		})
	}
}

func TestL8D2HelperServiceReadinessBehavioralTestGuardSelfTest(t *testing.T) {
	t.Parallel()
	spec := l8D2ReadinessServiceTestRequirement{exercise: []string{"NewService", "Serve"}, evidence: []string{"serveCalls"}, dependencyFields: map[string][]string{"serveCalls": {"Runtime"}}}
	for _, test := range []struct {
		name, body string
		want       bool
	}{
		{name: "canonical", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; result, err := service.Serve(ctx); if err != nil || result.Disposition() != ServiceClosed || runtime.serveCalls != 1 { t.Fatalf("unexpected result") }`, want: true},
		{name: "canonical with supplemental table", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; result, err := service.Serve(ctx); if err != nil || result.Disposition() != ServiceClosed || runtime.serveCalls != 1 { t.Fatalf("unexpected result") }; for _, tc := range []struct{ want int }{{want: 1}} { _ = tc }`, want: true},
		{name: "empty"},
		{name: "no assertion", body: `service, _ := NewService(options); _, _ = service.Serve(ctx); _ = runtime.serveCalls`},
		{name: "skip", body: `t.Skip("disabled"); service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "skip now", body: `t.SkipNow(); service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "goexit before exercise", body: `runtime.Goexit(); service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "return before exercise", body: `return; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "comment and string only", body: "marker := `NewService Serve serveCalls t.Fatal`; _ = marker"},
		{name: "dead markers", body: `if false { service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") } }`},
		{name: "assertion before exercise only", body: `if ready { t.Fatal("bad") }; service, _ := NewService(options); _, _ = service.Serve(ctx); _ = runtime.serveCalls`},
		{name: "missing promised evidence", body: `service, _ := NewService(options); result, err := service.Serve(ctx); if err != nil || result.Disposition() != ServiceClosed { t.Fatal("bad") }`},
		{name: "same named local is not observable", body: `service, _ := NewService(options); _, _ = service.Serve(ctx); serveCalls := 1; if serveCalls != 1 { t.Fatal("bad") }`},
		{name: "shadow constructor", body: `NewService := evilConstructor; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "foreign serve receiver", body: `service, _ := NewService(options); _, _ = foreign.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }; _ = service`},
		{name: "dead assertion marker", body: `service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { if false { t.Fatal("bad") } }`},
		{name: "statically dead assertion condition", body: `service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 && false { t.Fatal("bad") }`},
		{name: "panic before exercise", body: `panic("stop"); service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "service owner rebound", body: `service, _ := NewService(options); service = foreign; _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "deferred serve", body: `service, _ := NewService(options); defer service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "goroutine serve", body: `service, _ := NewService(options); go service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "short circuit dead serve", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _ = false && observe(service.Serve(ctx)); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "helper mediated stop", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; stop(t); service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "foreign observable selector", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if foreign.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "self comparison", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != runtime.serveCalls { t.Fatal("bad") }`},
		{name: "manual observable write", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); runtime.serveCalls = 1; if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "manual observable write through preconstructor alias", body: `runtime := &fakeRuntime{}; alias := runtime; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); alias.serveCalls = 1; if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "preseeded observable", body: `runtime := &fakeRuntime{serveCalls: 1}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "typed zero initialized observable", body: `const zero int = int(0); runtime := &fakeRuntime{serveCalls: zero}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`, want: true},
		{name: "positional preseeded observable", body: `runtime := &fakeRuntime{1}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "helper initialized observable", body: `runtime := newFakeRuntime(1); options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "manual observable write through nested alias", body: `holder := struct{ runtime *fakeRuntime }{runtime: &fakeRuntime{}}; runtime := holder.runtime; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); holder.runtime.serveCalls = 1; if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "manual observable write through container before constructor", body: `runtime := &fakeRuntime{}; holders := []*fakeRuntime{runtime}; holders[0].serveCalls = 1; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "manual observable write through local range", body: `runtime := &fakeRuntime{}; holders := []*fakeRuntime{runtime}; for _, alias := range holders { alias.serveCalls = 1 }; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "range alias escapes global then mutates", body: `runtime := &fakeRuntime{}; holders := []*fakeRuntime{runtime}; for _, alias := range holders { retainedRuntime = alias }; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); retainedRuntime.serveCalls = 1; if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "observable direct global transfer", body: `runtime := &fakeRuntime{}; retainedRuntime = runtime; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "channel roundtrip mutates observable", body: `runtime := &fakeRuntime{}; channel := make(chan *fakeRuntime, 1); channel <- runtime; alias := <-channel; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); alias.serveCalls = 1; if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "observable stored into selector before constructor", body: `runtime := &fakeRuntime{}; holder := struct{ runtime *fakeRuntime }{}; holder.runtime = runtime; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "manual observable write through field pointer", body: `runtime := &fakeRuntime{}; field := &runtime.serveCalls; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); *field = 1; if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "manual observable mutation helper before constructor", body: `runtime := &fakeRuntime{}; mutate(runtime); options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "manual observable receiver mutation before constructor", body: `runtime := &fakeRuntime{}; runtime.mutate(); options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "manual observable nested pointer write before constructor", body: `runtime := &fakeRuntime{}; *(&runtime.serveCalls) = 1; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "observable owner rebound", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); runtime = foreignRuntime; _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "observable owner passed to mutator", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); mutate(runtime); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "observable owner supplied through arbitrary helper", body: `runtime := &fakeRuntime{}; options := wrapOptions(runtime); service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "testing owner reassigned", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); t = fakeT; if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "service owner passed to helper", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); retain(service); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "service method value escape", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); retained := service.Serve; _ = retained; _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "expected derived from observed", body: `runtime := &fakeRuntime{}; expected := struct{ expectedCalls int }{expectedCalls: runtime.serveCalls}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expected.expectedCalls { t.Fatal("bad") }`},
		{name: "vacuous named false conjunction", body: `const never = false; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 && never { t.Fatal("bad") }`},
		{name: "vacuous named true disjunction", body: `const always = true; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 || always { t.Fatal("bad") }`},
		{name: "observable nested under dynamic conjunction", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 && ready { t.Fatal("bad") }`},
		{name: "observable polarity inverted", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if (runtime.serveCalls != 1) == false { t.Fatal("bad") }`},
		{name: "wrong equality direction", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls == 1 { t.Fatal("bad") }`},
		{name: "observable hidden in unrelated dependency field", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Core: runtime, Runtime: foreignRuntime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "observable duplicated into unrelated dependency field", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Core: runtime, Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "observable wrapped in allowed dependency field", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: wrapRuntime(runtime)}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal("bad") }`},
		{name: "untyped named expected constant", body: `const expectedCalls = 1; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
		{name: "explicit int expected constant", body: `const expectedCalls int = 1; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`, want: true},
		{name: "typed named expected constant", body: `const expectedCalls int = int(1); runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`, want: true},
		{name: "int64 named expected constant", body: `const expectedCalls int64 = 1; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
		{name: "named integer alias expected constant", body: `type counter int; const expectedCalls counter = 1; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
		{name: "shadowed predeclared int expected type", body: `type int = int64; const expectedCalls int = 1; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
		{name: "shadowed predeclared int conversion", body: `type int = int64; const expectedCalls int = int(1); runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
		{name: "local value named int shadows expected type", body: `int := int64(1); const expectedCalls int = 1; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }; _ = int`},
		{name: "parenthesized expected initializer", body: `const expectedCalls int = (1); runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
		{name: "parenthesized expected conversion initializer", body: `const expectedCalls int = (int(1)); runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
		{name: "grouped exact int expected constant", body: `const ( expectedCalls int = 1 ); runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`, want: true},
		{name: "noninteger named expected constant", body: `const expectedCalls string = "1"; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
		{name: "derived named expected constant", body: `const base int = 1; const expectedCalls int = base; runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
		{name: "unrelated map range positive", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); for key, value := range map[string]int{"one": 1} { _, _ = key, value }; if runtime.serveCalls != 1 { t.Fatal("bad") }`, want: true},
		{name: "unrelated nested table positive", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); table := map[string][][]int{"one": {{1}}}; for key, rows := range table { _, _ = key, rows }; if runtime.serveCalls != 1 { t.Fatal("bad") }`, want: true},
		{name: "expected constant declared after exercise", body: `runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, _ := NewService(options); _, _ = service.Serve(ctx); const expectedCalls int = 1; if runtime.serveCalls != expectedCalls { t.Fatal("bad") }`},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "package fixture\nimport (\"testing\"; \"runtime\")\ntype fakeRuntime struct{ serveCalls int }; type ServiceOptions struct{ Core any; Transport any; Policy any; Extensions any; Host any; Runtime *fakeRuntime }; var retainedRuntime *fakeRuntime; func stop(t *testing.T){ t.SkipNow() }\nfunc TestRequired(t *testing.T) {" + test.body + "}\n"
			file, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := l8D2ReadinessExactServiceBehavioralTest(file, "TestRequired", spec); got != test.want {
				t.Fatalf("behavioral test = %t, want %t", got, test.want)
			}
		})
	}
	mainFile, err := parser.ParseFile(token.NewFileSet(), "service_test.go", "package fixture\nimport \"testing\"\ntype fakeRuntime struct{ serveCalls int }; type ServiceOptions struct{ Runtime *fakeRuntime }\nfunc TestRequired(t *testing.T) { runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; stop(t); service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); if runtime.serveCalls != 1 { t.Fatal(\"bad\") } }", 0)
	if err != nil {
		t.Fatal(err)
	}
	helperFile, err := parser.ParseFile(token.NewFileSet(), "stop_test.go", "package fixture\nimport \"testing\"\nfunc stop(t *testing.T) { t.SkipNow() }", 0)
	if err != nil {
		t.Fatal(err)
	}
	if l8D2ReadinessExactServiceBehavioralTestInEnvironment(mainFile, "TestRequired", spec, l8D2ReadinessTerminalEnvironmentForFiles([]*ast.File{mainFile, helperFile})) {
		t.Fatal("cross-file terminal helper satisfied live Service test")
	}
	packageConstantMain, err := parser.ParseFile(token.NewFileSet(), "package_constant_test.go", "package fixture\nimport \"testing\"\ntype fakeRuntime struct{ serveCalls int }; type ServiceOptions struct{ Runtime *fakeRuntime }\nfunc TestRequired(t *testing.T) { runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal(\"bad\") } }", 0)
	if err != nil {
		t.Fatal(err)
	}
	paddedConstant, err := parser.ParseFile(token.NewFileSet(), "expected_test.go", "package fixture\n"+strings.Repeat("// padding\n", 200)+"const expectedCalls int = 1\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !l8D2ReadinessExactServiceBehavioralTestInEnvironment(packageConstantMain, "TestRequired", spec, l8D2ReadinessTerminalEnvironmentForFiles([]*ast.File{packageConstantMain, paddedConstant})) {
		t.Fatal("padded cross-file package expected constant did not satisfy live Service test")
	}
	shadowFile, err := parser.ParseFile(token.NewFileSet(), "shadow.go", "package fixture\ntype int = int64\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	if l8D2ReadinessExactServiceBehavioralTestInEnvironment(packageConstantMain, "TestRequired", spec, l8D2ReadinessTerminalEnvironmentForFiles([]*ast.File{packageConstantMain, paddedConstant, shadowFile})) {
		t.Fatal("cross-file package int alias satisfied named expected grammar")
	}
	dotImportMain, err := parser.ParseFile(token.NewFileSet(), "dot_import_test.go", "package fixture\nimport (\"testing\"; . \"math\")\ntype fakeRuntime struct{ serveCalls int }; type ServiceOptions struct{ Runtime *fakeRuntime }\nconst expectedCalls int = 1\nfunc TestRequired(t *testing.T) { runtime := &fakeRuntime{}; _ = Abs(1); options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal(\"bad\") } }", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !l8D2ReadinessExactServiceBehavioralTest(dotImportMain, "TestRequired", spec) {
		t.Fatal("live dot import of exported names rejected canonical typed expected constant")
	}
	explicitAliasMain, err := parser.ParseFile(token.NewFileSet(), "explicit_alias_test.go", "package fixture\nimport (\"testing\"; int \"math\")\ntype fakeRuntime struct{ serveCalls int }; type ServiceOptions struct{ Runtime *fakeRuntime }\nconst expectedCalls int = 1\nfunc TestRequired(t *testing.T) { runtime := &fakeRuntime{}; _ = int.Abs(1); options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal(\"bad\") } }", 0)
	if err != nil {
		t.Fatal(err)
	}
	if l8D2ReadinessExactServiceBehavioralTest(explicitAliasMain, "TestRequired", spec) {
		t.Fatal("explicit import alias int satisfied canonical typed expected grammar")
	}
	for _, test := range []struct {
		name, importPath, packageName, packageUse string
		want                                      bool
	}{
		{name: "path ending int with mathx declaration", importPath: "../ending/int", packageName: "mathx", packageUse: "mathx.Value", want: true},
		{name: "arbitrary path declaring int", importPath: "../arbitrary/pkg", packageName: "int", packageUse: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "credentialhelper")
			packageDir := filepath.Clean(filepath.Join(dir, test.importPath))
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(packageDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(packageDir, "package.go"), []byte("package "+test.packageName+"\nconst Value = 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			use := ""
			if test.packageUse != "" {
				use = "_ = " + test.packageUse + "; "
			}
			source := "package fixture\nimport (\"testing\"; \"" + test.importPath + "\")\ntype fakeRuntime struct{ serveCalls int }; type ServiceOptions struct{ Runtime *fakeRuntime }; const expectedCalls int = 1\nfunc TestRequired(t *testing.T) { runtime := &fakeRuntime{}; " + use + "options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal(\"bad\") } }"
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, "service_test.go"), source, 0)
			if err != nil {
				t.Fatal(err)
			}
			resolvedImports := map[*ast.File]map[string]string{file: l8D2ReadinessResolvedImportPackageNames(build.Default, dir, file)}
			environment := l8D2ReadinessTerminalEnvironmentForFilesWithImports([]*ast.File{file}, resolvedImports)
			if got := l8D2ReadinessExactServiceBehavioralTestInEnvironment(file, "TestRequired", spec, environment); got != test.want {
				t.Fatalf("behavioral resolved import = %t, want %t", got, test.want)
			}
		})
	}
	for _, test := range []struct {
		name, importPath, packageName string
		replace, vendor, externalTest bool
		want                          bool
	}{
		{name: "production int with external int test", importPath: "example.test/dependency", packageName: "int", replace: true, externalTest: true},
		{name: "local replace declaring int", importPath: "example.test/replaced", packageName: "int", replace: true},
		{name: "local replace declaring mathx", importPath: "example.test/replaced", packageName: "mathx", replace: true, want: true},
		{name: "vendor declaring int", importPath: "example.test/vendorint", packageName: "int", vendor: true},
		{name: "vendor declaring mathx", importPath: "example.test/vendorint", packageName: "mathx", vendor: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "credentialhelper")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			moduleText := "module example.test/main\n\ngo 1.25\n\nrequire " + test.importPath + " v0.0.0\n"
			packageDir := ""
			if test.replace {
				moduleText += "replace " + test.importPath + " => ./replacement\n"
				packageDir = filepath.Join(root, "replacement")
				if err := os.MkdirAll(packageDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(packageDir, "go.mod"), []byte("module "+test.importPath+"\n\ngo 1.25\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				packageDir = filepath.Join(root, "vendor", filepath.FromSlash(test.importPath))
				if err := os.MkdirAll(packageDir, 0o700); err != nil {
					t.Fatal(err)
				}
				modules := "# " + test.importPath + " v0.0.0\n## explicit; go 1.25\n" + test.importPath + "\n"
				if err := os.WriteFile(filepath.Join(root, "vendor", "modules.txt"), []byte(modules), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(moduleText), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(packageDir, "package.go"), []byte("package "+test.packageName+"\nconst Value = 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if test.externalTest {
				if err := os.WriteFile(filepath.Join(packageDir, "package_test.go"), []byte("package int_test\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			source := "package fixture\nimport (\"testing\"; \"" + test.importPath + "\")\ntype fakeRuntime struct{ serveCalls int }; type ServiceOptions struct{ Runtime *fakeRuntime }; const expectedCalls int = 1\nfunc TestRequired(t *testing.T) { runtime := &fakeRuntime{}; options := ServiceOptions{Runtime: runtime}; service, err := NewService(options); if err != nil { t.Fatal(err) }; _, _ = service.Serve(ctx); if runtime.serveCalls != expectedCalls { t.Fatal(\"bad\") } }"
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, "service_test.go"), source, 0)
			if err != nil {
				t.Fatal(err)
			}
			resolved := map[*ast.File]map[string]string{file: l8D2ReadinessResolvedImportPackageNames(build.Default, dir, file)}
			environment := l8D2ReadinessTerminalEnvironmentForFilesWithImports([]*ast.File{file}, resolved)
			if got := l8D2ReadinessExactServiceBehavioralTestInEnvironment(file, "TestRequired", spec, environment); got != test.want {
				t.Fatalf("behavioral module import = %t, want %t; resolved=%v", got, test.want, resolved[file])
			}
		})
	}
}

func TestL8D2HelperServiceReadinessConstantTimeGuardSelfTest(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		source string
		want   bool
	}{
		{name: "canonical controlling rejection", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return subtle.ConstantTimeCompare(left[:], right[:]) == 1 }
func admit(left, right [32]byte) error { if !helperExecDigestsEqual(left, right) { return errInvalid }; return nil }`, want: true},
		{name: "discarded result", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return subtle.ConstantTimeCompare(left[:], right[:]) == 1 }
func admit(left, right [32]byte) error { _ = helperExecDigestsEqual(left, right); return nil }`},
		{name: "noncontrolling result", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return subtle.ConstantTimeCompare(left[:], right[:]) == 1 }
func admit(left, right [32]byte) error { if !helperExecDigestsEqual(left, right) && false { return errInvalid }; return nil }`},
		{name: "dead nested rejection", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return subtle.ConstantTimeCompare(left[:], right[:]) == 1 }
func admit(left, right [32]byte) error { if false { if !helperExecDigestsEqual(left, right) { return errInvalid } }; return nil }`},
		{name: "rejection returns nil", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return subtle.ConstantTimeCompare(left[:], right[:]) == 1 }
func admit(left, right [32]byte) error { if !helperExecDigestsEqual(left, right) { return nil }; return nil }`},
		{name: "local helper shadow", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return subtle.ConstantTimeCompare(left[:], right[:]) == 1 }
func admit(left, right [32]byte) error { helperExecDigestsEqual := func([32]byte, [32]byte) bool { return true }; if !helperExecDigestsEqual(left, right) { return errInvalid }; return nil }`},
		{name: "helper returns native equality", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return left == right }
func admit(left, right [32]byte) error { if !helperExecDigestsEqual(left, right) { return errInvalid }; return nil }`},
		{name: "constant time self comparison", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return subtle.ConstantTimeCompare(left[:], right[:]) == 1 }
func admit(left, right [32]byte) error { if !helperExecDigestsEqual(left, left) { return errInvalid }; return nil }`},
		{name: "constant time foreign operand", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return subtle.ConstantTimeCompare(left[:], right[:]) == 1 }
func admit(left, right, foreign [32]byte) error { if !helperExecDigestsEqual(left, foreign) { return errInvalid }; return nil }`},
		{name: "helper hidden in function literal", source: `package fixture
func helperExecDigestsEqual(left, right [32]byte) bool { return subtle.ConstantTimeCompare(left[:], right[:]) == 1 }
func admit(left, right [32]byte) error { if !helperExecDigestsEqual(left, right) { return errInvalid }; _ = func() bool { return helperExecDigestsEqual(left, right) }; return nil }`},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			var helper, admit *ast.FuncDecl
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if function.Name.Name == "helperExecDigestsEqual" {
					helper = function
				}
				if function.Name.Name == "admit" {
					admit = function
				}
			}
			got := l8D2ReadinessExactDigestHelperReturn(helper, map[string]string{"subtle": "crypto/subtle"}) && l8D2ReadinessEveryHelperCallControlsRejection(admit, "helperExecDigestsEqual", 1) && l8D2ReadinessHelperCallsUseExactParamPair(admit, "helperExecDigestsEqual")
			if got != test.want {
				t.Fatalf("valid = %t, want %t", got, test.want)
			}
		})
	}
}

func TestL8D2HelperServiceReadinessObservationOperandGuardSelfTest(t *testing.T) {
	t.Parallel()
	canonicalObservedHelpers := `
func cloneHelperExecSHA256(owner *helperExecSHA256) *helperExecSHA256 { if owner == nil { return nil }; clone := *owner; return &clone }
func newHelperExecObservedStdinSink(stdin, transcript *helperExecSHA256) *helperExecObservedStdinSink { return &helperExecObservedStdinSink{stdin: stdin, transcript: transcript} }
`
	canonicalObservedStdin := `
func (transaction *HelperExecTransaction) ProposeObservedStdin(ctx Context, correlation Correlation, observation StreamObservation, view BorrowedView) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; candidateStdinHash := cloneHelperExecSHA256(transaction.owner.stdinHash); candidateTranscriptHash := cloneHelperExecSHA256(transaction.owner.transcriptHash); candidateStdinOffset := transaction.owner.stdinOffset + uint64(observation.owner.payloadLength); candidateStdinBytes := transaction.owner.stdinBytes + uint64(observation.owner.payloadLength); candidateStdinRecords := transaction.owner.stdinRecords + 1; candidateStdinEOF := observation.owner.flags == HelperExecStreamFlagEOF; sink := newHelperExecObservedStdinSink(candidateStdinHash, candidateTranscriptHash); writeErr := view.WriteTo(ctx, sink); _ = writeErr; digest := sink.Sum256(); if !helperExecDigestsEqual(observation.owner.payloadSHA256, digest) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalStdin, flags: observation.owner.flags, offset: observation.owner.offset, length: observation.owner.payloadLength, sha256: observation.owner.payloadSHA256, candidateStdinHash: candidateStdinHash, candidateTranscriptHash: candidateTranscriptHash, candidateStdinOffset: candidateStdinOffset, candidateStdinBytes: candidateStdinBytes, candidateStdinRecords: candidateStdinRecords, candidateStdinEOF: candidateStdinEOF, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }
`
	for _, test := range []struct {
		name, source, function string
		want                   bool
		deadline               time.Duration
	}{
		{name: "private constructor canonical", function: "NewHelperExecPrivateObservation", want: true, source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) { if !helperExecDigestsEqual(privateSHA256, observedSHA256) { return HelperExecPrivateObservation{}, errInvalid }; return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: privateSHA256}}, nil }`},
		{name: "private constructor swapped", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) error { if !helperExecDigestsEqual(observedSHA256, privateSHA256) { return errInvalid }; return nil }`},
		{name: "private constructor self compare", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) error { if !helperExecDigestsEqual(privateSHA256, privateSHA256) { return errInvalid }; return nil }`},
		{name: "stream constructor canonical", function: "NewHelperExecStreamObservation", want: true, source: `package fixture
func NewHelperExecStreamObservation(revision uint64, kind Kind, flags Flags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) { if !helperExecDigestsEqual(payloadSHA256, observedSHA256) { return HelperExecStreamObservation{}, errInvalid }; return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{revision: revision, streamKind: kind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256}}, nil }`},
		{name: "private admission canonical", function: "ProposeObservedPrivate", want: true, source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission correlation self compare", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) error { if !helperExecTransactionCorrelationEqual(correlation, correlation) { return errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return errInvalid }; return nil }`},
		{name: "private admission digest self compare", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) error { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return errInvalid }; if !helperExecDigestsEqual(transaction.owner.privateSHA, transaction.owner.privateSHA) { return errInvalid }; return nil }`},
		{name: "stdin admission canonical", function: "ProposeObservedStdin", want: true, source: "package fixture\n" + canonicalObservedHelpers + canonicalObservedStdin},
		{name: "stdin clone implementation aliases input", function: "ProposeObservedStdin", source: `package fixture
func cloneHelperExecSHA256(owner *helperExecSHA256) *helperExecSHA256 { return owner }
func newHelperExecObservedStdinSink(stdin, transcript *helperExecSHA256) *helperExecObservedStdinSink { return &helperExecObservedStdinSink{stdin: stdin, transcript: transcript} }
` + canonicalObservedStdin},
		{name: "stdin clone implementation retains input", function: "ProposeObservedStdin", source: `package fixture
func cloneHelperExecSHA256(owner *helperExecSHA256) *helperExecSHA256 { retained = owner; clone := *owner; return &clone }
func newHelperExecObservedStdinSink(stdin, transcript *helperExecSHA256) *helperExecObservedStdinSink { return &helperExecObservedStdinSink{stdin: stdin, transcript: transcript} }
` + canonicalObservedStdin},
		{name: "stdin sink implementation has side effect", function: "ProposeObservedStdin", source: `package fixture
func cloneHelperExecSHA256(owner *helperExecSHA256) *helperExecSHA256 { if owner == nil { return nil }; clone := *owner; return &clone }
func newHelperExecObservedStdinSink(stdin, transcript *helperExecSHA256) *helperExecObservedStdinSink { retained = stdin; return &helperExecObservedStdinSink{stdin: stdin, transcript: transcript} }
` + canonicalObservedStdin},
		{name: "stdin clone has duplicate alternate declaration", function: "ProposeObservedStdin", source: "package fixture\n" + canonicalObservedHelpers + `
func cloneHelperExecSHA256(owner *helperExecSHA256) *helperExecSHA256 { return owner }
` + canonicalObservedStdin},
		{name: "stdin digest from foreign view", function: "ProposeObservedStdin", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedStdin(ctx Context, correlation Correlation, observation StreamObservation, view BorrowedView) error { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return errInvalid }; sink := newHelperExecSHA256(); writeErr := foreignView.WriteTo(ctx, sink); _ = writeErr; digest := sink.Sum256(); if !helperExecDigestsEqual(observation.owner.payloadSHA256, digest) { return errInvalid }; return nil }`},
		{name: "private constructor mutates checked digest before issue", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) { if !helperExecDigestsEqual(privateSHA256, observedSHA256) { return HelperExecPrivateObservation{}, errInvalid }; privateSHA256 = foreignSHA; return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: privateSHA256}}, nil }`},
		{name: "stream constructor pointer alias mutates checked digest", function: "NewHelperExecStreamObservation", source: `package fixture
func NewHelperExecStreamObservation(revision uint64, kind Kind, flags Flags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) { if !helperExecDigestsEqual(payloadSHA256, observedSHA256) { return HelperExecStreamObservation{}, errInvalid }; alias := &payloadSHA256; *alias = foreignSHA; return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{revision: revision, streamKind: kind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256}}, nil }`},
		{name: "stream constructor self check then foreign issue", function: "NewHelperExecStreamObservation", source: `package fixture
func NewHelperExecStreamObservation(revision uint64, kind Kind, flags Flags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) { if !helperExecDigestsEqual(payloadSHA256, observedSHA256) { return HelperExecStreamObservation{}, errInvalid }; return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{revision: revision, streamKind: kind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: foreignSHA}}, nil }`},
		{name: "stream constructor closure mutates checked digest", function: "NewHelperExecStreamObservation", source: `package fixture
func NewHelperExecStreamObservation(revision uint64, kind Kind, flags Flags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) { if !helperExecDigestsEqual(payloadSHA256, observedSHA256) { return HelperExecStreamObservation{}, errInvalid }; func() { payloadSHA256 = foreignSHA }(); return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{revision: revision, streamKind: kind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256}}, nil }`},
		{name: "private constructor self check then foreign issue", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) { if !helperExecDigestsEqual(privateSHA256, observedSHA256) { return HelperExecPrivateObservation{}, errInvalid }; return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: foreignSHA}}, nil }`},
		{name: "private admission mutates checked observation owner", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; observation.owner.privateSHA256 = foreignSHA; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission alias mutates checked owner", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; owner := transaction.owner; owner.privateSHA = foreignSHA; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission checks then issues foreign observation", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: foreignObservation.owner.privateLength, sha256: foreignObservation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "stdin admission mutates checked correlation", function: "ProposeObservedStdin", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedStdin(ctx Context, correlation Correlation, observation StreamObservation, view BorrowedView) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; sink := newHelperExecSHA256(); writeErr := view.WriteTo(ctx, sink); _ = writeErr; digest := sink.Sum256(); if !helperExecDigestsEqual(observation.owner.payloadSHA256, digest) { return nil, errInvalid }; correlation = foreignCorrelation; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalStdin, flags: observation.owner.flags, offset: observation.owner.offset, length: observation.owner.payloadLength, sha256: observation.owner.payloadSHA256, candidateStdinHash: candidateStdinHash, candidateTranscriptHash: candidateTranscriptHash, candidateStdinOffset: candidateStdinOffset, candidateStdinBytes: candidateStdinBytes, candidateStdinRecords: candidateStdinRecords, candidateStdinEOF: candidateStdinEOF, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "stdin admission checks then issues foreign digest", function: "ProposeObservedStdin", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedStdin(ctx Context, correlation Correlation, observation StreamObservation, view BorrowedView) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; sink := newHelperExecSHA256(); writeErr := view.WriteTo(ctx, sink); _ = writeErr; digest := sink.Sum256(); if !helperExecDigestsEqual(observation.owner.payloadSHA256, digest) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalStdin, flags: observation.owner.flags, offset: observation.owner.offset, length: observation.owner.payloadLength, sha256: foreignSHA, candidateStdinHash: candidateStdinHash, candidateTranscriptHash: candidateTranscriptHash, candidateStdinOffset: candidateStdinOffset, candidateStdinBytes: candidateStdinBytes, candidateStdinRecords: candidateStdinRecords, candidateStdinEOF: candidateStdinEOF, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission mutates correlation between its gate and later digest gate", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; correlation = foreignCorrelation; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission proposal constructed before gates", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission pending install is dead", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; if false { transaction.owner.pending = proposalOwner }; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission pending install is overwritten", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; transaction.owner.pending = nil; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission passes checked owner to mutating helper", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; mutate(transaction.owner); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private constructor nested pre-gate struct pointer mutation", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) { holder := struct{ digest *[32]byte }{digest: &privateSHA256}; if !helperExecDigestsEqual(privateSHA256, observedSHA256) { return HelperExecPrivateObservation{}, errInvalid }; *holder.digest = foreignSHA; return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: privateSHA256}}, nil }`},
		{name: "stream constructor nested pre-gate map pointer mutation", function: "NewHelperExecStreamObservation", source: `package fixture
func NewHelperExecStreamObservation(revision uint64, kind Kind, flags Flags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) { holder := map[string]*[32]byte{"digest": &payloadSHA256}; if !helperExecDigestsEqual(payloadSHA256, observedSHA256) { return HelperExecStreamObservation{}, errInvalid }; *holder["digest"] = foreignSHA; return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{revision: revision, streamKind: kind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256}}, nil }`},
		{name: "private constructor second multi-result pre-gate alias mutation", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) { _, holder := split(&privateSHA256); if !helperExecDigestsEqual(privateSHA256, observedSHA256) { return HelperExecPrivateObservation{}, errInvalid }; *holder.digest = foreignSHA; return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: privateSHA256}}, nil }`},
		{name: "private constructor pre-gate mutating closure invoked after gate", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) { mutate := func(){ privateSHA256 = foreignSHA }; if !helperExecDigestsEqual(privateSHA256, observedSHA256) { return HelperExecPrivateObservation{}, errInvalid }; mutate(); return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: privateSHA256}}, nil }`},
		{name: "stream constructor wrapped mutating closure invoked after gate", function: "NewHelperExecStreamObservation", source: `package fixture
func NewHelperExecStreamObservation(revision uint64, kind Kind, flags Flags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) { mutate := func(){ payloadSHA256 = foreignSHA }; wrapped := any(mutate); if !helperExecDigestsEqual(payloadSHA256, observedSHA256) { return HelperExecStreamObservation{}, errInvalid }; wrapped.(func())(); return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{revision: revision, streamKind: kind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256}}, nil }`},
		{name: "stream constructor container wrapped mutator invoked after gate", function: "NewHelperExecStreamObservation", source: `package fixture
func NewHelperExecStreamObservation(revision uint64, kind Kind, flags Flags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) { mutators := []any{func(){ payloadSHA256 = foreignSHA }}; if !helperExecDigestsEqual(payloadSHA256, observedSHA256) { return HelperExecStreamObservation{}, errInvalid }; mutators[0].(func())(); return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{revision: revision, streamKind: kind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256}}, nil }`},
		{name: "private constructor slice wrapped mutator invoked after gate", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) { mutators := ([]func(){func(){ privateSHA256 = foreignSHA }})[:]; if !helperExecDigestsEqual(privateSHA256, observedSHA256) { return HelperExecPrivateObservation{}, errInvalid }; mutators[0](); return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: privateSHA256}}, nil }`},
		{name: "stream constructor full slice wrapped mutator invoked after gate", function: "NewHelperExecStreamObservation", source: `package fixture
func NewHelperExecStreamObservation(revision uint64, kind Kind, flags Flags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) { mutators := ([]func(){func(){ payloadSHA256 = foreignSHA }})[:1:1]; if !helperExecDigestsEqual(payloadSHA256, observedSHA256) { return HelperExecStreamObservation{}, errInvalid }; mutators[0](); return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{revision: revision, streamKind: kind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256}}, nil }`},
		{name: "private constructor captured mutator escapes after gate", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) { mutate := func(){ privateSHA256 = foreignSHA }; if !helperExecDigestsEqual(privateSHA256, observedSHA256) { return HelperExecPrivateObservation{}, errInvalid }; retained = []any{mutate}; return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: privateSHA256}}, nil }`},
		{name: "private constructor shadowed clone helper wraps mutator", function: "NewHelperExecPrivateObservation", source: `package fixture
func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) { cloneHelperExecSHA256 := func(value any) any { return value }; mutate := cloneHelperExecSHA256(func(){ privateSHA256 = foreignSHA }); if !helperExecDigestsEqual(privateSHA256, observedSHA256) { return HelperExecPrivateObservation{}, errInvalid }; mutate.(func())(); return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: privateSHA256}}, nil }`},
		{name: "stream constructor shadowed stdin sink helper wraps mutator", function: "NewHelperExecStreamObservation", source: `package fixture
func NewHelperExecStreamObservation(revision uint64, kind Kind, flags Flags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) { newHelperExecObservedStdinSink := func(value any) any { return value }; mutate := newHelperExecObservedStdinSink(func(){ payloadSHA256 = foreignSHA }); if !helperExecDigestsEqual(payloadSHA256, observedSHA256) { return HelperExecStreamObservation{}, errInvalid }; mutate.(func())(); return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{revision: revision, streamKind: kind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256}}, nil }`},
		{name: "private admission nested pre-gate slice alias passed to helper", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { aliases := []*PrivateObservation{&observation}; if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; mutate(aliases); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after unconditional error return", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return nil, errInvalid; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after panic", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; panic("dead success"); return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after runtime Goexit", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; runtime.Goexit(); return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after constant true terminal", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; if true { return nil, errInvalid }; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal method alias", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { stop := runtime.Goexit; if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stop(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal IIFE", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; func(){ runtime.Goexit() }(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after wrapped terminal closure", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { stop := func(){ panic("stop") }; wrapped := any(stop); if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; wrapped.(func())(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal container wrapper", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { stops := []any{func(){ runtime.Goexit() }}; if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stops[0].(func())(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after package terminal helper", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func stop() { runtime.Goexit() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stop(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after package terminal helper chain", function: "ProposeObservedPrivate", source: `package fixture
func stopLeaf() { panic("stop") }
func stopMiddle() { stopLeaf() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stopMiddle(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after exact recursive terminal helper cycle", function: "ProposeObservedPrivate", source: `package fixture
func stopA() { stopB() }
func stopB() { stopA() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stopA(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after constant equality terminal", function: "ProposeObservedPrivate", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; if 1 == 1 { panic("stop") }; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after sliced terminal container", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { stops := ([]func(){func(){ runtime.Goexit() }})[:1:1]; if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stops[0](); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after receiver terminal helper", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type stopper struct{}
func (stopper) Stop() { runtime.Goexit() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stopper{}.Stop(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal callable factory", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func stopFactory() func() { return runtime.Goexit }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stopFactory()(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal wrapper argument", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; invoke(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after multihop terminal wrapper argument", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func relay(stop func()) { invoke(stop) }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; relay(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after aliased terminal wrapper", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; alias := invoke; alias(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after multihop aliased terminal wrapper", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; first := invoke; second := first; second(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after container aliased terminal wrapper", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; wrappers := ([]any{invoke})[:]; wrappers[0].(func(func()))(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after map aliased terminal wrapper", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; wrappers := map[string]any{"stop": (invoke)}; wrappers["stop"].(func(func()))(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after struct aliased terminal wrapper", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; holder := struct{ call any }{call: invoke}; holder.call.(func(func()))(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after generic identity terminal wrapper", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func identity[T any](value T) T { return value }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; alias := identity[any](invoke); alias.(func(func()))(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "ambiguous reassigned wrapper rejects if any identity terminates", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; alias := invoke; alias = ignore; alias(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after returned terminal wrapper factory", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func wrapperFactory() func(func()) { return invoke }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; wrapperFactory()(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after aliased returned terminal wrapper factory", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func wrapperFactory() func(func()) { return invoke }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; factory := wrapperFactory; factory()(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after post declaration struct field wrapper assignment", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; var holder struct{ call func(func()) }; holder.call = invoke; holder.call(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after post declaration slice index wrapper assignment", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; wrappers := make([]func(func()), 1); wrappers[0] = invoke; wrappers[0](runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after post declaration map index wrapper assignment", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; wrappers := make(map[string]func(func())); wrappers["stop"] = invoke; wrappers["stop"](runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after nested pointer field wrapper assignment", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
type innerWrapper struct{ call func(func()) }; type outerWrapper struct{ inner *innerWrapper }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; holder := &outerWrapper{inner: &innerWrapper{}}; holder.inner.call = invoke; alias := holder; alias.inner.call(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "nested selector containing alias preserves terminal child", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
type innerWrapper struct{ call func(func()) }; type outerWrapper struct{ inner *innerWrapper }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; holder := &outerWrapper{inner: &innerWrapper{}}; holder.inner.call = invoke; alias := holder.inner; alias.call(runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "indexed containing alias preserves terminal child", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
type innerWrapper struct{ call func(func()) }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; holders := []innerWrapper{{}}; holders[0].call = invoke; alias := &holders[0]; alias.call(runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "distinct struct field wrapper remains returning", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; holder := struct{ stop, pass func(func()) }{}; holder.stop = invoke; holder.pass = ignore; holder.pass(runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "distinct constant slice index wrapper remains returning", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make([]func(func()), 2); wrappers[0] = invoke; wrappers[1] = ignore; wrappers[1](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "distinct constant map key wrapper remains returning", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make(map[string]func(func())); wrappers["stop"] = invoke; wrappers["pass"] = ignore; wrappers["pass"](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "dynamic slice index wrapper is ambiguous", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make([]func(func()), 2); wrappers[index] = invoke; wrappers[1] = ignore; wrappers[1](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "dynamic map key wrapper is ambiguous", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make(map[string]func(func())); wrappers[key] = invoke; wrappers["pass"] = ignore; wrappers["pass"](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "equivalent interpreted and raw string map key is terminal", function: "ProposeObservedPrivate", source: "package fixture\nimport \"runtime\"\nfunc invoke(stop func()) { stop() }\nfunc (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make(map[string]func(func())); wrappers[\"stop\"] = invoke; wrappers[`stop`](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }"},
		{name: "equivalent rune and integer array key is terminal", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; var wrappers [100]func(func()); wrappers['a'] = invoke; wrappers[97](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "named constant indexes keep siblings distinct", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
const stopIndex = 0; const passIndex = stopIndex + 1
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make([]func(func()), 2); wrappers[stopIndex] = invoke; wrappers[passIndex] = ignore; wrappers[1](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "named constant expression aliases terminal index", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
const baseIndex = 0; const stopIndex = baseIndex + 1
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make([]func(func()), 2); wrappers[stopIndex] = invoke; wrappers[1](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "dynamic local shadows package constant index", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
const stopIndex = 0
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; stopIndex := index; wrappers := make([]func(func()), 2); wrappers[stopIndex] = invoke; wrappers[1] = ignore; wrappers[1](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "iota indexes keep siblings distinct", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
const ( stopIndex = iota; passIndex )
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make([]func(func()), 2); wrappers[stopIndex] = invoke; wrappers[passIndex] = ignore; wrappers[passIndex](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "representably equal integer and float map keys are terminal", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make(map[float64]func(func())); wrappers[1] = invoke; wrappers[1.0](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "converted string constant indexes keep siblings distinct", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make(map[string]func(func())); wrappers[string('a')] = invoke; wrappers[string('b')] = ignore; wrappers[string('b')](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "forward package constant indexes keep siblings distinct", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
const stopIndex = passIndex - 1; const passIndex = 1
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make([]func(func()), 2); wrappers[stopIndex] = invoke; wrappers[passIndex] = ignore; wrappers[passIndex](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "float64 rounded map keys are terminal", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make(map[float64]func(func())); wrappers[9007199254740992] = invoke; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "helper returned named float map rounds keys", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[float64]func(func())
func newWrapperMap() wrapperMap { return wrapperMap{} }
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := newWrapperMap(); wrappers[9007199254740992] = invoke; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "helper returned generic named float map rounds keys", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap[K comparable] map[K]func(func())
func newWrapperMap() wrapperMap[float64] { return wrapperMap[float64]{} }
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := newWrapperMap(); wrappers[9007199254740992] = invoke; alias := wrappers; alias[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "local named float map rounds keys", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; type wrapperMap map[float64]func(func()); wrappers := make(wrapperMap); wrappers[9007199254740992] = invoke; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "local named float key rounds map indexes", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; type wrapperKey float64; wrappers := make(map[wrapperKey]func(func())); wrappers[9007199254740992] = invoke; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "receiver method returned float map rounds keys", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperFactory struct{}
func (wrapperFactory) wrappers() map[float64]func(func()) { return nil }
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := wrapperFactory{}.wrappers(); wrappers[9007199254740992] = invoke; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "receiver method returned map keeps distinct keys", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
type wrapperFactory struct{}
func (wrapperFactory) wrappers() map[float64]func(func()) { return nil }
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; factory := wrapperFactory{}; wrappers := factory.wrappers(); wrappers[1] = invoke; wrappers[2] = ignore; wrappers[2](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "local closure returned float map rounds keys", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; factory := func() map[float64]func(func()) { return nil }; wrappers := factory(); wrappers[9007199254740992] = invoke; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "asserted interface float map rounds keys", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := raw.(map[float64]func(func())); wrappers[9007199254740992] = invoke; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "pointer to named float map rounds keys", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[float64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := new(wrapperMap); (*wrappers)[9007199254740992] = invoke; (*wrappers)[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "unresolved indexed storage remains conservatively ambiguous", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := opaqueFactory(); wrappers[9007199254740992] = invoke; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "short declared value shadows package named map type", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrapperMap := make(map[float64]func(func())); wrappers := wrapperMap; wrappers[9007199254740992] = invoke; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "if init value shadows package named map type", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; if wrapperMap := make(map[float64]func(func())); ready { wrapperMap[9007199254740992] = invoke; wrapperMap[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }; return nil, errInvalid }`},
		{name: "for init value shadows package named map type", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; for wrapperMap := make(map[float64]func(func())); ready; { wrapperMap[9007199254740992] = invoke; wrapperMap[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }; return nil, errInvalid }`},
		{name: "range value shadows package named map type", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; for _, wrapperMap := range []map[float64]func(func()){{}} { wrapperMap[9007199254740992] = invoke; wrapperMap[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }; return nil, errInvalid }`},
		{name: "switch init value shadows package named map type", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; switch wrapperMap := make(map[float64]func(func())); ready { default: wrapperMap[9007199254740992] = invoke; wrapperMap[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }; return nil, errInvalid }`},
		{name: "type switch value shadows package named map type", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; switch wrapperMap := raw.(type) { case map[float64]func(func()): wrapperMap[9007199254740992] = invoke; wrapperMap[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }; return nil, errInvalid }`},
		{name: "select receive value shadows package named map type", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; select { case wrapperMap := <-maps: wrapperMap[9007199254740992] = invoke; wrapperMap[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }; return nil, errInvalid }`},
		{name: "switch case local value shadows package named map type", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; switch { default: wrapperMap := make(map[float64]func(func())); wrapperMap[9007199254740992] = invoke; wrapperMap[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }; return nil, errInvalid }`},
		{name: "closure parameter shadows package named map type", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; return func(wrapperMap map[float64]func(func())) (*HelperExecPayloadProposal, error) { wrapperMap[9007199254740992] = invoke; wrapperMap[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }(nil) }`},
		{name: "expired if init value does not hide package named map type", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
type wrapperMap map[int64]func(func())
func invoke(stop func()) { stop() }; func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; if wrapperMap := make(map[float64]func(func())); ready { _ = wrapperMap }; wrappers := wrapperMap{}; wrappers[9007199254740992] = invoke; wrappers[9007199254740993] = ignore; wrappers[9007199254740993](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "huge integer string conversions remain conservatively ambiguous", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make(map[string]func(func())); wrappers[string(1 << 100)] = invoke; wrappers[string(1 << 101)](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "nested dynamic parent index aliases exact descendant", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; wrappers := make(map[int][]func(func())); wrappers[index][0] = invoke; wrappers[1][0](runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "recursive containing alias converges and preserves child", function: "ProposeObservedPrivate", deadline: 2 * time.Second, source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
type wrapper struct { call func(func()); child *wrapper }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; holder := &wrapper{}; holder.call = invoke; holder.child = holder; holder.child.child.call(runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "recursive indexed containing alias converges", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
type wrapper struct { call func(func()); children map[int]*wrapper }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; holder := &wrapper{}; holder.call = invoke; holder.children[index] = holder; holder.children[1].children[2].call(runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after anonymous closure factory", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; factory := func() func(func()) { return invoke }; factory()(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after anonymous nested iife factory", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; func() func() func(func()) { return func() func(func()) { return invoke } }()()(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal wrapper assignment expression", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; dead := invoke(runtime.Goexit); _ = dead; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal wrapper var declaration", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; var dead = invoke(runtime.Goexit); _ = dead; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after nested terminal wrapper call argument", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) any { stop(); return nil }; func consume(any) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; consume(invoke(runtime.Goexit)); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal wrapper in composite", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) any { stop(); return nil }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; dead := []any{invoke(runtime.Goexit)}; _ = dead; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal wrapper in if init", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) any { stop(); return nil }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; if dead := invoke(runtime.Goexit); dead != nil {}; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal wrapper switch case expression", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) int { stop(); return 0 }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; switch value { case invoke(runtime.Goexit): }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "terminal switch case after default is still evaluated", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) int { stop(); return 0 }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; switch value { default: ; case invoke(runtime.Goexit): }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "tagless switch continues past named false constant", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
const never = false
func invoke(stop func()) bool { stop(); return false }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; switch { case never: ; case invoke(runtime.Goexit): }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal wrapper type switch assignment", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) any { stop(); return nil }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; switch invoke(runtime.Goexit).(type) { case int: }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after terminal wrapper select communication", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) int { stop(); return 0 }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; select { case output <- invoke(runtime.Goexit): default: }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "select receive destination is evaluated only after selection", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func invoke(stop func()) int { stop(); return 0 }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; select { case output[invoke(runtime.Goexit)] = <-input: default: }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "terminal wrapper in conditional switch body remains live", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; switch value { case 1: invoke(runtime.Goexit) }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "terminal wrapper inside uncalled closure remains live", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; deferred := func(){ invoke(runtime.Goexit) }; _ = deferred; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "deferred terminal wrapper body remains live", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; defer invoke(runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "goroutine terminal wrapper body remains live", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; go invoke(runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after receiver method wrapper alias", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
type invoker struct{}
func (invoker) Invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; alias := invoker{}.Invoke; alias(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "duplicate wrapper declarations union terminal parameter first", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) { stop() }
func invoke(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; alias := invoke; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; alias(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "duplicate wrapper declarations union terminal parameter last", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop func()) {}
func invoke(stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; alias := invoke; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; alias(runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after reordered terminal wrapper argument", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(value int, stop func()) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; invoke(1, runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after generic terminal wrapper argument", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke[T func()](stop T) { stop() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; invoke[func()](runtime.Goexit); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "private admission success after interface terminal wrapper argument", function: "ProposeObservedPrivate", source: `package fixture
import "runtime"
func invoke(stop any) { stop.(func())() }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; invoke(any(runtime.Goexit)); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "unused terminal wrapper argument does not terminate", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; ignore(runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "conditional terminal wrapper argument does not always terminate", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func maybe(stop func(), condition bool) { if condition { stop() } }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; maybe(runtime.Goexit, condition); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "aliased unused terminal wrapper argument does not terminate", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func ignore(stop func()) {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; alias := ignore; alias(runtime.Goexit); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "aliased conditional terminal wrapper argument does not always terminate", function: "ProposeObservedPrivate", want: true, source: `package fixture
import "runtime"
func maybe(stop func(), condition bool) { if condition { stop() } }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; alias := maybe; alias(runtime.Goexit, condition); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "duplicate helper declaration terminal variant first", function: "ProposeObservedPrivate", source: `package fixture
func stop() { panic("stop") }
func stop() {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stop(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "duplicate helper declaration terminal variant last", function: "ProposeObservedPrivate", source: `package fixture
func stop() {}
func stop() { panic("stop") }
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; stop(); transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "lookalike runtime import is not terminal", function: "ProposeObservedPrivate", want: true, source: `package fixture
import runtime "example.invalid/runtime"
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; runtime.Goexit(); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "lookalike testing import is not terminal", function: "ProposeObservedPrivate", want: true, source: `package fixture
import testing "example.invalid/testing"
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { var t *testing.T; if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; t.FailNow(); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "lookalike Fatal receiver is not terminal", function: "ProposeObservedPrivate", want: true, source: `package fixture
type harmless struct{}
func (harmless) Fatal() {}
func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation Correlation, observation PrivateObservation) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; if !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) { return nil, errInvalid }; harmless{}.Fatal(); proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalPrivate, length: observation.owner.privateLength, sha256: observation.owner.privateSHA256, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "stdin admission uses unrelated candidate locals", function: "ProposeObservedStdin", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedStdin(ctx Context, correlation Correlation, observation StreamObservation, view BorrowedView) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; sink := newHelperExecSHA256(); writeErr := view.WriteTo(ctx, sink); _ = writeErr; digest := sink.Sum256(); if !helperExecDigestsEqual(observation.owner.payloadSHA256, digest) { return nil, errInvalid }; candidateStdinHash := foreignHash; candidateTranscriptHash := foreignHash; candidateStdinOffset := uint64(9); candidateStdinBytes := uint64(9); candidateStdinRecords := uint32(9); candidateStdinEOF := true; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalStdin, flags: observation.owner.flags, offset: observation.owner.offset, length: observation.owner.payloadLength, sha256: observation.owner.payloadSHA256, candidateStdinHash: candidateStdinHash, candidateTranscriptHash: candidateTranscriptHash, candidateStdinOffset: candidateStdinOffset, candidateStdinBytes: candidateStdinBytes, candidateStdinRecords: candidateStdinRecords, candidateStdinEOF: candidateStdinEOF, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
		{name: "stdin admission candidate derivation is dead", function: "ProposeObservedStdin", source: `package fixture
func (transaction *HelperExecTransaction) ProposeObservedStdin(ctx Context, correlation Correlation, observation StreamObservation, view BorrowedView) (*HelperExecPayloadProposal, error) { if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) { return nil, errInvalid }; var candidateStdinHash, candidateTranscriptHash *helperExecSHA256; var candidateStdinOffset, candidateStdinBytes uint64; var candidateStdinRecords uint32; var candidateStdinEOF bool; if false { candidateStdinHash = cloneHelperExecSHA256(transaction.owner.stdinHash); candidateTranscriptHash = cloneHelperExecSHA256(transaction.owner.transcriptHash); candidateStdinOffset = transaction.owner.stdinOffset + uint64(observation.owner.payloadLength); candidateStdinBytes = transaction.owner.stdinBytes + uint64(observation.owner.payloadLength); candidateStdinRecords = transaction.owner.stdinRecords + 1; candidateStdinEOF = observation.owner.flags == HelperExecStreamFlagEOF }; sink := newHelperExecObservedStdinSink(candidateStdinHash, candidateTranscriptHash); writeErr := view.WriteTo(ctx, sink); _ = writeErr; digest := sink.Sum256(); if !helperExecDigestsEqual(observation.owner.payloadSHA256, digest) { return nil, errInvalid }; proposalOwner := &helperExecPayloadProposalOwner{transaction: transaction.owner, source: helperExecProposalSourceObserved, kind: helperExecProposalStdin, flags: observation.owner.flags, offset: observation.owner.offset, length: observation.owner.payloadLength, sha256: observation.owner.payloadSHA256, candidateStdinHash: candidateStdinHash, candidateTranscriptHash: candidateTranscriptHash, candidateStdinOffset: candidateStdinOffset, candidateStdinBytes: candidateStdinBytes, candidateStdinRecords: candidateStdinRecords, candidateStdinEOF: candidateStdinEOF, observedReady: true}; transaction.owner.pending = proposalOwner; return &HelperExecPayloadProposal{owner: proposalOwner}, nil }`},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			var function *ast.FuncDecl
			functions := make(map[string]*ast.FuncDecl)
			var declarations []*ast.FuncDecl
			aliases, _ := l8D2ReadinessImportAliases(file)
			aliasesByDeclaration := make(map[*ast.FuncDecl]map[string]string)
			for _, declaration := range file.Decls {
				candidate, ok := declaration.(*ast.FuncDecl)
				if ok {
					declarations = append(declarations, candidate)
					aliasesByDeclaration[candidate] = aliases
				}
				if ok && candidate.Recv == nil {
					functions[candidate.Name.Name] = candidate
				}
				if ok && candidate.Name.Name == test.function {
					function = candidate
				}
			}
			environment := l8D2ReadinessTerminalEnvironment{declarations: declarations, aliases: aliasesByDeclaration, constants: l8D2ReadinessDeclaredConstants(file.Decls), namedTypes: l8D2ReadinessDeclaredNamedTypes(file.Decls)}
			evaluate := func() bool {
				return l8D2ReadinessExactObservationHelperOperands(function, functions, environment)
			}
			var got bool
			if test.deadline == 0 {
				got = evaluate()
			} else {
				finished := make(chan bool, 1)
				go func() { finished <- evaluate() }()
				select {
				case got = <-finished:
				case <-time.After(test.deadline):
					t.Fatalf("analysis did not converge within %s", test.deadline)
				}
			}
			if got != test.want {
				t.Fatalf("valid = %t, want %t", got, test.want)
			}
		})
	}
}

func TestL8D2HelperServiceReadinessNoRetentionGuardSelfTest(t *testing.T) {
	t.Parallel()
	const credentialMemoryPath = "github.com/jywlabs/hal/internal/credentialmemory"
	for _, test := range []struct {
		name       string
		source     string
		wantIssues int
	}{
		{
			name:   "method parameters are scoped rather than retained",
			source: "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype holder struct{ count int }\nfunc (holder) Use(cm.BorrowedView, cm.CredentialSink) {}\n",
		},
		{
			name:       "function field parameters retain a scoped type channel",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype holder struct{ use func(cm.BorrowedView, cm.CredentialSink) error }\n",
			wantIssues: 1,
		},
		{
			name:       "function field result retains a scoped type channel",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype callback = func() cm.BorrowedView\ntype holder struct{ borrow callback }\n",
			wantIssues: 1,
		},
		{
			name:   "top level function parameters remain scoped",
			source: "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(cm.BorrowedView, cm.CredentialSink) error { return nil }\n",
		},
		{
			name:   "non-escaping local alias remains scoped",
			source: "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(view cm.BorrowedView) int { alias := view; return alias.Len() }\n",
		},
		{
			name:   "exact synchronous received body borrow callback is allowed",
			source: "package fixture\nimport (\"context\"; cm \"" + credentialMemoryPath + "\")\ntype ReceivedBodyCapability interface{ Borrow(context.Context, func(cm.BorrowedView) error) error }\nfunc use(ctx context.Context, body ReceivedBodyCapability) error { return body.Borrow(ctx, func(view cm.BorrowedView) error { _ = view.Len(); return nil }) }\n",
		},
		{
			name:       "lookalike borrow callback cannot retain scoped parameter",
			source:     "package fixture\nimport (\"context\"; cm \"" + credentialMemoryPath + "\")\ntype OtherBody interface{ Borrow(context.Context, func(cm.BorrowedView) error) error }\nfunc use(ctx context.Context, body OtherBody) error { return body.Borrow(ctx, func(view cm.BorrowedView) error { _ = view.Len(); return nil }) }\n",
			wantIssues: 1,
		},
		{
			name:       "direct aliased import",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype holder struct{ view cm.BorrowedView }\n",
			wantIssues: 1,
		},
		{
			name:       "named alias behind pointer array and map",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype viewAlias = cm.BorrowedView\ntype namedView viewAlias\ntype holder struct{ views map[string]*[2]namedView }\n",
			wantIssues: 1,
		},
		{
			name:       "generic index alias",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype box[T any] struct{ marker byte }\ntype sinkBox = box[cm.CredentialSink]\ntype holder struct{ sink sinkBox }\n",
			wantIssues: 1,
		},
		{
			name:       "generic constraint retains borrowed view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype holder[T cm.BorrowedView] struct{ retained T }\n",
			wantIssues: 1,
		},
		{
			name:       "generic constraint retains credential sink",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype holder[T cm.CredentialSink] struct{ retained T }\n",
			wantIssues: 1,
		},
		{
			name:       "generic constrained function result retains borrowed view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype callback[T cm.BorrowedView] func() T\ntype holder[T cm.BorrowedView] struct{ borrow callback[T] }\n",
			wantIssues: 1,
		},
		{
			name:       "generic constrained function parameter retains credential sink",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype callback[T cm.CredentialSink] func(T)\ntype holder[T cm.CredentialSink] struct{ use callback[T] }\n",
			wantIssues: 1,
		},
		{
			name:   "unconstrained generic retained field remains allowed",
			source: "package fixture\ntype holder[T any] struct{ value T }\n",
		},
		{
			name:       "anonymous nested field",
			source:     "package fixture\nimport . \"" + credentialMemoryPath + "\"\ntype holder struct{ nested struct{ view *BorrowedView } }\n",
			wantIssues: 1,
		},
		{
			name:       "package global direct scoped value",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar retained cm.BorrowedView\n",
			wantIssues: 1,
		},
		{
			name:       "package global inferred alias container",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar source []cm.CredentialSink\nvar retained = source\n",
			wantIssues: 2,
		},
		{
			name:       "package global function channel",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar retained = func() chan cm.BorrowedView { return nil }\n",
			wantIssues: 1,
		},
		{
			name:       "package global safe interface aliases scoped value",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar source cm.BorrowedView\nvar retained any = source\n",
			wantIssues: 2,
		},
		{
			name:       "package global closure captures scoped value",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar source cm.BorrowedView\nvar retained = func() { _ = source }\n",
			wantIssues: 2,
		},
		{
			name:       "package function variable assigned captured view later",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar retained func()\nfunc install(view cm.BorrowedView) { retained = func() { _ = view } }\n",
			wantIssues: 1,
		},
		{
			name:       "local returned closure captures sink through alias",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc retain(sink cm.CredentialSink) func() { alias := sink; return func() { _ = alias } }\n",
			wantIssues: 1,
		},
		{
			name:       "scoped value assigned through interface container",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar retained any\nfunc install(view cm.BorrowedView) { retained = []any{view} }\n",
			wantIssues: 1,
		},
		{
			name:       "scoped value retained by local ValueSpec composite",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc install(view cm.BorrowedView) { var retained any = map[string]any{\"view\": view}; _ = retained }\n",
			wantIssues: 1,
		},
		{
			name:       "scoped value sent to retained channel",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar retained = make(chan any)\nfunc install(sink cm.CredentialSink) { retained <- sink }\n",
			wantIssues: 1,
		},
		{
			name:       "ordinary function call can retain scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc retain(any) {}\nfunc use(view cm.BorrowedView) { retain(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "cross function helper stores scoped view globally",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar retained any\nfunc helper(value any) { retained = value }\nfunc use(view cm.BorrowedView) { helper(view) }\n",
			wantIssues: 2,
		},
		{
			name:       "variadic interface call can retain scoped sink",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc retain(...any) {}\nfunc use(sink cm.CredentialSink) { retain(1, sink) }\n",
			wantIssues: 1,
		},
		{
			name:       "method call can retain scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype holder struct{}\nfunc (holder) Retain(any) {}\nfunc use(view cm.BorrowedView) { holder{}.Retain(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "deferred call can retain scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc retain(any) {}\nfunc use(view cm.BorrowedView) { defer retain(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "goroutine call can retain scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc retain(any) {}\nfunc use(view cm.BorrowedView) { go retain(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "function value call can retain scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(view cm.BorrowedView, retain func(any)) { retain(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "lookalike configured dependency can retain scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(view cm.BorrowedView) { configuredDependency := func(any) bool { return true }; configuredDependency(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "parameter lookalike configured dependency can retain scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(view cm.BorrowedView, configuredDependency func(any) bool) { configuredDependency(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "lookalike WriteTo method can retain scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype evil struct{}\nfunc (evil) WriteTo(any) {}\nfunc use(view cm.BorrowedView) { evil{}.WriteTo(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "lookalike BeginExec method can retain scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype evil struct{}\nfunc (evil) BeginExec(any) {}\nfunc use(view cm.BorrowedView) { evil{}.BeginExec(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "function typed scoped consumer retains view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(view cm.BorrowedView, retain func(cm.BorrowedView)) { retain(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "borrowed view bound method value is retention",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nvar retained any\nfunc use(view cm.BorrowedView) { forwarding := view.WriteTo; retained = forwarding }\n",
			wantIssues: 1,
		},
		{
			name:       "credential sink bound method in container is retention",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(sink cm.CredentialSink) any { write := sink.WriteCredential; return []any{write} }\n",
			wantIssues: 1,
		},
		{
			name:       "bound method passed to ordinary helper is retention",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc retain(any) {}\nfunc use(view cm.BorrowedView) { retain(view.WriteTo) }\n",
			wantIssues: 1,
		},
		{
			name:       "reflect wrapped bound method remains retention",
			source:     "package fixture\nimport (\"reflect\"; cm \"" + credentialMemoryPath + "\")\nvar retained any\nfunc use(view cm.BorrowedView) { wrapped := reflect.ValueOf(view.WriteTo); retained = wrapped }\n",
			wantIssues: 1,
		},
		{
			name:       "custom identity wrapped bound method remains retention",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc identity[T any](value T) T { return value }\nfunc use(sink cm.CredentialSink) any { return identity(identity(sink.WriteCredential)) }\n",
			wantIssues: 2,
		},
		{
			name:       "interface conversion around bound method remains retention",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(view cm.BorrowedView) any { wrapped := any(view.CopyTo); return []any{wrapped} }\n",
			wantIssues: 1,
		},
		{
			name:       "slice expression around bound method remains retention",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(view cm.BorrowedView) any { return ([]any{view.WriteTo})[:] }\n",
			wantIssues: 1,
		},
		{
			name:       "full slice expression around bound method remains retention",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(sink cm.CredentialSink) any { wrapped := ([]any{sink.WriteCredential})[:1:1]; return wrapped[0] }\n",
			wantIssues: 1,
		},
		{
			name:       "nested expression wrappers around bound method remain retention",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc identity[T any](value T) T { return value }; func use(view cm.BorrowedView) any { wrapped := identity[any](any(([]any{view.WriteTo})[:][0])); return wrapped }\n",
			wantIssues: 2,
		},
		{
			name:       "lookalike Len receiver cannot declassify bound method",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\ntype evil struct{ retained any }; func (evil) Len() int { return 0 }; func use(view cm.BorrowedView) int { return evil{retained: view.WriteTo}.Len() }\n",
			wantIssues: 1,
		},
		{
			name:       "reflect ValueOf raw scoped view remains retention",
			source:     "package fixture\nimport (\"reflect\"; cm \"" + credentialMemoryPath + "\")\nfunc use(view cm.BorrowedView) any { return reflect.ValueOf(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "confined typed nil helper cannot store reflected sink globally",
			source:     "package fixture\nimport (\"reflect\"; cm \"" + credentialMemoryPath + "\")\nvar retained reflect.Value\nfunc isNilCoreDependency(sink cm.CredentialSink) bool { retained = reflect.ValueOf(sink); return false }\n",
			wantIssues: 1,
		},
		{
			name:       "confined typed nil helper cannot pass reflected sink to helper",
			source:     "package fixture\nimport (\"reflect\"; cm \"" + credentialMemoryPath + "\")\nfunc retain(any) {}\nfunc isNilCoreDependency(sink cm.CredentialSink) bool { retain(reflect.ValueOf(sink)); return false }\n",
			wantIssues: 1,
		},
		{
			name:       "confined typed nil helper cannot store reflected sink locally",
			source:     "package fixture\nimport (\"reflect\"; cm \"" + credentialMemoryPath + "\")\nfunc isNilCoreDependency(sink cm.CredentialSink) bool { retained := []any{reflect.ValueOf(sink)}; _ = retained; return false }\n",
			wantIssues: 1,
		},
		{
			name:       "confined typed nil helper cannot return reflected sink",
			source:     "package fixture\nimport (\"reflect\"; cm \"" + credentialMemoryPath + "\")\nfunc isNilCoreDependency(sink cm.CredentialSink) any { return reflect.ValueOf(sink) }\n",
			wantIssues: 1,
		},
		{
			name: "confined typed nil helper declaration is unique across package",
			source: "package fixture\nimport (\"reflect\"; cm \"" + credentialMemoryPath + "\")\n" +
				"func isNilCoreDependency(sink cm.CredentialSink) bool { if sink == nil { return true }; reflected := reflect.ValueOf(sink); switch reflected.Kind() { case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice: return reflected.IsNil(); default: return false } }\n" +
				"func isNilCoreDependency(sink cm.CredentialSink) bool { if sink == nil { return true }; reflected := reflect.ValueOf(sink); switch reflected.Kind() { case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice: return reflected.IsNil(); default: return false } }\n",
			wantIssues: 2,
		},
		{
			name:       "method expression cannot consume scoped view",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(view cm.BorrowedView) int { return cm.BorrowedView.Len(view) }\n",
			wantIssues: 1,
		},
		{
			name:       "lookalike canonical scratch helper captures sink",
			source:     "package fixture\nimport cm \"" + credentialMemoryPath + "\"\nfunc use(sink cm.CredentialSink) { withCanonicalScratch := func(any, any, func([]byte) error) error { return nil }; _ = withCanonicalScratch(nil, nil, func([]byte) error { _ = sink.MaxCredentialBytes(); return nil }) }\n",
			wantIssues: 1,
		},
		{
			name:   "exact scoped view methods remain synchronous",
			source: "package fixture\nimport (\"context\"; cm \"" + credentialMemoryPath + "\")\nfunc use(ctx context.Context, view cm.BorrowedView, sink cm.CredentialSink) error { _ = view.Len(); return view.WriteTo(ctx, sink) }\n",
		},
		{
			name:       "exact transport retained fields remain independently forbidden",
			source:     "package fixture\nimport (\"context\"; cm \"" + credentialMemoryPath + "\")\ntype borrowedPayloadView struct{ owner cm.BorrowedView; canonicalLength, offset, length int }; type payloadSlicingSink struct{ ctx context.Context; sink cm.CredentialSink; canonicalLength, offset, length int }; func (view borrowedPayloadView) WriteTo(ctx context.Context, sink cm.CredentialSink) error { return view.owner.WriteTo(ctx, &payloadSlicingSink{ctx: ctx, sink: sink, canonicalLength: view.canonicalLength, offset: view.offset, length: view.length}) }\n",
			wantIssues: 2,
		},
		{
			name:       "lookalike slicing sink forwarding is rejected",
			source:     "package fixture\nimport (\"context\"; cm \"" + credentialMemoryPath + "\")\ntype lookalikeView struct{ owner cm.BorrowedView }; type payloadSlicingSink struct{ ctx context.Context; sink cm.CredentialSink }; func (view lookalikeView) WriteTo(ctx context.Context, sink cm.CredentialSink) error { return view.owner.WriteTo(ctx, &payloadSlicingSink{ctx: ctx, sink: sink}) }\n",
			wantIssues: 3,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			issues := l8D2ReadinessRetainedScopedTypeIssues(map[string]*ast.File{"fixture.go": file})
			if len(issues) != test.wantIssues {
				t.Fatalf("issues = %v, want %d", issues, test.wantIssues)
			}
		})
	}
	first, err := parser.ParseFile(token.NewFileSet(), "first.go", "package fixture\nimport cm \""+credentialMemoryPath+"\"\nvar source cm.BorrowedView\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parser.ParseFile(token.NewFileSet(), "second.go", "package fixture\nvar retained = source\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	if issues := l8D2ReadinessRetainedScopedTypeIssues(map[string]*ast.File{"first.go": first, "second.go": second}); len(issues) != 2 {
		t.Fatalf("cross-file global alias issues = %v, want 2", issues)
	}
}

func TestL8D2HelperServiceReadinessServiceASTGuardSelfTest(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		source       string
		construction bool
		serve        bool
		private      bool
		stdin        bool
	}{
		{
			name: "canonical constructor and one-shot",
			source: l8D2ReadinessServiceFixture(`
func NewService(options ServiceOptions) (*Service, error) {
	if !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) { return nil, ErrContractDependency }
	extensions := snapshotServiceExtensionEntries(options.Extensions)
	return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil
}

func (s *Service) Serve(ctx context.Context) (ServiceResult, error) {
	if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }
	s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock()
	return ServiceResult{}, nil
}`), construction: true, serve: true,
		},
		{
			name:   "canonical private authority chain",
			source: l8D2ReadinessCanonicalPrivateServiceFixture(), private: true,
		},
		{
			name:   "private handler omits body cleanup",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "bodyDestroyErr := body.Destroy(ctx);", "bodyDestroyErr := error(nil);", 1),
		},
		{
			name:   "private handler duplicates body cleanup",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "bodyDestroyErr := body.Destroy(ctx);", "bodyDestroyErr := body.Destroy(ctx); _ = body.Destroy(ctx);", 1),
		},
		{
			name:   "private handler omits plan cleanup",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "corePlan.destroy();", "", 1),
		},
		{
			name:   "private handler duplicates plan cleanup",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "corePlan.destroy();", "corePlan.destroy(); corePlan.destroy();", 1),
		},
		{
			name:   "private handler captures proposal before its error gate",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "if proposalErr != nil { return proposalErr }; pending = proposal", "pending = proposal; if proposalErr != nil { return proposalErr }", 1),
		},
		{
			name:   "private handler has disconnected recovery",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "recovered != nil", "false", 1),
		},
		{
			name:   "private handler silently swallows recovered panic",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "; serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError); serviceErr = ErrContractOwnership", "", 1),
		},
		{
			name:   "private handler shadows terminal reducer",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "var pending Proposal;", "newServiceResult := evilResult; var pending Proposal;", 1),
		},
		{
			name:   "private handler shadows sanitized error",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "var pending Proposal;", "ErrContractOwnership := rawError; var pending Proposal;", 1),
		},
		{
			name:   "private handler discards body destroy failure",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "bodyDestroyErr := body.Destroy(ctx);", "_ = body.Destroy(ctx); bodyDestroyErr := error(nil);", 1),
		},
		{
			name:   "canonical stdin authority chain",
			source: l8D2ReadinessCanonicalStdinServiceFixture(), stdin: true,
		},
		{
			name:   "stdin handler omits body cleanup",
			source: strings.Replace(l8D2ReadinessCanonicalStdinServiceFixture(), "bodyDestroyErr := body.Destroy(ctx);", "bodyDestroyErr := error(nil);", 1),
		},
		{
			name:   "stdin handler has disconnected recovery",
			source: strings.Replace(l8D2ReadinessCanonicalStdinServiceFixture(), "recovered != nil", "false", 1),
		},
		{
			name:   "stdin handler silently swallows recovered panic",
			source: strings.Replace(l8D2ReadinessCanonicalStdinServiceFixture(), "; serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError); serviceErr = ErrContractOwnership", "", 1),
		},
		{
			name:   "stdin handler discards body destroy failure",
			source: strings.Replace(l8D2ReadinessCanonicalStdinServiceFixture(), "bodyDestroyErr := body.Destroy(ctx);", "_ = body.Destroy(ctx); bodyDestroyErr := error(nil);", 1),
		},
		{
			name: "combined canonical constructor one-shot private and stdin topology",
			source: l8D2ReadinessServiceFixture(`
func NewService(options ServiceOptions) (*Service, error) {
	if !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) { return nil, ErrContractDependency }
	extensions := snapshotServiceExtensionEntries(options.Extensions)
	return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil
}
func (s *Service) Serve(ctx context.Context) (ServiceResult, error) {
	if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }
	s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock()
	if dispatchPrivate { return s.dispatchPrivate(ctx) }
	return s.dispatchStdin(ctx)
}
func (s *Service) dispatchPrivate(ctx context.Context) (ServiceResult, error) { packet, receiveErr := s.transport.Receive(ctx, request); if receiveErr != nil { return ServiceResult{}, receiveErr }; arm, ok := packet.ExecPrivate(); if !ok { return ServiceResult{}, errInvalid }; dispatch, dispatchErr := s.takeExecDispatch(arm.Revision()); if dispatchErr != nil { return ServiceResult{}, dispatchErr }; return s.private(ctx, packet.body, dispatch.transaction, dispatch.correlation, arm.observation, dispatch.comparison) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, correlation credentialprotocol.HelperExecTransactionCorrelation, obs credentialprotocol.HelperExecPrivateObservation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }
func (s *Service) dispatchStdin(ctx context.Context) (ServiceResult, error) { packet, receiveErr := s.transport.Receive(ctx, request); if receiveErr != nil { return ServiceResult{}, receiveErr }; arm, ok := packet.ExecStream(); if !ok { return ServiceResult{}, errInvalid }; dispatch, dispatchErr := s.takeExecDispatch(arm.Revision()); if dispatchErr != nil { return ServiceResult{}, dispatchErr }; return s.stdin(ctx, packet.body, dispatch.transaction, dispatch.correlation, arm.observation, dispatch.comparison) }
func (s *Service) stdin(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, correlation credentialprotocol.HelperExecTransactionCorrelation, obs credentialprotocol.HelperExecStreamObservation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedStdin(obs, view); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; coreErr := s.state.execution.WriteStdin(ctx, view, 0, false); if coreErr != nil { _ = proposal.Wipe(); return coreErr }; return proposal.Commit() }); return ServiceResult{}, nil }`), construction: true, serve: true, private: true, stdin: true,
		},
		{
			name: "unknown returned Service call invalidates topology",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return s.unknown(ctx) }
func (s *Service) unknown(ctx context.Context) (ServiceResult, error) { return ServiceResult{}, nil }`),
		},
		{
			name: "returned Service method value invalidates topology",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return s.unknown }
func (s *Service) unknown(ctx context.Context) (ServiceResult, error) { return ServiceResult{}, nil }`),
		},
		{
			name:   "escaped Service receiver invalidates topology",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); escape(s); return ServiceResult{}, nil }`),
		},
		{
			name:   "ignored dependency validation result",
			source: l8D2ReadinessServiceFixture(`func NewService(options ServiceOptions) (*Service, error) { configuredDependency(options.Core); configuredDependency(options.Transport); configuredDependency(options.Policy); configuredDependency(options.Host); configuredDependency(options.Runtime); extensions := snapshotServiceExtensionEntries(options.Extensions); return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil }`),
		},
		{
			name:   "dependency checks syntactically present but cannot reject",
			source: l8D2ReadinessServiceFixture(`func NewService(options ServiceOptions) (*Service, error) { if (!configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime)) && false { return nil, ErrContractDependency }; extensions := snapshotServiceExtensionEntries(options.Extensions); return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil }`),
		},
		{
			name:   "configured dependency helper shadowed in validation init",
			source: l8D2ReadinessServiceFixture(`func NewService(options ServiceOptions) (*Service, error) { if configuredDependency := func(any) bool { return true }; !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) { return nil, ErrContractDependency }; extensions := snapshotServiceExtensionEntries(options.Extensions); return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil }`),
		},
		{
			name:   "late dependency validation after storage",
			source: l8D2ReadinessServiceFixture(`func NewService(options ServiceOptions) (*Service, error) { service := &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: snapshotServiceExtensionEntries(options.Extensions), host: options.Host, runtime: options.Runtime, state: &serviceState{}}; if !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) { return nil, ErrContractDependency }; return service, nil }`),
		},
		{
			name:   "registry alias retained",
			source: l8D2ReadinessServiceFixture(`func NewService(options ServiceOptions) (*Service, error) { if !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) { return nil, ErrContractDependency }; extensions := options.Extensions.entries; return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil }`),
		},
		{
			name: "descriptor snapshot is shallow",
			source: strings.Replace(l8D2ReadinessServiceFixture(`func NewService(options ServiceOptions) (*Service, error) { if !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) { return nil, ErrContractDependency }; extensions := snapshotServiceExtensionEntries(options.Extensions); return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil }`),
				"credentialprotocol.CloneExtensionDescriptor(entry.descriptor)", "entry.descriptor", 1),
		},
		{
			name: "descriptor clone package is lookalike",
			source: strings.Replace(l8D2ReadinessServiceFixture(`func NewService(options ServiceOptions) (*Service, error) { if !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) { return nil, ErrContractDependency }; extensions := snapshotServiceExtensionEntries(options.Extensions); return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil }`),
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol", "example.invalid/lookalike", 1),
		},
		{
			name: "descriptor clone loop is unreachable after return",
			source: strings.Replace(l8D2ReadinessServiceFixture(`func NewService(options ServiceOptions) (*Service, error) { if !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) { return nil, ErrContractDependency }; extensions := snapshotServiceExtensionEntries(options.Extensions); return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil }`),
				"for index, entry := range registry.entries { result[index] = extensionEntry{descriptor: credentialprotocol.CloneExtensionDescriptor(entry.descriptor), factory: entry.factory} }; return result", "return result; for index, entry := range registry.entries { result[index] = extensionEntry{descriptor: credentialprotocol.CloneExtensionDescriptor(entry.descriptor), factory: entry.factory} }", 1),
		},
		{
			name:   "context check after latch",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; return ServiceResult{}, nil }`),
		},
		{
			name:   "distributed latch critical sections",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); called := s.state.serveCalled; s.state.mu.Unlock(); if called { return ServiceResult{}, ErrContractTransition }; s.state.mu.Lock(); s.state.serveCalled = true; s.state.mu.Unlock(); return ServiceResult{}, nil }`),
		},
		{
			name:   "out of lock latch",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; if s.state.serveCalled { return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; return ServiceResult{}, nil }`),
		},
		{
			name:   "latch reset after critical section",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); s.state.serveCalled = false; return ServiceResult{}, nil }`),
		},
		{
			name:   "context error is suppressed",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, nil }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return ServiceResult{}, nil }`),
		},
		{
			name:   "context rejection is syntactically present but cannot run",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil && false { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return ServiceResult{}, nil }`),
		},
		{
			name: "reachable helper resets latch through state alias",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return s.reset() }
func (s *Service) reset() (ServiceResult, error) { state := s.state; state.serveCalled = false; return ServiceResult{}, nil }`),
		},
		{
			name: "reachable helper replaces state",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return s.replace() }
func (s *Service) replace() (ServiceResult, error) { s.state = &serviceState{}; return ServiceResult{}, nil }`),
		},
		{
			name: "receiver alias reaches latch reset helper",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); self := s; return self.reset() }
func (s *Service) reset() (ServiceResult, error) { state := s.state; state.serveCalled = false; return ServiceResult{}, nil }`),
		},
		{
			name: "var-declared state alias resets latch",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return s.reset() }
func (s *Service) reset() (ServiceResult, error) { var state = s.state; state.serveCalled = false; return ServiceResult{}, nil }`),
		},
		{
			name: "state alias escapes in retained composite",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return s.escape() }
func (s *Service) escape() (ServiceResult, error) { holder := struct{ state *serviceState }{state: s.state}; _ = holder; return ServiceResult{}, nil }`),
		},
		{
			name: "state-field pointer resets latch",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return s.reset() }
func (s *Service) reset() (ServiceResult, error) { state := &s.state; (*state).serveCalled = false; return ServiceResult{}, nil }`),
		},
		{
			name: "copied Service resets shared latch",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); return s.reset() }
func (s *Service) reset() (ServiceResult, error) { copy := *s; copy.state.serveCalled = false; return ServiceResult{}, nil }`),
		},
		{
			name:   "constructor installs nonfresh state",
			source: strings.Replace(l8D2ReadinessServiceFixture(`func NewService(options ServiceOptions) (*Service, error) { if !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) { return nil, ErrContractDependency }; extensions := snapshotServiceExtensionEntries(options.Extensions); return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil }`), "state: &serviceState{}", "state: &serviceState{serveCalled: true}", 1),
		},
		{
			name: "unrelated names and proposal substitution",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return ServiceResult{}, unrelated.ProposeObservedPrivate() }
func (s *Service) private(body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation) error { return body.Borrow(context.Background(), func(view BorrowedView) error { p, _ := tx.ProposeObservedPrivate(obs); _, _ = foreign.BeginExec(context.Background(), request, view); q := p; _ = q.Commit(); r := p; return r.Wipe() }) }`),
		},
		{
			name: "proposal p q r substitution",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { p, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { q := p; return q.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { r := p; _ = r.Wipe(); return errInvalid }; s.state.execution = execution; q := p; return q.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "lookalike transaction type",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, fakeTx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *other.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "wrong begin receiver",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := foreign.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "foreign execution receiver",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.stdin(ctx, body, tx, obs, false) }
func (s *Service) stdin(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedStdin(obs, view); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; coreErr := foreignExecution.WriteStdin(ctx, view, 0, false); if coreErr != nil { _ = proposal.Wipe(); return coreErr }; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "core called in comparison",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, true) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { _, _ = s.core.BeginExec(ctx, request, view); return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "suffix lookalike body and view types",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body other.ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view other.BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "borrow uses unrelated context",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(context.Background(), func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "stdin proposal uses unrelated context",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.stdin(ctx, body, tx, obs, false) }
func (s *Service) stdin(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedStdin(context.Background(), correlation, obs, view); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; coreErr := s.state.execution.WriteStdin(ctx, view, 0, false); if coreErr != nil { proposal.Wipe(); return coreErr }; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "Core uses unrelated context",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(context.Background(), request, view); if coreErr != nil || !configuredDependency(execution) { proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "comparison commit falls through to Core",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, true) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { _ = proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "comparison lookalike local",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation) (ServiceResult, error) { comparison := false; _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "comparison lookalike bool parameter",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, replay bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if replay { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "comparison parameter is shadowed in callback",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, true) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { comparison := false; proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "callback context is shadowed",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { ctx := context.Background(); proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "private Core gate cannot reject",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if (coreErr != nil || !configuredDependency(execution)) && false { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "private Core gate uses AND",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil && !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "private Core gate shadows configured dependency helper",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); configuredDependency := func(any) bool { return true }; if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "private Core gate is nested under false branch",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if false { if coreErr != nil || !configuredDependency(execution) { proposal.Wipe(); return errInvalid } }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "stdin Core gate cannot reject",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.stdin(ctx, body, tx, obs, false) }
func (s *Service) stdin(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedStdin(obs, view); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; coreErr := s.state.execution.WriteStdin(ctx, view, 0, false); if coreErr != nil && false { _ = proposal.Wipe(); return coreErr }; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "proposal results are ignored",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { _ = proposal.Commit(); return nil }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; _ = proposal.Commit(); return nil }); return ServiceResult{}, nil }`),
		},
		{
			name: "wipe is omitted",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "outer borrow hidden under false branch",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { if false { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }) }; return ServiceResult{}, nil }`),
		},
		{
			name: "outer borrow error swallowed",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { borrowErr := body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); _ = borrowErr; return ServiceResult{}, nil }`),
		},
		{
			name: "extra outer Borrow call",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { extraErr := body.Borrow(ctx, func(view BorrowedView) error { return nil }); if extraErr != nil { return ServiceResult{}, extraErr }; _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "comparison commits before proposal error gate",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if comparison { return proposal.Commit() }; if proposalErr != nil { return proposalErr }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "foreign correlation and observation",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(foreignCorrelation, foreignObservation); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "zero correlation and observation",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(credentialprotocol.HelperExecTransactionCorrelation{}, credentialprotocol.HelperExecPrivateObservation{}); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "package global observation substitutes handler parameter",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, correlation, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, correlation credentialprotocol.HelperExecTransactionCorrelation, observation credentialprotocol.HelperExecPrivateObservation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(correlation, obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "observation parameter shadowed in callback",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { obs := credentialprotocol.HelperExecPrivateObservation{}; proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "proposal rebound through foreign same-name method",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); proposal, proposalErr = foreign.ProposeObservedPrivate(correlation, obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "extra unassigned propose and Core calls",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { tx.ProposeObservedPrivate(correlation, obs); proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; s.core.BeginExec(ctx, request, view); execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "execution retained before canonical rejection",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); s.state.execution = execution; if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "proposal error ignored and extra terminal call",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, _ := tx.ProposeObservedPrivate(obs); proposal.Wipe(); if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "reachable direct state method can reset latch",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); s.state.reset(); return ServiceResult{}, nil }
func (state *serviceState) reset() { state.serveCalled = false }`),
		},
		{
			name: "reachable wrapped state method can reset latch",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if err := transportContextPrecondition(ctx); err != nil { return ServiceResult{}, err }; s.state.mu.Lock(); if s.state.serveCalled { s.state.mu.Unlock(); return ServiceResult{}, ErrContractTransition }; s.state.serveCalled = true; s.state.mu.Unlock(); (*(&s.state)).reset(); return ServiceResult{}, nil }
func (state *serviceState) reset() { state.serveCalled = false }`),
		},
		{
			name: "dead returned handler call",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { if false { return s.private(ctx, body, tx, obs, false) }; return ServiceResult{}, nil }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "handler method value is not a call edge",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { handler := s.private; _ = handler; return ServiceResult{}, nil }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "discarded noncontrolling handler result",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { s.private(ctx, body, tx, obs, false); return ServiceResult{}, nil }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "handler result assigned but not propagated",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { result, err := s.private(ctx, body, tx, obs, false); _, _ = result, err; return ServiceResult{}, nil }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "handler call after unconditional return",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return ServiceResult{}, nil; return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "extra terminal hidden in IIFE",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; func() { proposal.Commit() }(); if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "terminal method value hidden in callback",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; terminal := proposal.Commit; _ = terminal; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "extra terminal hidden in deferred closure",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; defer func() { proposal.Wipe() }(); if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name: "extra terminal hidden in goroutine closure",
			source: l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.private(ctx, body, tx, obs, false) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; go func() { proposal.Commit() }(); if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`),
		},
		{
			name:   "matching arm dispatch uses foreign packet body",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "packet.body, dispatch.transaction", "foreign.body, dispatch.transaction", 1),
		},
		{
			name:   "matching arm dispatch uses cross arm",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "packet.ExecPrivate()", "packet.ExecStream()", 1),
		},
		{
			name:   "matching arm dispatch uses zero observation",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "arm.observation, dispatch.comparison", "credentialprotocol.HelperExecPrivateObservation{}, dispatch.comparison", 1),
		},
		{
			name:   "matching arm dispatch uses foreign correlation",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "dispatch.correlation, arm.observation", "foreign.correlation, arm.observation", 1),
		},
		{
			name:   "matching arm dispatch uses background context",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "return s.private(ctx,", "return s.private(context.Background(),", 1),
		},
		{
			name: "matching arm local rebound before handler",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(),
				"if dispatchErr != nil { return ServiceResult{}, dispatchErr }; return s.private", "if dispatchErr != nil { return ServiceResult{}, dispatchErr }; arm = ReceivedExecPrivate{}; return s.private", 1),
		},
		{
			name:   "parent dispatcher substitutes background context",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "return s.dispatchPrivate(ctx)", "return s.dispatchPrivate(context.Background())", 1),
		},
		{
			name: "parent dispatcher receiver alias is reassigned",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(),
				"return s.dispatchPrivate(ctx)", "self := s; self = foreignService; return self.dispatchPrivate(ctx)", 1),
		},
		{
			name: "parent dispatcher receiver is reassigned",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(),
				"return s.dispatchPrivate(ctx)", "s = foreignService; return s.dispatchPrivate(ctx)", 1),
		},
		{
			name: "parent dispatcher receiver alias is shadowed",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(),
				"return s.dispatchPrivate(ctx)", "self := s; if true { self := foreignService; return self.dispatchPrivate(ctx) }; return self.dispatchPrivate(ctx)", 1),
		},
		{
			name:   "parent dispatcher uses parenthesized unknown receiver",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "return s.dispatchPrivate(ctx)", "return (s).unknown(ctx)", 1),
		},
		{
			name:   "parent dispatcher uses dereferenced unknown receiver",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "return s.dispatchPrivate(ctx)", "return (*(&s)).unknown(ctx)", 1),
		},
		{
			name:   "parent dispatcher exposes converted receiver method",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "return s.dispatchPrivate(ctx)", "return ServiceAlias(s).unknown(ctx)", 1),
		},
		{
			name:   "valid dispatch plus unknown Service call invalidates whole topology",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "return s.dispatchPrivate(ctx)", "s.unknown(ctx); return s.dispatchPrivate(ctx)", 1),
		},
		{
			name:   "private handler reassigns configured core before use",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "execution, coreErr := s.core.BeginExec", "s.core = foreignCore; execution, coreErr := s.core.BeginExec", 1),
		},
		{
			name:   "dispatcher reassigns configured transport before use",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "packet, receiveErr := s.transport.Receive", "s.transport = foreignTransport; packet, receiveErr := s.transport.Receive", 1),
		},
		{
			name:   "reachable helper replaces configured core through Service alias",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "return s.dispatchPrivate(ctx)", "self := s; self.core = foreignCore; return self.dispatchPrivate(ctx)", 1),
		},
		{
			name:   "configured core address escapes to helper",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "return s.dispatchPrivate(ctx)", "mutate(&s.core); return s.dispatchPrivate(ctx)", 1),
		},
		{
			name:   "configured transport address retained in composite",
			source: strings.Replace(l8D2ReadinessCanonicalPrivateServiceFixture(), "return s.dispatchPrivate(ctx)", "holder := struct{ dependency *Transport }{dependency: &s.transport}; _ = holder; return s.dispatchPrivate(ctx)", 1),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			analysis := l8D2ReadinessAnalyzeServiceAST(map[string]*ast.File{"fixture.go": file})
			if analysis.construction != test.construction || analysis.serveOneShot != test.serve || analysis.privateSequence != test.private || analysis.stdinSequence != test.stdin {
				t.Fatalf("analysis = %+v, want construction=%t serve=%t private=%t stdin=%t", analysis, test.construction, test.serve, test.private, test.stdin)
			}
		})
	}
}

func TestL8D2HelperServiceReadinessStateLedgerGuardSelfTest(t *testing.T) {
	t.Parallel()
	canonical := `package fixture
import ("context"; "sync"; credentialprotocol "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol")
type CoreExecution interface{ WriteStdin(context.Context, any, uint64, bool) error; Probe() }
type Core interface{ BeginExec(context.Context, any, any) (CoreExecution, error) }
type ExecPlanCapability struct{}; func (ExecPlanCapability) destroy() {}
type serviceExecDispatch struct{ transaction *credentialprotocol.HelperExecTransaction; correlation credentialprotocol.HelperExecTransactionCorrelation; comparison bool }
type serviceState struct{ mu sync.Mutex; serveCalled bool; execution CoreExecution; request any; plan ExecPlanCapability; revision uint64; transaction *credentialprotocol.HelperExecTransaction; correlation credentialprotocol.HelperExecTransactionCorrelation; comparison bool; dispatchTaken bool }
type Service struct{ core Core; state *serviceState }
var errInvalid error; func configuredDependency(any) bool { return true }
func (s *Service) Serve(context.Context) error { return nil }
func (s *Service) takeExecDispatch(revision uint64) (serviceExecDispatch, error) {
	s.state.mu.Lock()
	if revision != s.state.revision || s.state.dispatchTaken { s.state.mu.Unlock(); return serviceExecDispatch{}, errInvalid }
	transaction := s.state.transaction
	correlation := s.state.correlation
	comparison := s.state.comparison
	s.state.dispatchTaken = true
	s.state.mu.Unlock()
	return serviceExecDispatch{transaction: transaction, correlation: correlation, comparison: comparison}, nil
}
func (s *Service) private(ctx context.Context) error {
	s.state.mu.Lock()
	request := s.state.request
	plan := s.state.plan
	s.state.mu.Unlock()
	execution, coreErr := s.core.BeginExec(ctx, request, nil)
	plan.destroy()
	if coreErr != nil || !configuredDependency(execution) { return errInvalid }
	s.state.mu.Lock()
	s.state.execution = execution
	s.state.mu.Unlock()
	return nil
}
func (s *Service) stdin(ctx context.Context, view any) error {
	s.state.mu.Lock()
	execution := s.state.execution
	s.state.mu.Unlock()
	return execution.WriteStdin(ctx, view, 0, false)
}`
	for _, test := range []struct {
		name   string
		source string
		want   bool
	}{
		{name: "canonical mutex-bound value-copy and take", source: canonical, want: true},
		{name: "unlocked ledger read", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "request := s.state.request\n\ts.state.mu.Lock()", 1)},
		{name: "unlocked revision gate", source: strings.Replace(canonical, "s.state.mu.Lock()\n\tif revision", "if revision", 1)},
		{name: "dead lock does not authorize ledger read", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "if false { s.state.mu.Lock() }; request := s.state.request", 1)},
		{name: "conditional unlock falls through before ledger read", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "s.state.mu.Lock()\n\tif maybe { s.state.mu.Unlock() }\n\trequest := s.state.request", 1)},
		{name: "early return omits unlock", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "s.state.mu.Lock()\n\tif maybe { return errInvalid }\n\trequest := s.state.request", 1)},
		{name: "critical rejection condition calls panic-capable helper", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "s.state.mu.Lock()\n\tif helperBool() { s.state.mu.Unlock(); return errInvalid }\n\trequest := s.state.request", 1)},
		{name: "critical rejection condition can panic while indexing", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "s.state.mu.Lock()\n\tif flags[index] { s.state.mu.Unlock(); return errInvalid }\n\trequest := s.state.request", 1)},
		{name: "critical assignment can panic before unlock", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "s.state.mu.Lock()\n\tprobe := values[index]\n\t_ = probe\n\trequest := s.state.request", 1)},
		{name: "critical assignment target can panic before unlock", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "s.state.mu.Lock()\n\tvalues[index] = true\n\trequest := s.state.request", 1)},
		{name: "critical rejection else path panics before unlock", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "s.state.mu.Lock()\n\tif maybe { s.state.mu.Unlock(); return errInvalid } else { panic(errInvalid) }\n\trequest := s.state.request", 1)},
		{name: "nested panic omits unlock", source: strings.Replace(canonical, "s.state.mu.Lock()\n\trequest := s.state.request", "s.state.mu.Lock()\n\tif maybe { panic(errInvalid) }\n\trequest := s.state.request", 1)},
		{name: "terminal after take latch omits unlock", source: strings.Replace(canonical, "s.state.dispatchTaken = true\n\ts.state.mu.Unlock()", "s.state.dispatchTaken = true\n\tif maybe { panic(errInvalid) }\n\ts.state.mu.Unlock()", 1)},
		{name: "success path omits unlock", source: strings.Replace(canonical, "s.state.mu.Unlock()\n\texecution, coreErr := s.core.BeginExec", "execution, coreErr := s.core.BeginExec", 1)},
		{name: "success path unlocks twice", source: strings.Replace(canonical, "s.state.mu.Unlock()\n\texecution, coreErr := s.core.BeginExec", "s.state.mu.Unlock()\n\ts.state.mu.Unlock()\n\texecution, coreErr := s.core.BeginExec", 1)},
		{name: "wrong revision source", source: strings.Replace(canonical, "revision != s.state.revision", "revision != foreignRevision", 1)},
		{name: "noncontrolling take gate", source: strings.Replace(canonical, "revision != s.state.revision || s.state.dispatchTaken", "(revision != s.state.revision || s.state.dispatchTaken) && false", 1)},
		{name: "empty take rejection body", source: strings.Replace(canonical, "{ s.state.mu.Unlock(); return serviceExecDispatch{}, errInvalid }", "{}", 1)},
		{name: "duplicate take", source: strings.Replace(canonical, "s.state.dispatchTaken = true", "s.state.dispatchTaken = true\n\ts.state.dispatchTaken = true", 1)},
		{name: "dispatch return swaps entry values", source: strings.Replace(canonical, "transaction: transaction, correlation: correlation", "transaction: correlation, correlation: transaction", 1)},
		{name: "global request substitution", source: strings.Replace(canonical, "request := s.state.request", "request := globalRequest", 1)},
		{name: "state field address escape", source: strings.Replace(canonical, "request := s.state.request", "request := &s.state.request", 1)},
		{name: "state value passed to arbitrary helper", source: strings.Replace(canonical, "request := s.state.request", "request := helper(s.state.request)", 1)},
		{name: "copied state value passed to arbitrary helper", source: strings.Replace(canonical, "execution, coreErr := s.core.BeginExec", "helper(request); execution, coreErr := s.core.BeginExec", 1)},
		{name: "copied state value address escapes", source: strings.Replace(canonical, "execution, coreErr := s.core.BeginExec", "helper(&request); execution, coreErr := s.core.BeginExec", 1)},
		{name: "foreign execution overwrites validated Core result", source: strings.Replace(canonical, "s.state.execution = execution", "s.state.execution = foreignExecution", 1)},
		{name: "duplicate execution overwrite", source: strings.Replace(canonical, "s.state.execution = execution", "s.state.execution = execution\n\ts.state.execution = foreignExecution", 1)},
		{name: "validated execution address escapes", source: strings.Replace(canonical, "s.state.mu.Lock()\n\ts.state.execution = execution", "helper(&execution)\n\ts.state.mu.Lock()\n\ts.state.execution = execution", 1)},
		{name: "validated execution escapes to global before gate", source: strings.Replace(canonical, "if coreErr != nil || !configuredDependency(execution)", "globalExecution = execution\n\tif coreErr != nil || !configuredDependency(execution)", 1)},
		{name: "validated execution receiver used before gate", source: strings.Replace(canonical, "if coreErr != nil || !configuredDependency(execution)", "execution.Probe()\n\tif coreErr != nil || !configuredDependency(execution)", 1)},
		{name: "validated execution inspected before gate", source: strings.Replace(canonical, "if coreErr != nil || !configuredDependency(execution)", "switch execution {}\n\tif coreErr != nil || !configuredDependency(execution)", 1)},
		{name: "copied execution is rebound before Core", source: strings.Replace(canonical, "return execution.WriteStdin", "execution = foreignExecution; return execution.WriteStdin", 1)},
		{name: "cross-entry correlation", source: strings.Replace(canonical, "correlation := s.state.correlation", "correlation := other.state.correlation", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			reachable := make(map[*ast.FuncDecl]bool)
			var serve *ast.FuncDecl
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Recv == nil {
					continue
				}
				reachable[function] = true
				if function.Name.Name == "Serve" {
					serve = function
				}
			}
			if got := l8D2ReadinessReachableServiceStateStable(reachable, serve); got != test.want {
				t.Fatalf("state stability = %t, want %t", got, test.want)
			}
		})
	}
}

func TestL8D2HelperServiceReadinessZeroPrivateExecGuardSelfTest(t *testing.T) {
	t.Parallel()
	canonical := `package fixture
import "context"
type Core interface{ BeginExec(context.Context, any, any)(CoreExecution,error) }; type CoreExecution interface{}
type ReceivedExec struct{}; func (ReceivedExec) PrivateBindingLength() uint32{return 0}; func (ReceivedExec) PrivateBindingSHA256()[32]byte{return [32]byte{}}; func (ReceivedExec) ExecPrivate(){}
type ReceivedPacket struct{}; func (ReceivedPacket) Exec()(ReceivedExec,bool){return ReceivedExec{},true}
type mutex struct{}; func (*mutex) Lock(){}; func (*mutex) Unlock(){}
type ExecPlanCapability struct{}; func (ExecPlanCapability) destroy(){}; type serviceState struct{ mu mutex; request any; plan ExecPlanCapability; execution CoreExecution }; type Service struct{ core Core; state *serviceState }; type ServiceResult struct{}
var errInvalid error; var foreignArm ReceivedExec; var foreignPacket ReceivedPacket; func configuredDependency(any)bool{return true}; func helperCore(any){}
func (s *Service) zeroPrivate(ctx context.Context, packet ReceivedPacket, comparison bool)(ServiceResult,error){
	arm, ok := packet.Exec(); if !ok { return ServiceResult{}, errInvalid }
	if arm.PrivateBindingLength() == 0 && arm.PrivateBindingSHA256() == ([32]byte{}) {
		if comparison { return ServiceResult{}, nil }
		s.state.mu.Lock(); stateRequest := s.state.request; statePlan := s.state.plan; s.state.mu.Unlock()
		execution, coreErr := s.core.BeginExec(ctx, stateRequest, nil)
		statePlan.destroy()
		if coreErr != nil || !configuredDependency(execution) { return ServiceResult{}, errInvalid }
		s.state.mu.Lock(); s.state.execution = execution; s.state.mu.Unlock()
		return ServiceResult{}, nil
	}
	return ServiceResult{}, errInvalid
}`
	for _, test := range []struct {
		name   string
		source string
		want   bool
	}{
		{name: "canonical literal nil state-backed path", source: canonical, want: true},
		{name: "typed nil substitute", source: strings.Replace(canonical, "s.core.BeginExec(ctx, stateRequest, nil)", "s.core.BeginExec(ctx, stateRequest, nilView)", 1)},
		{name: "background context substitute", source: strings.Replace(canonical, "s.core.BeginExec(ctx, stateRequest, nil)", "s.core.BeginExec(context.Background(), stateRequest, nil)", 1)},
		{name: "global request", source: strings.Replace(canonical, "s.core.BeginExec(ctx, stateRequest, nil)", "s.core.BeginExec(ctx, globalRequest, nil)", 1)},
		{name: "cross-arm zero digest", source: strings.Replace(canonical, "arm.PrivateBindingSHA256()", "foreign.PrivateBindingSHA256()", 1)},
		{name: "foreign arm extraction", source: strings.Replace(canonical, "arm, ok := packet.Exec()", "arm, ok := foreignPacket.Exec()", 1)},
		{name: "foreign arm substitution after extraction", source: strings.Replace(canonical, "if arm.PrivateBindingLength()", "arm = foreignArm; if arm.PrivateBindingLength()", 1)},
		{name: "comparison path calls Core", source: strings.Replace(canonical, "if comparison { return ServiceResult{}, nil }", "if comparison { _, _ = s.core.BeginExec(ctx, stateRequest, nil); return ServiceResult{}, nil }", 1)},
		{name: "comparison path returns rejection instead of accepted terminal", source: strings.Replace(canonical, "if comparison { return ServiceResult{}, nil }", "if comparison { return ServiceResult{}, errInvalid }", 1)},
		{name: "comparison path passes Core to indirect helper", source: strings.Replace(canonical, "if comparison { return ServiceResult{}, nil }", "if comparison { helperCore(s.core); return ServiceResult{}, nil }", 1)},
		{name: "comparison path retains Core method value", source: strings.Replace(canonical, "if comparison { return ServiceResult{}, nil }", "if comparison { begin := s.core.BeginExec; _ = begin; return ServiceResult{}, nil }", 1)},
		{name: "comparison path aliases Core authority", source: strings.Replace(canonical, "if comparison { return ServiceResult{}, nil }", "if comparison { authority := s.core; _ = authority; return ServiceResult{}, nil }", 1)},
		{name: "private wait in zero path", source: strings.Replace(canonical, "execution, coreErr :=", "arm.ExecPrivate(); execution, coreErr :=", 1)},
		{name: "observed Borrow in zero path", source: strings.Replace(canonical, "execution, coreErr :=", "body.Borrow(ctx, callback); execution, coreErr :=", 1)},
		{name: "unlocked execution retention", source: strings.Replace(canonical, "s.state.mu.Lock(); s.state.execution = execution; s.state.mu.Unlock()", "s.state.execution = execution", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			var function *ast.FuncDecl
			for _, declaration := range file.Decls {
				candidate, ok := declaration.(*ast.FuncDecl)
				if ok && candidate.Name.Name == "zeroPrivate" {
					function = candidate
				}
			}
			got := function != nil && l8D2ReadinessZeroPrivateExecStable(map[*ast.FuncDecl]bool{function: true}) && l8D2ReadinessServiceMethodStateStable(function, nil)
			if got != test.want {
				t.Fatalf("zero-private stability = %t, want %t", got, test.want)
			}
		})
	}
}

func l8D2ReadinessCanonicalPrivateServiceFixture() string {
	return l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.dispatchPrivate(ctx) }
func (s *Service) dispatchPrivate(ctx context.Context) (ServiceResult, error) { packet, receiveErr := s.transport.Receive(ctx, request); if receiveErr != nil { return ServiceResult{}, receiveErr }; arm, ok := packet.ExecPrivate(); if !ok { return ServiceResult{}, errInvalid }; dispatch, dispatchErr := s.takeExecDispatch(arm.Revision()); if dispatchErr != nil { return ServiceResult{}, dispatchErr }; return s.private(ctx, packet.body, dispatch.transaction, dispatch.correlation, arm.observation, dispatch.comparison) }
func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedPrivate(obs); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; execution, coreErr := s.core.BeginExec(ctx, request, view); if coreErr != nil || !configuredDependency(execution) { _ = proposal.Wipe(); return errInvalid }; s.state.execution = execution; return proposal.Commit() }); return ServiceResult{}, nil }`)
}

func l8D2ReadinessCanonicalStdinServiceFixture() string {
	return l8D2ReadinessServiceFixture(`func (s *Service) Serve(ctx context.Context) (ServiceResult, error) { return s.dispatchStdin(ctx) }
func (s *Service) dispatchStdin(ctx context.Context) (ServiceResult, error) { packet, receiveErr := s.transport.Receive(ctx, request); if receiveErr != nil { return ServiceResult{}, receiveErr }; arm, ok := packet.ExecStream(); if !ok { return ServiceResult{}, errInvalid }; dispatch, dispatchErr := s.takeExecDispatch(arm.Revision()); if dispatchErr != nil { return ServiceResult{}, dispatchErr }; return s.stdin(ctx, packet.body, dispatch.transaction, dispatch.correlation, arm.observation, dispatch.comparison) }
func (s *Service) stdin(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, obs Observation, comparison bool) (ServiceResult, error) { _ = body.Borrow(ctx, func(view BorrowedView) error { proposal, proposalErr := tx.ProposeObservedStdin(obs, view); if proposalErr != nil { return proposalErr }; if comparison { return proposal.Commit() }; coreErr := s.state.execution.WriteStdin(ctx, view, 0, false); if coreErr != nil { _ = proposal.Wipe(); return coreErr }; return proposal.Commit() }); return ServiceResult{}, nil }`)
}

func l8D2ReadinessServiceFixture(declarations string) string {
	declarations = strings.ReplaceAll(declarations, "s.private(ctx, body, tx, obs", "s.private(ctx, body, tx, correlation, obs")
	declarations = strings.ReplaceAll(declarations, "s.private(ctx, body, fakeTx, obs", "s.private(ctx, body, fakeTx, correlation, obs")
	declarations = strings.ReplaceAll(declarations, "s.stdin(ctx, body, tx, obs", "s.stdin(ctx, body, tx, correlation, obs")
	if strings.Contains(declarations, "func (s *Service) stdin") {
		declarations = strings.ReplaceAll(declarations, "obs Observation", "correlation credentialprotocol.HelperExecTransactionCorrelation, obs credentialprotocol.HelperExecStreamObservation")
	} else {
		declarations = strings.ReplaceAll(declarations, "obs Observation", "correlation credentialprotocol.HelperExecTransactionCorrelation, obs credentialprotocol.HelperExecPrivateObservation")
	}
	declarations = strings.ReplaceAll(declarations, "func(view BorrowedView)", "func(view credentialmemory.BorrowedView)")
	declarations = strings.ReplaceAll(declarations, "ProposeObservedPrivate(obs)", "ProposeObservedPrivate(correlation, obs)")
	declarations = strings.ReplaceAll(declarations, "ProposeObservedStdin(obs, view)", "ProposeObservedStdin(ctx, correlation, obs, view)")
	declarations = strings.ReplaceAll(declarations, "_ = body.Borrow(", "borrowErr := body.Borrow(")
	declarations = strings.ReplaceAll(declarations, "}); return ServiceResult{}, nil", "}); if borrowErr != nil { return ServiceResult{}, borrowErr }; return ServiceResult{}, nil")
	declarations = strings.ReplaceAll(declarations, "_ = proposal.Wipe(); return errInvalid", "proposal.Wipe(); return errInvalid")
	declarations = strings.ReplaceAll(declarations, "_ = proposal.Wipe(); return coreErr", "proposal.Wipe(); return coreErr")
	decorateHandler := func(name string, transform func(string) string) {
		marker := "func (s *Service) " + name
		start := strings.Index(declarations, marker)
		if start < 0 {
			return
		}
		end := strings.Index(declarations[start+len(marker):], "\nfunc ")
		if end < 0 {
			end = len(declarations)
		} else {
			end += start + len(marker)
		}
		declarations = declarations[:start] + transform(declarations[start:end]) + declarations[end:]
	}
	decorateHandler("private", func(handler string) string {
		handler = strings.ReplaceAll(handler, "(ServiceResult, error) { borrowErr := body.Borrow", "(serviceResult ServiceResult, serviceErr error) { s.state.mu.Lock(); coreRequest := s.state.request; corePlan := s.state.plan; s.state.mu.Unlock(); var pending Proposal; defer func() { if recovered := recover(); recovered != nil { if pending != nil { pending.Wipe() }; serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError); serviceErr = ErrContractOwnership }; bodyDestroyErr := body.Destroy(ctx); corePlan.destroy(); if bodyDestroyErr != nil { serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError); serviceErr = ErrContractOwnership } }(); borrowErr := body.Borrow")
		handler = strings.ReplaceAll(handler, "s.core.BeginExec(ctx, request, view)", "s.core.BeginExec(ctx, coreRequest, view)")
		return strings.ReplaceAll(handler, "if proposalErr != nil { return proposalErr }; if comparison", "if proposalErr != nil { return proposalErr }; pending = proposal; if comparison")
	})
	decorateHandler("stdin", func(handler string) string {
		handler = strings.ReplaceAll(handler, "(ServiceResult, error) { borrowErr := body.Borrow", "(serviceResult ServiceResult, serviceErr error) { var pending Proposal; defer func() { if recovered := recover(); recovered != nil { if pending != nil { pending.Wipe() }; serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError); serviceErr = ErrContractOwnership }; bodyDestroyErr := body.Destroy(ctx); if bodyDestroyErr != nil { serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError); serviceErr = ErrContractOwnership } }(); borrowErr := body.Borrow")
		return strings.ReplaceAll(handler, "if proposalErr != nil { return proposalErr }; if comparison", "if proposalErr != nil { return proposalErr }; pending = proposal; if comparison")
	})
	declarations = strings.ReplaceAll(declarations, "s.state.execution = execution", "s.state.mu.Lock(); s.state.execution = execution; s.state.mu.Unlock()")
	declarations = strings.ReplaceAll(declarations, "coreErr := s.state.execution.WriteStdin", "s.state.mu.Lock(); retainedExecution := s.state.execution; s.state.mu.Unlock(); coreErr := retainedExecution.WriteStdin")
	return `package fixture
import ("context"; "sync"; credentialmemory "github.com/jywlabs/hal/internal/credentialmemory"; credentialprotocol "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol")
type Core interface{ BeginExec(context.Context, any, credentialmemory.BorrowedView) (CoreExecution, error) }; type CoreExecution interface{ WriteStdin(context.Context, credentialmemory.BorrowedView, uint64, bool) error }; type ExecPlanCapability struct{}; func (ExecPlanCapability) destroy(){}; type Transport interface{ Receive(context.Context, any) (ReceivedPacket, error) }; type Policy interface{}; type ExtensionHost interface{}; type ServiceRuntime interface{}; type ReceivedBodyCapability interface{ Borrow(context.Context, func(credentialmemory.BorrowedView) error) error; Destroy(context.Context) error }; type Proposal interface{ Commit() error; Wipe() error }; type Observation struct{}; type ReceivedExecPrivate struct{ observation credentialprotocol.HelperExecPrivateObservation }; func (ReceivedExecPrivate) Revision() uint64{return 1}; type ReceivedExecStream struct{ observation credentialprotocol.HelperExecStreamObservation }; func (ReceivedExecStream) Revision() uint64{return 1}; type ReceivedPacket struct{ body ReceivedBodyCapability }; func (ReceivedPacket) ExecPrivate()(ReceivedExecPrivate,bool){return ReceivedExecPrivate{},true}; func (ReceivedPacket) ExecStream()(ReceivedExecStream,bool){return ReceivedExecStream{},true}; type serviceExecDispatch struct{ transaction *credentialprotocol.HelperExecTransaction; correlation credentialprotocol.HelperExecTransactionCorrelation; comparison bool }; type descriptor struct{}; type extensionEntry struct{ descriptor descriptor; factory any }; type ExtensionRegistry struct{ entries []extensionEntry }; type ServiceOptions struct{ Core Core; Transport Transport; Policy Policy; Extensions *ExtensionRegistry; Host ExtensionHost; Runtime ServiceRuntime }; type serviceState struct{ mu sync.Mutex; serveCalled bool; execution CoreExecution; request any; plan ExecPlanCapability }; type Service struct{ core Core; transport Transport; policy Policy; extensions []extensionEntry; host ExtensionHost; runtime ServiceRuntime; state *serviceState }; func (s *Service) takeExecDispatch(uint64)(serviceExecDispatch,error){return serviceExecDispatch{},nil}; type ServiceDisposition uint8; const (ServiceClosed ServiceDisposition = 1; ServiceStopVMRequired ServiceDisposition = 2); type ServiceResult struct{ disposition ServiceDisposition; closeReason credentialprotocol.CloseReason }; func ValidateServiceDisposition(ServiceDisposition) error{return nil}; func newServiceResult(disposition ServiceDisposition, closeReason credentialprotocol.CloseReason)(ServiceResult,error){ if ValidateServiceDisposition(disposition) != nil || credentialprotocol.ValidateCloseReason(closeReason) != nil { return ServiceResult{}, ErrContractInvalidArgument }; clean := disposition == ServiceClosed && (closeReason == credentialprotocol.CloseReasonNormal || closeReason == credentialprotocol.CloseReasonShutdown); stop := disposition == ServiceStopVMRequired && (closeReason == credentialprotocol.CloseReasonProtocolError || closeReason == credentialprotocol.CloseReasonIdentityDrift || closeReason == credentialprotocol.CloseReasonExpired || closeReason == credentialprotocol.CloseReasonHelperLoss); if !clean && !stop { return ServiceResult{}, ErrContractResultMatrix }; return ServiceResult{disposition: disposition, closeReason: closeReason}, nil }; var errInvalid, ErrContractInvalidArgument, ErrContractResultMatrix, ErrContractDependency, ErrContractTransition, ErrContractOwnership error; var unrelated, foreign any; var foreignExecution CoreExecution; var foreignCore Core; var foreignTransport Transport; var foreignService *Service; var body ReceivedBodyCapability; var tx *credentialprotocol.HelperExecTransaction; var fakeTx *other.HelperExecTransaction; var obs Observation; var correlation credentialprotocol.HelperExecTransactionCorrelation; var request any; var ctx context.Context; func configuredDependency(any) bool{return true}; func transportContextPrecondition(context.Context) error{return nil}; func snapshotServiceExtensionEntries(registry *ExtensionRegistry) []extensionEntry { if registry == nil { return nil }; result := make([]extensionEntry, len(registry.entries)); for index, entry := range registry.entries { result[index] = extensionEntry{descriptor: credentialprotocol.CloneExtensionDescriptor(entry.descriptor), factory: entry.factory} }; return result }
` + declarations
}

type l8D2ReadinessServiceASTAnalysis struct {
	construction        bool
	serveOneShot        bool
	privateSequence     bool
	stdinSequence       bool
	zeroPrivateSequence bool
}

func assertL8D2ReadinessServiceStructuralBoundaries(t *testing.T, dir string) {
	t.Helper()
	allFiles := make(map[string]*ast.File)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		allFiles[path] = file
	}
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var files map[string]*ast.File
	for _, pkg := range packages {
		files = pkg.Files
		break
	}
	if !l8D2ReadinessExactServiceResultReducerAcrossBuilds(dir, allFiles) {
		t.Error("newServiceResult must be the unique exact package reducer for the frozen disposition/close-reason matrix")
	}
	analysis := l8D2ReadinessAnalyzeServiceAST(files)
	if !analysis.construction {
		t.Error("NewService must immediately reject all five invalid configured dependencies and store one owned canonical extension snapshot plus fresh state without caller aliases")
	}
	if !analysis.serveOneShot {
		t.Error("Serve must classify context first and atomically check/set serveCalled in one exact state mutex critical section before dependency calls")
	}
	if !analysis.privateSequence || !analysis.zeroPrivateSequence {
		t.Error("Serve-reachable private wiring must bind one ReceivedBodyCapability.Borrow view and one observed proposal to Service.core.BeginExec, its exact return matrix, Commit/Wipe, comparison no-Core, and retained execution owner")
	}
	if !analysis.stdinSequence {
		t.Error("Serve-reachable stdin wiring must bind one ReceivedBodyCapability.Borrow view and one observed proposal to the Service-owned CoreExecution.WriteStdin result, Commit/Wipe, and comparison no-Core")
	}
}

func l8D2ReadinessExactServiceResultReducer(files map[string]*ast.File) bool {
	const protocolPath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	var reducer *ast.FuncDecl
	var reducerAliases map[string]string
	declarations := 0
	for _, file := range files {
		aliases, _ := l8D2ReadinessImportAliases(file)
		for _, declaration := range file.Decls {
			switch value := declaration.(type) {
			case *ast.FuncDecl:
				if value.Name.Name == "newServiceResult" {
					declarations++
					reducer, reducerAliases = value, aliases
				}
			case *ast.GenDecl:
				for _, specification := range value.Specs {
					switch candidate := specification.(type) {
					case *ast.ValueSpec:
						for _, name := range candidate.Names {
							if name.Name == "newServiceResult" {
								declarations++
							}
						}
					case *ast.TypeSpec:
						if candidate.Name.Name == "newServiceResult" {
							declarations++
						}
					}
				}
			}
		}
	}
	if declarations != 1 || reducer == nil || reducer.Recv != nil || reducer.Body == nil || reducer.Type.TypeParams != nil || reducer.Type.Params == nil || reducer.Type.Results == nil || len(reducer.Type.Params.List) != 2 || len(reducer.Type.Results.List) != 2 {
		return false
	}
	if len(reducer.Type.Params.List[0].Names) != 1 || reducer.Type.Params.List[0].Names[0].Name != "disposition" || types.ExprString(reducer.Type.Params.List[0].Type) != "ServiceDisposition" || len(reducer.Type.Params.List[1].Names) != 1 || reducer.Type.Params.List[1].Names[0].Name != "closeReason" || !l8D2ReadinessExactImportedType(reducer.Type.Params.List[1].Type, reducerAliases, protocolPath, "CloseReason", false) {
		return false
	}
	if len(reducer.Type.Results.List[0].Names) != 0 || types.ExprString(reducer.Type.Results.List[0].Type) != "ServiceResult" || len(reducer.Type.Results.List[1].Names) != 0 || types.ExprString(reducer.Type.Results.List[1].Type) != "error" {
		return false
	}
	canonical, err := parser.ParseFile(token.NewFileSet(), "canonical.go", `package fixture
func newServiceResult(disposition ServiceDisposition, closeReason credentialprotocol.CloseReason) (ServiceResult, error) {
	if ValidateServiceDisposition(disposition) != nil || credentialprotocol.ValidateCloseReason(closeReason) != nil {
		return ServiceResult{}, ErrContractInvalidArgument
	}
	clean := disposition == ServiceClosed && (closeReason == credentialprotocol.CloseReasonNormal || closeReason == credentialprotocol.CloseReasonShutdown)
	stop := disposition == ServiceStopVMRequired && (closeReason == credentialprotocol.CloseReasonProtocolError || closeReason == credentialprotocol.CloseReasonIdentityDrift || closeReason == credentialprotocol.CloseReasonExpired || closeReason == credentialprotocol.CloseReasonHelperLoss)
	if !clean && !stop {
		return ServiceResult{}, ErrContractResultMatrix
	}
	return ServiceResult{disposition: disposition, closeReason: closeReason}, nil
}`, 0)
	if err != nil || len(canonical.Decls) != 1 {
		return false
	}
	want := canonical.Decls[0].(*ast.FuncDecl)
	return l8D2ReadinessFormattedNode(reducer.Body) == l8D2ReadinessFormattedNode(want.Body)
}

func l8D2ReadinessExactServiceResultReducerAcrossBuilds(dir string, files map[string]*ast.File) bool {
	if dir == "" || !l8D2ReadinessExactServiceResultReducer(files) {
		return false
	}
	for _, context := range l8D2ReadinessSupportedBuildContexts() {
		serviceActive, reducerActive := false, false
		for path, file := range files {
			active, err := context.MatchFile(dir, filepath.Base(path))
			if err != nil {
				return false
			}
			if !active {
				continue
			}
			if l8D2ReadinessFileDeclaresStruct(file, "Service") {
				serviceActive = true
			}
			if l8D2ReadinessFileDeclaresFunction(file, "newServiceResult") {
				reducerActive = true
			}
		}
		if serviceActive && !reducerActive {
			return false
		}
	}
	return true
}

func l8D2ReadinessSupportedBuildContexts() []build.Context {
	result := make([]build.Context, 0, 4)
	for _, goos := range []string{"linux", "darwin", "freebsd", "windows"} {
		context := build.Default
		context.GOOS = goos
		context.GOARCH = "amd64"
		context.CgoEnabled = false
		context.BuildTags = nil
		result = append(result, context)
	}
	return result
}

func l8D2ReadinessFileDeclaresStruct(file *ast.File, name string) bool {
	if file == nil {
		return false
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != name {
				continue
			}
			if _, ok := typeSpec.Type.(*ast.StructType); ok {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessFileDeclaresFunction(file *ast.File, name string) bool {
	if file == nil {
		return false
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.Name == name {
			return true
		}
	}
	return false
}

func l8D2ReadinessFormattedNode(node ast.Node) string {
	var output strings.Builder
	if node == nil || format.Node(&output, token.NewFileSet(), node) != nil {
		return ""
	}
	return output.String()
}

func l8D2ReadinessAnalyzeServiceAST(files map[string]*ast.File) l8D2ReadinessServiceASTAnalysis {
	var result l8D2ReadinessServiceASTAnalysis
	if !l8D2ReadinessExactServiceResultReducer(files) {
		return result
	}
	functions := make(map[string][]*ast.FuncDecl)
	serviceMethods := make(map[string]*ast.FuncDecl)
	aliasesByFunction := make(map[*ast.FuncDecl]map[string]string)
	var constructor, snapshot, serve *ast.FuncDecl
	for _, file := range files {
		aliases, _ := l8D2ReadinessImportAliases(file)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			aliasesByFunction[function] = aliases
			functions[function.Name.Name] = append(functions[function.Name.Name], function)
			switch function.Name.Name {
			case "NewService":
				if function.Recv == nil {
					constructor = function
				}
			case "snapshotServiceExtensionEntries":
				if function.Recv == nil {
					snapshot = function
				}
			}
			if function.Recv != nil && len(function.Recv.List) == 1 && types.ExprString(function.Recv.List[0].Type) == "*Service" {
				serviceMethods[function.Name.Name] = function
				if function.Name.Name == "Serve" {
					serve = function
				}
			}
		}
	}
	result.construction = l8D2ReadinessValidServiceConstructor(constructor, snapshot, aliasesByFunction[snapshot])
	result.serveOneShot = l8D2ReadinessValidServeOneShot(serve, aliasesByFunction[serve])
	if serve == nil {
		return result
	}
	reachable := map[*ast.FuncDecl]bool{serve: true}
	type serviceCallEdge struct {
		caller *ast.FuncDecl
		target *ast.FuncDecl
		call   *ast.CallExpr
	}
	var edges []serviceCallEdge
	for changed := true; changed; {
		changed = false
		for function := range reachable {
			receiverName := l8D2ReadinessReceiverName(function)
			if receiverName == "" {
				continue
			}
			receiverAliases := l8D2ReadinessServiceReceiverAliases(function)
			for _, call := range l8D2ReadinessLiveReturnedServiceCalls(function.Body, receiverName, receiverAliases) {
				selector := call.Fun.(*ast.SelectorExpr)
				for _, target := range functions[selector.Sel.Name] {
					if serviceMethods[selector.Sel.Name] != target {
						continue
					}
					edges = append(edges, serviceCallEdge{caller: function, target: target, call: call})
					if !reachable[target] {
						reachable[target] = true
						changed = true
					}
				}
			}
		}
	}
	privateCandidates := make(map[*ast.FuncDecl]bool)
	stdinCandidates := make(map[*ast.FuncDecl]bool)
	for function := range reachable {
		private, stdin := l8D2ReadinessAnalyzeServiceBorrowCallbacks(function, aliasesByFunction[function])
		privateCandidates[function] = private
		stdinCandidates[function] = stdin
	}
	trustedCalls := make(map[*ast.CallExpr]bool)
	dispatchers := make(map[*ast.FuncDecl]bool)
	privateDispatchers := make(map[*ast.FuncDecl]bool)
	stdinDispatchers := make(map[*ast.FuncDecl]bool)
	for _, edge := range edges {
		private := privateCandidates[edge.target] && l8D2ReadinessExactReceivedArmHandlerCall(edge.caller, edge.call, aliasesByFunction[edge.caller], "private")
		stdin := stdinCandidates[edge.target] && l8D2ReadinessExactReceivedArmHandlerCall(edge.caller, edge.call, aliasesByFunction[edge.caller], "stdin")
		if private || stdin {
			trustedCalls[edge.call] = true
			dispatchers[edge.caller] = true
			privateDispatchers[edge.caller] = privateDispatchers[edge.caller] || private
			stdinDispatchers[edge.caller] = stdinDispatchers[edge.caller] || stdin
		}
	}
	for changed := true; changed; {
		changed = false
		for _, edge := range edges {
			if trustedCalls[edge.call] || !dispatchers[edge.target] || !l8D2ReadinessExactDispatcherForwardCall(edge.caller, edge.target, edge.call, aliasesByFunction) {
				continue
			}
			targetCalls := l8D2ReadinessLiveReturnedServiceCalls(edge.target.Body, l8D2ReadinessReceiverName(edge.target), l8D2ReadinessServiceReceiverAliases(edge.target))
			allTrusted := len(targetCalls) != 0
			for _, targetCall := range targetCalls {
				if !trustedCalls[targetCall] {
					allTrusted = false
					break
				}
			}
			if allTrusted {
				trustedCalls[edge.call] = true
				dispatchers[edge.caller] = true
				privateDispatchers[edge.caller] = privateDispatchers[edge.caller] || privateDispatchers[edge.target]
				stdinDispatchers[edge.caller] = stdinDispatchers[edge.caller] || stdinDispatchers[edge.target]
				changed = true
			}
		}
	}
	stableReachable := map[*ast.FuncDecl]bool{serve: true}
	for changed := true; changed; {
		changed = false
		for function := range stableReachable {
			receiverName := l8D2ReadinessReceiverName(function)
			if receiverName == "" {
				continue
			}
			receiverAliases := l8D2ReadinessServiceReceiverAliases(function)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				owner, ownerOK := func() (*ast.Ident, bool) {
					if !ok {
						return nil, false
					}
					value, valid := selector.X.(*ast.Ident)
					return value, valid
				}()
				if !ownerOK || (owner.Name != receiverName && !receiverAliases[owner.Name]) {
					return true
				}
				if target := serviceMethods[selector.Sel.Name]; target != nil && !stableReachable[target] {
					stableReachable[target] = true
					changed = true
				}
				return true
			})
		}
	}
	topologyStable := l8D2ReadinessServiceCallTopologyStable(stableReachable, trustedCalls, dispatchers) &&
		l8D2ReadinessReachableServiceStateStable(stableReachable, serve)
	result.serveOneShot = result.serveOneShot && topologyStable
	result.privateSequence = privateDispatchers[serve] && topologyStable
	result.stdinSequence = stdinDispatchers[serve] && topologyStable
	result.zeroPrivateSequence = l8D2ReadinessZeroPrivateExecStable(stableReachable) && topologyStable
	return result
}

func l8D2ReadinessZeroPrivateExecStable(reachable map[*ast.FuncDecl]bool) bool {
	for function := range reachable {
		receiver := l8D2ReadinessReceiverName(function)
		if receiver == "" || function.Body == nil {
			continue
		}
		parameters := l8D2ReadinessNamedParameters(function)
		if len(parameters) != 3 || types.ExprString(parameters[0].typ) != "context.Context" || types.ExprString(parameters[1].typ) != "ReceivedPacket" || types.ExprString(parameters[2].typ) != "bool" || len(function.Body.List) < 3 {
			continue
		}
		arm, armOK := l8D2ReadinessExactExecArmExtraction(function.Body.List[0], parameters[1].name)
		if !armOK || !l8D2ReadinessBooleanArmGate(function.Body.List[1], arm.ok) {
			continue
		}
		for _, statement := range function.Body.List[2:] {
			branch, ok := statement.(*ast.IfStmt)
			protected := map[string]bool{parameters[1].name: true, parameters[2].name: true, arm.value: true, arm.ok: true}
			exempt := func(assignment *ast.AssignStmt, name string) bool {
				return assignment == function.Body.List[0] && (name == arm.value || name == arm.ok)
			}
			if ok && !l8D2ReadinessBodyRebindsNames(function.Body, protected, exempt) && l8D2ReadinessExactZeroPrivateCondition(branch.Cond, arm.value) && l8D2ReadinessZeroPrivateBranchStable(branch.Body, receiver, parameters[0].name, parameters[2].name) {
				return true
			}
		}
	}
	return false
}

type l8D2ReadinessExecArmNames struct {
	value string
	ok    string
}

func l8D2ReadinessExactExecArmExtraction(statement ast.Stmt, packet string) (l8D2ReadinessExecArmNames, bool) {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
		return l8D2ReadinessExecArmNames{}, false
	}
	arm, armOK := assignment.Lhs[0].(*ast.Ident)
	present, presentOK := assignment.Lhs[1].(*ast.Ident)
	call, callOK := assignment.Rhs[0].(*ast.CallExpr)
	selector, selectorOK := func() (*ast.SelectorExpr, bool) {
		if !callOK {
			return nil, false
		}
		candidate, valid := call.Fun.(*ast.SelectorExpr)
		return candidate, valid
	}()
	owner, ownerOK := func() (*ast.Ident, bool) {
		if !selectorOK {
			return nil, false
		}
		candidate, valid := selector.X.(*ast.Ident)
		return candidate, valid
	}()
	if !armOK || !presentOK || !ownerOK || arm.Name == "_" || present.Name == "_" || owner.Name != packet || selector.Sel.Name != "Exec" || len(call.Args) != 0 {
		return l8D2ReadinessExecArmNames{}, false
	}
	return l8D2ReadinessExecArmNames{value: arm.Name, ok: present.Name}, true
}

func l8D2ReadinessExactZeroPrivateCondition(expression ast.Expr, arm string) bool {
	condition, ok := expression.(*ast.BinaryExpr)
	if !ok || condition.Op != token.LAND {
		return false
	}
	exactCall := func(candidate ast.Expr, method string) bool {
		call, ok := candidate.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return false
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		owner, ownerOK := func() (*ast.Ident, bool) {
			if !ok {
				return nil, false
			}
			value, valid := selector.X.(*ast.Ident)
			return value, valid
		}()
		return ownerOK && owner.Name == arm && selector.Sel.Name == method
	}
	length := func(candidate ast.Expr) bool {
		comparison, ok := candidate.(*ast.BinaryExpr)
		return ok && comparison.Op == token.EQL && exactCall(comparison.X, "PrivateBindingLength") && types.ExprString(comparison.Y) == "0"
	}
	digest := func(candidate ast.Expr) bool {
		comparison, ok := candidate.(*ast.BinaryExpr)
		return ok && comparison.Op == token.EQL && exactCall(comparison.X, "PrivateBindingSHA256") && (types.ExprString(comparison.Y) == "[32]byte{}" || types.ExprString(comparison.Y) == "([32]byte{})")
	}
	return (length(condition.X) && digest(condition.Y)) || (digest(condition.X) && length(condition.Y))
}

func l8D2ReadinessZeroPrivateBranchStable(body *ast.BlockStmt, receiver, contextName, comparisonName string) bool {
	if body == nil {
		return false
	}
	var coreAssignment *ast.AssignStmt
	var execution, coreError, request, plan string
	stateRequest, statePlan, planDestroy, validMatrix, locked, retained, unlocked := token.NoPos, token.NoPos, token.NoPos, token.NoPos, token.NoPos, token.NoPos, token.NoPos
	comparisonGate := token.NoPos
	planDestroyCount := 0
	for _, statement := range body.List {
		switch value := statement.(type) {
		case *ast.AssignStmt:
			if len(value.Lhs) == 1 && len(value.Rhs) == 1 && types.ExprString(value.Rhs[0]) == receiver+".state.request" {
				if identifier, ok := value.Lhs[0].(*ast.Ident); ok && identifier.Name != "_" {
					request, stateRequest = identifier.Name, value.Pos()
				}
			}
			if len(value.Lhs) == 1 && len(value.Rhs) == 1 && types.ExprString(value.Rhs[0]) == receiver+".state.plan" {
				if identifier, ok := value.Lhs[0].(*ast.Ident); ok && identifier.Name != "_" {
					plan, statePlan = identifier.Name, value.Pos()
				}
			}
			if len(value.Lhs) == 2 && len(value.Rhs) == 1 {
				call, ok := value.Rhs[0].(*ast.CallExpr)
				selector, selectorOK := func() (*ast.SelectorExpr, bool) {
					if !ok {
						return nil, false
					}
					candidate, valid := call.Fun.(*ast.SelectorExpr)
					return candidate, valid
				}()
				if selectorOK && types.ExprString(selector.X) == receiver+".core" && selector.Sel.Name == "BeginExec" && len(call.Args) == 3 && types.ExprString(call.Args[0]) == contextName && l8D2ReadinessNilIdentifier(call.Args[2]) && types.ExprString(call.Args[1]) == request {
					first, firstOK := value.Lhs[0].(*ast.Ident)
					second, secondOK := value.Lhs[1].(*ast.Ident)
					if firstOK && secondOK && first.Name != "_" && second.Name != "_" {
						coreAssignment, execution, coreError = value, first.Name, second.Name
					}
				}
			}
			if len(value.Lhs) == 1 && len(value.Rhs) == 1 && execution != "" && types.ExprString(value.Lhs[0]) == receiver+".state.execution" && types.ExprString(value.Rhs[0]) == execution {
				retained = value.Pos()
			}
		case *ast.IfStmt:
			if types.ExprString(value.Cond) == comparisonName && value.Init == nil && value.Else == nil && l8D2ReadinessExactZeroPrivateComparisonReturn(value.Body) {
				authority := false
				ast.Inspect(value.Body, func(node ast.Node) bool {
					switch candidate := node.(type) {
					case *ast.CallExpr:
						authority = true
						return false
					case *ast.SelectorExpr:
						if types.ExprString(candidate.X) == receiver+".core" || candidate.Sel.Name == "Borrow" || candidate.Sel.Name == "BeginExec" || strings.HasPrefix(candidate.Sel.Name, "Propose") {
							authority = true
							return false
						}
					}
					return true
				})
				if !authority {
					comparisonGate = value.Pos()
				}
			}
			if coreAssignment != nil && l8D2ReadinessCoreResultFailureCondition(value.Cond, coreError, execution) {
				validMatrix = value.Pos()
			}
		case *ast.ExprStmt:
			call, ok := value.X.(*ast.CallExpr)
			if ok && l8D2ReadinessExactStateMutexCall(call, receiver, "Lock") {
				if coreAssignment == nil {
					locked = call.Pos()
				} else {
					locked = call.Pos()
				}
			}
			if ok && l8D2ReadinessExactStateMutexCall(call, receiver, "Unlock") {
				unlocked = call.Pos()
			}
			if ok {
				selector, selectorOK := call.Fun.(*ast.SelectorExpr)
				owner, ownerOK := func() (*ast.Ident, bool) {
					if !selectorOK {
						return nil, false
					}
					candidate, valid := selector.X.(*ast.Ident)
					return candidate, valid
				}()
				if ownerOK && owner.Name == plan && selector.Sel.Name == "destroy" && len(call.Args) == 0 {
					planDestroy, planDestroyCount = call.Pos(), planDestroyCount+1
				}
			}
		}
	}
	forbidden := false
	coreCalls := 0
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch l8D2ReadinessCallMethodName(call) {
		case "BeginExec":
			coreCalls++
		case "Borrow", "ExecPrivate", "ProposeObservedPrivate", "ProposeObservedStdin":
			forbidden = true
			return false
		}
		return true
	})
	return !forbidden && comparisonGate != token.NoPos && comparisonGate < stateRequest && coreCalls == 1 && coreAssignment != nil && stateRequest != token.NoPos && statePlan != token.NoPos && stateRequest <= statePlan && statePlan < coreAssignment.Pos() && coreAssignment.Pos() < planDestroy && planDestroy < validMatrix && planDestroyCount == 1 && validMatrix < locked && locked < retained && retained < unlocked
}

func l8D2ReadinessExactZeroPrivateComparisonReturn(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) != 1 {
		return false
	}
	returned, ok := body.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 2 || !l8D2ReadinessNilIdentifier(returned.Results[1]) {
		return false
	}
	literal, ok := returned.Results[0].(*ast.CompositeLit)
	return ok && types.ExprString(literal.Type) == "ServiceResult" && len(literal.Elts) == 0
}

func l8D2ReadinessExactDispatcherForwardCall(caller, target *ast.FuncDecl, call *ast.CallExpr, aliasesByFunction map[*ast.FuncDecl]map[string]string) bool {
	if caller == nil || target == nil || call == nil {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	owner, ok := selector.X.(*ast.Ident)
	callerReceiver := l8D2ReadinessReceiverName(caller)
	callerAliases := l8D2ReadinessServiceReceiverAliases(caller)
	if !ok || (owner.Name != callerReceiver && !callerAliases[owner.Name]) {
		return false
	}
	callerParameters := l8D2ReadinessNamedParameters(caller)
	targetParameters := l8D2ReadinessNamedParameters(target)
	if len(call.Args) != len(targetParameters) || len(callerParameters) < len(targetParameters) {
		return false
	}
	callerImports, targetImports := aliasesByFunction[caller], aliasesByFunction[target]
	for index, targetParameter := range targetParameters {
		argument, direct := call.Args[index].(*ast.Ident)
		if !direct || argument.Name != callerParameters[index].name ||
			!l8D2ReadinessEquivalentImportedType(callerParameters[index].typ, callerImports, targetParameter.typ, targetImports) {
			return false
		}
	}
	protected := l8D2ReadinessNameSet(callerParameters)
	protected[callerReceiver] = true
	return !l8D2ReadinessBodyRebindsNamesBefore(caller.Body, protected, call.Pos())
}

type l8D2ReadinessNamedParameter struct {
	name string
	typ  ast.Expr
}

func l8D2ReadinessNamedParameters(function *ast.FuncDecl) []l8D2ReadinessNamedParameter {
	var result []l8D2ReadinessNamedParameter
	if function == nil || function.Type.Params == nil {
		return result
	}
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			result = append(result, l8D2ReadinessNamedParameter{name: name.Name, typ: field.Type})
		}
	}
	return result
}

func l8D2ReadinessNameSet(parameters []l8D2ReadinessNamedParameter) map[string]bool {
	result := make(map[string]bool, len(parameters))
	for _, parameter := range parameters {
		result[parameter.name] = true
	}
	return result
}

func l8D2ReadinessEquivalentImportedType(left ast.Expr, leftAliases map[string]string, right ast.Expr, rightAliases map[string]string) bool {
	leftSelector, leftOK := left.(*ast.SelectorExpr)
	rightSelector, rightOK := right.(*ast.SelectorExpr)
	if leftOK || rightOK {
		if !leftOK || !rightOK || leftSelector.Sel.Name != rightSelector.Sel.Name {
			return false
		}
		leftOwner, leftOwnerOK := leftSelector.X.(*ast.Ident)
		rightOwner, rightOwnerOK := rightSelector.X.(*ast.Ident)
		return leftOwnerOK && rightOwnerOK && leftAliases[leftOwner.Name] == rightAliases[rightOwner.Name]
	}
	return types.ExprString(left) == types.ExprString(right)
}

func l8D2ReadinessBodyRebindsNamesBefore(body *ast.BlockStmt, names map[string]bool, before token.Pos) bool {
	rebound := false
	ast.Inspect(body, func(node ast.Node) bool {
		if rebound || node == nil || node.Pos() >= before {
			return !rebound
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if identifier, ok := left.(*ast.Ident); ok && names[identifier.Name] {
					rebound = true
					return false
				}
			}
		case *ast.ValueSpec:
			for _, name := range value.Names {
				if names[name.Name] {
					rebound = true
					return false
				}
			}
		}
		return true
	})
	return rebound
}

func l8D2ReadinessLiveReturnedServiceCalls(body *ast.BlockStmt, receiver string, aliases map[string]bool) []*ast.CallExpr {
	var calls []*ast.CallExpr
	var visitBlock func(*ast.BlockStmt)
	var visitStmt func(ast.Stmt)
	visitBlock = func(block *ast.BlockStmt) {
		if block == nil {
			return
		}
		for _, statement := range block.List {
			visitStmt(statement)
			if _, terminal := statement.(*ast.ReturnStmt); terminal {
				return
			}
		}
	}
	visitStmt = func(statement ast.Stmt) {
		switch value := statement.(type) {
		case *ast.ReturnStmt:
			for _, expression := range value.Results {
				call, ok := expression.(*ast.CallExpr)
				if !ok {
					continue
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				owner, ownerOK := selector.X.(*ast.Ident)
				if ok && ownerOK && (owner.Name == receiver || aliases[owner.Name]) {
					calls = append(calls, call)
				}
			}
		case *ast.IfStmt:
			if l8D2ReadinessStaticallyFalse(value.Cond) {
				if alternate, ok := value.Else.(*ast.BlockStmt); ok {
					visitBlock(alternate)
				}
				return
			}
			visitBlock(value.Body)
			if !l8D2ReadinessStaticallyTrue(value.Cond) {
				switch alternate := value.Else.(type) {
				case *ast.BlockStmt:
					visitBlock(alternate)
				case *ast.IfStmt:
					visitStmt(alternate)
				}
			}
		case *ast.BlockStmt:
			visitBlock(value)
		case *ast.LabeledStmt:
			visitStmt(value.Stmt)
		case *ast.ForStmt:
			if !l8D2ReadinessStaticallyFalse(value.Cond) {
				visitBlock(value.Body)
			}
		case *ast.RangeStmt:
			visitBlock(value.Body)
		case *ast.SwitchStmt:
			for _, clause := range value.Body.List {
				if candidate, ok := clause.(*ast.CaseClause); ok {
					visitBlock(&ast.BlockStmt{List: candidate.Body})
				}
			}
		case *ast.TypeSwitchStmt:
			for _, clause := range value.Body.List {
				if candidate, ok := clause.(*ast.CaseClause); ok {
					visitBlock(&ast.BlockStmt{List: candidate.Body})
				}
			}
		case *ast.SelectStmt:
			for _, clause := range value.Body.List {
				if candidate, ok := clause.(*ast.CommClause); ok {
					visitBlock(&ast.BlockStmt{List: candidate.Body})
				}
			}
		}
	}
	visitBlock(body)
	return calls
}

func l8D2ReadinessStaticallyFalse(expression ast.Expr) bool {
	value, exact := l8D2ReadinessStaticBoolean(expression)
	return exact && !value
}

func l8D2ReadinessStaticallyTrue(expression ast.Expr) bool {
	value, exact := l8D2ReadinessStaticBoolean(expression)
	return exact && value
}

func l8D2ReadinessStaticBoolean(expression ast.Expr) (bool, bool) {
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return l8D2ReadinessStaticBoolean(value.X)
	case *ast.Ident:
		switch value.Name {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	case *ast.UnaryExpr:
		if value.Op == token.NOT {
			inner, exact := l8D2ReadinessStaticBoolean(value.X)
			return !inner, exact
		}
	case *ast.BinaryExpr:
		switch value.Op {
		case token.LAND:
			left, leftExact := l8D2ReadinessStaticBoolean(value.X)
			right, rightExact := l8D2ReadinessStaticBoolean(value.Y)
			if (leftExact && !left) || (rightExact && !right) {
				return false, true
			}
			return left && right, leftExact && rightExact
		case token.LOR:
			left, leftExact := l8D2ReadinessStaticBoolean(value.X)
			right, rightExact := l8D2ReadinessStaticBoolean(value.Y)
			if (leftExact && left) || (rightExact && right) {
				return true, true
			}
			return left || right, leftExact && rightExact
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			left, leftExact := l8D2ReadinessStaticConstant(value.X)
			right, rightExact := l8D2ReadinessStaticConstant(value.Y)
			if leftExact && rightExact && left.Kind() == right.Kind() {
				return constant.Compare(left, value.Op, right), true
			}
		}
	}
	return false, false
}

func l8D2ReadinessStaticConstant(expression ast.Expr) (constant.Value, bool) {
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return l8D2ReadinessStaticConstant(value.X)
	case *ast.BasicLit:
		result := constant.MakeFromLiteral(value.Value, value.Kind, 0)
		return result, result.Kind() != constant.Unknown
	case *ast.Ident:
		switch value.Name {
		case "true":
			return constant.MakeBool(true), true
		case "false":
			return constant.MakeBool(false), true
		}
	}
	return nil, false
}

func l8D2ReadinessExactReceivedArmHandlerCall(caller *ast.FuncDecl, call *ast.CallExpr, aliases map[string]string, kind string) bool {
	if caller == nil || caller.Body == nil || call == nil || len(call.Args) != 6 {
		return false
	}
	contextName := ""
	if caller.Type.Params != nil {
		for _, field := range caller.Type.Params.List {
			if l8D2ReadinessExactImportedType(field.Type, aliases, "context", "Context", false) && len(field.Names) == 1 {
				contextName = field.Names[0].Name
			}
		}
	}
	if contextName == "" || types.ExprString(call.Args[0]) != contextName {
		return false
	}
	bodySelector, bodyOK := call.Args[1].(*ast.SelectorExpr)
	transactionSelector, transactionOK := call.Args[2].(*ast.SelectorExpr)
	correlationSelector, correlationOK := call.Args[3].(*ast.SelectorExpr)
	observationSelector, observationOK := call.Args[4].(*ast.SelectorExpr)
	comparisonSelector, comparisonOK := call.Args[5].(*ast.SelectorExpr)
	if !bodyOK || bodySelector.Sel.Name != "body" || !transactionOK || transactionSelector.Sel.Name != "transaction" || !correlationOK || correlationSelector.Sel.Name != "correlation" || !observationOK || observationSelector.Sel.Name != "observation" || !comparisonOK || comparisonSelector.Sel.Name != "comparison" {
		return false
	}
	packet, packetOK := bodySelector.X.(*ast.Ident)
	dispatchAtTransaction, transactionOwnerOK := transactionSelector.X.(*ast.Ident)
	dispatchAtCorrelation, correlationOwnerOK := correlationSelector.X.(*ast.Ident)
	dispatchAtComparison, comparisonOwnerOK := comparisonSelector.X.(*ast.Ident)
	arm, armOK := observationSelector.X.(*ast.Ident)
	if !packetOK || !transactionOwnerOK || !correlationOwnerOK || !comparisonOwnerOK || !armOK || dispatchAtTransaction.Name != dispatchAtCorrelation.Name || dispatchAtTransaction.Name != dispatchAtComparison.Name {
		return false
	}
	dispatch := dispatchAtTransaction.Name
	receiver := l8D2ReadinessReceiverName(caller)
	armMethod := "ExecPrivate"
	if kind == "stdin" {
		armMethod = "ExecStream"
	}
	packetReady, armReady, dispatchReady := false, false, false
	var packetAssignment, armAssignment, dispatchAssignment *ast.AssignStmt
	for index, statement := range caller.Body.List {
		if statement.Pos() >= call.Pos() {
			break
		}
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
			continue
		}
		first, firstOK := assignment.Lhs[0].(*ast.Ident)
		second, secondOK := assignment.Lhs[1].(*ast.Ident)
		assignedCall, callOK := assignment.Rhs[0].(*ast.CallExpr)
		selector, selectorOK := func() (*ast.SelectorExpr, bool) {
			if !callOK {
				return nil, false
			}
			value, ok := assignedCall.Fun.(*ast.SelectorExpr)
			return value, ok
		}()
		if !firstOK || !secondOK || !selectorOK || index+1 >= len(caller.Body.List) {
			continue
		}
		if first.Name == packet.Name && second.Name != "_" && types.ExprString(selector.X) == receiver+".transport" && selector.Sel.Name == "Receive" && len(assignedCall.Args) == 2 && types.ExprString(assignedCall.Args[0]) == contextName && l8D2ReadinessHandlerErrorGate(caller.Body.List[index+1], second.Name) {
			packetReady = true
			packetAssignment = assignment
		}
		if first.Name == arm.Name && second.Name != "_" && types.ExprString(selector.X) == packet.Name && selector.Sel.Name == armMethod && len(assignedCall.Args) == 0 && l8D2ReadinessBooleanArmGate(caller.Body.List[index+1], second.Name) {
			armReady = true
			armAssignment = assignment
		}
		if first.Name == dispatch && second.Name != "_" && types.ExprString(selector.X) == receiver && selector.Sel.Name == "takeExecDispatch" && len(assignedCall.Args) == 1 && types.ExprString(assignedCall.Args[0]) == arm.Name+".Revision()" && l8D2ReadinessHandlerErrorGate(caller.Body.List[index+1], second.Name) {
			dispatchReady = true
			dispatchAssignment = assignment
		}
	}
	protected := map[string]bool{contextName: true, packet.Name: true, arm.Name: true, dispatch: true}
	exempt := func(assignment *ast.AssignStmt, name string) bool {
		return (name == packet.Name && assignment == packetAssignment) || (name == arm.Name && assignment == armAssignment) || (name == dispatch && assignment == dispatchAssignment)
	}
	return packetReady && armReady && dispatchReady && packetAssignment.Pos() < armAssignment.Pos() && armAssignment.Pos() < dispatchAssignment.Pos() && dispatchAssignment.Pos() < call.Pos() && !l8D2ReadinessBodyRebindsNames(caller.Body, protected, exempt)
}

func l8D2ReadinessHandlerErrorGate(statement ast.Stmt, errorName string) bool {
	gate, ok := statement.(*ast.IfStmt)
	if !ok || gate.Init != nil || gate.Else != nil || !l8D2ReadinessExactErrorNonNilCondition(gate.Cond, errorName) || len(gate.Body.List) != 1 {
		return false
	}
	returned, ok := gate.Body.List[0].(*ast.ReturnStmt)
	return ok && len(returned.Results) > 0 && types.ExprString(returned.Results[len(returned.Results)-1]) == errorName
}

func l8D2ReadinessBooleanArmGate(statement ast.Stmt, booleanName string) bool {
	gate, ok := statement.(*ast.IfStmt)
	if !ok || gate.Init != nil || gate.Else != nil || len(gate.Body.List) != 1 {
		return false
	}
	negated, ok := gate.Cond.(*ast.UnaryExpr)
	identifier, identifierOK := negated.X.(*ast.Ident)
	returned, returnedOK := gate.Body.List[0].(*ast.ReturnStmt)
	return ok && negated.Op == token.NOT && identifierOK && identifier.Name == booleanName && returnedOK && len(returned.Results) > 0 && !l8D2ReadinessNilIdentifier(returned.Results[len(returned.Results)-1])
}

func l8D2ReadinessServiceReceiverAliases(function *ast.FuncDecl) map[string]bool {
	aliases := make(map[string]bool)
	if function == nil || function.Body == nil {
		return aliases
	}
	receiver := l8D2ReadinessReceiverName(function)
	type candidate struct {
		right string
		count int
	}
	candidates := make(map[string]candidate)
	record := func(name string, right ast.Expr) {
		if name == "_" {
			return
		}
		entry := candidates[name]
		entry.count++
		if identifier, ok := right.(*ast.Ident); ok {
			entry.right = identifier.Name
		} else {
			entry.right = ""
		}
		candidates[name] = entry
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.AssignStmt:
			for index, left := range value.Lhs {
				identifier, ok := left.(*ast.Ident)
				if !ok {
					continue
				}
				var right ast.Expr
				if index < len(value.Rhs) {
					right = value.Rhs[index]
				}
				record(identifier.Name, right)
			}
		case *ast.ValueSpec:
			for index, name := range value.Names {
				var right ast.Expr
				if index < len(value.Values) {
					right = value.Values[index]
				}
				record(name.Name, right)
			}
		}
		return true
	})
	changed := true
	for changed {
		changed = false
		for name, entry := range candidates {
			if entry.count == 1 && entry.right != "" && (entry.right == receiver || aliases[entry.right]) && !aliases[name] {
				aliases[name] = true
				changed = true
			}
		}
	}
	return aliases
}

func l8D2ReadinessExactImportedType(expression ast.Expr, aliases map[string]string, importPath, typeName string, pointer bool) bool {
	if pointer {
		star, ok := expression.(*ast.StarExpr)
		if !ok {
			return false
		}
		expression = star.X
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != typeName {
		return false
	}
	owner, ok := selector.X.(*ast.Ident)
	return ok && aliases[owner.Name] == importPath
}

func l8D2ReadinessServiceCallTopologyStable(reachable map[*ast.FuncDecl]bool, trustedCalls map[*ast.CallExpr]bool, dispatchers map[*ast.FuncDecl]bool) bool {
	for function := range reachable {
		receiver := l8D2ReadinessReceiverName(function)
		if receiver == "" {
			continue
		}
		if l8D2ReadinessBodyRebindsNames(function.Body, map[string]bool{receiver: true}, nil) {
			return false
		}
		aliases := l8D2ReadinessServiceReceiverAliases(function)
		if !l8D2ReadinessConfiguredServiceDependenciesStable(function, receiver, aliases) {
			return false
		}
		allowedSelectors := make(map[*ast.SelectorExpr]bool)
		stable := true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if !stable {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			owner, ok := selector.X.(*ast.Ident)
			if !ok {
				if l8D2ReadinessWrappedServiceReceiver(selector.X, receiver, aliases) {
					stable = false
					return false
				}
				return true
			}
			if owner.Name != receiver && !aliases[owner.Name] {
				return true
			}
			if trustedCalls[call] || (dispatchers[function] && selector.Sel.Name == "takeExecDispatch") {
				allowedSelectors[selector] = true
				return true
			}
			stable = false
			return false
		})
		if !stable {
			return false
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if !stable {
				return false
			}
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || allowedSelectors[selector] {
				return true
			}
			owner, ok := selector.X.(*ast.Ident)
			if !ok {
				if l8D2ReadinessWrappedServiceReceiver(selector.X, receiver, aliases) {
					stable = false
					return false
				}
				return true
			}
			if owner.Name != receiver && !aliases[owner.Name] {
				return true
			}
			switch selector.Sel.Name {
			case "core", "transport", "policy", "extensions", "host", "runtime", "state":
				return true
			default:
				stable = false
				return false
			}
		})
		if !stable {
			return false
		}
	}
	return true
}

func l8D2ReadinessConfiguredServiceDependenciesStable(function *ast.FuncDecl, receiver string, aliases map[string]bool) bool {
	if function == nil || function.Body == nil {
		return false
	}
	configuredField := func(expression ast.Expr) bool {
		selector, ok := expression.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		owner, ok := selector.X.(*ast.Ident)
		if !ok || (owner.Name != receiver && !aliases[owner.Name]) {
			return false
		}
		switch selector.Sel.Name {
		case "core", "transport", "policy", "extensions", "host", "runtime":
			return true
		default:
			return false
		}
	}
	containsConfiguredField := func(expression ast.Expr) bool {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			candidate, ok := node.(ast.Expr)
			if ok && configuredField(candidate) {
				found = true
				return false
			}
			return !found
		})
		return found
	}
	directDependencyCall := func(expression ast.Expr) bool {
		call, ok := expression.(*ast.CallExpr)
		if !ok {
			return false
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		return ok && configuredField(method.X)
	}
	stable := true
	fail := func() bool {
		stable = false
		return false
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !stable {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if containsConfiguredField(left) {
					return fail()
				}
			}
			for _, right := range value.Rhs {
				if containsConfiguredField(right) && !directDependencyCall(right) {
					return fail()
				}
			}
		case *ast.ValueSpec:
			for _, expression := range value.Values {
				if containsConfiguredField(expression) && !directDependencyCall(expression) {
					return fail()
				}
			}
		case *ast.IncDecStmt:
			if containsConfiguredField(value.X) {
				return fail()
			}
		case *ast.CallExpr:
			method, direct := value.Fun.(*ast.SelectorExpr)
			if direct && configuredField(method.X) {
				for _, argument := range value.Args {
					if containsConfiguredField(argument) {
						return fail()
					}
				}
				return true
			}
			if containsConfiguredField(value.Fun) {
				return fail()
			}
			for _, argument := range value.Args {
				if containsConfiguredField(argument) {
					return fail()
				}
			}
		case *ast.ReturnStmt:
			for _, result := range value.Results {
				if containsConfiguredField(result) && !directDependencyCall(result) {
					return fail()
				}
			}
		}
		return true
	})
	return stable
}

func l8D2ReadinessWrappedServiceReceiver(expression ast.Expr, receiver string, aliases map[string]bool) bool {
	var containsService func(ast.Expr) bool
	containsService = func(candidate ast.Expr) bool {
		switch value := candidate.(type) {
		case *ast.Ident:
			return value.Name == receiver || aliases[value.Name]
		case *ast.ParenExpr:
			return containsService(value.X)
		case *ast.StarExpr:
			return containsService(value.X)
		case *ast.UnaryExpr:
			return containsService(value.X)
		case *ast.TypeAssertExpr:
			return containsService(value.X)
		case *ast.CallExpr:
			for _, argument := range value.Args {
				if containsService(argument) {
					return true
				}
			}
		case *ast.IndexExpr:
			return containsService(value.X) || containsService(value.Index)
		case *ast.SelectorExpr:
			if root, ok := value.X.(*ast.Ident); ok && (root.Name == receiver || aliases[root.Name]) {
				switch value.Sel.Name {
				case "core", "transport", "policy", "extensions", "host", "runtime", "state":
					return false
				}
			}
			return containsService(value.X)
		}
		return false
	}
	return containsService(expression)
}

func l8D2ReadinessReachableServiceStateStable(reachable map[*ast.FuncDecl]bool, serve *ast.FuncDecl) bool {
	if len(reachable) == 0 {
		return l8D2ReadinessReachableServiceStateStableLegacy(reachable, serve)
	}
	for function := range reachable {
		if l8D2ReadinessFunctionUsesLedgerState(function) {
			if !l8D2ReadinessServiceMethodStateStable(function, serve) {
				return false
			}
			continue
		}
		if !l8D2ReadinessReachableServiceStateStableLegacy(map[*ast.FuncDecl]bool{function: true}, serve) {
			return false
		}
	}
	return true
}

func l8D2ReadinessFunctionUsesLedgerState(function *ast.FuncDecl) bool {
	if function == nil || function.Body == nil {
		return false
	}
	uses := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "request", "plan", "revision", "transaction", "correlation", "comparison", "execution", "dispatchTaken":
			if strings.Contains(types.ExprString(selector), ".state.") {
				uses = true
				return false
			}
		}
		return true
	})
	return uses
}

func l8D2ReadinessStateCriticalSectionsComplete(function *ast.FuncDecl, receiver string) bool {
	if function == nil || function.Body == nil {
		return false
	}
	var validateBlock func(*ast.BlockStmt) bool
	validateBlock = func(block *ast.BlockStmt) bool {
		if block == nil {
			return true
		}
		for index := 0; index < len(block.List); index++ {
			if l8D2ReadinessExactSelectorCallStatement(block.List[index], receiver+".state.mu", "Unlock") {
				return false
			}
			if !l8D2ReadinessExactSelectorCallStatement(block.List[index], receiver+".state.mu", "Lock") {
				continue
			}
			unlock := -1
			for candidate := index + 1; candidate < len(block.List); candidate++ {
				if l8D2ReadinessExactSelectorCallStatement(block.List[candidate], receiver+".state.mu", "Unlock") {
					unlock = candidate
					break
				}
			}
			if unlock < 0 {
				return false
			}
			for _, statement := range block.List[index+1 : unlock] {
				if branch, ok := statement.(*ast.IfStmt); ok {
					if !l8D2ReadinessExactCriticalRejectBranch(branch, receiver) {
						return false
					}
					continue
				}
				if _, ok := statement.(*ast.AssignStmt); !ok {
					return false
				}
				if !l8D2ReadinessPureCriticalAssignment(statement.(*ast.AssignStmt), receiver) {
					return false
				}
				forbidden := false
				ast.Inspect(statement, func(node ast.Node) bool {
					switch node.(type) {
					case *ast.CallExpr, *ast.FuncLit, *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt, *ast.DeferStmt:
						forbidden = true
						return false
					}
					return true
				})
				if forbidden {
					return false
				}
			}
			index = unlock
		}
		valid := true
		ast.Inspect(block, func(node ast.Node) bool {
			if !valid {
				return false
			}
			child, ok := node.(*ast.BlockStmt)
			if !ok || child == block {
				return true
			}
			if l8D2ReadinessExactUnlockThenReturn(child, receiver) {
				return false
			}
			if !validateBlock(child) {
				valid = false
			}
			return false
		})
		return valid
	}
	return validateBlock(function.Body)
}

func l8D2ReadinessPureCriticalAssignment(assignment *ast.AssignStmt, receiver string) bool {
	if assignment == nil || len(assignment.Rhs) == 0 {
		return false
	}
	var pure func(ast.Expr) bool
	pure = func(expression ast.Expr) bool {
		switch value := expression.(type) {
		case *ast.Ident, *ast.BasicLit:
			return true
		case *ast.ParenExpr:
			return pure(value.X)
		case *ast.SelectorExpr:
			text := types.ExprString(value)
			prefix := receiver + ".state."
			return strings.HasPrefix(text, prefix) && !strings.ContainsAny(strings.TrimPrefix(text, prefix), ".[()")
		}
		return false
	}
	for _, expression := range assignment.Rhs {
		if !pure(expression) {
			return false
		}
	}
	for _, expression := range assignment.Lhs {
		switch value := expression.(type) {
		case *ast.Ident:
		case *ast.SelectorExpr:
			text := types.ExprString(value)
			prefix := receiver + ".state."
			if !strings.HasPrefix(text, prefix) || strings.ContainsAny(strings.TrimPrefix(text, prefix), ".[()") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func l8D2ReadinessExactCriticalRejectBranch(branch *ast.IfStmt, receiver string) bool {
	if branch == nil || branch.Init != nil || branch.Else != nil || !l8D2ReadinessExactUnlockThenReturn(branch.Body, receiver) {
		return false
	}
	return l8D2ReadinessPureCriticalCondition(branch.Cond, receiver)
}

func l8D2ReadinessPureCriticalCondition(expression ast.Expr, receiver string) bool {
	switch value := expression.(type) {
	case *ast.Ident, *ast.BasicLit:
		return true
	case *ast.ParenExpr:
		return l8D2ReadinessPureCriticalCondition(value.X, receiver)
	case *ast.SelectorExpr:
		text := types.ExprString(value)
		prefix := receiver + ".state."
		return strings.HasPrefix(text, prefix) && !strings.ContainsAny(strings.TrimPrefix(text, prefix), ".[()")
	case *ast.UnaryExpr:
		return value.Op == token.NOT && l8D2ReadinessPureCriticalCondition(value.X, receiver)
	case *ast.BinaryExpr:
		switch value.Op {
		case token.LAND, token.LOR, token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			return l8D2ReadinessPureCriticalCondition(value.X, receiver) && l8D2ReadinessPureCriticalCondition(value.Y, receiver)
		}
	}
	return false
}

func l8D2ReadinessExactUnlockThenReturn(block *ast.BlockStmt, receiver string) bool {
	if block == nil || len(block.List) != 2 || !l8D2ReadinessExactSelectorCallStatement(block.List[0], receiver+".state.mu", "Unlock") {
		return false
	}
	returned, ok := block.List[1].(*ast.ReturnStmt)
	return ok && len(returned.Results) != 0
}

func l8D2ReadinessServiceMethodStateStable(function, serve *ast.FuncDecl) bool {
	receiver := l8D2ReadinessReceiverName(function)
	if receiver == "" || function.Body == nil {
		return true
	}
	if !l8D2ReadinessStateCriticalSectionsComplete(function, receiver) {
		return false
	}
	bodyParameters := make(map[string]bool)
	contextParameters := make(map[string]bool)
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				switch types.ExprString(field.Type) {
				case "ReceivedBodyCapability":
					bodyParameters[name.Name] = true
				case "context.Context":
					contextParameters[name.Name] = true
				}
			}
		}
	}
	statePrefix := receiver + ".state"
	allowedValueFields := map[string]bool{
		"request": true, "plan": true, "revision": true, "transaction": true,
		"correlation": true, "comparison": true, "execution": true, "dispatchTaken": true,
	}
	stateField := func(expression ast.Expr) (string, bool) {
		text := types.ExprString(expression)
		prefix := statePrefix + "."
		if !strings.HasPrefix(text, prefix) {
			return "", false
		}
		remainder := strings.TrimPrefix(text, prefix)
		if remainder == "" || strings.ContainsAny(remainder, ".[()") {
			return "", false
		}
		return remainder, true
	}
	referencesState := func(node ast.Node) bool {
		found := false
		ast.Inspect(node, func(candidate ast.Node) bool {
			if found {
				return false
			}
			expression, ok := candidate.(ast.Expr)
			if ok && (types.ExprString(expression) == statePrefix || strings.HasPrefix(types.ExprString(expression), statePrefix+".")) {
				found = true
				return false
			}
			return true
		})
		return found
	}
	exactBodyBorrow := func(expression ast.Expr) bool {
		call, ok := expression.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return false
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		owner, ownerOK := selector.X.(*ast.Ident)
		contextName, contextOK := call.Args[0].(*ast.Ident)
		_, callbackOK := call.Args[1].(*ast.FuncLit)
		return ownerOK && contextOK && callbackOK && selector.Sel.Name == "Borrow" && bodyParameters[owner.Name] && contextParameters[contextName.Name]
	}
	exactUnlockReturn := func(block *ast.BlockStmt) bool {
		if block == nil || len(block.List) != 2 || !l8D2ReadinessExactSelectorCallStatement(block.List[0], receiver+".state.mu", "Unlock") {
			return false
		}
		_, ok := block.List[1].(*ast.ReturnStmt)
		return ok
	}
	mutexBound := func(position token.Pos) bool {
		block := function.Body
		ast.Inspect(function.Body, func(node ast.Node) bool {
			candidate, ok := node.(*ast.BlockStmt)
			if ok && candidate.Pos() < position && position < candidate.End() && candidate.End()-candidate.Pos() < block.End()-block.Pos() {
				block = candidate
			}
			return true
		})
		lastLock, lastUnlock := token.NoPos, token.NoPos
		validEarlierBranches := true
		for _, statement := range block.List {
			if statement.Pos() >= position {
				break
			}
			if branch, branchOK := statement.(*ast.IfStmt); branchOK && lastLock != token.NoPos && lastUnlock < lastLock {
				branchUnlock := false
				ast.Inspect(branch.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if ok && l8D2ReadinessExactStateMutexCall(call, receiver, "Unlock") {
						branchUnlock = true
					}
					return true
				})
				branchReturn := false
				if len(branch.Body.List) != 0 {
					_, branchReturn = branch.Body.List[len(branch.Body.List)-1].(*ast.ReturnStmt)
				}
				if (branchUnlock || branchReturn) && !exactUnlockReturn(branch.Body) {
					validEarlierBranches = false
				}
				continue
			}
			expression, ok := statement.(*ast.ExprStmt)
			call, callOK := func() (*ast.CallExpr, bool) {
				if !ok {
					return nil, false
				}
				candidate, valid := expression.X.(*ast.CallExpr)
				return candidate, valid
			}()
			if !callOK {
				continue
			}
			if l8D2ReadinessExactStateMutexCall(call, receiver, "Lock") {
				lastLock = call.Pos()
			}
			if l8D2ReadinessExactStateMutexCall(call, receiver, "Unlock") {
				lastUnlock = call.Pos()
			}
		}
		futureUnlock := token.NoPos
		for _, statement := range block.List {
			if statement.Pos() <= position {
				continue
			}
			if l8D2ReadinessExactSelectorCallStatement(statement, receiver+".state.mu", "Unlock") {
				futureUnlock = statement.Pos()
				break
			}
		}
		return validEarlierBranches && lastLock != token.NoPos && lastUnlock < lastLock && futureUnlock != token.NoPos
	}
	copies := make(map[string]int)
	writes := make(map[string]int)
	stateCopies := make(map[string]string)
	copyField := func(expression ast.Expr) string {
		field := ""
		ast.Inspect(expression, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && stateCopies[identifier.Name] != "" {
				field = stateCopies[identifier.Name]
				return false
			}
			return field == ""
		})
		return field
	}
	stable := true
	fail := func() {
		stable = false
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !stable {
			return false
		}
		switch value := node.(type) {
		case *ast.UnaryExpr:
			if value.Op == token.AND && referencesState(value.X) {
				fail()
				return false
			}
		case *ast.AssignStmt:
			for index, left := range value.Lhs {
				if identifier, ok := left.(*ast.Ident); ok && stateCopies[identifier.Name] != "" {
					fail()
					return false
				}
				field, stateWrite := stateField(left)
				if stateWrite {
					if !mutexBound(left.Pos()) || index >= len(value.Rhs) {
						fail()
						return false
					}
					writes[field]++
					right := types.ExprString(value.Rhs[index])
					switch field {
					case "serveCalled":
						if function != serve || right != "true" {
							fail()
							return false
						}
					case "execution":
						if _, ok := value.Rhs[index].(*ast.Ident); !ok {
							fail()
							return false
						}
					case "dispatchTaken":
						if function.Name.Name != "takeExecDispatch" || right != "true" {
							fail()
							return false
						}
					default:
						fail()
						return false
					}
				}
				if index >= len(value.Rhs) {
					continue
				}
				right := value.Rhs[index]
				if types.ExprString(right) == statePrefix {
					fail()
					return false
				}
				field, stateRead := stateField(right)
				if stateRead {
					identifier, local := left.(*ast.Ident)
					if !local || identifier.Name == "_" || !allowedValueFields[field] || !mutexBound(right.Pos()) {
						fail()
						return false
					}
					copies[field]++
					stateCopies[identifier.Name] = field
				} else if referencesState(right) && !exactBodyBorrow(right) {
					fail()
					return false
				}
			}
		case *ast.CallExpr:
			if l8D2ReadinessExactStateMutexCall(value, receiver, "Lock") || l8D2ReadinessExactStateMutexCall(value, receiver, "Unlock") {
				return true
			}
			if exactBodyBorrow(value) {
				return true
			}
			selector, selectorCall := value.Fun.(*ast.SelectorExpr)
			if selectorCall && referencesState(selector.X) {
				fail()
				return false
			}
			if selectorCall {
				if owner, ok := selector.X.(*ast.Ident); ok && stateCopies[owner.Name] != "" {
					field := stateCopies[owner.Name]
					allowed := (field == "plan" && selector.Sel.Name == "destroy" && len(value.Args) == 0) || (field == "execution" && selector.Sel.Name == "WriteStdin")
					if !allowed || mutexBound(value.Pos()) {
						fail()
						return false
					}
				}
			}
			for index, argument := range value.Args {
				if referencesState(argument) {
					fail()
					return false
				}
				field := copyField(argument)
				if field != "" {
					identifier, direct := argument.(*ast.Ident)
					allowed := direct && selectorCall && types.ExprString(selector.X) == receiver+".core" && selector.Sel.Name == "BeginExec" && index == 1 && stateCopies[identifier.Name] == "request" && !mutexBound(value.Pos())
					if !allowed {
						fail()
						return false
					}
				}
			}
		case *ast.ReturnStmt:
			for _, result := range value.Results {
				if referencesState(result) {
					fail()
					return false
				}
				allowedCopyCall := false
				if call, ok := result.(*ast.CallExpr); ok {
					if selector, selectorOK := call.Fun.(*ast.SelectorExpr); selectorOK {
						if owner, ownerOK := selector.X.(*ast.Ident); ownerOK && stateCopies[owner.Name] == "execution" && selector.Sel.Name == "WriteStdin" && !mutexBound(call.Pos()) {
							allowedCopyCall = true
						}
					}
				}
				if copyField(result) != "" && function.Name.Name != "takeExecDispatch" && !allowedCopyCall {
					fail()
					return false
				}
			}
		case *ast.SelectorExpr:
			text := types.ExprString(value)
			if field, direct := stateField(value); direct && field != "mu" && !mutexBound(value.Pos()) {
				stable = false
				return false
			}
			for field := range allowedValueFields {
				suffix := ".state." + field
				if strings.HasSuffix(text, suffix) && !strings.HasPrefix(text, statePrefix+".") {
					fail()
					return false
				}
			}
		}
		return true
	})
	if !stable {
		return false
	}
	if function.Name.Name == "takeExecDispatch" {
		return l8D2ReadinessExactStateDispatchTake(function, receiver, copies, writes, stateCopies)
	}
	if writes["execution"] != 0 && (writes["execution"] != 1 || !l8D2ReadinessExactCoreExecutionInstall(function, receiver)) {
		return false
	}
	if copies["request"] != copies["plan"] {
		return false
	}
	return true
}

func l8D2ReadinessExactCoreExecutionInstall(function *ast.FuncDecl, receiver string) bool {
	if function == nil || function.Body == nil {
		return false
	}
	var coreAssignment, install *ast.AssignStmt
	execution, coreError := "", ""
	validGate := token.NoPos
	rebound := false
	coreCalls := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			selector, selectorOK := call.Fun.(*ast.SelectorExpr)
			if selectorOK && types.ExprString(selector.X) == receiver+".core" && selector.Sel.Name == "BeginExec" {
				coreCalls++
			}
		}
		switch value := node.(type) {
		case *ast.UnaryExpr:
			if execution != "" && value.Pos() > coreAssignment.Pos() && value.Op == token.AND && types.ExprString(value.X) == execution {
				rebound = true
			}
		case *ast.AssignStmt:
			if len(value.Lhs) == 2 && len(value.Rhs) == 1 {
				call, ok := value.Rhs[0].(*ast.CallExpr)
				selector, selectorOK := func() (*ast.SelectorExpr, bool) {
					if !ok {
						return nil, false
					}
					candidate, valid := call.Fun.(*ast.SelectorExpr)
					return candidate, valid
				}()
				first, firstOK := value.Lhs[0].(*ast.Ident)
				second, secondOK := value.Lhs[1].(*ast.Ident)
				if selectorOK && firstOK && secondOK && types.ExprString(selector.X) == receiver+".core" && selector.Sel.Name == "BeginExec" && first.Name != "_" && second.Name != "_" && coreAssignment == nil {
					coreAssignment, execution, coreError = value, first.Name, second.Name
				}
			}
			if execution != "" && value != coreAssignment {
				installCandidate := len(value.Lhs) == 1 && len(value.Rhs) == 1 && types.ExprString(value.Lhs[0]) == receiver+".state.execution" && types.ExprString(value.Rhs[0]) == execution
				for _, right := range value.Rhs {
					if l8D2ReadinessExpressionContainsIdentifier(right, execution) && !installCandidate {
						rebound = true
					}
				}
				for _, left := range value.Lhs {
					if types.ExprString(left) == execution && (install == nil || value != install) {
						rebound = true
					}
				}
			}
			if execution != "" && len(value.Lhs) == 1 && len(value.Rhs) == 1 && types.ExprString(value.Lhs[0]) == receiver+".state.execution" && types.ExprString(value.Rhs[0]) == execution {
				if install != nil {
					rebound = true
				} else {
					install = value
				}
			}
		case *ast.IfStmt:
			if coreAssignment != nil && value.Pos() > coreAssignment.Pos() && l8D2ReadinessCoreResultFailureCondition(value.Cond, coreError, execution) && l8D2ReadinessBlockReturns(value.Body) {
				validGate = value.Pos()
			}
		}
		if call, ok := node.(*ast.CallExpr); ok && execution != "" && coreAssignment != nil && call.Pos() > coreAssignment.Pos() {
			if selector, selectorOK := call.Fun.(*ast.SelectorExpr); selectorOK && l8D2ReadinessExpressionContainsIdentifier(selector.X, execution) {
				rebound = true
			}
			for _, argument := range call.Args {
				if types.ExprString(argument) != execution {
					continue
				}
				callee, exact := call.Fun.(*ast.Ident)
				if !exact || callee.Name != "configuredDependency" || len(call.Args) != 1 {
					rebound = true
				}
			}
		}
		if returned, ok := node.(*ast.ReturnStmt); ok && execution != "" && coreAssignment != nil && returned.Pos() > coreAssignment.Pos() {
			for _, result := range returned.Results {
				if l8D2ReadinessExpressionContainsIdentifier(result, execution) {
					rebound = true
				}
			}
		}
		if declaration, ok := node.(*ast.ValueSpec); ok && execution != "" && coreAssignment != nil && declaration.Pos() > coreAssignment.Pos() {
			for _, value := range declaration.Values {
				if l8D2ReadinessExpressionContainsIdentifier(value, execution) {
					rebound = true
				}
			}
		}
		return true
	})
	identifierUses := 0
	if coreAssignment != nil {
		selectorNames := make(map[token.Pos]bool)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok {
				selectorNames[selector.Sel.Pos()] = true
			}
			return true
		})
		ast.Inspect(function.Body, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && identifier.Name == execution && identifier.Pos() >= coreAssignment.Pos() && !selectorNames[identifier.Pos()] {
				identifierUses++
			}
			return true
		})
	}
	return !rebound && identifierUses == 3 && coreCalls == 1 && coreAssignment != nil && validGate != token.NoPos && install != nil && coreAssignment.Pos() < validGate && validGate < install.Pos()
}

func l8D2ReadinessExpressionContainsIdentifier(expression ast.Expr, name string) bool {
	if expression == nil || name == "" {
		return false
	}
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && identifier.Name == name {
			found = true
			return false
		}
		return !found
	})
	return found
}

func l8D2ReadinessBlockReturns(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) == 0 {
		return false
	}
	_, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	return ok
}

func l8D2ReadinessExactStateMutexCall(call *ast.CallExpr, receiver, method string) bool {
	if call == nil || len(call.Args) != 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == method && types.ExprString(selector.X) == receiver+".state.mu"
}

func l8D2ReadinessExactStateDispatchTake(function *ast.FuncDecl, receiver string, copies, writes map[string]int, stateCopies map[string]string) bool {
	if function == nil || function.Type.Params == nil || len(function.Type.Params.List) != 1 || len(function.Type.Params.List[0].Names) != 1 {
		return false
	}
	revision := function.Type.Params.List[0].Names[0].Name
	revisionGate := token.NoPos
	successUnlock := token.NoPos
	latchWrite := token.NoPos
	exactReturn := false
	if len(function.Body.List) == 0 || !l8D2ReadinessExactSelectorCallStatement(function.Body.List[0], receiver+".state.mu", "Lock") {
		return false
	}
	for _, statement := range function.Body.List {
		switch value := statement.(type) {
		case *ast.IfStmt:
			if revisionGate == token.NoPos && value.Init == nil && value.Else == nil && l8D2ReadinessExactDispatchRejectCondition(value.Cond, receiver, revision) && len(value.Body.List) == 2 && l8D2ReadinessExactSelectorCallStatement(value.Body.List[0], receiver+".state.mu", "Unlock") {
				returned, ok := value.Body.List[1].(*ast.ReturnStmt)
				if ok && len(returned.Results) == 2 && !l8D2ReadinessNilIdentifier(returned.Results[1]) {
					revisionGate = value.Pos()
				}
			}
		case *ast.AssignStmt:
			if len(value.Lhs) == 1 && types.ExprString(value.Lhs[0]) == receiver+".state.dispatchTaken" && len(value.Rhs) == 1 && types.ExprString(value.Rhs[0]) == "true" {
				latchWrite = value.Pos()
			}
		case *ast.ExprStmt:
			call, ok := value.X.(*ast.CallExpr)
			if ok && l8D2ReadinessExactStateMutexCall(call, receiver, "Unlock") {
				successUnlock = value.Pos()
			}
		case *ast.ReturnStmt:
			if len(value.Results) != 2 || !l8D2ReadinessNilIdentifier(value.Results[1]) {
				continue
			}
			literal, ok := value.Results[0].(*ast.CompositeLit)
			if !ok || types.ExprString(literal.Type) != "serviceExecDispatch" || len(literal.Elts) != 3 {
				continue
			}
			fields := make(map[string]string)
			for _, element := range literal.Elts {
				keyed, ok := element.(*ast.KeyValueExpr)
				key, keyOK := func() (*ast.Ident, bool) {
					if !ok {
						return nil, false
					}
					candidate, valid := keyed.Key.(*ast.Ident)
					return candidate, valid
				}()
				identifier, valueOK := func() (*ast.Ident, bool) {
					if !ok {
						return nil, false
					}
					candidate, valid := keyed.Value.(*ast.Ident)
					return candidate, valid
				}()
				if !keyOK || !valueOK {
					continue
				}
				fields[key.Name] = stateCopies[identifier.Name]
			}
			exactReturn = fields["transaction"] == "transaction" && fields["correlation"] == "correlation" && fields["comparison"] == "comparison" && successUnlock < value.Pos()
		}
	}
	return revisionGate != token.NoPos && revisionGate < latchWrite && latchWrite < successUnlock && exactReturn && copies["transaction"] == 1 && copies["correlation"] == 1 && copies["comparison"] == 1 && writes["dispatchTaken"] == 1
}

func l8D2ReadinessExactDispatchRejectCondition(expression ast.Expr, receiver, revision string) bool {
	condition, ok := expression.(*ast.BinaryExpr)
	if !ok || condition.Op != token.LOR {
		return false
	}
	mismatch := func(candidate ast.Expr) bool {
		binary, ok := candidate.(*ast.BinaryExpr)
		return ok && binary.Op == token.NEQ && types.ExprString(binary.X) == revision && types.ExprString(binary.Y) == receiver+".state.revision"
	}
	taken := func(candidate ast.Expr) bool {
		return types.ExprString(candidate) == receiver+".state.dispatchTaken"
	}
	return (mismatch(condition.X) && taken(condition.Y)) || (taken(condition.X) && mismatch(condition.Y))
}

func l8D2ReadinessReachableServiceStateStableLegacy(reachable map[*ast.FuncDecl]bool, serve *ast.FuncDecl) bool {
	for function := range reachable {
		receiver := l8D2ReadinessReceiverName(function)
		if receiver == "" {
			continue
		}
		stateAliases := make(map[string]bool)
		stateFieldPointers := make(map[string]bool)
		serviceAliases := l8D2ReadinessServiceReceiverAliases(function)
		var isServiceState func(ast.Expr) bool
		isServiceState = func(expression ast.Expr) bool {
			switch value := expression.(type) {
			case *ast.ParenExpr:
				return isServiceState(value.X)
			case *ast.UnaryExpr:
				return value.Op == token.AND && isServiceState(value.X)
			case *ast.StarExpr:
				if owner, ok := value.X.(*ast.Ident); ok {
					return stateFieldPointers[owner.Name]
				}
				return isServiceState(value.X)
			case *ast.Ident:
				return stateAliases[value.Name]
			case *ast.SelectorExpr:
				if value.Sel.Name != "state" {
					return false
				}
				owner, ok := value.X.(*ast.Ident)
				return ok && (owner.Name == receiver || serviceAliases[owner.Name])
			default:
				return false
			}
		}
		isStateLatch := func(expression ast.Expr) bool {
			selector, ok := expression.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "serveCalled" {
				return false
			}
			if isServiceState(selector.X) {
				return true
			}
			owner, ok := selector.X.(*ast.Ident)
			return ok && stateAliases[owner.Name]
		}
		expressionReferencesState := func(expression ast.Expr) bool {
			found := false
			ast.Inspect(expression, func(node ast.Node) bool {
				if found {
					return false
				}
				if selector, ok := node.(*ast.SelectorExpr); ok && types.ExprString(selector) == receiver+".state.execution" {
					return false
				}
				if candidate, ok := node.(ast.Expr); ok && isServiceState(candidate) {
					found = true
					return false
				}
				if identifier, ok := node.(*ast.Ident); ok && stateAliases[identifier.Name] {
					found = true
					return false
				}
				return true
			})
			return found
		}
		var expressionEscapesServiceOwner func(ast.Expr) bool
		expressionEscapesServiceOwner = func(expression ast.Expr) bool {
			switch value := expression.(type) {
			case *ast.Ident:
				return value.Name == receiver || serviceAliases[value.Name]
			case *ast.ParenExpr:
				return expressionEscapesServiceOwner(value.X)
			case *ast.UnaryExpr:
				return expressionEscapesServiceOwner(value.X)
			case *ast.StarExpr:
				return expressionEscapesServiceOwner(value.X)
			case *ast.SelectorExpr:
				if owner, ok := value.X.(*ast.Ident); ok && (owner.Name == receiver || serviceAliases[owner.Name]) {
					switch value.Sel.Name {
					case "core", "transport", "policy", "extensions", "host", "runtime", "state":
						return false
					}
				}
				return expressionEscapesServiceOwner(value.X)
			case *ast.CallExpr:
				for _, argument := range value.Args {
					if expressionEscapesServiceOwner(argument) {
						return true
					}
				}
			case *ast.CompositeLit:
				for _, element := range value.Elts {
					switch item := element.(type) {
					case *ast.KeyValueExpr:
						if expressionEscapesServiceOwner(item.Value) {
							return true
						}
					case ast.Expr:
						if expressionEscapesServiceOwner(item) {
							return true
						}
					}
				}
			case *ast.IndexExpr:
				return expressionEscapesServiceOwner(value.X) || expressionEscapesServiceOwner(value.Index)
			}
			return false
		}
		stable := true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if !stable {
				return false
			}
			switch value := node.(type) {
			case *ast.AssignStmt:
				for index, left := range value.Lhs {
					if isServiceState(left) {
						stable = false
						return false
					}
					if isStateLatch(left) {
						if function != serve || len(serve.Body.List) < 4 || value != serve.Body.List[3] {
							stable = false
							return false
						}
					}
					if star, ok := left.(*ast.StarExpr); ok {
						if identifier, ok := star.X.(*ast.Ident); ok && stateFieldPointers[identifier.Name] {
							stable = false
							return false
						}
					}
					identifier, identifierOK := left.(*ast.Ident)
					if !identifierOK || index >= len(value.Rhs) {
						continue
					}
					rightIdentifier, directServiceAlias := value.Rhs[index].(*ast.Ident)
					directServiceAlias = directServiceAlias && (rightIdentifier.Name == receiver || serviceAliases[rightIdentifier.Name])
					if directServiceAlias && value.Tok != token.DEFINE {
						stable = false
						return false
					}
					if expressionEscapesServiceOwner(value.Rhs[index]) && !directServiceAlias {
						stable = false
						return false
					}
					rightText := types.ExprString(value.Rhs[index])
					directStateAlias := isServiceState(value.Rhs[index]) || stateAliases[rightText]
					stateAliases[identifier.Name] = directStateAlias
					address, addressOK := value.Rhs[index].(*ast.UnaryExpr)
					stateFieldPointers[identifier.Name] = addressOK && address.Op == token.AND && isServiceState(address.X)
					if (stateAliases[identifier.Name] || stateFieldPointers[identifier.Name]) && value.Tok != token.DEFINE {
						stable = false
						return false
					}
					if expressionReferencesState(value.Rhs[index]) && !directStateAlias && !stateFieldPointers[identifier.Name] {
						stable = false
						return false
					}
					continue
				}
				for _, right := range value.Rhs {
					address, addressOK := right.(*ast.UnaryExpr)
					if isServiceState(right) || (addressOK && address.Op == token.AND && isServiceState(address.X)) {
						stable = false
						return false
					}
				}
			case *ast.CallExpr:
				if selector, ok := value.Fun.(*ast.SelectorExpr); ok {
					if isServiceState(selector.X) {
						stable = false
						return false
					}
					if owner, ok := selector.X.(*ast.Ident); ok && stateAliases[owner.Name] {
						stable = false
						return false
					}
				}
				for _, argument := range value.Args {
					argumentText := types.ExprString(argument)
					if expressionReferencesState(argument) || stateAliases[argumentText] || expressionEscapesServiceOwner(argument) {
						stable = false
						return false
					}
					address, ok := argument.(*ast.UnaryExpr)
					if ok && address.Op == token.AND && isServiceState(address.X) {
						stable = false
						return false
					}
				}
			case *ast.ReturnStmt:
				for _, result := range value.Results {
					if expressionReferencesState(result) || expressionEscapesServiceOwner(result) {
						stable = false
						return false
					}
				}
			case *ast.ValueSpec:
				for index, name := range value.Names {
					if index >= len(value.Values) {
						continue
					}
					right := value.Values[index]
					rightIdentifier, directServiceAlias := right.(*ast.Ident)
					directServiceAlias = directServiceAlias && (rightIdentifier.Name == receiver || serviceAliases[rightIdentifier.Name])
					if expressionEscapesServiceOwner(right) && !directServiceAlias {
						stable = false
						return false
					}
					rightText := types.ExprString(right)
					directStateAlias := isServiceState(right) || stateAliases[rightText]
					address, addressOK := right.(*ast.UnaryExpr)
					stateAliases[name.Name] = directStateAlias
					stateFieldPointers[name.Name] = addressOK && address.Op == token.AND && isServiceState(address.X)
					if expressionReferencesState(right) && !directStateAlias && !stateFieldPointers[name.Name] {
						stable = false
						return false
					}
				}
			}
			return true
		})
		if !stable {
			return false
		}
	}
	return true
}

func l8D2ReadinessValidServiceConstructor(constructor, snapshot *ast.FuncDecl, snapshotAliases map[string]string) bool {
	if constructor == nil || snapshot == nil || constructor.Type.Params == nil || len(constructor.Type.Params.List) != 1 || len(constructor.Type.Params.List[0].Names) != 1 || len(constructor.Body.List) != 3 {
		return false
	}
	options := constructor.Type.Params.List[0].Names[0].Name
	validation, ok := constructor.Body.List[0].(*ast.IfStmt)
	if !ok || validation.Init != nil || validation.Else != nil || !l8D2ReadinessConfiguredDependencyCondition(validation.Cond, options) || !l8D2ReadinessImmediateConstructorRejection(validation.Body) {
		return false
	}
	if !l8D2ReadinessValidExtensionSnapshot(snapshot, snapshotAliases) {
		return false
	}
	snapshotAssignment, ok := constructor.Body.List[1].(*ast.AssignStmt)
	if !ok || len(snapshotAssignment.Lhs) != 1 || len(snapshotAssignment.Rhs) != 1 {
		return false
	}
	snapshotName, nameOK := snapshotAssignment.Lhs[0].(*ast.Ident)
	snapshotCall, callOK := snapshotAssignment.Rhs[0].(*ast.CallExpr)
	if !nameOK || !callOK {
		return false
	}
	called, calledOK := snapshotCall.Fun.(*ast.Ident)
	if !calledOK || called.Name != "snapshotServiceExtensionEntries" || len(snapshotCall.Args) != 1 || types.ExprString(snapshotCall.Args[0]) != options+".Extensions" {
		return false
	}
	returned, ok := constructor.Body.List[2].(*ast.ReturnStmt)
	if ok && len(returned.Results) == 2 && l8D2ReadinessNilIdentifier(returned.Results[1]) {
		address, ok := returned.Results[0].(*ast.UnaryExpr)
		if !ok || address.Op != token.AND {
			return false
		}
		literal, literalOK := address.X.(*ast.CompositeLit)
		if !literalOK || types.ExprString(literal.Type) != "Service" {
			return false
		}
		fields := make(map[string]ast.Expr)
		for _, element := range literal.Elts {
			keyed, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, keyOK := keyed.Key.(*ast.Ident)
			if keyOK {
				fields[key.Name] = keyed.Value
			}
		}
		for field, option := range map[string]string{"core": "Core", "transport": "Transport", "policy": "Policy", "host": "Host", "runtime": "Runtime"} {
			if types.ExprString(fields[field]) != options+"."+option {
				return false
			}
		}
		extensions, extensionOK := fields["extensions"].(*ast.Ident)
		stateAddress, stateOK := fields["state"].(*ast.UnaryExpr)
		if !extensionOK || extensions.Name != snapshotName.Name || !stateOK || stateAddress.Op != token.AND {
			return false
		}
		stateLiteral, stateLiteralOK := stateAddress.X.(*ast.CompositeLit)
		return stateLiteralOK && types.ExprString(stateLiteral.Type) == "serviceState" && len(stateLiteral.Elts) == 0
	}
	return false
}

func l8D2ReadinessConfiguredDependencyCondition(condition ast.Expr, options string) bool {
	terms := l8D2ReadinessOrTerms(condition)
	if len(terms) != 5 {
		return false
	}
	found := make(map[string]bool)
	for _, term := range terms {
		for {
			parenthesized, ok := term.(*ast.ParenExpr)
			if !ok {
				break
			}
			term = parenthesized.X
		}
		unary, ok := term.(*ast.UnaryExpr)
		if !ok || unary.Op != token.NOT {
			return false
		}
		call, ok := unary.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return false
		}
		called, calledOK := call.Fun.(*ast.Ident)
		selector, selectorOK := call.Args[0].(*ast.SelectorExpr)
		if !calledOK || called.Name != "configuredDependency" || !selectorOK {
			return false
		}
		owner, ownerOK := selector.X.(*ast.Ident)
		if !ownerOK || owner.Name != options || found[selector.Sel.Name] {
			return false
		}
		found[selector.Sel.Name] = true
	}
	for _, name := range []string{"Core", "Transport", "Policy", "Host", "Runtime"} {
		if !found[name] {
			return false
		}
	}
	return true
}

func l8D2ReadinessOrTerms(expression ast.Expr) []ast.Expr {
	if parenthesized, ok := expression.(*ast.ParenExpr); ok {
		return l8D2ReadinessOrTerms(parenthesized.X)
	}
	if binary, ok := expression.(*ast.BinaryExpr); ok && binary.Op == token.LOR {
		return append(l8D2ReadinessOrTerms(binary.X), l8D2ReadinessOrTerms(binary.Y)...)
	}
	return []ast.Expr{expression}
}

func l8D2ReadinessImmediateConstructorRejection(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) != 1 {
		return false
	}
	returned, ok := body.List[0].(*ast.ReturnStmt)
	return ok && len(returned.Results) == 2 && l8D2ReadinessNilIdentifier(returned.Results[0]) && types.ExprString(returned.Results[1]) == "ErrContractDependency"
}

func l8D2ReadinessValidExtensionSnapshot(function *ast.FuncDecl, aliases map[string]string) bool {
	if function == nil || function.Type.Params == nil || len(function.Type.Params.List) != 1 || len(function.Type.Params.List[0].Names) != 1 || types.ExprString(function.Type.Params.List[0].Type) != "*ExtensionRegistry" || strings.Join(l8D2ReadinessFieldListTypes(function.Type.Results), ",") != "[]extensionEntry" {
		return false
	}
	registry := function.Type.Params.List[0].Names[0].Name
	if len(function.Body.List) != 4 {
		return false
	}
	nilCheck, ok := function.Body.List[0].(*ast.IfStmt)
	if !ok || !l8D2ReadinessNilEquality(nilCheck.Cond, registry) || nilCheck.Else != nil || len(nilCheck.Body.List) != 1 {
		return false
	}
	nilReturn, ok := nilCheck.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(nilReturn.Results) != 1 || !l8D2ReadinessNilIdentifier(nilReturn.Results[0]) {
		return false
	}
	allocated := make(map[string]token.Pos)
	returned := make(map[string]token.Pos)
	validRange := make(map[string]token.Pos)
	for _, statement := range function.Body.List {
		switch value := statement.(type) {
		case *ast.AssignStmt:
			if len(value.Lhs) != 1 || len(value.Rhs) != 1 {
				continue
			}
			name, nameOK := value.Lhs[0].(*ast.Ident)
			call, callOK := value.Rhs[0].(*ast.CallExpr)
			if !nameOK || !callOK {
				continue
			}
			called, calledOK := call.Fun.(*ast.Ident)
			if calledOK && called.Name == "make" && len(call.Args) == 2 && types.ExprString(call.Args[0]) == "[]extensionEntry" && types.ExprString(call.Args[1]) == "len("+registry+".entries)" {
				allocated[name.Name] = value.Pos()
			}
		case *ast.RangeStmt:
			index, indexOK := value.Key.(*ast.Ident)
			entry, entryOK := value.Value.(*ast.Ident)
			if !indexOK || !entryOK || types.ExprString(value.X) != registry+".entries" || len(value.Body.List) != 1 {
				continue
			}
			assignment, ok := value.Body.List[0].(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				continue
			}
			indexed, indexedOK := assignment.Lhs[0].(*ast.IndexExpr)
			literal, literalOK := assignment.Rhs[0].(*ast.CompositeLit)
			if !indexedOK || !literalOK || types.ExprString(indexed.Index) != index.Name || types.ExprString(literal.Type) != "extensionEntry" {
				continue
			}
			resultName, resultOK := indexed.X.(*ast.Ident)
			if !resultOK || allocated[resultName.Name] == token.NoPos {
				continue
			}
			fields := make(map[string]ast.Expr)
			for _, element := range literal.Elts {
				keyed, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, keyOK := keyed.Key.(*ast.Ident)
				if keyOK {
					fields[key.Name] = keyed.Value
				}
			}
			descriptorCall, descriptorOK := fields["descriptor"].(*ast.CallExpr)
			factory := types.ExprString(fields["factory"])
			var descriptorFunction *ast.SelectorExpr
			var packageName *ast.Ident
			functionOK, packageOK := false, false
			if descriptorOK {
				descriptorFunction, functionOK = descriptorCall.Fun.(*ast.SelectorExpr)
			}
			if functionOK {
				packageName, packageOK = descriptorFunction.X.(*ast.Ident)
			}
			if descriptorOK && functionOK && packageOK && aliases[packageName.Name] == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol" && descriptorFunction.Sel.Name == "CloneExtensionDescriptor" && len(descriptorCall.Args) == 1 && types.ExprString(descriptorCall.Args[0]) == entry.Name+".descriptor" && factory == entry.Name+".factory" {
				validRange[resultName.Name] = value.Pos()
			}
		case *ast.ReturnStmt:
			if len(value.Results) == 1 {
				if name, ok := value.Results[0].(*ast.Ident); ok && allocated[name.Name] != token.NoPos {
					returned[name.Name] = value.Pos()
				}
			}
		}
	}
	for name, returnPosition := range returned {
		if allocationPosition, rangePosition := allocated[name], validRange[name]; allocationPosition != token.NoPos && rangePosition != token.NoPos && nilCheck.Pos() < allocationPosition && allocationPosition < rangePosition && rangePosition < returnPosition {
			return true
		}
	}
	return false
}

func l8D2ReadinessNilEquality(condition ast.Expr, name string) bool {
	binary, ok := condition.(*ast.BinaryExpr)
	return ok && binary.Op == token.EQL && ((types.ExprString(binary.X) == name && l8D2ReadinessNilIdentifier(binary.Y)) || (types.ExprString(binary.Y) == name && l8D2ReadinessNilIdentifier(binary.X)))
}

func l8D2ReadinessValidServeOneShot(serve *ast.FuncDecl, aliases map[string]string) bool {
	if serve == nil || serve.Type.Params == nil || len(serve.Type.Params.List) != 1 || len(serve.Type.Params.List[0].Names) != 1 || len(serve.Body.List) < 5 {
		return false
	}
	receiver := l8D2ReadinessReceiverName(serve)
	ctx := serve.Type.Params.List[0].Names[0].Name
	if !l8D2ReadinessExactImportedType(serve.Type.Params.List[0].Type, aliases, "context", "Context", false) {
		return false
	}
	contextCheck, ok := serve.Body.List[0].(*ast.IfStmt)
	if !ok || contextCheck.Init == nil || !l8D2ReadinessIsContextPrecondition(contextCheck.Init, contextCheck.Cond, contextCheck.Body, ctx) {
		return false
	}
	lock := l8D2ReadinessExactSelectorCallStatement(serve.Body.List[1], receiver+".state.mu", "Lock")
	called, ok := serve.Body.List[2].(*ast.IfStmt)
	if !ok || types.ExprString(called.Cond) != receiver+".state.serveCalled" || called.Else != nil || len(called.Body.List) != 2 || !l8D2ReadinessExactSelectorCallStatement(called.Body.List[0], receiver+".state.mu", "Unlock") || !l8D2ReadinessTransitionReturn(called.Body.List[1]) {
		return false
	}
	assignment, ok := serve.Body.List[3].(*ast.AssignStmt)
	set := ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 && types.ExprString(assignment.Lhs[0]) == receiver+".state.serveCalled" && types.ExprString(assignment.Rhs[0]) == "true"
	unlock := l8D2ReadinessExactSelectorCallStatement(serve.Body.List[4], receiver+".state.mu", "Unlock")
	lockCalls, unlockCalls, latchReads, latchWrites := 0, 0, 0, 0
	ast.Inspect(serve.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.CallExpr:
			selector, ok := value.Fun.(*ast.SelectorExpr)
			if !ok || types.ExprString(selector.X) != receiver+".state.mu" {
				return true
			}
			if selector.Sel.Name == "Lock" {
				lockCalls++
			}
			if selector.Sel.Name == "Unlock" {
				unlockCalls++
			}
		case *ast.SelectorExpr:
			if types.ExprString(value) == receiver+".state.serveCalled" {
				latchReads++
			}
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if types.ExprString(left) == receiver+".state.serveCalled" {
					latchWrites++
				}
			}
		}
		return true
	})
	// Selector inspection counts the one assignment LHS as a selector use too.
	return lock && set && unlock && lockCalls == 1 && unlockCalls == 2 && latchReads == 2 && latchWrites == 1
}

func l8D2ReadinessAnalyzeServiceBorrowCallbacks(function *ast.FuncDecl, aliases map[string]string) (bool, bool) {
	receiver := l8D2ReadinessReceiverName(function)
	if receiver == "" {
		return false, false
	}
	bodyParams := make(map[string]bool)
	transactionParams := make(map[string]bool)
	contextParams := make(map[string]bool)
	comparisonParams := make(map[string]bool)
	correlationParams := make(map[string]bool)
	privateObservationParams := make(map[string]bool)
	streamObservationParams := make(map[string]bool)
	configuredDependencyShadowed := false
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				if name.Name == "configuredDependency" {
					configuredDependencyShadowed = true
				}
				if types.ExprString(field.Type) == "ReceivedBodyCapability" {
					bodyParams[name.Name] = true
				}
				if l8D2ReadinessExactImportedType(field.Type, aliases, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol", "HelperExecTransaction", true) {
					transactionParams[name.Name] = true
				}
				if l8D2ReadinessExactImportedType(field.Type, aliases, "context", "Context", false) {
					contextParams[name.Name] = true
				}
				if name.Name == "comparison" && types.ExprString(field.Type) == "bool" {
					comparisonParams[name.Name] = true
				}
				if l8D2ReadinessExactImportedType(field.Type, aliases, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol", "HelperExecTransactionCorrelation", false) {
					correlationParams[name.Name] = true
				}
				if l8D2ReadinessExactImportedType(field.Type, aliases, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol", "HelperExecPrivateObservation", false) {
					privateObservationParams[name.Name] = true
				}
				if l8D2ReadinessExactImportedType(field.Type, aliases, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol", "HelperExecStreamObservation", false) {
					streamObservationParams[name.Name] = true
				}
			}
		}
	}
	protected := map[string]bool{receiver: true}
	for name := range bodyParams {
		protected[name] = true
	}
	for name := range transactionParams {
		protected[name] = true
	}
	for name := range contextParams {
		protected[name] = true
	}
	for name := range comparisonParams {
		protected[name] = true
	}
	for name := range correlationParams {
		protected[name] = true
	}
	for name := range privateObservationParams {
		protected[name] = true
	}
	for name := range streamObservationParams {
		protected[name] = true
	}
	if configuredDependencyShadowed || l8D2ReadinessBodyRebindsNames(function.Body, protected, nil) {
		return false, false
	}
	if len(bodyParams) != 1 || len(transactionParams) != 1 || len(contextParams) != 1 || len(comparisonParams) != 1 || len(correlationParams) != 1 || (len(privateObservationParams) == 0) == (len(streamObservationParams) == 0) || len(privateObservationParams)+len(streamObservationParams) != 1 {
		return false, false
	}
	private, stdin := false, false
	borrowCalls := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		body, bodyOK := selector.X.(*ast.Ident)
		if bodyOK && selector.Sel.Name == "Borrow" && bodyParams[body.Name] {
			borrowCalls++
		}
		return true
	})
	if borrowCalls != 1 {
		return false, false
	}
	for statementIndex, statement := range function.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			continue
		}
		borrowError, errorOK := assignment.Lhs[0].(*ast.Ident)
		call, callOK := assignment.Rhs[0].(*ast.CallExpr)
		if !errorOK || !callOK || !l8D2ReadinessBorrowErrorPropagated(function.Body, statementIndex, borrowError.Name) {
			continue
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		body, bodyOK := selector.X.(*ast.Ident)
		if !bodyOK || selector.Sel.Name != "Borrow" || !bodyParams[body.Name] || len(call.Args) != 2 {
			continue
		}
		ctx, ctxOK := call.Args[0].(*ast.Ident)
		callback, callbackOK := call.Args[1].(*ast.FuncLit)
		if !ctxOK || !contextParams[ctx.Name] || !callbackOK || callback.Type.Params == nil || len(callback.Type.Params.List) != 1 || len(callback.Type.Params.List[0].Names) != 1 || !l8D2ReadinessExactImportedType(callback.Type.Params.List[0].Type, aliases, "github.com/jywlabs/hal/internal/credentialmemory", "BorrowedView", false) {
			continue
		}
		view := callback.Type.Params.List[0].Names[0].Name
		private = private || (l8D2ReadinessValidPrivateCallback(callback, receiver, ctx.Name, view, transactionParams, comparisonParams, correlationParams, privateObservationParams) && l8D2ReadinessObservedHandlerCleanupStable(function, callback, receiver, ctx.Name, body.Name, true))
		stdin = stdin || (l8D2ReadinessValidStdinCallback(callback, receiver, ctx.Name, view, transactionParams, comparisonParams, correlationParams, streamObservationParams) && l8D2ReadinessObservedHandlerCleanupStable(function, callback, receiver, ctx.Name, body.Name, false))
	}
	return private, stdin
}

func l8D2ReadinessBorrowErrorPropagated(body *ast.BlockStmt, assignmentIndex int, errorName string) bool {
	if body == nil || assignmentIndex < 0 || assignmentIndex+1 >= len(body.List) {
		return false
	}
	gate, ok := body.List[assignmentIndex+1].(*ast.IfStmt)
	if !ok || gate.Init != nil || gate.Else != nil || !l8D2ReadinessExactErrorNonNilCondition(gate.Cond, errorName) || len(gate.Body.List) == 0 {
		return false
	}
	returned, ok := gate.Body.List[len(gate.Body.List)-1].(*ast.ReturnStmt)
	return ok && len(returned.Results) > 0 && types.ExprString(returned.Results[len(returned.Results)-1]) == errorName
}

func l8D2ReadinessObservedHandlerCleanupStable(function *ast.FuncDecl, callback *ast.FuncLit, receiver, contextName, bodyName string, planRequired bool) bool {
	if function == nil || function.Body == nil || callback == nil || callback.Body == nil {
		return false
	}
	resultName, errorName, namedResults := l8D2ReadinessNamedServiceHandlerResults(function)
	if !namedResults {
		return false
	}
	if l8D2ReadinessFunctionShadowsCleanupAuthority(function) {
		return false
	}
	planName, pendingName := "", ""
	planPosition, pendingPosition, deferPosition, borrowPosition := token.NoPos, token.NoPos, token.NoPos, token.NoPos
	var recovery *ast.IfStmt
	var deferredBody *ast.BlockStmt
	deferCount := 0
	for _, statement := range function.Body.List {
		if returned, ok := statement.(*ast.ReturnStmt); ok && deferPosition == token.NoPos && len(returned.Results) != 0 {
			return false
		}
		switch value := statement.(type) {
		case *ast.AssignStmt:
			if len(value.Lhs) == 1 && len(value.Rhs) == 1 && types.ExprString(value.Rhs[0]) == receiver+".state.plan" {
				if identifier, ok := value.Lhs[0].(*ast.Ident); ok && identifier.Name != "_" {
					planName, planPosition = identifier.Name, value.Pos()
				}
			}
			if len(value.Rhs) == 1 {
				call, ok := value.Rhs[0].(*ast.CallExpr)
				selector, selectorOK := func() (*ast.SelectorExpr, bool) {
					if !ok {
						return nil, false
					}
					candidate, valid := call.Fun.(*ast.SelectorExpr)
					return candidate, valid
				}()
				owner, ownerOK := func() (*ast.Ident, bool) {
					if !selectorOK {
						return nil, false
					}
					candidate, valid := selector.X.(*ast.Ident)
					return candidate, valid
				}()
				if ownerOK && owner.Name == bodyName && selector.Sel.Name == "Borrow" {
					borrowPosition = value.Pos()
				}
			}
		case *ast.DeclStmt:
			declaration, ok := value.Decl.(*ast.GenDecl)
			if !ok || declaration.Tok != token.VAR {
				continue
			}
			for _, specification := range declaration.Specs {
				valueSpec, ok := specification.(*ast.ValueSpec)
				if ok && len(valueSpec.Names) == 1 && len(valueSpec.Values) == 0 && types.ExprString(valueSpec.Type) == "Proposal" {
					pendingName, pendingPosition = valueSpec.Names[0].Name, value.Pos()
				}
			}
		case *ast.DeferStmt:
			deferCount++
			if deferPosition != token.NoPos || len(value.Call.Args) != 0 {
				continue
			}
			deferred, ok := value.Call.Fun.(*ast.FuncLit)
			if !ok || deferred.Body == nil {
				continue
			}
			deferPosition = value.Pos()
			deferredBody = deferred.Body
			for _, deferredStatement := range deferred.Body.List {
				candidate, ok := deferredStatement.(*ast.IfStmt)
				if ok && l8D2ReadinessExactRecoverGate(candidate) {
					recovery = candidate
				}
			}
		}
	}
	if deferCount != 1 || deferPosition == token.NoPos || borrowPosition == token.NoPos || deferPosition >= borrowPosition || pendingName == "" || pendingPosition == token.NoPos || pendingPosition >= deferPosition || recovery == nil || deferredBody == nil || (planRequired && (planName == "" || planPosition == token.NoPos || planPosition >= deferPosition)) {
		return false
	}
	callbackDefers := 0
	proposalName, proposalErrorName := "", ""
	proposePosition, proposalGate, pendingInstall, firstAuthority := token.NoPos, token.NoPos, token.NoPos, token.NoPos
	directCallback := l8D2ReadinessDirectStatements(callback.Body)
	ast.Inspect(callback.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.DeferStmt:
			callbackDefers++
		case *ast.AssignStmt:
			if len(value.Lhs) == 2 && len(value.Rhs) == 1 {
				call, ok := value.Rhs[0].(*ast.CallExpr)
				method := ""
				if ok {
					method = l8D2ReadinessCallMethodName(call)
				}
				if (method == "ProposeObservedPrivate" || method == "ProposeObservedStdin") && directCallback[value] {
					if proposal, ok := value.Lhs[0].(*ast.Ident); ok && proposal.Name != "_" {
						proposalName, proposePosition = proposal.Name, value.Pos()
					}
					if proposalError, ok := value.Lhs[1].(*ast.Ident); ok && proposalError.Name != "_" {
						proposalErrorName = proposalError.Name
					}
				}
			}
			if proposalName != "" && len(value.Lhs) == 1 && len(value.Rhs) == 1 && types.ExprString(value.Lhs[0]) == pendingName && types.ExprString(value.Rhs[0]) == proposalName && directCallback[value] {
				if pendingInstall != token.NoPos {
					pendingInstall = token.NoPos
				} else {
					pendingInstall = value.Pos()
				}
			}
		case *ast.IfStmt:
			if proposalName != "" && proposalErrorName != "" && directCallback[value] && value.Pos() > proposePosition && proposalGate == token.NoPos && l8D2ReadinessExactErrorReturnGate(value, proposalErrorName) {
				proposalGate = value.Pos()
			}
		case *ast.CallExpr:
			method := l8D2ReadinessCallMethodName(value)
			if proposePosition != token.NoPos && value.Pos() > proposePosition && method != "ProposeObservedPrivate" && method != "ProposeObservedStdin" && firstAuthority == token.NoPos && (method == "BeginExec" || method == "WriteStdin" || method == "Commit") {
				firstAuthority = value.Pos()
			}
		}
		return true
	})
	if callbackDefers != 0 || proposalName == "" || proposalErrorName == "" || proposePosition == token.NoPos || proposalGate == token.NoPos || pendingInstall == token.NoPos || firstAuthority == token.NoPos || !(proposePosition < proposalGate && proposalGate < pendingInstall && pendingInstall < firstAuthority) {
		return false
	}
	if !l8D2ReadinessExactRecoveredHandlerFailure(recovery.Body, pendingName, resultName, errorName) {
		return false
	}
	wantDeferredStatements := 3
	if planRequired {
		wantDeferredStatements = 4
	}
	if len(deferredBody.List) != wantDeferredStatements || deferredBody.List[0] != recovery {
		return false
	}
	bodyDestroyError, bodyDestroyOK := l8D2ReadinessExactBoundBodyDestroy(deferredBody.List[1], bodyName, contextName)
	if !bodyDestroyOK {
		return false
	}
	failureIndex := 2
	if planRequired {
		if !l8D2ReadinessExactPrivatePlanDestroy(deferredBody.List[2], planName) {
			return false
		}
		failureIndex = 3
	}
	if !l8D2ReadinessExactCleanupFailureGate(deferredBody.List[failureIndex], bodyDestroyError, resultName, errorName) {
		return false
	}
	bodyDestroyCount, planDestroyCount := 0, 0
	bodyDestroyPosition, planDestroyPosition := token.NoPos, token.NoPos
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		owner, ownerOK := func() (*ast.Ident, bool) {
			if !ok {
				return nil, false
			}
			candidate, valid := selector.X.(*ast.Ident)
			return candidate, valid
		}()
		if ownerOK && owner.Name == bodyName && l8D2ReadinessCallMethodName(call) == "Destroy" && len(call.Args) == 1 && types.ExprString(call.Args[0]) == contextName {
			bodyDestroyCount++
			bodyDestroyPosition = call.Pos()
		}
		if ownerOK && owner.Name == planName && l8D2ReadinessCallMethodName(call) == "destroy" && len(call.Args) == 0 {
			planDestroyCount++
			planDestroyPosition = call.Pos()
		}
		return true
	})
	if bodyDestroyCount != 1 || (planRequired && planDestroyCount != 1) || (!planRequired && planDestroyCount != 0) {
		return false
	}
	return recovery.Pos() < bodyDestroyPosition && (!planRequired || bodyDestroyPosition < planDestroyPosition)
}

func l8D2ReadinessFunctionShadowsCleanupAuthority(function *ast.FuncDecl) bool {
	if function == nil || function.Body == nil {
		return true
	}
	protected := map[string]bool{
		"newServiceResult":      true,
		"ErrContractOwnership":  true,
		"ServiceStopVMRequired": true,
		"credentialprotocol":    true,
	}
	shadowed := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if shadowed {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if identifier, ok := left.(*ast.Ident); ok && protected[identifier.Name] {
					shadowed = true
					return false
				}
			}
		case *ast.ValueSpec:
			for _, name := range value.Names {
				if protected[name.Name] {
					shadowed = true
					return false
				}
			}
		}
		return true
	})
	return shadowed
}

func l8D2ReadinessNamedServiceHandlerResults(function *ast.FuncDecl) (string, string, bool) {
	if function == nil || function.Type.Results == nil || len(function.Type.Results.List) != 2 {
		return "", "", false
	}
	result, failure := function.Type.Results.List[0], function.Type.Results.List[1]
	if len(result.Names) != 1 || len(failure.Names) != 1 || types.ExprString(result.Type) != "ServiceResult" || types.ExprString(failure.Type) != "error" || result.Names[0].Name == "_" || failure.Names[0].Name == "_" {
		return "", "", false
	}
	return result.Names[0].Name, failure.Names[0].Name, true
}

func l8D2ReadinessExactBoundBodyDestroy(statement ast.Stmt, ownerName, contextName string) (string, bool) {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return "", false
	}
	failure, failureOK := assignment.Lhs[0].(*ast.Ident)
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !failureOK || !ok || failure.Name == "_" || len(call.Args) != 1 || types.ExprString(call.Args[0]) != contextName || l8D2ReadinessCallMethodName(call) != "Destroy" {
		return "", false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	owner, ok := func() (*ast.Ident, bool) {
		if !ok {
			return nil, false
		}
		candidate, valid := selector.X.(*ast.Ident)
		return candidate, valid
	}()
	return failure.Name, ok && owner.Name == ownerName
}

func l8D2ReadinessExactPrivatePlanDestroy(statement ast.Stmt, ownerName string) bool {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 || l8D2ReadinessCallMethodName(call) != "destroy" {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	owner, ownerOK := func() (*ast.Ident, bool) {
		if !ok {
			return nil, false
		}
		candidate, valid := selector.X.(*ast.Ident)
		return candidate, valid
	}()
	return ownerOK && owner.Name == ownerName
}

func l8D2ReadinessExactProtocolFailureReduction(body *ast.BlockStmt, resultName, errorName string) bool {
	if body == nil || len(body.List) != 2 {
		return false
	}
	resultAssignment, ok := body.List[0].(*ast.AssignStmt)
	if !ok || resultAssignment.Tok != token.ASSIGN || len(resultAssignment.Lhs) != 2 || len(resultAssignment.Rhs) != 1 || types.ExprString(resultAssignment.Lhs[0]) != resultName || types.ExprString(resultAssignment.Lhs[1]) != "_" {
		return false
	}
	call, ok := resultAssignment.Rhs[0].(*ast.CallExpr)
	callee, callOK := func() (*ast.Ident, bool) {
		if !ok {
			return nil, false
		}
		candidate, valid := call.Fun.(*ast.Ident)
		return candidate, valid
	}()
	if !callOK || callee.Name != "newServiceResult" || len(call.Args) != 2 || types.ExprString(call.Args[0]) != "ServiceStopVMRequired" || types.ExprString(call.Args[1]) != "credentialprotocol.CloseReasonProtocolError" {
		return false
	}
	errorAssignment, ok := body.List[1].(*ast.AssignStmt)
	return ok && errorAssignment.Tok == token.ASSIGN && len(errorAssignment.Lhs) == 1 && len(errorAssignment.Rhs) == 1 && types.ExprString(errorAssignment.Lhs[0]) == errorName && types.ExprString(errorAssignment.Rhs[0]) == "ErrContractOwnership"
}

func l8D2ReadinessExactRecoveredHandlerFailure(body *ast.BlockStmt, pendingName, resultName, errorName string) bool {
	if body == nil || len(body.List) != 3 {
		return false
	}
	wipe := &ast.BlockStmt{List: body.List[:1]}
	reduction := &ast.BlockStmt{List: body.List[1:]}
	return l8D2ReadinessExactPendingRecoveryWipe(wipe, pendingName) && l8D2ReadinessExactProtocolFailureReduction(reduction, resultName, errorName)
}

func l8D2ReadinessExactCleanupFailureGate(statement ast.Stmt, destroyError, resultName, errorName string) bool {
	gate, ok := statement.(*ast.IfStmt)
	return ok && gate.Init == nil && gate.Else == nil && l8D2ReadinessExactErrorNonNilCondition(gate.Cond, destroyError) && l8D2ReadinessExactProtocolFailureReduction(gate.Body, resultName, errorName)
}

func l8D2ReadinessExactPendingRecoveryWipe(body *ast.BlockStmt, pendingName string) bool {
	if body == nil || len(body.List) != 1 || pendingName == "" {
		return false
	}
	gate, ok := body.List[0].(*ast.IfStmt)
	if !ok || gate.Init != nil || gate.Else != nil || len(gate.Body.List) != 1 {
		return false
	}
	condition, ok := gate.Cond.(*ast.BinaryExpr)
	if !ok || condition.Op != token.NEQ || types.ExprString(condition.X) != pendingName || !l8D2ReadinessNilIdentifier(condition.Y) {
		return false
	}
	statement, ok := gate.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := statement.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 || l8D2ReadinessCallMethodName(call) != "Wipe" {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	owner, ok := selector.X.(*ast.Ident)
	return ok && owner.Name == pendingName
}

func l8D2ReadinessExactRecoverGate(gate *ast.IfStmt) bool {
	if gate == nil || gate.Else != nil || gate.Init == nil {
		return false
	}
	assignment, ok := gate.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	recovered, recoveredOK := assignment.Lhs[0].(*ast.Ident)
	call, callOK := assignment.Rhs[0].(*ast.CallExpr)
	builtin, builtinOK := func() (*ast.Ident, bool) {
		if !callOK {
			return nil, false
		}
		candidate, valid := call.Fun.(*ast.Ident)
		return candidate, valid
	}()
	if !recoveredOK || !builtinOK || recovered.Name == "_" || builtin.Name != "recover" || len(call.Args) != 0 {
		return false
	}
	return l8D2ReadinessExactErrorNonNilCondition(gate.Cond, recovered.Name) && l8D2ReadinessBlockReturnsOrContinues(gate.Body)
}

func l8D2ReadinessBlockReturnsOrContinues(body *ast.BlockStmt) bool {
	return body != nil && len(body.List) != 0
}

type l8D2ReadinessProposalFlow struct {
	proposal             string
	propose              token.Pos
	core                 token.Pos
	normalCommit         token.Pos
	wipe                 token.Pos
	comparisonGood       bool
	coreReceiver         string
	coreError            string
	execution            string
	proposalError        string
	proposalErrorGate    token.Pos
	viewAtPropose        bool
	viewAtCore           bool
	contextAtPropose     bool
	contextAtCore        bool
	proposeCount         int
	coreCount            int
	normalCommits        int
	proposeDirect        bool
	coreDirect           bool
	commitDirect         bool
	comparisonDirect     bool
	correlationAtPropose bool
	observationAtPropose bool
	totalProposeCalls    int
	totalCoreCalls       int
	commitCalls          int
	wipeCalls            int
	proposeAssignment    *ast.AssignStmt
	coreAssignment       *ast.AssignStmt
}

func l8D2ReadinessValidPrivateCallback(callback *ast.FuncLit, serviceReceiver, contextName, view string, transactionParams, comparisonParams, correlationParams, observationParams map[string]bool) bool {
	flow := l8D2ReadinessProposalCallbackFlow(callback, "ProposeObservedPrivate", "BeginExec", serviceReceiver, contextName, view, transactionParams, comparisonParams, correlationParams, observationParams)
	if l8D2ReadinessCallbackRetainsScopedIdentifier(callback, view) || l8D2ReadinessCallbackContainsNestedAuthority(callback, flow.proposal) || flow.proposal == "" || flow.propose == token.NoPos || flow.proposalErrorGate == token.NoPos || flow.core == token.NoPos || flow.normalCommit == token.NoPos || flow.wipe == token.NoPos || !flow.proposeDirect || !flow.coreDirect || !flow.commitDirect || !flow.comparisonDirect || !flow.comparisonGood || flow.coreReceiver != serviceReceiver+".core" || !flow.viewAtCore || !flow.contextAtCore || !flow.correlationAtPropose || !flow.observationAtPropose || !(flow.propose < flow.proposalErrorGate && flow.proposalErrorGate < flow.core && flow.core < flow.normalCommit) || flow.execution == "" || flow.coreError == "" || flow.proposalError == "" || flow.proposeCount != 1 || flow.coreCount != 1 || flow.normalCommits != 1 || flow.totalProposeCalls != 1 || flow.totalCoreCalls != 1 || flow.commitCalls != 2 || flow.wipeCalls != 1 || l8D2ReadinessCallbackRebindsAuthority(callback, serviceReceiver, contextName, view, transactionParams, comparisonParams, correlationParams, observationParams, flow) {
		return false
	}
	var validMatrix, retainedExecution token.Pos
	direct := l8D2ReadinessDirectStatements(callback.Body)
	ast.Inspect(callback.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.IfStmt:
			if direct[value] && value.Pos() > flow.core && value.Pos() < flow.normalCommit && l8D2ReadinessCoreResultFailureCondition(value.Cond, flow.coreError, flow.execution) && l8D2ReadinessBlockWipesThenReturnsError(value.Body, flow.proposal) {
				validMatrix = value.Pos()
			}
		case *ast.AssignStmt:
			if direct[value] && value.Pos() > flow.core && value.Pos() < flow.normalCommit && len(value.Lhs) == 1 && len(value.Rhs) == 1 && types.ExprString(value.Lhs[0]) == serviceReceiver+".state.execution" && types.ExprString(value.Rhs[0]) == flow.execution {
				retainedExecution = value.Pos()
			}
		}
		return true
	})
	return validMatrix != token.NoPos && retainedExecution != token.NoPos && flow.core < validMatrix && validMatrix < retainedExecution && retainedExecution < flow.normalCommit
}

func l8D2ReadinessValidStdinCallback(callback *ast.FuncLit, serviceReceiver, contextName, view string, transactionParams, comparisonParams, correlationParams, observationParams map[string]bool) bool {
	flow := l8D2ReadinessProposalCallbackFlow(callback, "ProposeObservedStdin", "WriteStdin", serviceReceiver, contextName, view, transactionParams, comparisonParams, correlationParams, observationParams)
	if l8D2ReadinessCallbackRetainsScopedIdentifier(callback, view) || l8D2ReadinessCallbackContainsNestedAuthority(callback, flow.proposal) || flow.proposal == "" || flow.propose == token.NoPos || flow.proposalErrorGate == token.NoPos || flow.core == token.NoPos || flow.normalCommit == token.NoPos || flow.wipe == token.NoPos || !flow.proposeDirect || !flow.coreDirect || !flow.commitDirect || !flow.comparisonDirect || !flow.comparisonGood || !l8D2ReadinessCallbackUsesStateExecution(callback, serviceReceiver, flow.coreReceiver, flow.core) || !flow.viewAtPropose || !flow.viewAtCore || !flow.contextAtPropose || !flow.contextAtCore || !flow.correlationAtPropose || !flow.observationAtPropose || !(flow.propose < flow.proposalErrorGate && flow.proposalErrorGate < flow.core && flow.core < flow.normalCommit) || flow.coreError == "" || flow.proposalError == "" || flow.proposeCount != 1 || flow.coreCount != 1 || flow.normalCommits != 1 || flow.totalProposeCalls != 1 || flow.totalCoreCalls != 1 || flow.commitCalls != 2 || flow.wipeCalls != 1 || l8D2ReadinessCallbackRebindsAuthority(callback, serviceReceiver, contextName, view, transactionParams, comparisonParams, correlationParams, observationParams, flow) {
		return false
	}
	validErrorGate := false
	direct := l8D2ReadinessDirectStatements(callback.Body)
	ast.Inspect(callback.Body, func(node ast.Node) bool {
		condition, ok := node.(*ast.IfStmt)
		if ok && direct[condition] && condition.Pos() > flow.core && condition.Pos() < flow.normalCommit && l8D2ReadinessExactErrorNonNilCondition(condition.Cond, flow.coreError) && l8D2ReadinessBlockWipesThenReturnsError(condition.Body, flow.proposal) {
			validErrorGate = true
		}
		return true
	})
	return validErrorGate
}

func l8D2ReadinessCallbackUsesStateExecution(callback *ast.FuncLit, serviceReceiver, execution string, corePosition token.Pos) bool {
	if callback == nil || callback.Body == nil || execution == "" || corePosition == token.NoPos {
		return false
	}
	locked, copied, unlocked := token.NoPos, token.NoPos, token.NoPos
	for _, statement := range callback.Body.List {
		if statement.Pos() >= corePosition {
			break
		}
		switch value := statement.(type) {
		case *ast.ExprStmt:
			call, ok := value.X.(*ast.CallExpr)
			if ok && l8D2ReadinessExactStateMutexCall(call, serviceReceiver, "Lock") {
				locked = call.Pos()
			}
			if ok && l8D2ReadinessExactStateMutexCall(call, serviceReceiver, "Unlock") {
				unlocked = call.Pos()
			}
		case *ast.AssignStmt:
			if len(value.Lhs) == 1 && len(value.Rhs) == 1 && types.ExprString(value.Lhs[0]) == execution && types.ExprString(value.Rhs[0]) == serviceReceiver+".state.execution" {
				copied = value.Pos()
			}
		}
	}
	return locked != token.NoPos && locked < copied && copied < unlocked && unlocked < corePosition
}

func l8D2ReadinessCallbackRetainsScopedIdentifier(callback *ast.FuncLit, view string) bool {
	referencesView := func(expression ast.Expr) bool {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && identifier.Name == view {
				found = true
				return false
			}
			return !found
		})
		return found
	}
	retained := false
	ast.Inspect(callback.Body, func(node ast.Node) bool {
		if retained {
			return false
		}
		switch value := node.(type) {
		case *ast.FuncLit:
			retained = true
			return false
		case *ast.AssignStmt:
			for index, left := range value.Lhs {
				if index >= len(value.Rhs) || !referencesView(value.Rhs[index]) {
					continue
				}
				if call, ok := value.Rhs[index].(*ast.CallExpr); ok && l8D2ReadinessAllowedScopedCall(call, view) {
					continue
				}
				identifier, ok := left.(*ast.Ident)
				if !ok || identifier.Name != "_" {
					retained = true
					return false
				}
			}
		case *ast.ReturnStmt:
			for _, expression := range value.Results {
				if referencesView(expression) {
					if call, ok := expression.(*ast.CallExpr); !ok || !l8D2ReadinessAllowedScopedCall(call, view) {
						retained = true
						return false
					}
				}
			}
		case *ast.SendStmt:
			if referencesView(value.Value) {
				retained = true
				return false
			}
		case *ast.DeclStmt:
			general, ok := value.Decl.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				return true
			}
			for _, specification := range general.Specs {
				valueSpec, ok := specification.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, expression := range valueSpec.Values {
					if referencesView(expression) {
						retained = true
						return false
					}
				}
			}
		}
		return true
	})
	return retained
}

func l8D2ReadinessAllowedScopedCall(call *ast.CallExpr, view string) bool {
	if call == nil {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == view {
		return selector.Sel.Name == "Len" || selector.Sel.Name == "WriteTo" || selector.Sel.Name == "CopyTo"
	}
	return selector.Sel.Name == "ProposeObservedStdin" || selector.Sel.Name == "BeginExec" || selector.Sel.Name == "WriteStdin"
}

func l8D2ReadinessCallbackContainsNestedAuthority(callback *ast.FuncLit, proposal string) bool {
	invalid := false
	ast.Inspect(callback.Body, func(node ast.Node) bool {
		if invalid {
			return false
		}
		if _, ok := node.(*ast.FuncLit); ok {
			invalid = true
			return false
		}
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || (selector.Sel.Name != "Commit" && selector.Sel.Name != "Wipe") {
			return true
		}
		owner, ownerOK := selector.X.(*ast.Ident)
		if !ownerOK || owner.Name != proposal {
			return true
		}
		called := false
		ast.Inspect(callback.Body, func(candidate ast.Node) bool {
			call, ok := candidate.(*ast.CallExpr)
			if ok && call.Fun == selector {
				called = true
				return false
			}
			return true
		})
		if !called {
			invalid = true
			return false
		}
		return true
	})
	return invalid
}

func l8D2ReadinessCallbackRebindsAuthority(callback *ast.FuncLit, serviceReceiver, contextName, view string, transactionParams, comparisonParams, correlationParams, observationParams map[string]bool, flow l8D2ReadinessProposalFlow) bool {
	protected := map[string]bool{
		serviceReceiver:        true,
		contextName:            true,
		view:                   true,
		flow.proposal:          true,
		flow.coreError:         true,
		flow.proposalError:     true,
		"configuredDependency": true,
	}
	if flow.execution != "" {
		protected[flow.execution] = true
	}
	for name := range transactionParams {
		protected[name] = true
	}
	for name := range comparisonParams {
		protected[name] = true
	}
	for name := range correlationParams {
		protected[name] = true
	}
	for name := range observationParams {
		protected[name] = true
	}
	exempt := func(assignment *ast.AssignStmt, name string) bool {
		if name == flow.proposal {
			return assignment == flow.proposeAssignment
		}
		if name == flow.execution || name == flow.coreError {
			return assignment == flow.coreAssignment
		}
		if name == flow.proposalError {
			return assignment == flow.proposeAssignment
		}
		return false
	}
	return l8D2ReadinessBodyRebindsNames(callback.Body, protected, exempt)
}

func l8D2ReadinessBodyRebindsNames(body *ast.BlockStmt, protected map[string]bool, exempt func(*ast.AssignStmt, string) bool) bool {
	rebound := false
	ast.Inspect(body, func(node ast.Node) bool {
		if rebound {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				identifier, ok := left.(*ast.Ident)
				if ok && protected[identifier.Name] && (exempt == nil || !exempt(value, identifier.Name)) {
					rebound = true
					return false
				}
			}
		case *ast.ValueSpec:
			for _, name := range value.Names {
				if protected[name.Name] {
					rebound = true
					return false
				}
			}
		case *ast.RangeStmt:
			for _, expression := range []ast.Expr{value.Key, value.Value} {
				identifier, ok := expression.(*ast.Ident)
				if ok && protected[identifier.Name] {
					rebound = true
					return false
				}
			}
		case *ast.FuncLit:
			if value.Type.Params != nil {
				for _, field := range value.Type.Params.List {
					for _, name := range field.Names {
						if protected[name.Name] {
							rebound = true
							return false
						}
					}
				}
			}
		}
		return true
	})
	return rebound
}

func l8D2ReadinessDirectStatements(body *ast.BlockStmt) map[ast.Node]bool {
	direct := make(map[ast.Node]bool)
	if body != nil {
		for _, statement := range body.List {
			direct[statement] = true
		}
	}
	return direct
}

func l8D2ReadinessProposalCallbackFlow(callback *ast.FuncLit, proposeMethod, coreMethod, serviceReceiver, contextName, view string, transactionParams, comparisonParams, correlationParams, observationParams map[string]bool) l8D2ReadinessProposalFlow {
	var flow l8D2ReadinessProposalFlow
	var comparisonBranches []*ast.IfStmt
	direct := l8D2ReadinessDirectStatements(callback.Body)
	ast.Inspect(callback.Body, func(node ast.Node) bool {
		if nested, ok := node.(*ast.FuncLit); ok && nested != callback {
			return false
		}
		if call, ok := node.(*ast.CallExpr); ok {
			method := l8D2ReadinessCallMethodName(call)
			if method == "ProposeObservedPrivate" || method == "ProposeObservedStdin" {
				flow.totalProposeCalls++
			}
			if method == "BeginExec" || method == "WriteStdin" {
				flow.totalCoreCalls++
			}
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			if len(value.Rhs) != 1 {
				return true
			}
			call, ok := value.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			method := l8D2ReadinessCallMethodName(call)
			if method == proposeMethod && len(value.Lhs) == 2 {
				if (proposeMethod == "ProposeObservedPrivate" && len(call.Args) != 2) || (proposeMethod == "ProposeObservedStdin" && len(call.Args) != 4) {
					return true
				}
				selector, selectorOK := call.Fun.(*ast.SelectorExpr)
				if !selectorOK {
					return true
				}
				transaction, transactionOK := selector.X.(*ast.Ident)
				if !transactionOK || !transactionParams[transaction.Name] {
					return true
				}
				flow.proposeCount++
				proposal, proposalOK := value.Lhs[0].(*ast.Ident)
				proposalError, errorOK := value.Lhs[1].(*ast.Ident)
				if proposalOK && errorOK && proposal.Name != "_" && proposalError.Name != "_" && flow.proposal == "" {
					flow.proposal = proposal.Name
					flow.proposalError = proposalError.Name
					flow.propose = call.Pos()
					flow.proposeAssignment = value
					flow.proposeDirect = direct[value]
					if proposeMethod == "ProposeObservedPrivate" {
						flow.correlationAtPropose = l8D2ReadinessCallArgumentIn(call, 0, correlationParams)
						flow.observationAtPropose = l8D2ReadinessCallArgumentIn(call, 1, observationParams)
					} else {
						flow.viewAtPropose = l8D2ReadinessCallArgumentIs(call, 3, view)
						flow.contextAtPropose = l8D2ReadinessCallArgumentIs(call, 0, contextName)
						flow.correlationAtPropose = l8D2ReadinessCallArgumentIn(call, 1, correlationParams)
						flow.observationAtPropose = l8D2ReadinessCallArgumentIn(call, 2, observationParams)
					}
				}
			}
			if method == coreMethod {
				if (coreMethod == "BeginExec" && len(call.Args) != 3) || (coreMethod == "WriteStdin" && len(call.Args) != 4) {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				flow.coreReceiver = types.ExprString(selector.X)
				flow.coreCount++
				flow.core = call.Pos()
				flow.coreAssignment = value
				flow.coreDirect = direct[value]
				flow.contextAtCore = l8D2ReadinessCallArgumentIs(call, 0, contextName)
				if coreMethod == "BeginExec" && len(value.Lhs) == 2 {
					flow.viewAtCore = l8D2ReadinessCallArgumentIs(call, 2, view)
					flow.execution = types.ExprString(value.Lhs[0])
					flow.coreError = types.ExprString(value.Lhs[1])
				} else if coreMethod == "WriteStdin" && len(value.Lhs) == 1 {
					flow.viewAtCore = l8D2ReadinessCallArgumentIs(call, 1, view)
					flow.coreError = types.ExprString(value.Lhs[0])
				}
			}
		case *ast.IfStmt:
			comparison, ok := value.Cond.(*ast.Ident)
			if ok && comparisonParams[comparison.Name] {
				comparisonBranches = append(comparisonBranches, value)
			}
			if direct[value] && flow.proposalError != "" && value.Pos() > flow.propose && l8D2ReadinessExactErrorReturnGate(value, flow.proposalError) {
				flow.proposalErrorGate = value.Pos()
			}
		}
		return true
	})
	if flow.proposal == "" {
		return flow
	}
	ast.Inspect(callback.Body, func(node ast.Node) bool {
		if nested, ok := node.(*ast.FuncLit); ok && nested != callback {
			return false
		}
		if statement, ok := node.(*ast.ExprStmt); ok && l8D2ReadinessExactProposalCallExpression(statement.X, flow.proposal, "Wipe") && flow.wipe == token.NoPos {
			flow.wipe = statement.Pos()
		}
		if call, ok := node.(*ast.CallExpr); ok {
			if l8D2ReadinessExactProposalCallExpression(call, flow.proposal, "Commit") {
				flow.commitCalls++
			}
			if l8D2ReadinessExactProposalCallExpression(call, flow.proposal, "Wipe") {
				flow.wipeCalls++
			}
		}
		returned, ok := node.(*ast.ReturnStmt)
		if ok && l8D2ReadinessExactReturnedProposalCall(returned, flow.proposal, "Commit") {
			inComparison := false
			for _, branch := range comparisonBranches {
				if returned.Pos() > branch.Body.Pos() && returned.End() < branch.Body.End() {
					inComparison = true
				}
			}
			if !inComparison && returned.Pos() > flow.core {
				flow.normalCommits++
				if flow.normalCommit == token.NoPos || returned.Pos() < flow.normalCommit {
					flow.normalCommit = returned.Pos()
				}
				flow.commitDirect = flow.commitDirect || direct[returned]
			}
		}
		return true
	})
	for _, branch := range comparisonBranches {
		if direct[branch] && branch.Pos() > flow.proposalErrorGate && branch.Pos() < flow.core && len(branch.Body.List) == 1 && l8D2ReadinessExactReturnedProposalCallStatement(branch.Body.List[0], flow.proposal, "Commit") && !l8D2ReadinessBlockCallsMethod(branch.Body, "BeginExec") && !l8D2ReadinessBlockCallsMethod(branch.Body, "WriteStdin") && !l8D2ReadinessBlockCallsReceiver(branch.Body, serviceReceiver+".core") && !l8D2ReadinessBlockCallsReceiver(branch.Body, serviceReceiver+".state.execution") {
			flow.comparisonGood = true
			flow.comparisonDirect = true
		}
	}
	return flow
}

func l8D2ReadinessExactErrorReturnGate(gate *ast.IfStmt, errorName string) bool {
	if gate == nil || gate.Init != nil || gate.Else != nil || !l8D2ReadinessExactErrorNonNilCondition(gate.Cond, errorName) || len(gate.Body.List) != 1 {
		return false
	}
	returned, ok := gate.Body.List[0].(*ast.ReturnStmt)
	return ok && len(returned.Results) == 1 && types.ExprString(returned.Results[0]) == errorName
}

func l8D2ReadinessCoreResultFailureCondition(condition ast.Expr, errorName, executionName string) bool {
	terms := l8D2ReadinessOrTerms(condition)
	return len(terms) == 2 && ((l8D2ReadinessExactErrorNonNilCondition(terms[0], errorName) && l8D2ReadinessExactNegatedConfiguredDependency(terms[1], executionName)) || (l8D2ReadinessExactErrorNonNilCondition(terms[1], errorName) && l8D2ReadinessExactNegatedConfiguredDependency(terms[0], executionName)))
}

func l8D2ReadinessExactErrorNonNilCondition(condition ast.Expr, errorName string) bool {
	for {
		parenthesized, ok := condition.(*ast.ParenExpr)
		if !ok {
			break
		}
		condition = parenthesized.X
	}
	binary, ok := condition.(*ast.BinaryExpr)
	return ok && binary.Op == token.NEQ && ((types.ExprString(binary.X) == errorName && l8D2ReadinessNilIdentifier(binary.Y)) || (types.ExprString(binary.Y) == errorName && l8D2ReadinessNilIdentifier(binary.X)))
}

func l8D2ReadinessExactNegatedConfiguredDependency(condition ast.Expr, name string) bool {
	for {
		parenthesized, ok := condition.(*ast.ParenExpr)
		if !ok {
			break
		}
		condition = parenthesized.X
	}
	unary, ok := condition.(*ast.UnaryExpr)
	if !ok || unary.Op != token.NOT {
		return false
	}
	call, ok := unary.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || types.ExprString(call.Args[0]) != name {
		return false
	}
	called, ok := l8D2ReadinessDirectCalledIdentifier(call.Fun)
	return ok && called.Name == "configuredDependency"
}

func l8D2ReadinessBlockWipesThenReturnsError(block *ast.BlockStmt, proposal string) bool {
	if block == nil || len(block.List) < 2 || !l8D2ReadinessExactProposalCallStatement(block.List[len(block.List)-2], proposal, "Wipe") {
		return false
	}
	returned, ok := block.List[len(block.List)-1].(*ast.ReturnStmt)
	return ok && len(returned.Results) == 1 && !l8D2ReadinessNilIdentifier(returned.Results[0])
}

func l8D2ReadinessExactProposalCallStatement(statement ast.Stmt, proposal, method string) bool {
	expression, ok := statement.(*ast.ExprStmt)
	return ok && l8D2ReadinessExactProposalCallExpression(expression.X, proposal, method)
}

func l8D2ReadinessExactProposalCallExpression(expression ast.Expr, proposal, method string) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	owner, ownerOK := selector.X.(*ast.Ident)
	return ok && ownerOK && owner.Name == proposal && selector.Sel.Name == method
}

func l8D2ReadinessExactReturnedProposalCall(returned *ast.ReturnStmt, proposal, method string) bool {
	if returned == nil || len(returned.Results) != 1 {
		return false
	}
	call, ok := returned.Results[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	owner, ownerOK := selector.X.(*ast.Ident)
	return ok && ownerOK && owner.Name == proposal && selector.Sel.Name == method
}

func l8D2ReadinessExactReturnedProposalCallStatement(statement ast.Stmt, proposal, method string) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	return ok && l8D2ReadinessExactReturnedProposalCall(returned, proposal, method)
}

func l8D2ReadinessBlockCallsMethod(block *ast.BlockStmt, method string) bool {
	found := false
	ast.Inspect(block, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && l8D2ReadinessCallMethodName(call) == method {
			found = true
		}
		return true
	})
	return found
}

func l8D2ReadinessBlockCallsReceiver(block *ast.BlockStmt, receiver string) bool {
	found := false
	ast.Inspect(block, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && types.ExprString(selector.X) == receiver {
			found = true
		}
		return true
	})
	return found
}

func l8D2ReadinessCallMethodName(call *ast.CallExpr) string {
	switch called := call.Fun.(type) {
	case *ast.Ident:
		return called.Name
	case *ast.SelectorExpr:
		return called.Sel.Name
	default:
		return ""
	}
}

func l8D2ReadinessCallArgumentIs(call *ast.CallExpr, index int, name string) bool {
	if call == nil || index < 0 || index >= len(call.Args) {
		return false
	}
	identifier, ok := call.Args[index].(*ast.Ident)
	return ok && identifier.Name == name
}

func l8D2ReadinessCallArgumentIn(call *ast.CallExpr, index int, names map[string]bool) bool {
	if call == nil || index < 0 || index >= len(call.Args) {
		return false
	}
	identifier, ok := call.Args[index].(*ast.Ident)
	return ok && names[identifier.Name]
}

func l8D2ReadinessReceiverName(function *ast.FuncDecl) string {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 || len(function.Recv.List[0].Names) != 1 || types.ExprString(function.Recv.List[0].Type) != "*Service" {
		return ""
	}
	return function.Recv.List[0].Names[0].Name
}

func l8D2ReadinessIsContextPrecondition(initializer ast.Stmt, condition ast.Expr, body *ast.BlockStmt, contextName string) bool {
	assignment, ok := initializer.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	errorName, ok := assignment.Lhs[0].(*ast.Ident)
	call, callOK := assignment.Rhs[0].(*ast.CallExpr)
	if !ok || !callOK {
		return false
	}
	called, calledOK := call.Fun.(*ast.Ident)
	if !calledOK || called.Name != "transportContextPrecondition" || len(call.Args) != 1 || types.ExprString(call.Args[0]) != contextName || !l8D2ReadinessExactErrorNonNilCondition(condition, errorName.Name) || body == nil || len(body.List) != 1 {
		return false
	}
	returned, ok := body.List[0].(*ast.ReturnStmt)
	return ok && len(returned.Results) == 2 && types.ExprString(returned.Results[0]) == "ServiceResult{}" && types.ExprString(returned.Results[1]) == errorName.Name
}

func l8D2ReadinessTransitionReturn(statement ast.Stmt) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	return ok && len(returned.Results) == 2 && types.ExprString(returned.Results[1]) == "ErrContractTransition"
}

func l8D2ReadinessExactSelectorCallStatement(statement ast.Stmt, receiver, method string) bool {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, callOK := expression.X.(*ast.CallExpr)
	if !callOK {
		return false
	}
	selector, selectorOK := call.Fun.(*ast.SelectorExpr)
	return selectorOK && types.ExprString(selector.X) == receiver && selector.Sel.Name == method && len(call.Args) == 0
}

func l8D2ReadinessNilIdentifier(expression ast.Expr) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == "nil"
}

func readL8D2ReadinessFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func readL8D2ReadinessGoFiles(t *testing.T, root string, tests bool) string {
	t.Helper()
	var source strings.Builder
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") != tests {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		source.Write(content)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return source.String()
}

func l8D2ReadinessExactTopLevelTests(root string) (map[string]int, error) {
	files := make(map[string]*ast.File)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		files[path] = file
		return nil
	})
	if err != nil {
		return nil, err
	}
	return l8D2ReadinessExactTestDeclarations(files), nil
}

func l8D2ReadinessExactTestDeclarations(files map[string]*ast.File) map[string]int {
	counts := make(map[string]int)
	for _, file := range files {
		aliases, _ := l8D2ReadinessImportAliases(file)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || function.Body == nil || !strings.HasPrefix(function.Name.Name, "Test") || function.Type.TypeParams != nil || function.Type.Results != nil || function.Type.Params == nil || len(function.Type.Params.List) != 1 || len(function.Type.Params.List[0].Names) != 1 || function.Type.Params.List[0].Names[0].Name != "t" || !l8D2ReadinessExactImportedType(function.Type.Params.List[0].Type, aliases, "testing", "T", true) {
				continue
			}
			counts[function.Name.Name]++
		}
	}
	return counts
}

type l8D2ReadinessServiceTestRequirement struct {
	exercise         []string
	evidence         []string
	dependencyFields map[string][]string
}

func l8D2ReadinessServiceTestRequirements() map[string]l8D2ReadinessServiceTestRequirement {
	transport := map[string][]string{
		"planDestroyCalls": {"Transport"}, "takeCalls": {"Transport"}, "commitCalls": {"Transport"},
		"bodyDestroyCalls": {"Transport"}, "wipeCalls": {"Transport"},
	}
	core := map[string][]string{"beginExecCalls": {"Core"}, "writeStdinCalls": {"Core"}}
	fields := func(names ...string) map[string][]string {
		result := make(map[string][]string)
		for _, name := range names {
			if values := transport[name]; values != nil {
				result[name] = values
			}
			if values := core[name]; values != nil {
				result[name] = values
			}
		}
		return result
	}
	return map[string]l8D2ReadinessServiceTestRequirement{
		"TestServiceDestroysClaimedExecPlanOnEveryDispatchPath": {exercise: []string{"NewService", "Serve"}, evidence: []string{"planDestroyCalls"}, dependencyFields: fields("planDestroyCalls")},
		"TestServiceConstructorDependenciesSnapshotAndServeOneShot": {exercise: []string{"NewService", "Serve"}, evidence: []string{"dependencyCalls", "snapshotEntries", "serveCalls"}, dependencyFields: map[string][]string{
			"dependencyCalls": {"Core", "Transport", "Policy", "Host", "Runtime"}, "snapshotEntries": {"Extensions"}, "serveCalls": {"Transport", "Runtime"},
		}},
		"TestServiceServeContextPreconditionBeforeOneShotLatch": {exercise: []string{"NewService", "Serve"}, evidence: []string{"dependencyCalls", "serveCalls"}, dependencyFields: map[string][]string{
			"dependencyCalls": {"Core", "Transport", "Policy", "Host", "Runtime"}, "serveCalls": {"Transport", "Runtime"},
		}},
		"TestServiceObservedInputsTakenOnceBeforeDispatch":           {exercise: []string{"NewService", "Serve"}, evidence: []string{"takeCalls"}, dependencyFields: fields("takeCalls")},
		"TestServiceObservedPrivateCoreCommitCleanupMatrix":          {exercise: []string{"NewService", "Serve"}, evidence: []string{"beginExecCalls", "commitCalls", "bodyDestroyCalls", "planDestroyCalls"}, dependencyFields: fields("beginExecCalls", "commitCalls", "bodyDestroyCalls", "planDestroyCalls")},
		"TestServiceObservedPrivateCommitRequiresValidCoreExecution": {exercise: []string{"NewService", "Serve"}, evidence: []string{"beginExecCalls", "commitCalls", "wipeCalls"}, dependencyFields: fields("beginExecCalls", "commitCalls", "wipeCalls")},
		"TestServiceObservedStdinCoreCommitCleanupMatrix":            {exercise: []string{"NewService", "Serve"}, evidence: []string{"writeStdinCalls", "commitCalls", "bodyDestroyCalls"}, dependencyFields: fields("writeStdinCalls", "commitCalls", "bodyDestroyCalls")},
		"TestServiceObservedStdinCommitRequiresNilCoreError":         {exercise: []string{"NewService", "Serve"}, evidence: []string{"writeStdinCalls", "commitCalls", "wipeCalls"}, dependencyFields: fields("writeStdinCalls", "commitCalls", "wipeCalls")},
		"TestServiceObservedComparisonNeverCallsCore":                {exercise: []string{"NewService", "Serve"}, evidence: []string{"beginExecCalls", "writeStdinCalls", "commitCalls"}, dependencyFields: fields("beginExecCalls", "writeStdinCalls", "commitCalls")},
		"TestServiceObservedBodiesDestroyedExactlyOnce":              {exercise: []string{"NewService", "Serve"}, evidence: []string{"bodyDestroyCalls"}, dependencyFields: fields("bodyDestroyCalls")},
		"TestServiceObservedFailureAndPanicCleanupIsExhaustive":      {exercise: []string{"NewService", "Serve"}, evidence: []string{"wipeCalls", "bodyDestroyCalls", "planDestroyCalls"}, dependencyFields: fields("wipeCalls", "bodyDestroyCalls", "planDestroyCalls")},
	}
}

func l8D2ReadinessExactServiceBehavioralTests(root string, requirements map[string]l8D2ReadinessServiceTestRequirement) (map[string]bool, error) {
	dir := filepath.Join(root, "credentialhelper")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	testFiles := make(map[string]*ast.File)
	productionFiles := make(map[string]*ast.File)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return nil, parseErr
		}
		if file.Name == nil || file.Name.Name != "credentialhelper" {
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.go") {
			testFiles[path] = file
		} else {
			productionFiles[path] = file
		}
	}
	contexts := l8D2ReadinessSupportedBuildContexts()
	var applicable []build.Context
	for _, context := range contexts {
		active := false
		for path, file := range productionFiles {
			matched, matchErr := context.MatchFile(dir, filepath.Base(path))
			if matchErr != nil {
				return nil, matchErr
			}
			if matched && l8D2ReadinessFileDeclaresStruct(file, "Service") {
				active = true
				break
			}
		}
		if active {
			applicable = append(applicable, context)
		}
	}
	if len(applicable) == 0 {
		applicable = contexts
	}
	results := make(map[string]bool)
	resolver := l8D2ReadinessNewImportResolver()
	for name, requirement := range requirements {
		validEverywhere := true
		for _, context := range applicable {
			var contextFiles []*ast.File
			resolvedImports := make(map[*ast.File]map[string]string)
			for path, file := range productionFiles {
				matched, matchErr := context.MatchFile(dir, filepath.Base(path))
				if matchErr != nil {
					return nil, matchErr
				}
				if matched {
					contextFiles = append(contextFiles, file)
					resolvedImports[file] = resolver.resolve(context, filepath.Dir(path), file)
				}
			}
			for path, file := range testFiles {
				matched, matchErr := context.MatchFile(dir, filepath.Base(path))
				if matchErr != nil {
					return nil, matchErr
				}
				if matched {
					contextFiles = append(contextFiles, file)
					resolvedImports[file] = resolver.resolve(context, filepath.Dir(path), file)
				}
			}
			environment := l8D2ReadinessTerminalEnvironmentForFilesWithImports(contextFiles, resolvedImports)
			validHere := false
			for path, file := range testFiles {
				matched, matchErr := context.MatchFile(dir, filepath.Base(path))
				if matchErr != nil {
					return nil, matchErr
				}
				if matched && l8D2ReadinessExactServiceBehavioralTestInEnvironment(file, name, requirement, environment) {
					validHere = true
				}
			}
			if !validHere {
				validEverywhere = false
				break
			}
		}
		results[name] = validEverywhere
	}
	return results, nil
}

func l8D2ReadinessExactServiceBehavioralTest(file *ast.File, name string, requirement l8D2ReadinessServiceTestRequirement) bool {
	return l8D2ReadinessExactServiceBehavioralTestInEnvironment(file, name, requirement, l8D2ReadinessTerminalEnvironmentForFiles([]*ast.File{file}))
}

func l8D2ReadinessTerminalEnvironmentForFiles(files []*ast.File) l8D2ReadinessTerminalEnvironment {
	return l8D2ReadinessTerminalEnvironmentForFilesWithImports(files, nil)
}

func l8D2ReadinessTerminalEnvironmentForFilesWithImports(files []*ast.File, resolvedImports map[*ast.File]map[string]string) l8D2ReadinessTerminalEnvironment {
	declarations := make([]*ast.FuncDecl, 0)
	aliasesByFunction := make(map[*ast.FuncDecl]map[string]string)
	functionFiles := make(map[*ast.FuncDecl]*ast.File)
	globals := make(map[string]bool)
	expectedConstants := make(map[string][]l8D2ReadinessExpectedConstantDeclaration)
	fileIntShadowed := make(map[*ast.File]bool)
	packageIntShadowed := false
	var allDeclarations []ast.Decl
	for _, file := range files {
		if file == nil {
			continue
		}
		aliases, _ := l8D2ReadinessImportAliases(file)
		for _, imported := range file.Imports {
			if imported.Name != nil {
				if imported.Name.Name == "int" {
					fileIntShadowed[file] = true
				}
				continue
			}
			path := strings.Trim(imported.Path.Value, `"`)
			if resolvedImports[file][path] == "int" {
				fileIntShadowed[file] = true
			}
		}
		allDeclarations = append(allDeclarations, file.Decls...)
		for _, declaration := range file.Decls {
			if group, ok := declaration.(*ast.GenDecl); ok {
				for _, specification := range group.Specs {
					if typeSpec, ok := specification.(*ast.TypeSpec); ok && typeSpec.Name.Name == "int" {
						packageIntShadowed = true
					}
					values, ok := specification.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range values.Names {
						if name.Name == "int" {
							packageIntShadowed = true
						}
						switch group.Tok {
						case token.VAR:
							globals[name.Name] = true
						case token.CONST:
							expectedConstants[name.Name] = append(expectedConstants[name.Name], l8D2ReadinessExpectedConstantDeclaration{file: file, group: group, values: values, packageScope: true})
						}
					}
				}
			}
			candidate, ok := declaration.(*ast.FuncDecl)
			if !ok || candidate.Body == nil {
				continue
			}
			if candidate.Recv == nil && candidate.Name.Name == "int" {
				packageIntShadowed = true
			}
			declarations = append(declarations, candidate)
			aliasesByFunction[candidate] = aliases
			functionFiles[candidate] = file
		}
	}
	return l8D2ReadinessTerminalEnvironment{
		declarations:       declarations,
		aliases:            aliasesByFunction,
		functionFiles:      functionFiles,
		constants:          l8D2ReadinessDeclaredConstants(allDeclarations),
		namedTypes:         l8D2ReadinessDeclaredNamedTypes(allDeclarations),
		globals:            globals,
		expectedConstants:  expectedConstants,
		packageIntShadowed: packageIntShadowed,
		fileIntShadowed:    fileIntShadowed,
	}
}

func l8D2ReadinessResolvedImportPackageNames(context build.Context, sourceDir string, file *ast.File) map[string]string {
	return l8D2ReadinessNewImportResolver().resolve(context, sourceDir, file)
}

type l8D2ReadinessImportResolver struct {
	cache       map[string]l8D2ReadinessImportResolution
	goCommand   string
	timeout     time.Duration
	environment []string
}

func l8D2ReadinessNewImportResolver() *l8D2ReadinessImportResolver {
	return &l8D2ReadinessImportResolver{cache: make(map[string]l8D2ReadinessImportResolution), goCommand: "go", timeout: 5 * time.Second}
}

func (resolver *l8D2ReadinessImportResolver) resolve(context build.Context, sourceDir string, file *ast.File) map[string]string {
	result := make(map[string]string)
	if file == nil {
		return result
	}
	canonicalSource, ok := l8D2ReadinessCanonicalDirectory(sourceDir)
	if !ok {
		return result
	}
	sourceDir = canonicalSource
	for _, imported := range file.Imports {
		if imported.Name != nil {
			continue
		}
		importPath := strings.Trim(imported.Path.Value, `"`)
		if importPath == "" {
			continue
		}
		if packageInfo, err := context.Import(importPath, sourceDir, 0); err == nil && packageInfo.Goroot && packageInfo.Name != "" {
			result[importPath] = packageInfo.Name
			continue
		}
		if moduleRoot, ok := l8D2ReadinessModuleRoot(sourceDir); ok {
			if packageName, resolved := resolver.goListPackageName(context, moduleRoot, importPath); resolved {
				result[importPath] = packageName
				continue
			}
		}
		if packageName, ok := l8D2ReadinessModuleLocalPackageName(context, sourceDir, importPath); ok {
			result[importPath] = packageName
			continue
		}
		if _, module := l8D2ReadinessModuleRoot(sourceDir); !module {
			if packageInfo, err := context.Import(importPath, sourceDir, 0); err == nil && packageInfo.Name != "" {
				result[importPath] = packageInfo.Name
			}
		}
	}
	return result
}

type l8D2ReadinessImportResolution struct {
	name string
	ok   bool
}

func (resolver *l8D2ReadinessImportResolver) goListPackageName(context build.Context, moduleRoot, importPath string) (string, bool) {
	cleanRoot, canonical := l8D2ReadinessCanonicalDirectory(moduleRoot)
	if !canonical {
		return "", false
	}
	if info, err := os.Stat(filepath.Join(cleanRoot, "go.mod")); err != nil || info.IsDir() {
		return "", false
	}
	key := strings.Join([]string{cleanRoot, context.GOOS, context.GOARCH, importPath}, "\x00")
	if result, ok := resolver.cache[key]; ok {
		return result.name, result.ok
	}
	mode := "readonly"
	if _, err := os.Stat(filepath.Join(cleanRoot, "vendor", "modules.txt")); err == nil {
		mode = "vendor"
	}
	timeout := resolver.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	commandContext, cancel := stdcontext.WithTimeout(stdcontext.Background(), timeout)
	defer cancel()
	goCommand := resolver.goCommand
	if goCommand == "" {
		goCommand = "go"
	}
	command := exec.CommandContext(commandContext, goCommand, "list", "-e", "-json", "-mod="+mode, importPath)
	command.Dir = cleanRoot
	baseEnvironment := resolver.environment
	if baseEnvironment == nil {
		baseEnvironment = os.Environ()
	}
	command.Env = l8D2ReadinessOfflineGoEnvironmentFrom(context, baseEnvironment)
	output, err := command.Output()
	result := l8D2ReadinessImportResolution{}
	if err == nil && commandContext.Err() == nil {
		var listed struct {
			ImportPath string
			Name       string
			Dir        string
			Error      *struct{ Err string }
		}
		if decodeErr := json.Unmarshal(output, &listed); decodeErr == nil && listed.ImportPath == importPath && listed.Name != "" && listed.Dir != "" && listed.Error == nil {
			result = l8D2ReadinessImportResolution{name: listed.Name, ok: true}
		}
	}
	if result.ok {
		resolver.cache[key] = result
	}
	return result.name, result.ok
}

func l8D2ReadinessOfflineGoEnvironmentFrom(context build.Context, base []string) []string {
	overrides := map[string]string{
		"CGO_ENABLED": "0",
		"GO111MODULE": "on",
		"GOARCH":      context.GOARCH,
		"GOENV":       "off",
		"GOFLAGS":     "",
		"GOINSECURE":  "",
		"GONOPROXY":   "none",
		"GONOSUMDB":   "none",
		"GOOS":        context.GOOS,
		"GOPRIVATE":   "",
		"GOPROXY":     "off",
		"GOSUMDB":     "off",
		"GOTOOLCHAIN": "local",
		"GOVCS":       "*:off",
		"GOWORK":      "off",
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		name, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[name]; !replaced {
			result = append(result, item)
		}
	}
	keys := make([]string, 0, len(overrides))
	for name := range overrides {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		result = append(result, name+"="+overrides[name])
	}
	return result
}

func l8D2ReadinessModuleRoot(sourceDir string) (string, bool) {
	directory, ok := l8D2ReadinessCanonicalDirectory(sourceDir)
	if !ok {
		return "", false
	}
	for {
		if info, statErr := os.Stat(filepath.Join(directory, "go.mod")); statErr == nil && !info.IsDir() {
			return directory, true
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", false
		}
		directory = parent
	}
}

func l8D2ReadinessCanonicalDirectory(path string) (string, bool) {
	if path == "" || strings.ContainsAny(path, "\x00\r\n") {
		return "", false
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", false
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) || strings.ContainsAny(resolved, "\x00\r\n") {
		return "", false
	}
	info, err := os.Stat(resolved)
	return resolved, err == nil && info.IsDir()
}

func l8D2ReadinessPathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func l8D2ReadinessModuleLocalPackageName(context build.Context, sourceDir, importPath string) (string, bool) {
	directory, ok := l8D2ReadinessModuleRoot(sourceDir)
	if !ok {
		return "", false
	}
	moduleFile := filepath.Join(directory, "go.mod")
	content, readErr := os.ReadFile(moduleFile)
	if readErr == nil {
		modulePath := ""
		for _, line := range strings.Split(string(content), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "module" {
				modulePath = fields[1]
				break
			}
		}
		if modulePath == "" || importPath != modulePath && !strings.HasPrefix(importPath, modulePath+"/") {
			return "", false
		}
		relative := strings.TrimPrefix(strings.TrimPrefix(importPath, modulePath), "/")
		packageDir, canonical := l8D2ReadinessCanonicalDirectory(filepath.Join(directory, filepath.FromSlash(relative)))
		if !canonical || !l8D2ReadinessPathWithin(directory, packageDir) {
			return "", false
		}
		entries, readDirErr := os.ReadDir(packageDir)
		if readDirErr != nil {
			return "", false
		}
		packageName := ""
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			matched, matchErr := context.MatchFile(packageDir, entry.Name())
			if matchErr != nil || !matched {
				continue
			}
			parsed, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Join(packageDir, entry.Name()), nil, parser.PackageClauseOnly)
			if parseErr != nil || parsed.Name == nil || parsed.Name.Name == "" {
				return "", false
			}
			if packageName != "" && packageName != parsed.Name.Name {
				return "", false
			}
			packageName = parsed.Name.Name
		}
		return packageName, packageName != ""
	}
	return "", false
}

func l8D2ReadinessExactServiceBehavioralTestInEnvironment(file *ast.File, name string, requirement l8D2ReadinessServiceTestRequirement, terminalEnvironment l8D2ReadinessTerminalEnvironment) bool {
	if file == nil {
		return false
	}
	aliases, _ := l8D2ReadinessImportAliases(file)
	var function *ast.FuncDecl
	count := 0
	for _, declaration := range file.Decls {
		candidate, ok := declaration.(*ast.FuncDecl)
		if !ok || candidate.Name.Name != name || candidate.Recv != nil || candidate.Body == nil || candidate.Type.TypeParams != nil || candidate.Type.Results != nil || candidate.Type.Params == nil || len(candidate.Type.Params.List) != 1 || len(candidate.Type.Params.List[0].Names) != 1 || candidate.Type.Params.List[0].Names[0].Name != "t" || !l8D2ReadinessExactImportedType(candidate.Type.Params.List[0].Type, aliases, "testing", "T", true) {
			continue
		}
		count++
		function = candidate
	}
	if count != 1 || function == nil || len(function.Body.List) == 0 {
		return false
	}
	if l8D2ReadinessBodyRebindsNames(function.Body, map[string]bool{"NewService": true, "t": true}, nil) {
		return false
	}
	terminalFacts := l8D2ReadinessPackageTerminalFunctions(terminalEnvironment)
	terminalAliases := l8D2ReadinessTerminalCallableAliases(function, terminalFacts, terminalEnvironment, nil)
	exercisePosition := make(map[string]token.Pos)
	exerciseCalls := make(map[string]*ast.CallExpr)
	exerciseCounts := make(map[string]int)
	serviceOwners := make(map[string]bool)
	assertedEvidence := make(map[string]bool)
	terminated := false
	var visitBlock func(*ast.BlockStmt, bool)
	var visitStatement func(ast.Stmt, bool)
	visitBlock = func(body *ast.BlockStmt, live bool) {
		if body == nil || !live || terminated {
			return
		}
		for _, statement := range body.List {
			visitStatement(statement, true)
			if terminated {
				return
			}
		}
	}
	visitStatement = func(statement ast.Stmt, live bool) {
		if statement == nil || !live || terminated {
			return
		}
		if l8D2ReadinessStatementNeverReturns(function, statement, terminalAliases, terminalFacts, terminalEnvironment) {
			terminated = true
			return
		}
		if returned, ok := statement.(*ast.ReturnStmt); ok {
			for _, expression := range returned.Results {
				l8D2ReadinessCollectExerciseCalls(expression, exercisePosition, exerciseCalls, exerciseCounts, serviceOwners)
			}
			terminated = true
			return
		}
		if l8D2ReadinessStatementHasImmediateTestTermination(statement, "t") {
			terminated = true
			return
		}
		switch value := statement.(type) {
		case *ast.IfStmt:
			l8D2ReadinessCollectExerciseCalls(value.Init, exercisePosition, exerciseCalls, exerciseCounts, serviceOwners)
			l8D2ReadinessCollectExerciseCalls(value.Cond, exercisePosition, exerciseCalls, exerciseCounts, serviceOwners)
			if !l8D2ReadinessStaticallyFalse(value.Cond) && l8D2ReadinessBlockHasTestingFailure(value.Body, "t") {
				for _, evidence := range requirement.evidence {
					if l8D2ReadinessConditionAssertsCausalObservable(function, value.Cond, evidence, exerciseCalls["NewService"], requirement.dependencyFields[evidence], terminalEnvironment) && l8D2ReadinessAllExerciseBefore(exercisePosition, requirement.exercise, value.Pos()) {
						assertedEvidence[evidence] = true
					}
				}
			}
			if l8D2ReadinessStaticallyTrue(value.Cond) {
				visitBlock(value.Body, true)
			}
			if l8D2ReadinessStaticallyFalse(value.Cond) {
				switch alternate := value.Else.(type) {
				case *ast.BlockStmt:
					visitBlock(alternate, true)
				case *ast.IfStmt:
					visitStatement(alternate, true)
				}
			}
		case *ast.BlockStmt:
			visitBlock(value, true)
		case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.GoStmt, *ast.DeferStmt:
			// Required Service tests use one direct, unconditionally reached
			// exercise path. Conditional/table bodies are supplementary only.
		default:
			l8D2ReadinessCollectExerciseCalls(statement, exercisePosition, exerciseCalls, exerciseCounts, serviceOwners)
		}
	}
	visitBlock(function.Body, true)
	if !l8D2ReadinessTestServiceOwnersStable(function.Body, serviceOwners) || len(serviceOwners) != 1 || exerciseCounts["NewService"] != 1 || exerciseCounts["Serve"] != 1 {
		return false
	}
	for owner := range serviceOwners {
		if !l8D2ReadinessServiceOwnerConfinedUntilServe(function.Body, owner, exerciseCalls["NewService"], exerciseCalls["Serve"]) {
			return false
		}
	}
	for _, exercise := range requirement.exercise {
		if exercisePosition[exercise] == token.NoPos {
			return false
		}
	}
	for _, evidence := range requirement.evidence {
		if !assertedEvidence[evidence] {
			return false
		}
	}
	return true
}

func l8D2ReadinessTestServiceOwnersStable(body *ast.BlockStmt, owners map[string]bool) bool {
	if body == nil || len(owners) == 0 {
		return false
	}
	assignments := make(map[string]int)
	stable := true
	ast.Inspect(body, func(node ast.Node) bool {
		if !stable {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for index, left := range value.Lhs {
				identifier, ok := left.(*ast.Ident)
				if !ok || !owners[identifier.Name] {
					continue
				}
				assignments[identifier.Name]++
				if assignments[identifier.Name] != 1 || index != 0 || len(value.Rhs) != 1 {
					stable = false
					return false
				}
				call, ok := value.Rhs[0].(*ast.CallExpr)
				called, ok := func() (*ast.Ident, bool) {
					if !ok {
						return nil, false
					}
					candidate, valid := call.Fun.(*ast.Ident)
					return candidate, valid
				}()
				if !ok || called.Name != "NewService" {
					stable = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if identifier, ok := value.X.(*ast.Ident); ok && owners[identifier.Name] {
				stable = false
				return false
			}
		case *ast.RangeStmt:
			for _, expression := range []ast.Expr{value.Key, value.Value} {
				if identifier, ok := expression.(*ast.Ident); ok && owners[identifier.Name] {
					stable = false
					return false
				}
			}
		}
		return true
	})
	if !stable {
		return false
	}
	for owner := range owners {
		if assignments[owner] != 1 {
			return false
		}
	}
	return true
}

func l8D2ReadinessCollectExerciseCalls(node ast.Node, positions map[string]token.Pos, calls map[string]*ast.CallExpr, counts map[string]int, serviceOwners map[string]bool) {
	if node == nil {
		return
	}
	if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Rhs) == 1 && len(assignment.Lhs) >= 1 {
		call, callOK := assignment.Rhs[0].(*ast.CallExpr)
		called, identOK := func() (*ast.Ident, bool) {
			if !callOK {
				return nil, false
			}
			candidate, valid := call.Fun.(*ast.Ident)
			return candidate, valid
		}()
		owner, ownerOK := assignment.Lhs[0].(*ast.Ident)
		if identOK && called.Name == "NewService" && ownerOK && owner.Name != "_" {
			counts["NewService"]++
			if positions["NewService"] == token.NoPos {
				positions["NewService"], calls["NewService"] = call.Pos(), call
			}
			serviceOwners[owner.Name] = true
		}
		selector, ok := func() (*ast.SelectorExpr, bool) {
			if !callOK {
				return nil, false
			}
			candidate, valid := call.Fun.(*ast.SelectorExpr)
			return candidate, valid
		}()
		serveOwner, serveOwnerOK := func() (*ast.Ident, bool) {
			if !ok {
				return nil, false
			}
			candidate, valid := selector.X.(*ast.Ident)
			return candidate, valid
		}()
		if serveOwnerOK && serviceOwners[serveOwner.Name] && selector.Sel.Name == "Serve" && positions["Serve"] == token.NoPos {
			positions["Serve"], calls["Serve"] = call.Pos(), call
			counts["Serve"]++
		} else if serveOwnerOK && serviceOwners[serveOwner.Name] && selector.Sel.Name == "Serve" {
			counts["Serve"]++
		}
	}
}

func l8D2ReadinessStatementHasImmediateTestTermination(statement ast.Stmt, testingName string) bool {
	if expression, ok := statement.(*ast.ExprStmt); ok {
		call, callOK := expression.X.(*ast.CallExpr)
		if callOK {
			if builtin, ok := call.Fun.(*ast.Ident); ok && builtin.Name == "panic" {
				return true
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
				if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == testingName && (selector.Sel.Name == "Fatal" || selector.Sel.Name == "Fatalf" || selector.Sel.Name == "Skip" || selector.Sel.Name == "Skipf" || selector.Sel.Name == "SkipNow" || selector.Sel.Name == "FailNow") {
					return true
				}
				if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == "runtime" && selector.Sel.Name == "Goexit" {
					return true
				}
			}
		}
	}
	terminated := false
	ast.Inspect(statement, func(node ast.Node) bool {
		if terminated {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == testingName && (selector.Sel.Name == "Skip" || selector.Sel.Name == "Skipf" || selector.Sel.Name == "SkipNow" || selector.Sel.Name == "FailNow") {
				terminated = true
				return false
			}
			if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == "runtime" && selector.Sel.Name == "Goexit" {
				terminated = true
				return false
			}
		}
		return true
	})
	return terminated
}

func l8D2ReadinessBlockHasTestingFailure(body *ast.BlockStmt, testingName string) bool {
	if body == nil {
		return false
	}
	for _, statement := range body.List {
		expression, ok := statement.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expression.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		owner, ownerOK := func() (*ast.Ident, bool) {
			if !ok {
				return nil, false
			}
			candidate, valid := selector.X.(*ast.Ident)
			return candidate, valid
		}()
		if ownerOK && owner.Name == testingName && (selector.Sel.Name == "Fatal" || selector.Sel.Name == "Fatalf" || selector.Sel.Name == "Error" || selector.Sel.Name == "Errorf") {
			return true
		}
	}
	return false
}

func l8D2ReadinessConditionAssertsCausalObservable(function *ast.FuncDecl, condition ast.Expr, field string, constructor *ast.CallExpr, dependencyFields []string, environment l8D2ReadinessTerminalEnvironment) bool {
	if function == nil || function.Body == nil || condition == nil || constructor == nil || len(dependencyFields) == 0 {
		return false
	}
	body := function.Body
	constants := l8D2ReadinessWrapperConstantValues(function, condition.Pos(), environment)
	owners := make(map[string]bool)
	validComparison := false
	var inspectClause func(ast.Expr)
	inspectClause = func(clause ast.Expr) {
		for {
			parenthesized, ok := clause.(*ast.ParenExpr)
			if !ok {
				break
			}
			clause = parenthesized.X
		}
		if disjunction, ok := clause.(*ast.BinaryExpr); ok && disjunction.Op == token.LOR {
			inspectClause(disjunction.X)
			inspectClause(disjunction.Y)
			return
		}
		comparison, ok := clause.(*ast.BinaryExpr)
		if !ok || comparison.Op != token.NEQ {
			return
		}
		for _, pair := range [][2]ast.Expr{{comparison.X, comparison.Y}, {comparison.Y, comparison.X}} {
			selector, selectorOK := pair[0].(*ast.SelectorExpr)
			owner, ownerOK := func() (*ast.Ident, bool) {
				if !selectorOK {
					return nil, false
				}
				candidate, valid := selector.X.(*ast.Ident)
				return candidate, valid
			}()
			if !ownerOK || selector.Sel.Name != field || types.ExprString(pair[0]) == types.ExprString(pair[1]) || !l8D2ReadinessCanonicalExpectedObservable(function, pair[1], constructor, constants, environment) {
				continue
			}
			owners[owner.Name] = true
			validComparison = true
		}
	}
	inspectClause(condition)
	conditionValue, conditionExact := l8D2ReadinessConstantExpression(condition, constants)
	if conditionExact && conditionValue.Kind() == constant.Bool {
		return false
	}
	if !validComparison || len(owners) != 1 || l8D2ReadinessBooleanMasksObservable(condition, constants) {
		return false
	}
	for owner := range owners {
		if !l8D2ReadinessObservableOwnerFeedsConstructor(body, owner, constructor, dependencyFields) || !l8D2ReadinessObservableOwnerStartsZero(body, owner, field, constructor, environment, constants) || !l8D2ReadinessObservableOwnerStable(body, owner) || !l8D2ReadinessObservableOwnerConfinedAfterConstructor(body, owner, constructor) || l8D2ReadinessObservableFieldWritten(body, owner, field, constructor, environment.globals) {
			return false
		}
	}
	return true
}

func l8D2ReadinessBooleanMasksObservable(expression ast.Expr, constants map[string]constant.Value) bool {
	masked := false
	ast.Inspect(expression, func(node ast.Node) bool {
		binary, ok := node.(*ast.BinaryExpr)
		if !ok || (binary.Op != token.LAND && binary.Op != token.LOR) {
			return true
		}
		for _, operand := range []ast.Expr{binary.X, binary.Y} {
			value, exact := l8D2ReadinessConstantExpression(operand, constants)
			if exact && value.Kind() == constant.Bool && ((binary.Op == token.LAND && !constant.BoolVal(value)) || (binary.Op == token.LOR && constant.BoolVal(value))) {
				masked = true
				return false
			}
		}
		return !masked
	})
	return masked
}

func l8D2ReadinessObservableOwnerConfinedAfterConstructor(body *ast.BlockStmt, owner string, constructor *ast.CallExpr) bool {
	if body == nil || owner == "" || constructor == nil {
		return false
	}
	aliases := map[string]bool{owner: true}
	carries := func(expression ast.Expr) bool {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if found {
				return false
			}
			if selector, ok := node.(*ast.SelectorExpr); ok {
				return selector == expression
			}
			if identifier, ok := node.(*ast.Ident); ok && aliases[identifier.Name] {
				found = true
				return false
			}
			return true
		})
		return found
	}
	for changed := true; changed; {
		changed = false
		for _, statement := range body.List {
			if statement.End() >= constructor.Pos() {
				break
			}
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok {
				continue
			}
			for index, left := range assignment.Lhs {
				identifier, ok := left.(*ast.Ident)
				if !ok || aliases[identifier.Name] || index >= len(assignment.Rhs) || !carries(assignment.Rhs[index]) {
					continue
				}
				aliases[identifier.Name] = true
				changed = true
			}
		}
	}
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			if len(stack) != 0 {
				stack = stack[:len(stack)-1]
			}
			return true
		}
		if len(stack) != 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	confined := true
	ast.Inspect(body, func(node ast.Node) bool {
		if !confined {
			return false
		}
		identifier, ok := node.(*ast.Ident)
		if !ok || !aliases[identifier.Name] || identifier.Pos() <= constructor.End() {
			return true
		}
		if identifier.Name != owner {
			confined = false
			return false
		}
		selector, ok := parents[identifier].(*ast.SelectorExpr)
		if !ok || selector.X != identifier {
			confined = false
			return false
		}
		parent := parents[selector]
		if call, ok := parent.(*ast.CallExpr); ok && call.Fun == selector {
			confined = false
			return false
		}
		if unary, ok := parent.(*ast.UnaryExpr); ok && unary.Op == token.AND {
			confined = false
			return false
		}
		return true
	})
	return confined
}

func l8D2ReadinessCanonicalExpectedObservable(function *ast.FuncDecl, expression ast.Expr, before ast.Node, constants map[string]constant.Value, environment l8D2ReadinessTerminalEnvironment) bool {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			break
		}
		expression = parenthesized.X
	}
	value, exact := l8D2ReadinessConstantExpression(expression, constants)
	if !exact || value == nil || value.Kind() != constant.Int {
		return false
	}
	if literal, ok := expression.(*ast.BasicLit); ok {
		return literal.Kind == token.INT
	}
	identifier, ok := expression.(*ast.Ident)
	if !ok || function == nil || function.Body == nil {
		return false
	}
	declaration, ok := l8D2ReadinessExpectedConstantDeclarationFor(function, identifier, environment)
	if !ok || declaration.group.Tok != token.CONST || !declaration.packageScope && (declaration.file != environment.functionFiles[function] || !l8D2ReadinessNodePrecedes(function.Body, declaration.values, before)) || environment.packageIntShadowed || environment.fileIntShadowed[declaration.file] || !l8D2ReadinessExactIntType(declaration.values.Type) || !l8D2ReadinessCanonicalExpectedConstantInitializer(declaration.values, identifier.Name) {
		return false
	}
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid || node == nil {
			return valid
		}
		switch item := node.(type) {
		case *ast.AssignStmt:
			for _, left := range item.Lhs {
				if assigned, ok := left.(*ast.Ident); ok && assigned.Name == identifier.Name {
					valid = false
					return false
				}
			}
		case *ast.ValueSpec:
			for _, name := range item.Names {
				if name.Name == identifier.Name && item != declaration.values {
					if localGroup, ok := l8D2ReadinessParentGenDecl(function.Body, item); !ok || localGroup.Tok != token.CONST || !l8D2ReadinessNodePrecedes(function.Body, item, before) {
						valid = false
						return false
					}
				}
			}
		}
		return true
	})
	return valid
}

func l8D2ReadinessExpectedConstantDeclarationFor(function *ast.FuncDecl, identifier *ast.Ident, environment l8D2ReadinessTerminalEnvironment) (l8D2ReadinessExpectedConstantDeclaration, bool) {
	if identifier == nil {
		return l8D2ReadinessExpectedConstantDeclaration{}, false
	}
	if identifier.Obj != nil {
		if declaration, ok := identifier.Obj.Decl.(*ast.ValueSpec); ok {
			if group, found := l8D2ReadinessParentGenDecl(function.Body, declaration); found {
				return l8D2ReadinessExpectedConstantDeclaration{file: environment.functionFiles[function], group: group, values: declaration}, true
			}
			for _, candidate := range environment.expectedConstants[identifier.Name] {
				if candidate.values == declaration {
					return candidate, true
				}
			}
		}
	}
	candidates := environment.expectedConstants[identifier.Name]
	if len(candidates) != 1 {
		return l8D2ReadinessExpectedConstantDeclaration{}, false
	}
	return candidates[0], true
}

func l8D2ReadinessNodePrecedes(root ast.Node, declaration, before ast.Node) bool {
	if root == nil || declaration == nil || before == nil {
		return false
	}
	declarationSeen := false
	beforeSeen := false
	ast.Inspect(root, func(node ast.Node) bool {
		if beforeSeen || node == nil {
			return !beforeSeen
		}
		if node == declaration {
			declarationSeen = true
		}
		if node == before {
			beforeSeen = true
			return false
		}
		return true
	})
	return beforeSeen && declarationSeen
}

func l8D2ReadinessExactIntType(expression ast.Expr) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == "int" && identifier.Obj == nil
}

func l8D2ReadinessCanonicalExpectedConstantInitializer(declaration *ast.ValueSpec, name string) bool {
	if declaration == nil || len(declaration.Names) != len(declaration.Values) {
		return false
	}
	var initializer ast.Expr
	for index, candidate := range declaration.Names {
		if candidate.Name == name {
			initializer = declaration.Values[index]
			break
		}
	}
	if literal, ok := initializer.(*ast.BasicLit); ok {
		return literal.Kind == token.INT
	}
	conversion, ok := initializer.(*ast.CallExpr)
	if !ok || len(conversion.Args) != 1 || conversion.Ellipsis.IsValid() {
		return false
	}
	target, ok := conversion.Fun.(*ast.Ident)
	literal, literalOK := conversion.Args[0].(*ast.BasicLit)
	return ok && target.Name == "int" && target.Obj == nil && literalOK && literal.Kind == token.INT
}

func l8D2ReadinessParentGenDecl(root ast.Node, target *ast.ValueSpec) (*ast.GenDecl, bool) {
	var result *ast.GenDecl
	ast.Inspect(root, func(node ast.Node) bool {
		group, ok := node.(*ast.GenDecl)
		if !ok {
			return result == nil
		}
		for _, specification := range group.Specs {
			if specification == target {
				result = group
				return false
			}
		}
		return result == nil
	})
	return result, result != nil
}

func l8D2ReadinessObservableOwnerStable(body *ast.BlockStmt, owner string) bool {
	if body == nil || owner == "" {
		return false
	}
	definitions := 0
	stable := true
	ast.Inspect(body, func(node ast.Node) bool {
		if !stable {
			return false
		}
		switch declaration := node.(type) {
		case *ast.AssignStmt:
			for _, left := range declaration.Lhs {
				if identifier, ok := left.(*ast.Ident); ok && identifier.Name == owner {
					definitions++
				}
			}
		case *ast.ValueSpec:
			for _, name := range declaration.Names {
				if name.Name == owner {
					definitions++
				}
			}
		case *ast.IncDecStmt:
			if identifier, ok := declaration.X.(*ast.Ident); ok && identifier.Name == owner {
				stable = false
				return false
			}
		case *ast.RangeStmt:
			for _, expression := range []ast.Expr{declaration.Key, declaration.Value} {
				if identifier, ok := expression.(*ast.Ident); ok && identifier.Name == owner {
					stable = false
					return false
				}
			}
		}
		return true
	})
	return stable && definitions == 1
}

func l8D2ReadinessObservableOwnerStartsZero(body *ast.BlockStmt, owner, field string, constructor *ast.CallExpr, environment l8D2ReadinessTerminalEnvironment, constants map[string]constant.Value) bool {
	if body == nil || owner == "" || field == "" || constructor == nil {
		return false
	}
	var initializer ast.Expr
	for _, statement := range body.List {
		if statement.Pos() >= constructor.Pos() {
			break
		}
		switch declaration := statement.(type) {
		case *ast.AssignStmt:
			for index, left := range declaration.Lhs {
				if identifier, ok := left.(*ast.Ident); ok && identifier.Name == owner && index < len(declaration.Rhs) {
					initializer = declaration.Rhs[index]
				}
			}
		case *ast.DeclStmt:
			group, ok := declaration.Decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, raw := range group.Specs {
				specification, ok := raw.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, name := range specification.Names {
					if name.Name == owner && index < len(specification.Values) {
						initializer = specification.Values[index]
					}
				}
			}
		}
	}
	if initializer == nil {
		return false
	}
	for {
		switch value := initializer.(type) {
		case *ast.ParenExpr:
			initializer = value.X
			continue
		case *ast.UnaryExpr:
			if value.Op != token.AND {
				return false
			}
			initializer = value.X
			continue
		}
		break
	}
	literal, ok := initializer.(*ast.CompositeLit)
	if !ok {
		return false
	}
	typeName, ok := literal.Type.(*ast.Ident)
	if !ok || len(environment.namedTypes[typeName.Name]) != 1 {
		return false
	}
	structure, ok := environment.namedTypes[typeName.Name][0].underlying.(*ast.StructType)
	if !ok || structure.Fields == nil {
		return false
	}
	directField := 0
	for _, declared := range structure.Fields.List {
		for _, name := range declared.Names {
			if name.Name == field {
				directField++
			}
		}
	}
	if directField != 1 {
		return false
	}
	zero := true
	for _, element := range literal.Elts {
		if _, keyed := element.(*ast.KeyValueExpr); !keyed {
			return false
		}
	}
	ast.Inspect(literal, func(node ast.Node) bool {
		keyValue, ok := node.(*ast.KeyValueExpr)
		key, keyOK := func() (*ast.Ident, bool) {
			if !ok {
				return nil, false
			}
			identifier, valid := keyValue.Key.(*ast.Ident)
			return identifier, valid
		}()
		if keyOK && key.Name == field {
			value, exact := l8D2ReadinessConstantExpression(keyValue.Value, constants)
			if !exact || value.Kind() != constant.Int || constant.Sign(value) != 0 {
				zero = false
				return false
			}
		}
		return zero
	})
	return zero
}

func l8D2ReadinessObservableOwnerFeedsConstructor(body *ast.BlockStmt, owner string, constructor *ast.CallExpr, dependencyFields []string) bool {
	if body == nil || owner == "" || constructor == nil || len(dependencyFields) == 0 || len(constructor.Args) != 1 {
		return false
	}
	definitions := make(map[string][]ast.Expr)
	definitionCounts := make(map[string]int)
	ownerInitialized := false
	for _, statement := range body.List {
		if statement.Pos() >= constructor.Pos() {
			break
		}
		switch declaration := statement.(type) {
		case *ast.AssignStmt:
			for index, left := range declaration.Lhs {
				identifier, ok := left.(*ast.Ident)
				if !ok || index >= len(declaration.Rhs) {
					continue
				}
				definitions[identifier.Name] = append(definitions[identifier.Name], declaration.Rhs[index])
				definitionCounts[identifier.Name]++
				if identifier.Name == owner {
					ownerInitialized = true
				}
			}
		case *ast.DeclStmt:
			general, ok := declaration.Decl.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				continue
			}
			for _, specification := range general.Specs {
				values, ok := specification.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, name := range values.Names {
					if index >= len(values.Values) {
						continue
					}
					definitions[name.Name] = append(definitions[name.Name], values.Values[index])
					definitionCounts[name.Name]++
					if name.Name == owner {
						ownerInitialized = true
					}
				}
			}
		}
	}
	if !ownerInitialized || definitionCounts[owner] != 1 {
		return false
	}
	visiting := make(map[string]bool)
	var contains func(ast.Expr) bool
	contains = func(expression ast.Expr) bool {
		if expression == nil {
			return false
		}
		switch value := expression.(type) {
		case *ast.Ident:
			if value.Name == owner {
				return true
			}
			if visiting[value.Name] || definitionCounts[value.Name] != 1 {
				return false
			}
			visiting[value.Name] = true
			result := contains(definitions[value.Name][0])
			delete(visiting, value.Name)
			return result
		case *ast.ParenExpr:
			return contains(value.X)
		case *ast.UnaryExpr:
			return value.Op == token.AND && contains(value.X)
		case *ast.CompositeLit:
			for _, element := range value.Elts {
				if contains(element) {
					return true
				}
			}
		case *ast.KeyValueExpr:
			return contains(value.Value)
		}
		return false
	}
	options := constructor.Args[0]
	if identifier, ok := options.(*ast.Ident); ok && definitionCounts[identifier.Name] == 1 {
		options = definitions[identifier.Name][0]
	}
	literal, ok := options.(*ast.CompositeLit)
	if !ok || types.ExprString(literal.Type) != "ServiceOptions" {
		return false
	}
	allowed := make(map[string]bool, len(dependencyFields))
	for _, field := range dependencyFields {
		allowed[field] = true
	}
	matches := 0
	invalid := false
	var exactOwner func(ast.Expr, map[string]bool) bool
	exactOwner = func(expression ast.Expr, visiting map[string]bool) bool {
		switch value := expression.(type) {
		case *ast.Ident:
			if value.Name == owner {
				return true
			}
			if visiting[value.Name] || definitionCounts[value.Name] != 1 {
				return false
			}
			visiting[value.Name] = true
			result := exactOwner(definitions[value.Name][0], visiting)
			delete(visiting, value.Name)
			return result
		case *ast.ParenExpr:
			return exactOwner(value.X, visiting)
		}
		return false
	}
	for _, element := range literal.Elts {
		keyValue, ok := element.(*ast.KeyValueExpr)
		key, keyOK := func() (*ast.Ident, bool) {
			if !ok {
				return nil, false
			}
			identifier, valid := keyValue.Key.(*ast.Ident)
			return identifier, valid
		}()
		if !keyOK || !contains(keyValue.Value) {
			continue
		}
		if !allowed[key.Name] || !exactOwner(keyValue.Value, make(map[string]bool)) {
			invalid = true
			continue
		}
		matches++
	}
	return !invalid && matches == 1
}

func l8D2ReadinessObservableFieldWritten(body *ast.BlockStmt, owner, field string, constructor *ast.CallExpr, globals map[string]bool) bool {
	aliases := map[string]bool{owner: true}
	fieldPointers := make(map[string]bool)
	aliasEscaped := false
	carriesAlias := func(expression ast.Expr) bool {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if identifier, ok := node.(*ast.Ident); ok && aliases[identifier.Name] {
				found = true
				return false
			}
			return !found
		})
		return found
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(node ast.Node) bool {
			var names []*ast.Ident
			var values []ast.Expr
			switch declaration := node.(type) {
			case *ast.AssignStmt:
				for _, left := range declaration.Lhs {
					if identifier, ok := left.(*ast.Ident); ok {
						names = append(names, identifier)
					} else {
						names = append(names, nil)
					}
				}
				values = declaration.Rhs
			case *ast.ValueSpec:
				names, values = declaration.Names, declaration.Values
			case *ast.RangeStmt:
				if !carriesAlias(declaration.X) {
					return true
				}
				for _, expression := range []ast.Expr{declaration.Key, declaration.Value} {
					if expression == nil {
						continue
					}
					identifier, ok := expression.(*ast.Ident)
					if !ok || identifier.Name == "_" {
						aliasEscaped = true
						continue
					}
					if !aliases[identifier.Name] {
						aliases[identifier.Name] = true
						changed = true
					}
				}
				return true
			case *ast.SendStmt:
				if carriesAlias(declaration.Value) {
					aliasEscaped = true
				}
				return true
			default:
				return true
			}
			for index, identifier := range names {
				if index >= len(values) {
					continue
				}
				right := values[index]
				if right == constructor {
					continue
				}
				if identifier == nil {
					if carriesAlias(right) {
						aliasEscaped = true
					}
					continue
				}
				if carriesAlias(right) && !aliases[identifier.Name] {
					aliases[identifier.Name] = true
					changed = true
				}
				if carriesAlias(right) && globals[identifier.Name] {
					aliasEscaped = true
				}
				if unary, ok := right.(*ast.UnaryExpr); ok && unary.Op == token.AND {
					if selector, ok := unary.X.(*ast.SelectorExpr); ok {
						if carriesAlias(selector.X) && selector.Sel.Name == field && !fieldPointers[identifier.Name] {
							fieldPointers[identifier.Name] = true
							changed = true
						}
					}
				}
			}
			return true
		})
	}
	if aliasEscaped {
		return true
	}
	written := false
	var isField func(ast.Expr) bool
	isField = func(expression ast.Expr) bool {
		switch wrapped := expression.(type) {
		case *ast.ParenExpr:
			return isField(wrapped.X)
		case *ast.StarExpr:
			if identifier, ok := wrapped.X.(*ast.Ident); ok && fieldPointers[identifier.Name] {
				return true
			}
			return isField(wrapped.X)
		case *ast.UnaryExpr:
			return wrapped.Op == token.AND && isField(wrapped.X)
		}
		selector, ok := expression.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != field {
			return false
		}
		found := false
		ast.Inspect(selector.X, func(node ast.Node) bool {
			if identifier, ok := node.(*ast.Ident); ok && aliases[identifier.Name] {
				found = true
				return false
			}
			return !found
		})
		return found
	}
	ast.Inspect(body, func(node ast.Node) bool {
		if written {
			return false
		}
		switch value := node.(type) {
		case *ast.CallExpr:
			if value == constructor {
				return true
			}
			for _, argument := range append([]ast.Expr{value.Fun}, value.Args...) {
				found := false
				ast.Inspect(argument, func(node ast.Node) bool {
					if identifier, ok := node.(*ast.Ident); ok && aliases[identifier.Name] {
						found = true
						return false
					}
					return !found
				})
				if found {
					written = true
					return false
				}
			}
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if isField(left) {
					written = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if isField(value.X) {
				written = true
				return false
			}
		}
		return true
	})
	return written
}

func l8D2ReadinessServiceOwnerConfinedUntilServe(body *ast.BlockStmt, owner string, constructor, serve *ast.CallExpr) bool {
	if body == nil || owner == "" || constructor == nil || serve == nil || constructor.End() >= serve.Pos() {
		return false
	}
	allowedOwner, ok := serve.Fun.(*ast.SelectorExpr)
	if !ok || allowedOwner.Sel.Name != "Serve" {
		return false
	}
	allowed, ok := allowedOwner.X.(*ast.Ident)
	if !ok || allowed.Name != owner {
		return false
	}
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			if len(stack) != 0 {
				stack = stack[:len(stack)-1]
			}
			return true
		}
		if len(stack) != 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	confined := true
	ast.Inspect(body, func(node ast.Node) bool {
		if !confined {
			return false
		}
		identifier, ok := node.(*ast.Ident)
		if !ok || identifier.Name != owner || identifier.Pos() <= constructor.End() || identifier.Pos() >= serve.End() {
			return true
		}
		if identifier == allowed {
			return true
		}
		parent := parents[identifier]
		if comparison, ok := parent.(*ast.BinaryExpr); ok && (comparison.Op == token.EQL || comparison.Op == token.NEQ) {
			other := comparison.X
			if other == identifier {
				other = comparison.Y
			}
			if l8D2ReadinessNilIdentifier(other) {
				return true
			}
		}
		confined = false
		return false
	})
	return confined
}

func l8D2ReadinessAllExerciseBefore(positions map[string]token.Pos, required []string, boundary token.Pos) bool {
	for _, name := range required {
		if positions[name] == token.NoPos || positions[name] >= boundary {
			return false
		}
	}
	return true
}

func assertL8D2ReadinessStructFields(t *testing.T, dir, typeName string, want []string) {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, declaration := range file.Decls {
				general, ok := declaration.(*ast.GenDecl)
				if !ok || general.Tok != token.TYPE {
					continue
				}
				for _, specification := range general.Specs {
					typeSpec, ok := specification.(*ast.TypeSpec)
					if !ok || typeSpec.Name.Name != typeName {
						continue
					}
					structure, ok := typeSpec.Type.(*ast.StructType)
					if !ok {
						t.Fatalf("%s is not a struct", typeName)
					}
					var got []string
					for _, field := range structure.Fields.List {
						if len(field.Names) == 0 {
							identifier, ok := field.Type.(*ast.Ident)
							if !ok {
								t.Fatalf("%s has non-identifier embedded field", typeName)
							}
							got = append(got, identifier.Name)
							continue
						}
						for _, name := range field.Names {
							got = append(got, name.Name)
						}
					}
					if strings.Join(got, ",") != strings.Join(want, ",") {
						t.Errorf("%s fields = %v, want %v", typeName, got, want)
					}
					return
				}
			}
		}
	}
	t.Errorf("missing struct %s", typeName)
}

func assertL8D2ReadinessStructFieldTypes(t *testing.T, dir, typeName string, want map[string]string) {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, declaration := range file.Decls {
				general, ok := declaration.(*ast.GenDecl)
				if !ok || general.Tok != token.TYPE {
					continue
				}
				for _, specification := range general.Specs {
					typeSpec, ok := specification.(*ast.TypeSpec)
					if !ok || typeSpec.Name.Name != typeName {
						continue
					}
					structure, ok := typeSpec.Type.(*ast.StructType)
					if !ok {
						t.Fatalf("%s is not a struct", typeName)
					}
					got := make(map[string]string)
					for _, field := range structure.Fields.List {
						fieldType := types.ExprString(field.Type)
						if len(field.Names) == 0 {
							got[fieldType] = fieldType
							continue
						}
						for _, name := range field.Names {
							got[name.Name] = fieldType
						}
					}
					for name, wantType := range want {
						if got[name] != wantType {
							t.Errorf("%s.%s type = %q, want %q", typeName, name, got[name], wantType)
						}
					}
					return
				}
			}
		}
	}
	t.Errorf("missing struct %s", typeName)
}

func assertL8D2ReadinessTypedConstValues(t *testing.T, dir, typeName string, want map[string]string) {
	t.Helper()
	found := make(map[string]bool)
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, declaration := range file.Decls {
				general, ok := declaration.(*ast.GenDecl)
				if !ok || general.Tok != token.CONST {
					continue
				}
				for _, specification := range general.Specs {
					valueSpec, ok := specification.(*ast.ValueSpec)
					if !ok || valueSpec.Type == nil || types.ExprString(valueSpec.Type) != typeName || len(valueSpec.Names) != len(valueSpec.Values) {
						continue
					}
					for index, name := range valueSpec.Names {
						wantValue, required := want[name.Name]
						if !required {
							continue
						}
						if types.ExprString(valueSpec.Values[index]) != wantValue {
							t.Errorf("%s %s value = %s, want %s", typeName, name.Name, types.ExprString(valueSpec.Values[index]), wantValue)
						}
						found[name.Name] = true
					}
				}
			}
		}
	}
	for name := range want {
		if !found[name] {
			t.Errorf("missing explicitly typed %s constant %s", typeName, name)
		}
	}
}

func assertL8D2ReadinessErrorCatalog(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	found := make(map[string]bool)
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, declaration := range file.Decls {
				general, ok := declaration.(*ast.GenDecl)
				if !ok || general.Tok != token.VAR {
					continue
				}
				for _, specification := range general.Specs {
					valueSpec, ok := specification.(*ast.ValueSpec)
					if !ok || len(valueSpec.Names) != len(valueSpec.Values) {
						continue
					}
					for index, name := range valueSpec.Names {
						wantExpression, required := want[name.Name]
						if !required {
							continue
						}
						got := types.ExprString(valueSpec.Values[index])
						if got != wantExpression {
							t.Errorf("error %s expression = %q, want %q", name.Name, got, wantExpression)
						}
						found[name.Name] = true
					}
				}
			}
		}
	}
	for name := range want {
		if !found[name] {
			t.Errorf("missing readiness error %s", name)
		}
	}
}

func assertL8D2ReadinessFunctionSignature(t *testing.T, dir, receiver, functionName string, wantParams, wantResults []string) {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != functionName {
					continue
				}
				gotReceiver := ""
				if function.Recv != nil && len(function.Recv.List) == 1 {
					gotReceiver = types.ExprString(function.Recv.List[0].Type)
				}
				if gotReceiver != receiver {
					continue
				}
				gotParams := l8D2ReadinessFieldListTypes(function.Type.Params)
				gotResults := l8D2ReadinessFieldListTypes(function.Type.Results)
				if strings.Join(gotParams, ",") != strings.Join(wantParams, ",") || strings.Join(gotResults, ",") != strings.Join(wantResults, ",") {
					t.Errorf("%s%s signature = (%s) (%s), want (%s) (%s)", receiver, functionName, strings.Join(gotParams, ", "), strings.Join(gotResults, ", "), strings.Join(wantParams, ", "), strings.Join(wantResults, ", "))
				}
				return
			}
		}
	}
	t.Errorf("missing function signature %s%s", receiver, functionName)
}

func l8D2ReadinessFieldListTypes(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var result []string
	for _, field := range fields.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for range count {
			result = append(result, types.ExprString(field.Type))
		}
	}
	return result
}

func l8D2ReadinessDirectCalledIdentifier(expression ast.Expr) (*ast.Ident, bool) {
	switch value := expression.(type) {
	case *ast.Ident:
		return value, true
	case *ast.ParenExpr:
		return l8D2ReadinessDirectCalledIdentifier(value.X)
	case *ast.IndexExpr:
		return l8D2ReadinessDirectCalledIdentifier(value.X)
	case *ast.IndexListExpr:
		return l8D2ReadinessDirectCalledIdentifier(value.X)
	}
	return nil, false
}

func assertL8D2ReadinessExportedMethods(t *testing.T, dir, typeName string, want []string) {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Recv == nil || len(function.Recv.List) != 1 || !ast.IsExported(function.Name.Name) {
					continue
				}
				receiver := strings.TrimPrefix(types.ExprString(function.Recv.List[0].Type), "*")
				if receiver == typeName {
					got = append(got, function.Name.Name)
				}
			}
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s exported methods = %v, want exact %v", typeName, got, want)
	}
}

func assertL8D2ReadinessExactImports(t *testing.T, path string, want []string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		// The exact-file absence is already reported by the product guard. Keep
		// collecting the rest of the red implementation evidence in one run.
		return
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, content, parser.ImportsOnly)
	if err != nil {
		t.Errorf("parse imports in %s: %v", filepath.Base(path), err)
		return
	}
	var got []string
	for _, imported := range file.Imports {
		got = append(got, strings.Trim(imported.Path.Value, `"`))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s imports = %v, want exact pure imports %v", filepath.Base(path), got, want)
	}
}

func assertL8D2ReadinessNoRetainedScopedTypes(t *testing.T, dir string) {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for _, issue := range l8D2ReadinessRetainedScopedTypeIssues(pkg.Files) {
			t.Error(issue)
		}
	}
}

func assertL8D2ReadinessNoDynamicScopedEscapes(t *testing.T, dir string) {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for _, issue := range l8D2ReadinessRetainedScopedTypeIssues(pkg.Files) {
			if strings.Contains(issue, " dynamically retains ") {
				t.Error(issue)
			}
		}
	}
}

type l8D2ReadinessTypeDefinition struct {
	expression     ast.Expr
	typeParameters map[string]ast.Expr
	aliases        map[string]string
	dotImport      bool
}

type l8D2ReadinessGlobalDefinition struct {
	typeExpression  ast.Expr
	valueExpression ast.Expr
	aliases         map[string]string
	dotImport       bool
	fileName        string
}

func l8D2ReadinessRetainedScopedTypeIssues(files map[string]*ast.File) []string {
	definitions := make(map[string]l8D2ReadinessTypeDefinition)
	aliasesByFile := make(map[*ast.File]map[string]string)
	dotImportByFile := make(map[*ast.File]bool)
	typeParametersByStruct := make(map[*ast.StructType]map[string]ast.Expr)
	globals := make(map[string]l8D2ReadinessGlobalDefinition)
	for fileName, file := range files {
		aliases, dotImport := l8D2ReadinessImportAliases(file)
		aliasesByFile[file] = aliases
		dotImportByFile[file] = dotImport
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok {
				continue
			}
			if general.Tok == token.VAR {
				for _, specification := range general.Specs {
					valueSpec, ok := specification.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for index, variable := range valueSpec.Names {
						var expression ast.Expr
						if index < len(valueSpec.Values) {
							expression = valueSpec.Values[index]
						} else if len(valueSpec.Values) == 1 {
							expression = valueSpec.Values[0]
						}
						globals[variable.Name] = l8D2ReadinessGlobalDefinition{typeExpression: valueSpec.Type, valueExpression: expression, aliases: aliases, dotImport: dotImport, fileName: fileName}
					}
				}
				continue
			}
			if general.Tok != token.TYPE {
				continue
			}
			for _, specification := range general.Specs {
				typeSpec, ok := specification.(*ast.TypeSpec)
				if ok {
					typeParameters := l8D2ReadinessTypeParameters(typeSpec.TypeParams)
					definitions[typeSpec.Name.Name] = l8D2ReadinessTypeDefinition{
						expression:     typeSpec.Type,
						typeParameters: typeParameters,
						aliases:        aliases,
						dotImport:      dotImport,
					}
					ast.Inspect(typeSpec.Type, func(node ast.Node) bool {
						if structure, ok := node.(*ast.StructType); ok {
							typeParametersByStruct[structure] = typeParameters
						}
						return true
					})
				}
			}
		}
	}

	var globalRetainsScoped func(string, map[string]bool) bool
	globalRetainsScoped = func(variable string, stack map[string]bool) bool {
		definition, ok := globals[variable]
		if !ok || stack[variable] {
			return false
		}
		stack[variable] = true
		defer delete(stack, variable)
		if l8D2ReadinessTypeRetainsScoped(definition.typeExpression, definition.aliases, definition.dotImport, nil, definitions, make(map[string]bool)) {
			return true
		}
		retained := false
		if definition.valueExpression == nil {
			return false
		}
		ast.Inspect(definition.valueExpression, func(node ast.Node) bool {
			if retained {
				return false
			}
			switch candidate := node.(type) {
			case *ast.Ident:
				if globalRetainsScoped(candidate.Name, stack) {
					retained = true
					return false
				}
			case ast.Expr:
				if l8D2ReadinessTypeRetainsScoped(candidate, definition.aliases, definition.dotImport, nil, definitions, make(map[string]bool)) {
					retained = true
					return false
				}
			}
			return true
		})
		return retained
	}
	var issues []string
	for variable, definition := range globals {
		if globalRetainsScoped(variable, make(map[string]bool)) {
			issues = append(issues, filepath.Base(definition.fileName)+" retains credentialmemory.BorrowedView or CredentialSink in package variable "+variable)
		}
	}
	functionsByName := make(map[string][]*ast.FuncDecl)
	functionFiles := make(map[*ast.FuncDecl]*ast.File)
	for _, file := range files {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Body != nil {
				functionsByName[function.Name.Name] = append(functionsByName[function.Name.Name], function)
				functionFiles[function] = file
			}
		}
	}
	seededScoped := l8D2ReadinessPropagateScopedParameters(functionsByName, functionFiles, aliasesByFile, dotImportByFile, definitions)
	for name, file := range files {
		aliases, dotImport := aliasesByFile[file], dotImportByFile[file]
		ast.Inspect(file, func(node ast.Node) bool {
			structure, ok := node.(*ast.StructType)
			if !ok {
				return true
			}
			typeParameters := typeParametersByStruct[structure]
			for _, field := range structure.Fields.List {
				if l8D2ReadinessTypeRetainsScoped(field.Type, aliases, dotImport, typeParameters, definitions, make(map[string]bool)) {
					fieldName := "<embedded>"
					if len(field.Names) != 0 {
						fieldName = field.Names[0].Name
					}
					issues = append(issues, filepath.Base(name)+" retains credentialmemory.BorrowedView or CredentialSink in struct field "+fieldName)
				}
			}
			return false
		})
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil || !l8D2ReadinessFunctionDynamicallyRetainsScoped(function, aliases, dotImport, definitions, globals, seededScoped[function], functionsByName) {
				continue
			}
			issues = append(issues, filepath.Base(name)+" dynamically retains credentialmemory.BorrowedView or CredentialSink in function "+function.Name.Name)
		}
	}
	sort.Strings(issues)
	return issues
}

func l8D2ReadinessPropagateScopedParameters(functionsByName map[string][]*ast.FuncDecl, functionFiles map[*ast.FuncDecl]*ast.File, aliasesByFile map[*ast.File]map[string]string, dotImportByFile map[*ast.File]bool, definitions map[string]l8D2ReadinessTypeDefinition) map[*ast.FuncDecl]map[string]bool {
	result := make(map[*ast.FuncDecl]map[string]bool)
	for _, functions := range functionsByName {
		for _, function := range functions {
			result[function] = make(map[string]bool)
			file := functionFiles[function]
			if function.Type.Params == nil {
				continue
			}
			for _, field := range function.Type.Params.List {
				if !l8D2ReadinessDirectScopedValueType(field.Type, aliasesByFile[file], dotImportByFile[file], definitions, make(map[string]bool)) {
					continue
				}
				for _, name := range field.Names {
					result[function][name.Name] = true
				}
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for caller, seeds := range result {
			names := l8D2ReadinessScopedLocalAliases(caller.Body, seeds)
			ast.Inspect(caller.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				called, ok := l8D2ReadinessDirectCalledIdentifier(call.Fun)
				if !ok || len(functionsByName[called.Name]) != 1 {
					return true
				}
				switch called.Name {
				case "configuredDependency", "typedNil", "isNilCoreDependency", "destroyTransportBody":
					return true
				}
				target := functionsByName[called.Name][0]
				parameters := l8D2ReadinessFunctionParameterNames(target)
				for index, argument := range call.Args {
					if !l8D2ReadinessExpressionCarriesScoped(argument, names) || len(parameters) == 0 {
						continue
					}
					parameterIndex := index
					if parameterIndex >= len(parameters) {
						parameterIndex = len(parameters) - 1
					}
					if !result[target][parameters[parameterIndex]] {
						result[target][parameters[parameterIndex]] = true
						changed = true
					}
				}
				return true
			})
		}
	}
	return result
}

func l8D2ReadinessScopedLocalAliases(body *ast.BlockStmt, seeds map[string]bool) map[string]bool {
	result := make(map[string]bool, len(seeds))
	for name := range seeds {
		result[name] = true
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.AssignStmt:
				for index, left := range value.Lhs {
					identifier, ok := left.(*ast.Ident)
					if ok && identifier.Name != "_" && index < len(value.Rhs) && l8D2ReadinessExpressionCarriesScoped(value.Rhs[index], result) && !result[identifier.Name] {
						result[identifier.Name] = true
						changed = true
					}
				}
			case *ast.ValueSpec:
				for index, name := range value.Names {
					if index < len(value.Values) && l8D2ReadinessExpressionCarriesScoped(value.Values[index], result) && !result[name.Name] {
						result[name.Name] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	return result
}

func l8D2ReadinessExpressionCarriesScoped(expression ast.Expr, names map[string]bool) bool {
	if expression == nil {
		return false
	}
	switch value := expression.(type) {
	case *ast.Ident:
		return names[value.Name]
	case *ast.ParenExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.X, names)
	case *ast.UnaryExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.X, names)
	case *ast.StarExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.X, names)
	case *ast.SelectorExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.X, names)
	case *ast.IndexExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.X, names) || l8D2ReadinessExpressionCarriesScoped(value.Index, names)
	case *ast.IndexListExpr:
		if l8D2ReadinessExpressionCarriesScoped(value.X, names) {
			return true
		}
		for _, index := range value.Indices {
			if l8D2ReadinessExpressionCarriesScoped(index, names) {
				return true
			}
		}
	case *ast.SliceExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.X, names) || l8D2ReadinessExpressionCarriesScoped(value.Low, names) || l8D2ReadinessExpressionCarriesScoped(value.High, names) || l8D2ReadinessExpressionCarriesScoped(value.Max, names)
	case *ast.TypeAssertExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.X, names) || l8D2ReadinessExpressionCarriesScoped(value.Type, names)
	case *ast.BinaryExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.X, names) || l8D2ReadinessExpressionCarriesScoped(value.Y, names)
	case *ast.KeyValueExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.Key, names) || l8D2ReadinessExpressionCarriesScoped(value.Value, names)
	case *ast.Ellipsis:
		return l8D2ReadinessExpressionCarriesScoped(value.Elt, names)
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			switch item := element.(type) {
			case *ast.KeyValueExpr:
				if l8D2ReadinessExpressionCarriesScoped(item.Value, names) {
					return true
				}
			case ast.Expr:
				if l8D2ReadinessExpressionCarriesScoped(item, names) {
					return true
				}
			}
		}
	case *ast.FuncLit:
		captured := false
		ast.Inspect(value.Body, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && names[identifier.Name] {
				captured = true
				return false
			}
			return !captured
		})
		return captured
	case *ast.CallExpr:
		if l8D2ReadinessExpressionCarriesScoped(value.Fun, names) {
			return true
		}
		for _, argument := range value.Args {
			if l8D2ReadinessExpressionCarriesScoped(argument, names) {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessDirectScopedValueType(expression ast.Expr, aliases map[string]string, dotImport bool, definitions map[string]l8D2ReadinessTypeDefinition, stack map[string]bool) bool {
	switch value := expression.(type) {
	case *ast.SelectorExpr:
		owner, ok := value.X.(*ast.Ident)
		return ok && aliases[owner.Name] == "github.com/jywlabs/hal/internal/credentialmemory" && (value.Sel.Name == "BorrowedView" || value.Sel.Name == "CredentialSink")
	case *ast.Ident:
		if dotImport && (value.Name == "BorrowedView" || value.Name == "CredentialSink") {
			return true
		}
		definition, ok := definitions[value.Name]
		if !ok || stack[value.Name] {
			return false
		}
		stack[value.Name] = true
		result := l8D2ReadinessDirectScopedValueType(definition.expression, definition.aliases, definition.dotImport, definitions, stack)
		delete(stack, value.Name)
		return result
	case *ast.ParenExpr:
		return l8D2ReadinessDirectScopedValueType(value.X, aliases, dotImport, definitions, stack)
	}
	return false
}

func l8D2ReadinessFunctionDynamicallyRetainsScoped(function *ast.FuncDecl, aliases map[string]string, dotImport bool, definitions map[string]l8D2ReadinessTypeDefinition, globals map[string]l8D2ReadinessGlobalDefinition, seeded map[string]bool, functionsByName map[string][]*ast.FuncDecl) bool {
	scoped := make(map[string]bool)
	bodyParams := make(map[string]bool)
	contextParams := make(map[string]bool)
	borrowOwnerParams := make(map[string]bool)
	collectParameters := func(fields *ast.FieldList, destination map[string]bool) {
		if fields == nil {
			return
		}
		for _, field := range fields.List {
			if !l8D2ReadinessDirectScopedValueType(field.Type, aliases, dotImport, definitions, make(map[string]bool)) {
				continue
			}
			for _, name := range field.Names {
				destination[name.Name] = true
			}
		}
	}
	collectParameters(function.Type.Params, scoped)
	for name := range seeded {
		scoped[name] = true
	}
	if function.Name.Name == "withCanonicalScratch" && l8D2ReadinessExactScopedHelperDeclaration(functionsByName[function.Name.Name], function.Name.Name, aliases, definitions) {
		delete(scoped, "consume")
	}
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				bodyParams[name.Name] = types.ExprString(field.Type) == "ReceivedBodyCapability"
				borrowOwnerParams[name.Name] = types.ExprString(field.Type) == "ReceivedBodyCapability" || types.ExprString(field.Type) == "CoreOutputBody"
				contextParams[name.Name] = l8D2ReadinessExactImportedType(field.Type, aliases, "context", "Context", false)
			}
		}
	}
	approvedScopedHelpers := map[string]bool{"configuredDependency": true, "typedNil": true, "isNilCoreDependency": true, "destroyTransportBody": true, "withCanonicalScratch": true}
	shadowedScopedHelpers := make(map[string]bool)
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				if approvedScopedHelpers[name.Name] {
					shadowedScopedHelpers[name.Name] = true
				}
			}
		}
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if identifier, ok := left.(*ast.Ident); ok && approvedScopedHelpers[identifier.Name] {
					shadowedScopedHelpers[identifier.Name] = true
				}
			}
		case *ast.ValueSpec:
			for _, name := range value.Names {
				if approvedScopedHelpers[name.Name] {
					shadowedScopedHelpers[name.Name] = true
				}
			}
		case *ast.FuncLit:
			if value.Type.Params != nil {
				for _, field := range value.Type.Params.List {
					for _, name := range field.Names {
						if approvedScopedHelpers[name.Name] {
							shadowedScopedHelpers[name.Name] = true
						}
					}
				}
			}
		}
		return true
	})
	retained := false
	var carriesScoped func(ast.Expr, map[string]bool) bool
	carriesScoped = func(expression ast.Expr, names map[string]bool) bool {
		switch value := expression.(type) {
		case *ast.Ident:
			return names[value.Name]
		case *ast.ParenExpr:
			return carriesScoped(value.X, names)
		case *ast.UnaryExpr:
			return carriesScoped(value.X, names)
		case *ast.StarExpr:
			return carriesScoped(value.X, names)
		case *ast.SelectorExpr:
			return carriesScoped(value.X, names)
		case *ast.IndexExpr:
			return carriesScoped(value.X, names) || carriesScoped(value.Index, names)
		case *ast.IndexListExpr:
			if carriesScoped(value.X, names) {
				return true
			}
			for _, index := range value.Indices {
				if carriesScoped(index, names) {
					return true
				}
			}
		case *ast.SliceExpr:
			return carriesScoped(value.X, names) || carriesScoped(value.Low, names) || carriesScoped(value.High, names) || carriesScoped(value.Max, names)
		case *ast.TypeAssertExpr:
			return carriesScoped(value.X, names) || carriesScoped(value.Type, names)
		case *ast.BinaryExpr:
			return carriesScoped(value.X, names) || carriesScoped(value.Y, names)
		case *ast.KeyValueExpr:
			return carriesScoped(value.Key, names) || carriesScoped(value.Value, names)
		case *ast.Ellipsis:
			return carriesScoped(value.Elt, names)
		case *ast.CompositeLit:
			for _, element := range value.Elts {
				switch item := element.(type) {
				case *ast.KeyValueExpr:
					if carriesScoped(item.Key, names) || carriesScoped(item.Value, names) {
						return true
					}
				case ast.Expr:
					if carriesScoped(item, names) {
						return true
					}
				}
			}
		case *ast.FuncLit:
			captured := false
			ast.Inspect(value.Body, func(node ast.Node) bool {
				identifier, ok := node.(*ast.Ident)
				if ok && names[identifier.Name] {
					captured = true
					return false
				}
				return !captured
			})
			return captured
		case *ast.CallExpr:
			if l8D2ReadinessExactNonretainingScopedCall(function, value, names, aliases, definitions, functionsByName) {
				return false
			}
			if carriesScoped(value.Fun, names) {
				return true
			}
			for _, argument := range value.Args {
				if carriesScoped(argument, names) {
					return true
				}
			}
		}
		return false
	}
	// First propagate direct local aliases so a closure/composite cannot hide a
	// scoped capability behind one or more inferred identifiers.
	for changed := true; changed; {
		changed = false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if ok {
				for index, left := range assignment.Lhs {
					if index >= len(assignment.Rhs) || !carriesScoped(assignment.Rhs[index], scoped) {
						continue
					}
					if assignment.Tok == token.DEFINE && l8D2ReadinessApprovedScopedWrapper(function, assignment.Rhs[index], definitions) {
						continue
					}
					identifier, ok := left.(*ast.Ident)
					if ok && identifier.Name != "_" && !scoped[identifier.Name] {
						scoped[identifier.Name] = true
						changed = true
					}
				}
			}
			valueSpec, ok := node.(*ast.ValueSpec)
			if ok {
				for index, name := range valueSpec.Names {
					if index < len(valueSpec.Values) && carriesScoped(valueSpec.Values[index], scoped) && !scoped[name.Name] {
						scoped[name.Name] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	allowedBorrowCallbacks := make(map[*ast.FuncLit]bool)
	allowedSynchronousCallbacks := make(map[*ast.FuncLit]bool)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if called, direct := call.Fun.(*ast.Ident); direct && called.Name == "withCanonicalScratch" && len(call.Args) == 3 && !shadowedScopedHelpers[called.Name] && l8D2ReadinessExactScopedHelperDeclaration(functionsByName[called.Name], called.Name, aliases, definitions) {
			if callback, ok := call.Args[2].(*ast.FuncLit); ok {
				allowedSynchronousCallbacks[callback] = true
			}
		}
		if len(call.Args) != 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		callback, callbackOK := call.Args[1].(*ast.FuncLit)
		owner, ownerOK := func() (*ast.Ident, bool) {
			if !ok {
				return nil, false
			}
			value, valid := selector.X.(*ast.Ident)
			return value, valid
		}()
		ctx, ctxOK := call.Args[0].(*ast.Ident)
		exactCallback := callbackOK && callback.Type.Params != nil && len(callback.Type.Params.List) == 1 && len(callback.Type.Params.List[0].Names) == 1 && l8D2ReadinessExactImportedType(callback.Type.Params.List[0].Type, aliases, "github.com/jywlabs/hal/internal/credentialmemory", "BorrowedView", false)
		exactBodyOwner := ok && ((ownerOK && (bodyParams[owner.Name] || borrowOwnerParams[owner.Name])) || l8D2ReadinessExactReceivedBodyExpression(function, selector.X, definitions))
		if exactBodyOwner && ctxOK && contextParams[ctx.Name] && selector.Sel.Name == "Borrow" && exactCallback {
			allowedBorrowCallbacks[callback] = true
		}
		return true
	})
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if retained {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for index, left := range value.Lhs {
				if index >= len(value.Rhs) || !carriesScoped(value.Rhs[index], scoped) {
					continue
				}
				if value.Tok == token.DEFINE && l8D2ReadinessApprovedScopedWrapper(function, value.Rhs[index], definitions) {
					continue
				}
				identifier, identifierOK := left.(*ast.Ident)
				directAlias, directAliasOK := value.Rhs[index].(*ast.Ident)
				if value.Tok == token.DEFINE && identifierOK && directAliasOK && scoped[directAlias.Name] {
					continue
				}
				if !identifierOK || identifier.Name != "_" || globals[identifier.Name].fileName != "" {
					retained = true
					return false
				}
			}
		case *ast.ReturnStmt:
			for _, result := range value.Results {
				if carriesScoped(result, scoped) {
					retained = true
					return false
				}
			}
		case *ast.DeclStmt:
			general, ok := value.Decl.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				return true
			}
			for _, specification := range general.Specs {
				valueSpec, ok := specification.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, expression := range valueSpec.Values {
					identifier, directAlias := expression.(*ast.Ident)
					if carriesScoped(expression, scoped) && !(directAlias && scoped[identifier.Name]) {
						retained = true
						return false
					}
				}
			}
		case *ast.SendStmt:
			if carriesScoped(value.Value, scoped) {
				retained = true
				return false
			}
		case *ast.CallExpr:
			if l8D2ReadinessCallCarriesScoped(value, scoped) && !l8D2ReadinessAllowedDynamicScopedCall(function, value, scoped, contextParams, shadowedScopedHelpers, aliases, definitions, functionsByName) {
				retained = true
				return false
			}
		case *ast.FuncLit:
			callbackScoped := make(map[string]bool)
			collectParameters(value.Type.Params, callbackScoped)
			capturesOuter := false
			ast.Inspect(value.Body, func(inner ast.Node) bool {
				identifier, ok := inner.(*ast.Ident)
				if ok && scoped[identifier.Name] && !callbackScoped[identifier.Name] {
					capturesOuter = true
					return false
				}
				return !capturesOuter
			})
			allowedCallback := allowedBorrowCallbacks[value] || allowedSynchronousCallbacks[value]
			capturesPermittedSink := allowedSynchronousCallbacks[value] && scoped["sink"]
			if (capturesOuter && !capturesPermittedSink) || (len(scoped) != 0 && !allowedCallback) || (len(callbackScoped) != 0 && !allowedCallback) {
				retained = true
				return false
			}
			if allowedCallback {
				callbackSeeds := make(map[string]bool)
				for name := range scoped {
					callbackSeeds[name] = true
				}
				for name := range callbackScoped {
					callbackSeeds[name] = true
				}
				callbackNames := l8D2ReadinessScopedLocalAliases(value.Body, callbackSeeds)
				nested, callbackRetention := false, false
				ast.Inspect(value.Body, func(inner ast.Node) bool {
					if _, ok := inner.(*ast.FuncLit); ok {
						nested = true
						return false
					}
					switch statement := inner.(type) {
					case *ast.CallExpr:
						if l8D2ReadinessCallCarriesScoped(statement, callbackNames) && !l8D2ReadinessAllowedDynamicScopedCall(function, statement, callbackNames, contextParams, shadowedScopedHelpers, aliases, definitions, functionsByName) {
							callbackRetention = true
							return false
						}
					case *ast.AssignStmt:
						for index, left := range statement.Lhs {
							if index < len(statement.Rhs) && carriesScoped(statement.Rhs[index], callbackScoped) {
								identifier, ok := left.(*ast.Ident)
								if !ok || identifier.Name != "_" {
									callbackRetention = true
									return false
								}
							}
						}
					case *ast.ReturnStmt:
						for _, result := range statement.Results {
							if carriesScoped(result, callbackScoped) {
								callbackRetention = true
								return false
							}
						}
					}
					return !nested && !callbackRetention
				})
				if nested || callbackRetention {
					retained = true
					return false
				}
			}
		}
		return true
	})
	return retained
}

func l8D2ReadinessExactNonretainingScopedCall(function *ast.FuncDecl, call *ast.CallExpr, names map[string]bool, aliases map[string]string, definitions map[string]l8D2ReadinessTypeDefinition, functionsByName map[string][]*ast.FuncDecl) bool {
	if call == nil {
		return false
	}
	switch called := call.Fun.(type) {
	case *ast.Ident:
		switch called.Name {
		case "configuredDependency", "typedNil", "isNilCoreDependency", "destroyTransportBody", "withCanonicalScratch":
			return l8D2ReadinessExactScopedHelperDeclaration(functionsByName[called.Name], called.Name, aliases, definitions)
		}
		return l8D2ReadinessExactBorrowCallbackInvocation(function, called.Name, call, names, aliases)
	case *ast.SelectorExpr:
		kind := l8D2ReadinessExactScopedReceiverKind(function, called.X, aliases, definitions, make(map[string]bool))
		if kind == "view" {
			switch called.Sel.Name {
			case "Len":
				return len(call.Args) == 0
			case "WriteTo", "CopyTo":
				return len(call.Args) == 2
			}
		}
		if kind == "sink" {
			switch called.Sel.Name {
			case "MaxCredentialBytes":
				return len(call.Args) == 0
			case "WriteCredential":
				return len(call.Args) == 1
			}
		}
		if called.Sel.Name == "ValueOf" && len(call.Args) == 1 && function != nil && function.Name.Name == "isNilCoreDependency" {
			owner, ok := called.X.(*ast.Ident)
			return ok && aliases[owner.Name] == "reflect" && l8D2ReadinessExactScopedReceiverKind(function, call.Args[0], aliases, definitions, make(map[string]bool)) == "sink" && l8D2ReadinessExactScopedHelperDeclaration(functionsByName["isNilCoreDependency"], "isNilCoreDependency", aliases, definitions)
		}
	}
	return false
}

func l8D2ReadinessExactScopedReceiverKind(function *ast.FuncDecl, expression ast.Expr, aliases map[string]string, definitions map[string]l8D2ReadinessTypeDefinition, stack map[string]bool) string {
	if function == nil || expression == nil {
		return ""
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		if stack[identifier.Name] {
			return ""
		}
		kindFromFields := func(fields *ast.FieldList) string {
			if fields == nil {
				return ""
			}
			for _, field := range fields.List {
				for _, name := range field.Names {
					if name.Name != identifier.Name {
						continue
					}
					if l8D2ReadinessExactImportedType(field.Type, aliases, "github.com/jywlabs/hal/internal/credentialmemory", "BorrowedView", false) {
						return "view"
					}
					if l8D2ReadinessExactImportedType(field.Type, aliases, "github.com/jywlabs/hal/internal/credentialmemory", "CredentialSink", false) {
						return "sink"
					}
				}
			}
			return ""
		}
		if kind := kindFromFields(function.Type.Params); kind != "" {
			return kind
		}
		kind := ""
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if kind != "" {
				return false
			}
			if literal, ok := node.(*ast.FuncLit); ok {
				kind = kindFromFields(literal.Type.Params)
			}
			return true
		})
		if kind != "" {
			return kind
		}
		stack[identifier.Name] = true
		defer delete(stack, identifier.Name)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if kind != "" {
				return false
			}
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for index, left := range assignment.Lhs {
				leftID, direct := left.(*ast.Ident)
				if direct && leftID.Name == identifier.Name && index < len(assignment.Rhs) {
					kind = l8D2ReadinessExactScopedReceiverKind(function, assignment.Rhs[index], aliases, definitions, stack)
				}
			}
			return true
		})
		return kind
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	typeName := l8D2ReadinessExpressionConcreteTypeName(function, selector.X)
	definition, ok := definitions[typeName]
	structure, structural := definition.expression.(*ast.StructType)
	if !ok || !structural {
		return ""
	}
	for _, field := range structure.Fields.List {
		for _, name := range field.Names {
			if name.Name != selector.Sel.Name {
				continue
			}
			if l8D2ReadinessExactImportedType(field.Type, definition.aliases, "github.com/jywlabs/hal/internal/credentialmemory", "BorrowedView", false) {
				return "view"
			}
			if l8D2ReadinessExactImportedType(field.Type, definition.aliases, "github.com/jywlabs/hal/internal/credentialmemory", "CredentialSink", false) {
				return "sink"
			}
		}
	}
	return ""
}

func l8D2ReadinessExpressionConcreteTypeName(function *ast.FuncDecl, expression ast.Expr) string {
	identifier, ok := expression.(*ast.Ident)
	if !ok || function == nil {
		return ""
	}
	if function.Recv != nil && len(function.Recv.List) == 1 && len(function.Recv.List[0].Names) == 1 && function.Recv.List[0].Names[0].Name == identifier.Name {
		return strings.TrimPrefix(types.ExprString(function.Recv.List[0].Type), "*")
	}
	result := ""
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if result != "" {
			return false
		}
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for index, left := range assignment.Lhs {
			leftID, direct := left.(*ast.Ident)
			if !direct || leftID.Name != identifier.Name || index >= len(assignment.Rhs) {
				continue
			}
			right := assignment.Rhs[index]
			if address, addressOK := right.(*ast.UnaryExpr); addressOK && address.Op == token.AND {
				right = address.X
			}
			if literal, literalOK := right.(*ast.CompositeLit); literalOK {
				result = strings.TrimPrefix(types.ExprString(literal.Type), "*")
			}
		}
		return true
	})
	return result
}

func l8D2ReadinessExpressionContainsBoundScopedMethod(expression ast.Expr, names map[string]bool) bool {
	switch value := expression.(type) {
	case *ast.SelectorExpr:
		return l8D2ReadinessExpressionCarriesScoped(value.X, names) || l8D2ReadinessExpressionContainsBoundScopedMethod(value.X, names)
	case *ast.ParenExpr:
		return l8D2ReadinessExpressionContainsBoundScopedMethod(value.X, names)
	case *ast.TypeAssertExpr:
		return l8D2ReadinessExpressionContainsBoundScopedMethod(value.X, names)
	case *ast.UnaryExpr:
		return l8D2ReadinessExpressionContainsBoundScopedMethod(value.X, names)
	case *ast.StarExpr:
		return l8D2ReadinessExpressionContainsBoundScopedMethod(value.X, names)
	case *ast.IndexExpr:
		return l8D2ReadinessExpressionContainsBoundScopedMethod(value.X, names) || l8D2ReadinessExpressionContainsBoundScopedMethod(value.Index, names)
	case *ast.IndexListExpr:
		if l8D2ReadinessExpressionContainsBoundScopedMethod(value.X, names) {
			return true
		}
		for _, index := range value.Indices {
			if l8D2ReadinessExpressionContainsBoundScopedMethod(index, names) {
				return true
			}
		}
	case *ast.SliceExpr:
		return l8D2ReadinessExpressionContainsBoundScopedMethod(value.X, names) || l8D2ReadinessExpressionContainsBoundScopedMethod(value.Low, names) || l8D2ReadinessExpressionContainsBoundScopedMethod(value.High, names) || l8D2ReadinessExpressionContainsBoundScopedMethod(value.Max, names)
	case *ast.BinaryExpr:
		return l8D2ReadinessExpressionContainsBoundScopedMethod(value.X, names) || l8D2ReadinessExpressionContainsBoundScopedMethod(value.Y, names)
	case *ast.KeyValueExpr:
		return l8D2ReadinessExpressionContainsBoundScopedMethod(value.Key, names) || l8D2ReadinessExpressionContainsBoundScopedMethod(value.Value, names)
	case *ast.Ellipsis:
		return l8D2ReadinessExpressionContainsBoundScopedMethod(value.Elt, names)
	case *ast.CallExpr:
		if l8D2ReadinessExpressionContainsBoundScopedMethod(value.Fun, names) {
			return true
		}
		for _, argument := range value.Args {
			if l8D2ReadinessExpressionContainsBoundScopedMethod(argument, names) {
				return true
			}
		}
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			switch item := element.(type) {
			case *ast.KeyValueExpr:
				if l8D2ReadinessExpressionContainsBoundScopedMethod(item.Value, names) {
					return true
				}
			case ast.Expr:
				if l8D2ReadinessExpressionContainsBoundScopedMethod(item, names) {
					return true
				}
			}
		}
	}
	return false
}

func l8D2ReadinessCallCarriesScoped(call *ast.CallExpr, names map[string]bool) bool {
	if call == nil {
		return false
	}
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok && l8D2ReadinessExpressionCarriesScoped(selector.X, names) {
		return true
	}
	for _, argument := range call.Args {
		if l8D2ReadinessExpressionCarriesScoped(argument, names) {
			return true
		}
	}
	return false
}

func l8D2ReadinessApprovedScopedWrapper(function *ast.FuncDecl, expression ast.Expr, definitions map[string]l8D2ReadinessTypeDefinition) bool {
	if function == nil || function.Name.Name != "WriteCanonicalBody" || function.Recv == nil || types.ExprString(function.Recv.List[0].Type) != "SendPacket" {
		return false
	}
	address, ok := expression.(*ast.UnaryExpr)
	if !ok || address.Op != token.AND {
		return false
	}
	literal, ok := address.X.(*ast.CompositeLit)
	if !ok || types.ExprString(literal.Type) != "exactForwardingSink" {
		return false
	}
	definition := definitions["exactForwardingSink"]
	structure, ok := definition.expression.(*ast.StructType)
	if !ok {
		return false
	}
	want := []string{"mu:sync.Mutex", "ctx:context.Context", "target:credentialmemory.CredentialSink", "expected:int", "calls:int", "valid:bool", "err:error"}
	var got []string
	for _, field := range structure.Fields.List {
		if len(field.Names) != 1 {
			return false
		}
		got = append(got, field.Names[0].Name+":"+types.ExprString(field.Type))
	}
	return strings.Join(got, ",") == strings.Join(want, ",")
}

func l8D2ReadinessAllowedDynamicScopedCall(function *ast.FuncDecl, call *ast.CallExpr, names, contextParams, shadowedScopedHelpers map[string]bool, aliases map[string]string, definitions map[string]l8D2ReadinessTypeDefinition, functionsByName map[string][]*ast.FuncDecl) bool {
	if call == nil {
		return false
	}
	for _, argument := range call.Args {
		if l8D2ReadinessExpressionContainsBoundScopedMethod(argument, names) {
			return false
		}
	}
	switch called := call.Fun.(type) {
	case *ast.Ident:
		switch called.Name {
		case "configuredDependency", "typedNil", "isNilCoreDependency", "destroyTransportBody", "withCanonicalScratch":
			return !shadowedScopedHelpers[called.Name] && l8D2ReadinessExactScopedHelperDeclaration(functionsByName[called.Name], called.Name, aliases, definitions)
		}
		return l8D2ReadinessExactBorrowCallbackInvocation(function, called.Name, call, names, aliases)
	case *ast.SelectorExpr:
		receiverScoped := l8D2ReadinessExpressionCarriesScoped(called.X, names)
		if receiverScoped {
			kind := l8D2ReadinessExactScopedReceiverKind(function, called.X, aliases, definitions, make(map[string]bool))
			if kind == "view" {
				switch called.Sel.Name {
				case "Len":
					return len(call.Args) == 0
				case "WriteTo", "CopyTo":
					return len(call.Args) == 2 && l8D2ReadinessExactContextArgument(call.Args[0], contextParams)
				}
			}
			if kind == "sink" {
				switch called.Sel.Name {
				case "MaxCredentialBytes":
					return len(call.Args) == 0
				case "WriteCredential":
					return len(call.Args) == 1
				}
			}
			return false
		}
		if called.Sel.Name == "Borrow" && len(call.Args) == 2 && l8D2ReadinessExactContextArgument(call.Args[0], contextParams) && l8D2ReadinessExactReceivedBodyExpression(function, called.X, definitions) {
			_, callback := call.Args[1].(*ast.FuncLit)
			return callback
		}
		if called.Sel.Name == "WriteTo" && len(call.Args) == 2 && l8D2ReadinessExactContextArgument(call.Args[0], contextParams) && l8D2ReadinessExactAuditedTransportWrite(function, called.X, call.Args[1], names) {
			return true
		}
		if called.Sel.Name == "ValueOf" && len(call.Args) == 1 && function.Name.Name == "isNilCoreDependency" {
			owner, ok := called.X.(*ast.Ident)
			return ok && aliases[owner.Name] == "reflect" && l8D2ReadinessExactScopedReceiverKind(function, call.Args[0], aliases, definitions, make(map[string]bool)) == "sink" && !shadowedScopedHelpers["isNilCoreDependency"] && l8D2ReadinessExactScopedHelperDeclaration(functionsByName["isNilCoreDependency"], "isNilCoreDependency", aliases, definitions)
		}
		if called.Sel.Name == "ProposeObservedStdin" && len(call.Args) == 4 {
			return l8D2ReadinessExactTransactionReceiver(function, called.X, aliases) && l8D2ReadinessExactContextArgument(call.Args[0], contextParams) && l8D2ReadinessExpressionCarriesScoped(call.Args[3], names)
		}
		serviceReceiver := l8D2ReadinessReceiverName(function)
		if called.Sel.Name == "BeginExec" && types.ExprString(called.X) == serviceReceiver+".core" && len(call.Args) == 3 {
			return l8D2ReadinessExactContextArgument(call.Args[0], contextParams) && l8D2ReadinessExpressionCarriesScoped(call.Args[2], names)
		}
		if called.Sel.Name == "WriteStdin" && types.ExprString(called.X) == serviceReceiver+".state.execution" && len(call.Args) == 4 {
			return l8D2ReadinessExactContextArgument(call.Args[0], contextParams) && l8D2ReadinessExpressionCarriesScoped(call.Args[1], names)
		}
	}
	return false
}

func l8D2ReadinessExactAuditedTransportWrite(function *ast.FuncDecl, receiver, sink ast.Expr, names map[string]bool) bool {
	if function == nil || function.Body == nil {
		return false
	}
	receiverText := types.ExprString(receiver)
	switch function.Name.Name {
	case "WriteTo":
		receiverName := l8D2ReadinessAnyReceiverName(function)
		if function.Recv == nil || types.ExprString(function.Recv.List[0].Type) != "borrowedPayloadView" || receiverText != receiverName+".owner" {
			return false
		}
		address, ok := sink.(*ast.UnaryExpr)
		literal, literalOK := func() (*ast.CompositeLit, bool) {
			if !ok || address.Op != token.AND {
				return nil, false
			}
			value, valid := address.X.(*ast.CompositeLit)
			return value, valid
		}()
		if !literalOK || types.ExprString(literal.Type) != "payloadSlicingSink" {
			return false
		}
		fields := l8D2ReadinessExactCompositeFields(literal, "payloadSlicingSink", false)
		return len(fields) == 5 && types.ExprString(fields["ctx"]) == "ctx" && types.ExprString(fields["sink"]) == "sink" && types.ExprString(fields["canonicalLength"]) == receiverName+".canonicalLength" && types.ExprString(fields["offset"]) == receiverName+".offset" && types.ExprString(fields["length"]) == receiverName+".length"
	case "validSendExecStreamArm":
		if receiverText != "view" || !names["view"] {
			return false
		}
		identifier, ok := sink.(*ast.Ident)
		if !ok || identifier.Name != "sink" {
			return false
		}
		expression, unique := l8D2ReadinessUniqueLocalExpressionBefore(function.Body, "sink", sink.Pos())
		if !unique {
			return false
		}
		literal, literalOK := expression.(*ast.UnaryExpr)
		if !literalOK || literal.Op != token.AND {
			return false
		}
		composite, ok := literal.X.(*ast.CompositeLit)
		return ok && types.ExprString(composite.Type) == "bodyValidationSink"
	}
	return false
}

func l8D2ReadinessExactContextArgument(expression ast.Expr, contextParams map[string]bool) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && contextParams[identifier.Name]
}

func l8D2ReadinessExactTransactionReceiver(function *ast.FuncDecl, expression ast.Expr, aliases map[string]string) bool {
	identifier, ok := expression.(*ast.Ident)
	if !ok || function == nil || function.Type.Params == nil {
		return false
	}
	for _, field := range function.Type.Params.List {
		if !l8D2ReadinessExactImportedType(field.Type, aliases, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol", "HelperExecTransaction", true) {
			continue
		}
		for _, name := range field.Names {
			if name.Name == identifier.Name {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessExactBorrowCallbackInvocation(function *ast.FuncDecl, called string, call *ast.CallExpr, names map[string]bool, aliases map[string]string) bool {
	if function == nil || function.Recv == nil || function.Name.Name != "Borrow" || len(call.Args) != 1 || !l8D2ReadinessExpressionCarriesScoped(call.Args[0], names) {
		return false
	}
	receiverType := types.ExprString(function.Recv.List[0].Type)
	if receiverType != "receivedPayloadBody" {
		return false
	}
	if function.Type.Params == nil {
		return false
	}
	for _, field := range function.Type.Params.List {
		callbackType, ok := field.Type.(*ast.FuncType)
		if !ok || callbackType.Params == nil || len(callbackType.Params.List) != 1 || !l8D2ReadinessExactImportedType(callbackType.Params.List[0].Type, aliases, "github.com/jywlabs/hal/internal/credentialmemory", "BorrowedView", false) {
			continue
		}
		for _, name := range field.Names {
			if name.Name == called {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessExactScopedHelperDeclaration(functions []*ast.FuncDecl, name string, aliases map[string]string, definitions map[string]l8D2ReadinessTypeDefinition) bool {
	if len(functions) != 1 || functions[0].Recv != nil || functions[0].Name.Name != name {
		return false
	}
	function := functions[0]
	parameters := l8D2ReadinessNamedParameters(function)
	switch name {
	case "configuredDependency", "typedNil":
		return len(parameters) == 1 && types.ExprString(parameters[0].typ) == "any"
	case "isNilCoreDependency":
		return len(parameters) == 1 && l8D2ReadinessExactImportedType(parameters[0].typ, aliases, "github.com/jywlabs/hal/internal/credentialmemory", "CredentialSink", false) && l8D2ReadinessExactTypedNilHelperBody(function, parameters[0].name, aliases)
	case "destroyTransportBody":
		return len(parameters) == 2 && l8D2ReadinessExactImportedType(parameters[0].typ, aliases, "context", "Context", false) && types.ExprString(parameters[1].typ) == "ReceivedBodyCapability"
	case "withCanonicalScratch":
		if len(parameters) != 3 || types.ExprString(parameters[0].typ) != "sendPacketArm" || types.ExprString(parameters[1].typ) != "uint32" {
			return false
		}
		callback, ok := parameters[2].typ.(*ast.FuncType)
		return ok && callback.Params != nil && len(callback.Params.List) == 1 && types.ExprString(callback.Params.List[0].Type) == "[]byte"
	}
	_ = definitions
	return false
}

func l8D2ReadinessExactTypedNilHelperBody(function *ast.FuncDecl, parameter string, aliases map[string]string) bool {
	if function == nil || function.Body == nil || function.Type.Results == nil || len(function.Type.Results.List) != 1 || types.ExprString(function.Type.Results.List[0].Type) != "bool" || len(function.Body.List) != 3 {
		return false
	}
	nilGate, ok := function.Body.List[0].(*ast.IfStmt)
	if !ok || nilGate.Init != nil || nilGate.Else != nil || types.ExprString(nilGate.Cond) != parameter+" == nil" || len(nilGate.Body.List) != 1 || !l8D2ReadinessExactSingleBooleanReturn(nilGate.Body.List[0], true) {
		return false
	}
	assignment, ok := function.Body.List[1].(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	reflected, ok := assignment.Lhs[0].(*ast.Ident)
	call, callOK := assignment.Rhs[0].(*ast.CallExpr)
	selector, selectorOK := func() (*ast.SelectorExpr, bool) {
		if !callOK {
			return nil, false
		}
		value, valid := call.Fun.(*ast.SelectorExpr)
		return value, valid
	}()
	owner, ownerOK := func() (*ast.Ident, bool) {
		if !selectorOK {
			return nil, false
		}
		value, valid := selector.X.(*ast.Ident)
		return value, valid
	}()
	if !ok || !ownerOK || aliases[owner.Name] != "reflect" || selector.Sel.Name != "ValueOf" || len(call.Args) != 1 || types.ExprString(call.Args[0]) != parameter {
		return false
	}
	classified, ok := function.Body.List[2].(*ast.SwitchStmt)
	if !ok || classified.Init != nil || len(classified.Body.List) != 2 {
		return false
	}
	kindCall, ok := classified.Tag.(*ast.CallExpr)
	kindSelector, selectorOK := func() (*ast.SelectorExpr, bool) {
		if !ok {
			return nil, false
		}
		value, valid := kindCall.Fun.(*ast.SelectorExpr)
		return value, valid
	}()
	if !selectorOK || types.ExprString(kindSelector.X) != reflected.Name || kindSelector.Sel.Name != "Kind" || len(kindCall.Args) != 0 {
		return false
	}
	nilKinds := map[string]bool{"reflect.Chan": true, "reflect.Func": true, "reflect.Interface": true, "reflect.Map": true, "reflect.Pointer": true, "reflect.Slice": true}
	seenKinds := make(map[string]bool)
	for index, rawClause := range classified.Body.List {
		clause, valid := rawClause.(*ast.CaseClause)
		if !valid || len(clause.Body) != 1 {
			return false
		}
		if index == 0 {
			for _, expression := range clause.List {
				name := types.ExprString(expression)
				if !nilKinds[name] || seenKinds[name] {
					return false
				}
				seenKinds[name] = true
			}
			returned, direct := clause.Body[0].(*ast.ReturnStmt)
			if !direct || len(returned.Results) != 1 || types.ExprString(returned.Results[0]) != reflected.Name+".IsNil()" {
				return false
			}
			continue
		}
		if clause.List != nil || !l8D2ReadinessExactSingleBooleanReturn(clause.Body[0], false) {
			return false
		}
	}
	return len(seenKinds) == len(nilKinds)
}

func l8D2ReadinessExactSingleBooleanReturn(statement ast.Stmt, want bool) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	identifier, ok := returned.Results[0].(*ast.Ident)
	return ok && identifier.Name == map[bool]string{true: "true", false: "false"}[want]
}

func l8D2ReadinessExactReceivedBodyExpression(function *ast.FuncDecl, expression ast.Expr, definitions map[string]l8D2ReadinessTypeDefinition) bool {
	if identifier, ok := expression.(*ast.Ident); ok {
		if function != nil && function.Type.Params != nil {
			for _, field := range function.Type.Params.List {
				if types.ExprString(field.Type) != "ReceivedBodyCapability" && types.ExprString(field.Type) != "CoreOutputBody" {
					continue
				}
				for _, name := range field.Names {
					if name.Name == identifier.Name {
						return true
					}
				}
			}
		}
		return false
	}
	selector, ok := expression.(*ast.SelectorExpr)
	owner, ownerOK := func() (*ast.Ident, bool) {
		if !ok {
			return nil, false
		}
		identifier, valid := selector.X.(*ast.Ident)
		return identifier, valid
	}()
	if !ownerOK {
		return false
	}
	typeName := ""
	if function != nil && function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				if name.Name == owner.Name {
					typeName = strings.TrimPrefix(types.ExprString(field.Type), "*")
				}
			}
		}
	}
	if function != nil && function.Recv != nil && len(function.Recv.List) == 1 && len(function.Recv.List[0].Names) == 1 && function.Recv.List[0].Names[0].Name == owner.Name {
		typeName = strings.TrimPrefix(types.ExprString(function.Recv.List[0].Type), "*")
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if typeName != "" {
			return false
		}
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for index, left := range assignment.Lhs {
			identifier, direct := left.(*ast.Ident)
			if !direct || identifier.Name != owner.Name || index >= len(assignment.Rhs) {
				continue
			}
			assertion, asserted := assignment.Rhs[index].(*ast.TypeAssertExpr)
			if asserted {
				typeName = types.ExprString(assertion.Type)
			}
		}
		return true
	})
	definition, exists := definitions[typeName]
	structure, structural := definition.expression.(*ast.StructType)
	if !exists || !structural {
		return false
	}
	for _, field := range structure.Fields.List {
		for _, name := range field.Names {
			if name.Name == selector.Sel.Name && (types.ExprString(field.Type) == "ReceivedBodyCapability" || types.ExprString(field.Type) == "CoreOutputBody") {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessTypeParameters(fields *ast.FieldList) map[string]ast.Expr {
	typeParameters := make(map[string]ast.Expr)
	if fields == nil {
		return typeParameters
	}
	for _, field := range fields.List {
		for _, name := range field.Names {
			typeParameters[name.Name] = field.Type
		}
	}
	return typeParameters
}

func l8D2ReadinessImportAliases(file *ast.File) (map[string]string, bool) {
	aliases := make(map[string]string)
	dotImport := false
	for _, imported := range file.Imports {
		importPath := strings.Trim(imported.Path.Value, `"`)
		localName := filepath.Base(importPath)
		if imported.Name != nil {
			localName = imported.Name.Name
		}
		if importPath == "github.com/jywlabs/hal/internal/credentialmemory" && localName == "." {
			dotImport = true
			continue
		}
		aliases[localName] = importPath
	}
	return aliases, dotImport
}

func l8D2ReadinessTypeRetainsScoped(expression ast.Expr, aliases map[string]string, dotImport bool, typeParameters map[string]ast.Expr, definitions map[string]l8D2ReadinessTypeDefinition, stack map[string]bool) bool {
	if expression == nil {
		return false
	}
	switch typed := expression.(type) {
	case *ast.SelectorExpr:
		owner, ok := typed.X.(*ast.Ident)
		return ok && aliases[owner.Name] == "github.com/jywlabs/hal/internal/credentialmemory" && (typed.Sel.Name == "BorrowedView" || typed.Sel.Name == "CredentialSink")
	case *ast.Ident:
		if dotImport && (typed.Name == "BorrowedView" || typed.Name == "CredentialSink") {
			return true
		}
		if constraint, ok := typeParameters[typed.Name]; ok {
			return l8D2ReadinessTypeRetainsScoped(constraint, aliases, dotImport, nil, definitions, stack)
		}
		definition, ok := definitions[typed.Name]
		if !ok || stack[typed.Name] {
			return false
		}
		stack[typed.Name] = true
		retained := l8D2ReadinessTypeRetainsScoped(definition.expression, definition.aliases, definition.dotImport, definition.typeParameters, definitions, stack)
		delete(stack, typed.Name)
		return retained
	case *ast.StarExpr:
		return l8D2ReadinessTypeRetainsScoped(typed.X, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.ArrayType:
		return l8D2ReadinessTypeRetainsScoped(typed.Elt, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.Ellipsis:
		return l8D2ReadinessTypeRetainsScoped(typed.Elt, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.MapType:
		return l8D2ReadinessTypeRetainsScoped(typed.Key, aliases, dotImport, typeParameters, definitions, stack) || l8D2ReadinessTypeRetainsScoped(typed.Value, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.ChanType:
		return l8D2ReadinessTypeRetainsScoped(typed.Value, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.ParenExpr:
		return l8D2ReadinessTypeRetainsScoped(typed.X, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.UnaryExpr:
		return l8D2ReadinessTypeRetainsScoped(typed.X, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.BinaryExpr:
		return l8D2ReadinessTypeRetainsScoped(typed.X, aliases, dotImport, typeParameters, definitions, stack) || l8D2ReadinessTypeRetainsScoped(typed.Y, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.IndexExpr:
		return l8D2ReadinessTypeRetainsScoped(typed.X, aliases, dotImport, typeParameters, definitions, stack) || l8D2ReadinessTypeRetainsScoped(typed.Index, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.IndexListExpr:
		if l8D2ReadinessTypeRetainsScoped(typed.X, aliases, dotImport, typeParameters, definitions, stack) {
			return true
		}
		for _, index := range typed.Indices {
			if l8D2ReadinessTypeRetainsScoped(index, aliases, dotImport, typeParameters, definitions, stack) {
				return true
			}
		}
	case *ast.StructType:
		return l8D2ReadinessFieldListRetainsScoped(typed.Fields, aliases, dotImport, typeParameters, definitions, stack)
	case *ast.InterfaceType:
		if typed.Methods == nil {
			return false
		}
		for _, method := range typed.Methods.List {
			if l8D2ReadinessTypeRetainsScoped(method.Type, aliases, dotImport, typeParameters, definitions, stack) {
				return true
			}
		}
	case *ast.FuncType:
		// Reaching a function type here means the function value itself is retained
		// by a struct field (possibly through a named/aliased/container type). Any
		// scoped input or result in that retained call channel is forbidden. Top-
		// level function and method declarations are never roots of this walk, so
		// their ordinary scoped parameters remain allowed.
		return l8D2ReadinessFieldListRetainsScoped(typed.Params, aliases, dotImport, typeParameters, definitions, stack) ||
			l8D2ReadinessFieldListRetainsScoped(typed.Results, aliases, dotImport, typeParameters, definitions, stack)
	}
	return false
}

func l8D2ReadinessFieldListRetainsScoped(fields *ast.FieldList, aliases map[string]string, dotImport bool, typeParameters map[string]ast.Expr, definitions map[string]l8D2ReadinessTypeDefinition, stack map[string]bool) bool {
	if fields == nil {
		return false
	}
	for _, field := range fields.List {
		if l8D2ReadinessTypeRetainsScoped(field.Type, aliases, dotImport, typeParameters, definitions, stack) {
			return true
		}
	}
	return false
}

func assertL8D2ReadinessObservationReflectBoundary(t *testing.T, protocolDir string) {
	t.Helper()
	observationPath := filepath.Join(protocolDir, "helper_exec_transaction_observation.go")
	content, err := os.ReadFile(observationPath)
	if err != nil {
		// The exact-file absence is already intentional red evidence.
		return
	}
	file, err := parser.ParseFile(token.NewFileSet(), observationPath, content, 0)
	if err != nil {
		t.Errorf("parse observation reflection boundary: %v", err)
		return
	}
	aliases, _ := l8D2ReadinessImportAliases(file)
	reflectName := ""
	for name, importPath := range aliases {
		if importPath == "reflect" {
			reflectName = name
		}
	}
	if reflectName == "" {
		t.Error("observation file omits exact reflect import for arbitrary typed-nil detection")
	}

	foundHelper, foundValueOf, foundKind, foundIsNil := false, false, false, false
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		insideHelper := function.Name.Name == "helperExecConfiguredDependencyNil"
		if insideHelper {
			foundHelper = true
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == reflectName {
				if !insideHelper {
					t.Errorf("reflect.%s occurs outside helperExecConfiguredDependencyNil", selector.Sel.Name)
				}
				allowed := map[string]bool{"ValueOf": true, "Chan": true, "Func": true, "Interface": true, "Map": true, "Pointer": true, "Slice": true}
				if !allowed[selector.Sel.Name] {
					t.Errorf("typed-nil helper uses unexpected reflect selector %s", selector.Sel.Name)
				}
				if selector.Sel.Name == "ValueOf" {
					foundValueOf = true
				}
			}
			if selector.Sel.Name == "Kind" || selector.Sel.Name == "IsNil" {
				if !insideHelper {
					t.Errorf("reflection method %s occurs outside helperExecConfiguredDependencyNil", selector.Sel.Name)
				}
				foundKind = foundKind || selector.Sel.Name == "Kind"
				foundIsNil = foundIsNil || selector.Sel.Name == "IsNil"
			}
			return true
		})
	}
	if !foundHelper || !foundValueOf || !foundKind || !foundIsNil {
		t.Errorf("typed-nil reflection helper markers = helper:%t ValueOf:%t Kind:%t IsNil:%t", foundHelper, foundValueOf, foundKind, foundIsNil)
	}
	text := string(content)
	for _, required := range []string{"reflect.Chan", "reflect.Func", "reflect.Interface", "reflect.Map", "reflect.Pointer", "reflect.Slice"} {
		if !strings.Contains(text, required) {
			t.Errorf("typed-nil helper omits nil-capable kind %s", required)
		}
	}
	for _, forbidden := range []string{"reflect.TypeOf(", ".Type()", ".String()", "fmt.Errorf(", "fmt.Fprintf(", "fmt.Sprintf(", "fmt.Sprint(", "%T"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("observation file contains forbidden dynamic reflection/formatting marker %q", forbidden)
		}
	}

	entries, err := os.ReadDir(protocolDir)
	if err != nil {
		t.Error(err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") || entry.Name() == filepath.Base(observationPath) {
			continue
		}
		other, err := parser.ParseFile(token.NewFileSet(), filepath.Join(protocolDir, entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parse imports in %s: %v", entry.Name(), err)
			continue
		}
		otherAliases, _ := l8D2ReadinessImportAliases(other)
		for _, importPath := range otherAliases {
			if importPath == "reflect" {
				t.Errorf("credentialprotocol production %s imports reflect outside observation file", entry.Name())
			}
		}
	}
}

func assertL8D2ReadinessObservationConstantTimeBoundary(t *testing.T, protocolDir string) {
	t.Helper()
	type functionRequirement struct {
		receiver string
		name     string
		calls    map[string]int
	}
	requirements := []functionRequirement{
		{name: "NewHelperExecPrivateObservation", calls: map[string]int{"helperExecDigestsEqual": 1}},
		{name: "NewHelperExecStreamObservation", calls: map[string]int{"helperExecDigestsEqual": 1}},
		{receiver: "*HelperExecTransaction", name: "ProposeObservedPrivate", calls: map[string]int{"helperExecTransactionCorrelationEqual": 1, "helperExecDigestsEqual": 1}},
		{receiver: "*HelperExecTransaction", name: "ProposeObservedStdin", calls: map[string]int{"helperExecTransactionCorrelationEqual": 1, "helperExecDigestsEqual": 1}},
		{name: "helperExecTransactionCorrelationEqual", calls: map[string]int{"subtle.ConstantTimeCompare": 2}},
		{name: "helperExecDigestsEqual", calls: map[string]int{"subtle.ConstantTimeCompare": 1}},
	}

	packages, err := parser.ParseDir(token.NewFileSet(), protocolDir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[string]bool)
	functions := make(map[string]*ast.FuncDecl)
	aliasesByFunction := make(map[*ast.FuncDecl]map[string]string)
	var declarations []*ast.FuncDecl
	var packageDeclarations []ast.Decl
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			packageDeclarations = append(packageDeclarations, file.Decls...)
			aliases, _ := l8D2ReadinessImportAliases(file)
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				receiver := ""
				if function.Recv != nil && len(function.Recv.List) == 1 {
					receiver = types.ExprString(function.Recv.List[0].Type)
				}
				functions[receiver+function.Name.Name] = function
				aliasesByFunction[function] = aliases
				declarations = append(declarations, function)
				for _, requirement := range requirements {
					if receiver != requirement.receiver || function.Name.Name != requirement.name {
						continue
					}
					key := requirement.receiver + requirement.name
					found[key] = true
					counts := make(map[string]int)
					ast.Inspect(function.Body, func(node ast.Node) bool {
						call, ok := node.(*ast.CallExpr)
						if !ok {
							return true
						}
						if name := l8D2ReadinessCanonicalCallName(call.Fun, aliases); name != "" {
							counts[name]++
						}
						return true
					})
					for call, minimum := range requirement.calls {
						if counts[call] < minimum {
							t.Errorf("%s%s has %d direct %s calls, want at least %d", requirement.receiver, requirement.name, counts[call], call, minimum)
						}
					}
				}
			}
		}
	}
	for _, requirement := range requirements {
		key := requirement.receiver + requirement.name
		if !found[key] {
			t.Errorf("missing constant-time guarded function %s%s", requirement.receiver, requirement.name)
		}
	}
	if function := functions["helperExecDigestsEqual"]; function != nil && !l8D2ReadinessExactDigestHelperReturn(function, aliasesByFunction[function]) {
		t.Error("helperExecDigestsEqual must return the exact subtle.ConstantTimeCompare result")
	}
	if function := functions["helperExecTransactionCorrelationEqual"]; function != nil && !l8D2ReadinessExactCorrelationHelperReturn(function, aliasesByFunction[function]) {
		t.Error("helperExecTransactionCorrelationEqual must return two exact subtle comparisons plus revision equality")
	}
	for _, gate := range []struct {
		key, helper string
	}{
		{key: "NewHelperExecPrivateObservation", helper: "helperExecDigestsEqual"},
		{key: "NewHelperExecStreamObservation", helper: "helperExecDigestsEqual"},
		{key: "*HelperExecTransactionProposeObservedPrivate", helper: "helperExecTransactionCorrelationEqual"},
		{key: "*HelperExecTransactionProposeObservedPrivate", helper: "helperExecDigestsEqual"},
		{key: "*HelperExecTransactionProposeObservedStdin", helper: "helperExecTransactionCorrelationEqual"},
		{key: "*HelperExecTransactionProposeObservedStdin", helper: "helperExecDigestsEqual"},
	} {
		if function := functions[gate.key]; function != nil && !l8D2ReadinessEveryHelperCallControlsRejection(function, gate.helper, 1) {
			t.Errorf("%s must consume every %s result in a controlling rejection", gate.key, gate.helper)
		}
	}
	for _, key := range []string{"NewHelperExecPrivateObservation", "NewHelperExecStreamObservation", "*HelperExecTransactionProposeObservedPrivate", "*HelperExecTransactionProposeObservedStdin"} {
		if function := functions[key]; function != nil && !l8D2ReadinessExactObservationHelperOperands(function, functions, l8D2ReadinessTerminalEnvironment{declarations: declarations, aliases: aliasesByFunction, constants: l8D2ReadinessDeclaredConstants(packageDeclarations), namedTypes: l8D2ReadinessDeclaredNamedTypes(packageDeclarations)}) {
			t.Errorf("%s must bind constant-time helpers to the exact declared/observed or supplied/owner/current-view operands", key)
		}
	}
}

func l8D2ReadinessExactDigestHelperReturn(function *ast.FuncDecl, aliases map[string]string) bool {
	if function == nil || function.Type.Params == nil || len(function.Type.Params.List) != 1 || len(function.Type.Params.List[0].Names) != 2 || len(function.Body.List) != 1 {
		return false
	}
	left, right := function.Type.Params.List[0].Names[0].Name, function.Type.Params.List[0].Names[1].Name
	returned, ok := function.Body.List[0].(*ast.ReturnStmt)
	return ok && len(returned.Results) == 1 && l8D2ReadinessExactSubtleCompare(returned.Results[0], aliases, left, right)
}

func l8D2ReadinessExactCorrelationHelperReturn(function *ast.FuncDecl, aliases map[string]string) bool {
	if function == nil || function.Type.Params == nil || len(function.Type.Params.List) != 1 || len(function.Type.Params.List[0].Names) != 2 || len(function.Body.List) != 1 {
		return false
	}
	left, right := function.Type.Params.List[0].Names[0].Name, function.Type.Params.List[0].Names[1].Name
	returned, ok := function.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	terms := l8D2ReadinessAndTerms(returned.Results[0])
	if len(terms) != 3 {
		return false
	}
	want := map[string]bool{"requestID": false, "identityDigest": false}
	revision := false
	for _, term := range terms {
		matched := false
		for field := range want {
			if l8D2ReadinessExactSubtleCompare(term, aliases, left+"."+field, right+"."+field) {
				if want[field] {
					return false
				}
				want[field] = true
				matched = true
			}
		}
		if l8D2ReadinessExactEquality(term, left+".revision", right+".revision") {
			if revision {
				return false
			}
			revision = true
			matched = true
		}
		if !matched {
			return false
		}
	}
	return want["requestID"] && want["identityDigest"] && revision
}

func l8D2ReadinessAndTerms(expression ast.Expr) []ast.Expr {
	if parenthesized, ok := expression.(*ast.ParenExpr); ok {
		return l8D2ReadinessAndTerms(parenthesized.X)
	}
	if binary, ok := expression.(*ast.BinaryExpr); ok && binary.Op == token.LAND {
		return append(l8D2ReadinessAndTerms(binary.X), l8D2ReadinessAndTerms(binary.Y)...)
	}
	return []ast.Expr{expression}
}

func l8D2ReadinessExactSubtleCompare(expression ast.Expr, aliases map[string]string, left, right string) bool {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			break
		}
		expression = parenthesized.X
	}
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != token.EQL || types.ExprString(binary.Y) != "1" {
		return false
	}
	call, ok := binary.X.(*ast.CallExpr)
	return ok && l8D2ReadinessCanonicalCallName(call.Fun, aliases) == "subtle.ConstantTimeCompare" && len(call.Args) == 2 && types.ExprString(call.Args[0]) == left+"[:]" && types.ExprString(call.Args[1]) == right+"[:]"
}

func l8D2ReadinessExactEquality(expression ast.Expr, left, right string) bool {
	binary, ok := expression.(*ast.BinaryExpr)
	return ok && binary.Op == token.EQL && ((types.ExprString(binary.X) == left && types.ExprString(binary.Y) == right) || (types.ExprString(binary.X) == right && types.ExprString(binary.Y) == left))
}

func l8D2ReadinessEveryHelperCallControlsRejection(function *ast.FuncDecl, helper string, minimum int) bool {
	if function == nil || function.Body == nil {
		return false
	}
	protected := map[string]bool{helper: true}
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				if name.Name == helper {
					return false
				}
			}
		}
	}
	if l8D2ReadinessBodyRebindsNames(function.Body, protected, nil) {
		return false
	}
	total, controlled := 0, 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && l8D2ReadinessExactNamedCall(call, helper) {
			total++
		}
		return true
	})
	direct := l8D2ReadinessDirectStatements(function.Body)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		gate, ok := node.(*ast.IfStmt)
		if !ok || !direct[gate] || gate.Init != nil || gate.Else != nil || len(gate.Body.List) == 0 {
			return true
		}
		returned, ok := gate.Body.List[len(gate.Body.List)-1].(*ast.ReturnStmt)
		if !ok || len(returned.Results) == 0 || l8D2ReadinessNilIdentifier(returned.Results[len(returned.Results)-1]) {
			return true
		}
		for _, term := range l8D2ReadinessOrTerms(gate.Cond) {
			for {
				parenthesized, ok := term.(*ast.ParenExpr)
				if !ok {
					break
				}
				term = parenthesized.X
			}
			negated, ok := term.(*ast.UnaryExpr)
			if !ok || negated.Op != token.NOT {
				continue
			}
			call, ok := negated.X.(*ast.CallExpr)
			if ok && l8D2ReadinessExactNamedCall(call, helper) {
				controlled++
			}
		}
		return true
	})
	return total >= minimum && total == controlled
}

func l8D2ReadinessHelperCallsUseExactParamPair(function *ast.FuncDecl, helper string) bool {
	parameters := l8D2ReadinessFunctionParameterNames(function)
	if len(parameters) < 2 {
		return false
	}
	return l8D2ReadinessEveryNamedHelperCallMatches(function, helper, func(call *ast.CallExpr, _ map[string]ast.Expr) bool {
		return len(call.Args) == 2 && types.ExprString(call.Args[0]) == parameters[0] && types.ExprString(call.Args[1]) == parameters[1]
	})
}

type l8D2ReadinessTerminalEnvironment struct {
	declarations       []*ast.FuncDecl
	aliases            map[*ast.FuncDecl]map[string]string
	functionFiles      map[*ast.FuncDecl]*ast.File
	constants          map[string]constant.Value
	namedTypes         map[string][]l8D2ReadinessNamedType
	globals            map[string]bool
	expectedConstants  map[string][]l8D2ReadinessExpectedConstantDeclaration
	packageIntShadowed bool
	fileIntShadowed    map[*ast.File]bool
}

type l8D2ReadinessExpectedConstantDeclaration struct {
	file         *ast.File
	group        *ast.GenDecl
	values       *ast.ValueSpec
	packageScope bool
}

type l8D2ReadinessNamedType struct {
	parameters []string
	underlying ast.Expr
}

func l8D2ReadinessExactObservationHelperOperands(function *ast.FuncDecl, functions map[string]*ast.FuncDecl, terminal l8D2ReadinessTerminalEnvironment) bool {
	if function == nil {
		return false
	}
	parameters := l8D2ReadinessFunctionParameterNames(function)
	receiver := l8D2ReadinessAnyReceiverName(function)
	switch function.Name.Name {
	case "NewHelperExecPrivateObservation":
		return len(parameters) == 4 && l8D2ReadinessEveryNamedHelperCallMatches(function, "helperExecDigestsEqual", func(call *ast.CallExpr, _ map[string]ast.Expr) bool {
			return l8D2ReadinessExactCallArgumentStrings(call, parameters[2], parameters[3])
		}) && l8D2ReadinessExactIssuedObservation(function, parameters, false)
	case "NewHelperExecStreamObservation":
		return len(parameters) == 7 && l8D2ReadinessEveryNamedHelperCallMatches(function, "helperExecDigestsEqual", func(call *ast.CallExpr, _ map[string]ast.Expr) bool {
			return l8D2ReadinessExactCallArgumentStrings(call, parameters[5], parameters[6])
		}) && l8D2ReadinessExactIssuedObservation(function, parameters, true)
	case "ProposeObservedPrivate":
		if len(parameters) != 2 {
			return false
		}
		correlationOK := l8D2ReadinessEveryNamedHelperCallMatches(function, "helperExecTransactionCorrelationEqual", func(call *ast.CallExpr, aliases map[string]ast.Expr) bool {
			return l8D2ReadinessExactExpandedCallArguments(call, aliases, parameters[0], receiver+".owner.correlation")
		})
		digestOK := l8D2ReadinessEveryNamedHelperCallMatches(function, "helperExecDigestsEqual", func(call *ast.CallExpr, aliases map[string]ast.Expr) bool {
			return l8D2ReadinessExactExpandedCallArguments(call, aliases, parameters[1]+".owner.privateSHA256", receiver+".owner.privateSHA")
		})
		return correlationOK && digestOK && l8D2ReadinessExactIssuedObservedProposal(function, parameters, receiver, false, functions, terminal)
	case "ProposeObservedStdin":
		if len(parameters) != 4 {
			return false
		}
		correlationOK := l8D2ReadinessEveryNamedHelperCallMatches(function, "helperExecTransactionCorrelationEqual", func(call *ast.CallExpr, aliases map[string]ast.Expr) bool {
			return l8D2ReadinessExactExpandedCallArguments(call, aliases, parameters[1], receiver+".owner.correlation")
		})
		digestOK := l8D2ReadinessEveryNamedHelperCallMatches(function, "helperExecDigestsEqual", func(call *ast.CallExpr, aliases map[string]ast.Expr) bool {
			if len(call.Args) != 2 || l8D2ReadinessExpandedExpression(call.Args[0], aliases) != parameters[2]+".owner.payloadSHA256" {
				return false
			}
			return l8D2ReadinessDigestComesFromExactBorrowedView(function, call.Args[1], parameters[0], parameters[3], aliases)
		})
		return correlationOK && digestOK && l8D2ReadinessExactIssuedObservedProposal(function, parameters, receiver, true, functions, terminal)
	}
	return false
}

func l8D2ReadinessExactIssuedObservation(function *ast.FuncDecl, parameters []string, stream bool) bool {
	boundary := l8D2ReadinessLastNamedCallEnd(function, "helperExecDigestsEqual")
	if boundary == token.NoPos || !l8D2ReadinessAuthorityInputsImmutableAfter(function, boundary, parameters, "", false) || !l8D2ReadinessNoAuthorityAssignmentEscape(function, boundary, nil, parameters) {
		return false
	}
	returned, expression := l8D2ReadinessSuccessfulAuthorityReturn(function)
	if returned == nil {
		return false
	}
	outerType, ownerType := "HelperExecPrivateObservation", "helperExecPrivateObservationOwner"
	want := map[string]string{"revision": parameters[0], "privateLength": parameters[1], "privateSHA256": parameters[2]}
	if stream {
		outerType, ownerType = "HelperExecStreamObservation", "helperExecStreamObservationOwner"
		want = map[string]string{"revision": parameters[0], "streamKind": parameters[1], "flags": parameters[2], "offset": parameters[3], "payloadLength": parameters[4], "payloadSHA256": parameters[5]}
	}
	outer := l8D2ReadinessExactCompositeFields(expression, outerType, false)
	owner := l8D2ReadinessExactCompositeFields(outer["owner"], ownerType, true)
	if outer == nil || len(outer) != 1 || owner == nil || len(owner) != len(want) || returned.Pos() <= boundary {
		return false
	}
	for field, value := range want {
		if types.ExprString(owner[field]) != value {
			return false
		}
	}
	return true
}

func l8D2ReadinessExactIssuedObservedProposal(function *ast.FuncDecl, parameters []string, receiver string, stdin bool, functions map[string]*ast.FuncDecl, terminal l8D2ReadinessTerminalEnvironment) bool {
	fail := func(string) bool { return false }
	verifiedObservedHelpers := !stdin || l8D2ReadinessExactObservedStdinHelperImplementations(terminal.declarations)
	if !verifiedObservedHelpers {
		return fail("observed helper implementations")
	}
	boundary := l8D2ReadinessLastNamedCallEnd(function, "helperExecDigestsEqual")
	correlationBoundary := l8D2ReadinessLastNamedCallEnd(function, "helperExecTransactionCorrelationEqual")
	correlationParameter := parameters[0]
	if stdin {
		correlationParameter = parameters[1]
	}
	if correlationBoundary == token.NoPos || !l8D2ReadinessAuthorityExpressionsImmutableAfter(function, correlationBoundary, []string{correlationParameter, receiver + ".owner.correlation"}, verifiedObservedHelpers) {
		return fail("correlation immutable")
	}
	if correlationBoundary > boundary {
		boundary = correlationBoundary
	}
	if boundary == token.NoPos || !l8D2ReadinessAuthorityInputsImmutableAfter(function, boundary, parameters, receiver+".owner.pending", verifiedObservedHelpers) {
		return fail("inputs immutable")
	}
	returned, expression := l8D2ReadinessSuccessfulAuthorityReturn(function)
	if returned == nil || returned.Pos() <= boundary {
		return fail("return")
	}
	outer := l8D2ReadinessExactCompositeFields(expression, "HelperExecPayloadProposal", true)
	if outer == nil || len(outer) != 1 {
		return fail("outer")
	}
	proposalName, ok := outer["owner"].(*ast.Ident)
	if !ok {
		return fail("proposal name")
	}
	proposalExpression, proposalStatement, ok := l8D2ReadinessUniqueDirectLocalExpression(function.Body, proposalName.Name, boundary, returned.Pos())
	if !ok || proposalExpression.Pos() <= boundary || !l8D2ReadinessAuthorityExpressionsImmutableAfter(function, proposalExpression.Pos(), []string{proposalName.Name}, verifiedObservedHelpers) {
		return fail("proposal expression")
	}
	proposal := l8D2ReadinessExactCompositeFields(proposalExpression, "helperExecPayloadProposalOwner", true)
	if proposal == nil || types.ExprString(proposal["transaction"]) != receiver+".owner" || types.ExprString(proposal["source"]) != "helperExecProposalSourceObserved" || types.ExprString(proposal["observedReady"]) != "true" {
		return fail("proposal fields")
	}
	observation := parameters[1]
	want := map[string]string{
		"kind":   "helperExecProposalPrivate",
		"length": observation + ".owner.privateLength",
		"sha256": observation + ".owner.privateSHA256",
	}
	if stdin {
		observation = parameters[2]
		want = map[string]string{
			"kind":                    "helperExecProposalStdin",
			"flags":                   observation + ".owner.flags",
			"offset":                  observation + ".owner.offset",
			"length":                  observation + ".owner.payloadLength",
			"sha256":                  observation + ".owner.payloadSHA256",
			"candidateStdinHash":      "candidateStdinHash",
			"candidateTranscriptHash": "candidateTranscriptHash",
			"candidateStdinOffset":    "candidateStdinOffset",
			"candidateStdinBytes":     "candidateStdinBytes",
			"candidateStdinRecords":   "candidateStdinRecords",
			"candidateStdinEOF":       "candidateStdinEOF",
		}
	}
	if len(proposal) != len(want)+3 {
		return fail("proposal length")
	}
	for field, value := range want {
		if types.ExprString(proposal[field]) != value {
			return fail("want field")
		}
	}
	if stdin && !l8D2ReadinessExactStdinCandidateOrigins(function, proposalExpression.Pos(), receiver, parameters[2], parameters[3]) {
		return fail("stdin origins")
	}
	pending := 0
	var pendingStatement ast.Stmt
	for _, statement := range function.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if ok && assignment.Pos() > proposalExpression.Pos() && assignment.Pos() < returned.Pos() && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 && types.ExprString(assignment.Lhs[0]) == receiver+".owner.pending" && types.ExprString(assignment.Rhs[0]) == proposalName.Name {
			pending++
			pendingStatement = statement
		}
	}
	totalPending := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if ok {
			for _, left := range assignment.Lhs {
				if types.ExprString(left) == receiver+".owner.pending" {
					totalPending++
				}
			}
		}
		return true
	})
	protected := append(append([]string(nil), parameters...), receiver, proposalName.Name)
	if stdin {
		protected = append(protected, "candidateStdinHash", "candidateTranscriptHash", "candidateStdinOffset", "candidateStdinBytes", "candidateStdinRecords", "candidateStdinEOF")
	}
	allowed := map[ast.Stmt]bool{proposalStatement: true, pendingStatement: true}
	return pending == 1 && totalPending == 1 && proposalStatement.Pos() < pendingStatement.Pos() && pendingStatement.Pos() < returned.Pos() && l8D2ReadinessPendingImmediatelyDominatesLiveSuccess(function, pendingStatement, returned, terminal) && l8D2ReadinessNoAuthorityAssignmentEscape(function, boundary, allowed, protected)
}

func l8D2ReadinessPendingImmediatelyDominatesLiveSuccess(function *ast.FuncDecl, pending ast.Stmt, success *ast.ReturnStmt, terminal l8D2ReadinessTerminalEnvironment) bool {
	if function == nil || function.Body == nil || pending == nil || success == nil {
		return false
	}
	body := function.Body
	terminalFunctions := l8D2ReadinessPackageTerminalFunctions(terminal)
	terminalAliases := l8D2ReadinessTerminalCallableAliases(function, terminalFunctions, terminal, nil)
	pendingIndex, successIndex := -1, -1
	for index, statement := range body.List {
		if statement == pending {
			pendingIndex = index
		}
		if statement == success {
			successIndex = index
			break
		}
		if l8D2ReadinessStatementAlwaysTerminates(function, statement, terminalAliases, terminalFunctions, terminal) {
			return false
		}
	}
	return pendingIndex >= 0 && successIndex == pendingIndex+1
}

type l8D2ReadinessTerminalFacts struct {
	neverReturns      map[string]bool
	returnsStop       map[string]bool
	terminalParameter map[string]map[int]bool
	returnedWrappers  map[string]map[string]bool
}

func l8D2ReadinessPackageTerminalFunctions(environment l8D2ReadinessTerminalEnvironment) l8D2ReadinessTerminalFacts {
	facts := l8D2ReadinessTerminalFacts{
		neverReturns:      make(map[string]bool),
		returnsStop:       make(map[string]bool),
		terminalParameter: make(map[string]map[int]bool),
		returnedWrappers:  make(map[string]map[string]bool),
	}
	for identity := range l8D2ReadinessExactRecursiveTerminalCycles(environment) {
		facts.neverReturns[identity] = true
	}
	for changed := true; changed; {
		changed = false
		for _, function := range environment.declarations {
			if function == nil || function.Body == nil {
				continue
			}
			identity := l8D2ReadinessFunctionIdentity(function)
			aliases := l8D2ReadinessTerminalCallableAliases(function, facts, environment, nil)
			if !facts.neverReturns[identity] && l8D2ReadinessBlockNeverReturns(function, function.Body, aliases, facts, environment) {
				facts.neverReturns[identity] = true
				changed = true
			}
			if !facts.returnsStop[identity] && l8D2ReadinessFunctionReturnsTerminalCallable(function, aliases, facts, environment) {
				facts.returnsStop[identity] = true
				changed = true
			}
			for index, parameter := range l8D2ReadinessFunctionParameterNames(function) {
				if facts.terminalParameter[identity] != nil && facts.terminalParameter[identity][index] {
					continue
				}
				seeded := l8D2ReadinessTerminalCallableAliases(function, facts, environment, map[string]bool{parameter: true})
				if !l8D2ReadinessBlockNeverReturns(function, function.Body, seeded, facts, environment) {
					continue
				}
				if facts.terminalParameter[identity] == nil {
					facts.terminalParameter[identity] = make(map[int]bool)
				}
				facts.terminalParameter[identity][index] = true
				changed = true
			}
			returnedWrappers := l8D2ReadinessFunctionReturnedWrapperIdentities(function, facts, environment)
			if facts.returnedWrappers[identity] == nil && len(returnedWrappers) != 0 {
				facts.returnedWrappers[identity] = make(map[string]bool)
			}
			for wrapper := range returnedWrappers {
				if !facts.returnedWrappers[identity][wrapper] {
					facts.returnedWrappers[identity][wrapper] = true
					changed = true
				}
			}
		}
	}
	return facts
}

func l8D2ReadinessFunctionIdentity(function *ast.FuncDecl) string {
	if function == nil || function.Name == nil {
		return ""
	}
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return function.Name.Name
	}
	receiver := strings.TrimPrefix(types.ExprString(function.Recv.List[0].Type), "*")
	return receiver + "." + function.Name.Name
}

func l8D2ReadinessExactLocalCallIdentity(function *ast.FuncDecl, expression ast.Expr) string {
	for {
		switch wrapped := expression.(type) {
		case *ast.ParenExpr:
			expression = wrapped.X
			continue
		case *ast.IndexExpr:
			expression = wrapped.X
			continue
		case *ast.IndexListExpr:
			expression = wrapped.X
			continue
		default:
			break
		}
		break
	}
	switch called := expression.(type) {
	case *ast.Ident:
		return called.Name
	case *ast.SelectorExpr:
		receiverType := l8D2ReadinessTerminalReceiverType(function, called.X)
		if receiverType != "" {
			return receiverType + "." + called.Sel.Name
		}
	}
	return ""
}

func l8D2ReadinessExactTerminalSelectorIdentity(function *ast.FuncDecl, selector *ast.SelectorExpr, environment l8D2ReadinessTerminalEnvironment) string {
	if function == nil || selector == nil {
		return ""
	}
	if owner, ok := selector.X.(*ast.Ident); ok && !l8D2ReadinessNameShadowedInFunction(function, owner.Name) {
		importPath := environment.aliases[function][owner.Name]
		switch {
		case importPath == "runtime" && selector.Sel.Name == "Goexit":
			return "runtime.Goexit"
		case importPath == "os" && selector.Sel.Name == "Exit":
			return "os.Exit"
		}
	}
	receiverType := l8D2ReadinessTerminalReceiverType(function, selector.X)
	if separator := strings.IndexByte(receiverType, '.'); separator > 0 && receiverType[separator+1:] == "T" && environment.aliases[function][receiverType[:separator]] == "testing" {
		switch selector.Sel.Name {
		case "FailNow", "Fatal", "Fatalf", "Skip", "Skipf", "SkipNow":
			return "testing." + selector.Sel.Name
		}
	}
	if receiverType != "" {
		return receiverType + "." + selector.Sel.Name
	}
	return ""
}

func l8D2ReadinessTerminalReceiverType(function *ast.FuncDecl, expression ast.Expr) string {
	for {
		switch value := expression.(type) {
		case *ast.ParenExpr:
			expression = value.X
			continue
		case *ast.StarExpr:
			expression = value.X
			continue
		case *ast.UnaryExpr:
			if value.Op == token.AND {
				expression = value.X
				continue
			}
		}
		break
	}
	if composite, ok := expression.(*ast.CompositeLit); ok {
		return strings.TrimPrefix(types.ExprString(composite.Type), "*")
	}
	identifier, ok := expression.(*ast.Ident)
	if !ok || function == nil {
		return ""
	}
	fieldType := func(fields *ast.FieldList) string {
		if fields == nil {
			return ""
		}
		for _, field := range fields.List {
			for _, name := range field.Names {
				if name.Name == identifier.Name {
					return strings.TrimPrefix(types.ExprString(field.Type), "*")
				}
			}
		}
		return ""
	}
	if result := fieldType(function.Recv); result != "" {
		return result
	}
	if result := fieldType(function.Type.Params); result != "" {
		return result
	}
	if function.Body != nil {
		result := ""
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if result != "" {
				return false
			}
			switch declaration := node.(type) {
			case *ast.AssignStmt:
				for index, left := range declaration.Lhs {
					name, direct := left.(*ast.Ident)
					if !direct || name.Name != identifier.Name || index >= len(declaration.Rhs) {
						continue
					}
					if composite, direct := declaration.Rhs[index].(*ast.CompositeLit); direct {
						result = strings.TrimPrefix(types.ExprString(composite.Type), "*")
					}
				}
			case *ast.ValueSpec:
				for index, name := range declaration.Names {
					if name.Name != identifier.Name {
						continue
					}
					if declaration.Type != nil {
						result = strings.TrimPrefix(types.ExprString(declaration.Type), "*")
					} else if index < len(declaration.Values) {
						if composite, direct := declaration.Values[index].(*ast.CompositeLit); direct {
							result = strings.TrimPrefix(types.ExprString(composite.Type), "*")
						}
					}
				}
			}
			return true
		})
		if result != "" {
			return result
		}
	}
	return ""
}

func l8D2ReadinessExactRecursiveTerminalCycles(environment l8D2ReadinessTerminalEnvironment) map[string]bool {
	known := make(map[string]bool)
	for _, declaration := range environment.declarations {
		known[l8D2ReadinessFunctionIdentity(declaration)] = true
	}
	edges := make(map[string][]string)
	for _, function := range environment.declarations {
		if function == nil || function.Body == nil || len(function.Body.List) != 1 {
			continue
		}
		expression, ok := function.Body.List[0].(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, callOK := expression.X.(*ast.CallExpr)
		if !callOK || len(call.Args) != 0 {
			continue
		}
		identity := l8D2ReadinessExactLocalCallIdentity(function, call.Fun)
		if known[identity] {
			from := l8D2ReadinessFunctionIdentity(function)
			edges[from] = append(edges[from], identity)
		}
	}
	terminal := make(map[string]bool)
	var visit func(string, []string, map[string]int)
	visit = func(current string, path []string, positions map[string]int) {
		if index, seen := positions[current]; seen {
			for _, identity := range path[index:] {
				terminal[identity] = true
			}
			return
		}
		positions[current] = len(path)
		path = append(path, current)
		for _, next := range edges[current] {
			visit(next, path, positions)
		}
		delete(positions, current)
	}
	for start := range edges {
		visit(start, nil, make(map[string]int))
	}
	return terminal
}

func l8D2ReadinessFunctionReturnsTerminalCallable(function *ast.FuncDecl, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if function == nil || function.Body == nil {
		return false
	}
	for _, statement := range function.Body.List {
		returned, ok := statement.(*ast.ReturnStmt)
		if !ok || len(returned.Results) != 1 {
			continue
		}
		if l8D2ReadinessTerminalCallableExpression(function, returned.Results[0], aliases, facts, environment) {
			return true
		}
	}
	return false
}

func l8D2ReadinessTerminalCallableAliases(function *ast.FuncDecl, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment, seeds map[string]bool) map[string]bool {
	aliases := make(map[string]bool)
	for name := range seeds {
		aliases[name] = true
	}
	if function == nil || function.Body == nil {
		return aliases
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.AssignStmt:
				for index, left := range value.Lhs {
					identifier, ok := left.(*ast.Ident)
					if !ok || identifier.Name == "_" || aliases[identifier.Name] {
						continue
					}
					var right ast.Expr
					if index < len(value.Rhs) {
						right = value.Rhs[index]
					} else if len(value.Rhs) == 1 {
						right = value.Rhs[0]
					}
					if l8D2ReadinessTerminalCallableExpression(function, right, aliases, facts, environment) {
						aliases[identifier.Name] = true
						changed = true
					}
				}
			case *ast.ValueSpec:
				for index, name := range value.Names {
					if name.Name == "_" || aliases[name.Name] {
						continue
					}
					var expression ast.Expr
					if index < len(value.Values) {
						expression = value.Values[index]
					} else if len(value.Values) == 1 {
						expression = value.Values[0]
					}
					if l8D2ReadinessTerminalCallableExpression(function, expression, aliases, facts, environment) {
						aliases[name.Name] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	return aliases
}

func l8D2ReadinessTerminalCallableExpression(function *ast.FuncDecl, expression ast.Expr, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name == "panic" || aliases[value.Name] || facts.neverReturns[value.Name]
	case *ast.SelectorExpr:
		identity := l8D2ReadinessExactTerminalSelectorIdentity(function, value, environment)
		return identity == "runtime.Goexit" || identity == "os.Exit" || identity == "testing.FailNow" || identity == "testing.Fatal" || identity == "testing.Fatalf" || identity == "testing.Skip" || identity == "testing.Skipf" || identity == "testing.SkipNow" || facts.neverReturns[identity] || l8D2ReadinessTerminalCallableExpression(function, value.X, aliases, facts, environment)
	case *ast.FuncLit:
		return l8D2ReadinessBlockNeverReturns(function, value.Body, aliases, facts, environment)
	case *ast.ParenExpr:
		return l8D2ReadinessTerminalCallableExpression(function, value.X, aliases, facts, environment)
	case *ast.TypeAssertExpr:
		return l8D2ReadinessTerminalCallableExpression(function, value.X, aliases, facts, environment)
	case *ast.IndexExpr:
		return l8D2ReadinessTerminalCallableExpression(function, value.X, aliases, facts, environment) || l8D2ReadinessTerminalCallableExpression(function, value.Index, aliases, facts, environment)
	case *ast.IndexListExpr:
		if l8D2ReadinessTerminalCallableExpression(function, value.X, aliases, facts, environment) {
			return true
		}
		for _, index := range value.Indices {
			if l8D2ReadinessTerminalCallableExpression(function, index, aliases, facts, environment) {
				return true
			}
		}
	case *ast.SliceExpr:
		return l8D2ReadinessTerminalCallableExpression(function, value.X, aliases, facts, environment) || l8D2ReadinessTerminalCallableExpression(function, value.Low, aliases, facts, environment) || l8D2ReadinessTerminalCallableExpression(function, value.High, aliases, facts, environment) || l8D2ReadinessTerminalCallableExpression(function, value.Max, aliases, facts, environment)
	case *ast.UnaryExpr:
		return l8D2ReadinessTerminalCallableExpression(function, value.X, aliases, facts, environment)
	case *ast.StarExpr:
		return l8D2ReadinessTerminalCallableExpression(function, value.X, aliases, facts, environment)
	case *ast.BinaryExpr:
		return l8D2ReadinessTerminalCallableExpression(function, value.X, aliases, facts, environment) || l8D2ReadinessTerminalCallableExpression(function, value.Y, aliases, facts, environment)
	case *ast.KeyValueExpr:
		return l8D2ReadinessTerminalCallableExpression(function, value.Key, aliases, facts, environment) || l8D2ReadinessTerminalCallableExpression(function, value.Value, aliases, facts, environment)
	case *ast.Ellipsis:
		return l8D2ReadinessTerminalCallableExpression(function, value.Elt, aliases, facts, environment)
	case *ast.CallExpr:
		identity := l8D2ReadinessExactLocalCallIdentity(function, value.Fun)
		if facts.returnsStop[identity] || l8D2ReadinessTerminalCallableExpression(function, value.Fun, aliases, facts, environment) {
			return true
		}
		for _, argument := range value.Args {
			if l8D2ReadinessTerminalCallableExpression(function, argument, aliases, facts, environment) {
				return true
			}
		}
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			switch item := element.(type) {
			case *ast.KeyValueExpr:
				if l8D2ReadinessTerminalCallableExpression(function, item.Value, aliases, facts, environment) {
					return true
				}
			case ast.Expr:
				if l8D2ReadinessTerminalCallableExpression(function, item, aliases, facts, environment) {
					return true
				}
			}
		}
	}
	return false
}

func l8D2ReadinessFunctionReturnedWrapperIdentities(function *ast.FuncDecl, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) map[string]bool {
	result := make(map[string]bool)
	if function == nil || function.Body == nil {
		return result
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		returned, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		aliases := l8D2ReadinessWrapperIdentityAliases(function, facts, environment, returned.Pos())
		for _, expression := range returned.Results {
			for identity := range l8D2ReadinessWrapperIdentities(function, expression, aliases, facts, environment) {
				if len(facts.terminalParameter[identity]) != 0 {
					result[identity] = true
				}
			}
		}
		return false
	})
	return result
}

func l8D2ReadinessConstantExpression(expression ast.Expr, values map[string]constant.Value) (result constant.Value, ok bool) {
	defer func() {
		if recover() != nil {
			result, ok = nil, false
		}
	}()
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return l8D2ReadinessConstantExpression(value.X, values)
	case *ast.BasicLit:
		result := constant.MakeFromLiteral(value.Value, value.Kind, 0)
		return result, result.Kind() != constant.Unknown
	case *ast.Ident:
		if result, exists := values[value.Name]; exists {
			return result, result != nil && result.Kind() != constant.Unknown
		}
		if value.Name == "true" {
			return constant.MakeBool(true), true
		}
		if value.Name == "false" {
			return constant.MakeBool(false), true
		}
		return nil, false
	case *ast.CallExpr:
		name, named := value.Fun.(*ast.Ident)
		if !named || len(value.Args) != 1 {
			return nil, false
		}
		if shadow, exists := values[name.Name]; exists && shadow != nil && shadow.Kind() == constant.Unknown {
			return nil, false
		}
		operand, exact := l8D2ReadinessConstantExpression(value.Args[0], values)
		if !exact {
			return nil, false
		}
		return l8D2ReadinessConvertConstant(operand, name.Name)
	case *ast.UnaryExpr:
		operand, exact := l8D2ReadinessConstantExpression(value.X, values)
		if !exact || (value.Op != token.ADD && value.Op != token.SUB && value.Op != token.XOR) {
			return nil, false
		}
		return constant.UnaryOp(value.Op, operand, 0), true
	case *ast.BinaryExpr:
		left, leftExact := l8D2ReadinessConstantExpression(value.X, values)
		right, rightExact := l8D2ReadinessConstantExpression(value.Y, values)
		if !leftExact || !rightExact {
			return nil, false
		}
		switch value.Op {
		case token.SHL, token.SHR:
			shift, exact := constant.Uint64Val(right)
			if !exact {
				return nil, false
			}
			return constant.Shift(left, value.Op, uint(shift)), true
		case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.AND_NOT:
			return constant.BinaryOp(left, value.Op, right), true
		}
	}
	return nil, false
}

func l8D2ReadinessDeclaredConstants(declarations []ast.Decl) map[string]constant.Value {
	values := make(map[string]constant.Value)
	groups := make([]*ast.GenDecl, 0)
	constantCount := 0
	for _, declaration := range declarations {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		groups = append(groups, group)
		l8D2ReadinessMarkConstantGroupNames(values, group)
		for _, specification := range group.Specs {
			if item, ok := specification.(*ast.ValueSpec); ok {
				constantCount += len(item.Names)
			}
		}
	}
	for pass := 0; pass <= constantCount; pass++ {
		changed := false
		for _, group := range groups {
			changed = l8D2ReadinessApplyConstantGroup(values, group) || changed
		}
		if !changed {
			break
		}
	}
	return values
}

func l8D2ReadinessDeclaredNamedTypes(declarations []ast.Decl) map[string][]l8D2ReadinessNamedType {
	result := make(map[string][]l8D2ReadinessNamedType)
	for _, declaration := range declarations {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.TYPE {
			continue
		}
		for _, raw := range group.Specs {
			specification, ok := raw.(*ast.TypeSpec)
			if !ok {
				continue
			}
			var parameters []string
			if specification.TypeParams != nil {
				for _, field := range specification.TypeParams.List {
					for _, name := range field.Names {
						parameters = append(parameters, name.Name)
					}
				}
			}
			result[specification.Name.Name] = append(result[specification.Name.Name], l8D2ReadinessNamedType{parameters: parameters, underlying: specification.Type})
		}
	}
	return result
}

func l8D2ReadinessApplyNamedTypeGroup(typesByName map[string][]l8D2ReadinessNamedType, group *ast.GenDecl) {
	if group == nil || group.Tok != token.TYPE {
		return
	}
	for _, raw := range group.Specs {
		specification, ok := raw.(*ast.TypeSpec)
		if !ok {
			continue
		}
		var parameters []string
		if specification.TypeParams != nil {
			for _, field := range specification.TypeParams.List {
				for _, name := range field.Names {
					parameters = append(parameters, name.Name)
				}
			}
		}
		typesByName[specification.Name.Name] = []l8D2ReadinessNamedType{{parameters: parameters, underlying: specification.Type}}
	}
}

func l8D2ReadinessWrapperNamedTypes(function *ast.FuncDecl, position token.Pos, environment l8D2ReadinessTerminalEnvironment) map[string][]l8D2ReadinessNamedType {
	result := make(map[string][]l8D2ReadinessNamedType, len(environment.namedTypes))
	for name, declarations := range environment.namedTypes {
		result[name] = append([]l8D2ReadinessNamedType(nil), declarations...)
	}
	if function == nil || function.Body == nil {
		return result
	}
	removeFields := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, field := range fields.List {
			for _, name := range field.Names {
				delete(result, name.Name)
			}
		}
	}
	removeFields(function.Recv)
	removeFields(function.Type.Params)
	removeFields(function.Type.Results)
	removeFields(function.Type.TypeParams)
	removeExpressions := func(expressions []ast.Expr) {
		for _, expression := range expressions {
			if name, ok := expression.(*ast.Ident); ok && name.Name != "_" {
				delete(result, name.Name)
			}
		}
	}
	apply := func(statement ast.Stmt) {
		switch item := statement.(type) {
		case *ast.AssignStmt:
			if item.Tok == token.DEFINE {
				removeExpressions(item.Lhs)
			}
			return
		case *ast.DeclStmt:
			group, ok := item.Decl.(*ast.GenDecl)
			if !ok {
				return
			}
			if group.Tok == token.TYPE {
				l8D2ReadinessApplyNamedTypeGroup(result, group)
				return
			}
			for _, raw := range group.Specs {
				if specification, ok := raw.(*ast.ValueSpec); ok {
					for _, name := range specification.Names {
						delete(result, name.Name)
					}
				}
			}
			return
		}
	}
	contains := func(node ast.Node) bool {
		return node != nil && node.Pos() <= position && position <= node.End()
	}
	var walkBlock func(*ast.BlockStmt)
	var walkStatements func([]ast.Stmt)
	var walkStatement func(ast.Stmt)
	enterFunctionLiteral := func(node ast.Node) bool {
		var literal *ast.FuncLit
		ast.Inspect(node, func(candidate ast.Node) bool {
			if literal != nil || candidate == nil || !contains(candidate) {
				return false
			}
			if item, ok := candidate.(*ast.FuncLit); ok {
				literal = item
				return false
			}
			return true
		})
		if literal == nil {
			return false
		}
		removeFields(literal.Type.Params)
		removeFields(literal.Type.Results)
		removeFields(literal.Type.TypeParams)
		walkBlock(literal.Body)
		return true
	}
	walkStatements = func(statements []ast.Stmt) {
		for _, statement := range statements {
			if statement.End() < position {
				apply(statement)
				continue
			}
			if contains(statement) {
				walkStatement(statement)
			}
			return
		}
	}
	walkBlock = func(block *ast.BlockStmt) {
		if contains(block) {
			walkStatements(block.List)
		}
	}
	walkStatement = func(statement ast.Stmt) {
		switch item := statement.(type) {
		case *ast.BlockStmt:
			walkBlock(item)
		case *ast.LabeledStmt:
			walkStatement(item.Stmt)
		case *ast.IfStmt:
			if item.Init != nil {
				if contains(item.Init) {
					walkStatement(item.Init)
					return
				}
				if item.Init.End() < position {
					apply(item.Init)
				}
			}
			if contains(item.Cond) {
				enterFunctionLiteral(item.Cond)
				return
			}
			if contains(item.Body) {
				walkBlock(item.Body)
				return
			}
			if item.Else != nil && contains(item.Else) {
				walkStatement(item.Else)
			}
		case *ast.ForStmt:
			if item.Init != nil {
				if contains(item.Init) {
					walkStatement(item.Init)
					return
				}
				if item.Init.End() < position {
					apply(item.Init)
				}
			}
			if contains(item.Cond) {
				enterFunctionLiteral(item.Cond)
				return
			}
			if contains(item.Post) {
				walkStatement(item.Post)
				return
			}
			walkBlock(item.Body)
		case *ast.RangeStmt:
			if contains(item.X) {
				enterFunctionLiteral(item.X)
				return
			}
			if contains(item.Body) {
				if item.Tok == token.DEFINE {
					removeExpressions([]ast.Expr{item.Key, item.Value})
				}
				walkBlock(item.Body)
			}
		case *ast.SwitchStmt:
			if item.Init != nil {
				if contains(item.Init) {
					walkStatement(item.Init)
					return
				}
				if item.Init.End() < position {
					apply(item.Init)
				}
			}
			if contains(item.Tag) {
				enterFunctionLiteral(item.Tag)
				return
			}
			for _, raw := range item.Body.List {
				clause, ok := raw.(*ast.CaseClause)
				if !ok || !contains(clause) {
					continue
				}
				for _, expression := range clause.List {
					if contains(expression) {
						enterFunctionLiteral(expression)
						return
					}
				}
				walkStatements(clause.Body)
				return
			}
		case *ast.TypeSwitchStmt:
			if item.Init != nil {
				if contains(item.Init) {
					walkStatement(item.Init)
					return
				}
				if item.Init.End() < position {
					apply(item.Init)
				}
			}
			if contains(item.Assign) {
				walkStatement(item.Assign)
				return
			}
			for _, raw := range item.Body.List {
				clause, ok := raw.(*ast.CaseClause)
				if !ok || !contains(clause) {
					continue
				}
				for _, expression := range clause.List {
					if contains(expression) {
						enterFunctionLiteral(expression)
						return
					}
				}
				if assignment, ok := item.Assign.(*ast.AssignStmt); ok && assignment.Tok == token.DEFINE {
					removeExpressions(assignment.Lhs)
				}
				walkStatements(clause.Body)
				return
			}
		case *ast.SelectStmt:
			for _, raw := range item.Body.List {
				clause, ok := raw.(*ast.CommClause)
				if !ok || !contains(clause) {
					continue
				}
				if clause.Comm != nil && contains(clause.Comm) {
					walkStatement(clause.Comm)
					return
				}
				if assignment, ok := clause.Comm.(*ast.AssignStmt); ok && assignment.Tok == token.DEFINE {
					removeExpressions(assignment.Lhs)
				}
				walkStatements(clause.Body)
				return
			}
		default:
			enterFunctionLiteral(statement)
		}
	}
	walkBlock(function.Body)
	return result
}

func l8D2ReadinessMarkConstantGroupNames(values map[string]constant.Value, group *ast.GenDecl) {
	if group == nil || group.Tok != token.CONST {
		return
	}
	for _, specification := range group.Specs {
		if item, ok := specification.(*ast.ValueSpec); ok {
			for _, name := range item.Names {
				values[name.Name] = constant.MakeUnknown()
			}
		}
	}
}

func l8D2ReadinessConstantValuesEqual(left, right constant.Value) bool {
	if left == nil || right == nil || left.Kind() != right.Kind() {
		return false
	}
	if left.Kind() == constant.Unknown {
		return true
	}
	return left.ExactString() == right.ExactString()
}

func l8D2ReadinessApplyConstantGroup(values map[string]constant.Value, group *ast.GenDecl) bool {
	if group == nil || group.Tok != token.CONST {
		return false
	}
	changed := false
	var inherited []ast.Expr
	for specificationIndex, specification := range group.Specs {
		item, ok := specification.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if len(item.Values) != 0 {
			inherited = item.Values
		}
		scope := make(map[string]constant.Value, len(values)+1)
		for name, value := range values {
			scope[name] = value
		}
		scope["iota"] = constant.MakeInt64(int64(specificationIndex))
		for index, name := range item.Names {
			if index >= len(inherited) {
				continue
			}
			value, exact := l8D2ReadinessConstantExpression(inherited[index], scope)
			if exact && item.Type != nil {
				value, exact = l8D2ReadinessConvertConstantToTypeExpression(value, item.Type)
			}
			if exact {
				if !l8D2ReadinessConstantValuesEqual(values[name.Name], value) {
					changed = true
				}
				values[name.Name] = value
				scope[name.Name] = value
			}
		}
	}
	return changed
}

func l8D2ReadinessConvertConstantToTypeExpression(value constant.Value, expression ast.Expr) (constant.Value, bool) {
	for {
		switch item := expression.(type) {
		case *ast.ParenExpr:
			expression = item.X
			continue
		case *ast.Ident:
			return l8D2ReadinessConvertConstant(value, item.Name)
		}
		return nil, false
	}
}

func l8D2ReadinessConvertConstant(value constant.Value, target string) (constant.Value, bool) {
	if value == nil || value.Kind() == constant.Unknown {
		return nil, false
	}
	signed := func(bits uint) (constant.Value, bool) {
		integer := constant.ToInt(value)
		if integer.Kind() == constant.Unknown {
			return nil, false
		}
		number, exact := constant.Int64Val(integer)
		if !exact || (bits < 64 && (number < -(int64(1)<<(bits-1)) || number > (int64(1)<<(bits-1))-1)) {
			return nil, false
		}
		return constant.MakeInt64(number), true
	}
	unsigned := func(bits uint) (constant.Value, bool) {
		integer := constant.ToInt(value)
		if integer.Kind() == constant.Unknown {
			return nil, false
		}
		number, exact := constant.Uint64Val(integer)
		if !exact || (bits < 64 && number > (uint64(1)<<bits)-1) {
			return nil, false
		}
		return constant.MakeUint64(number), true
	}
	switch target {
	case "string":
		if value.Kind() == constant.String {
			return value, true
		}
		integer := constant.ToInt(value)
		if integer.Kind() == constant.Unknown {
			return nil, false
		}
		number, exact := constant.Int64Val(integer)
		if !exact {
			return nil, false
		}
		return constant.MakeString(string(rune(number))), true
	case "bool":
		return value, value.Kind() == constant.Bool
	case "int8":
		return signed(8)
	case "int16":
		return signed(16)
	case "int32", "rune":
		return signed(32)
	case "int", "int64":
		return signed(64)
	case "uint8", "byte":
		return unsigned(8)
	case "uint16":
		return unsigned(16)
	case "uint32":
		return unsigned(32)
	case "uint", "uint64", "uintptr":
		return unsigned(64)
	case "float32":
		number, _ := constant.Float32Val(value)
		if math.IsInf(float64(number), 0) {
			return nil, false
		}
		return constant.MakeFloat64(float64(number)), true
	case "float64":
		number, _ := constant.Float64Val(value)
		if math.IsInf(number, 0) {
			return nil, false
		}
		return constant.MakeFloat64(number), true
	case "complex64", "complex128":
		complexValue := constant.ToComplex(value)
		if complexValue.Kind() == constant.Unknown {
			return nil, false
		}
		realValue, imaginaryValue := constant.Real(complexValue), constant.Imag(complexValue)
		var realNumber, imaginaryNumber float64
		if target == "complex64" {
			realPart, _ := constant.Float32Val(realValue)
			imaginaryPart, _ := constant.Float32Val(imaginaryValue)
			realNumber, imaginaryNumber = float64(realPart), float64(imaginaryPart)
		} else {
			realNumber, _ = constant.Float64Val(realValue)
			imaginaryNumber, _ = constant.Float64Val(imaginaryValue)
		}
		if math.IsInf(realNumber, 0) || math.IsInf(imaginaryNumber, 0) {
			return nil, false
		}
		return constant.BinaryOp(constant.MakeFloat64(realNumber), token.ADD, constant.MakeImag(constant.MakeFloat64(imaginaryNumber))), true
	}
	return nil, false
}

func l8D2ReadinessRemoveFieldConstants(values map[string]constant.Value, fields *ast.FieldList) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		for _, name := range field.Names {
			values[name.Name] = constant.MakeUnknown()
		}
	}
}

func l8D2ReadinessApplyCompletedBinding(statement ast.Stmt, values map[string]constant.Value) {
	switch item := statement.(type) {
	case *ast.DeclStmt:
		group, ok := item.Decl.(*ast.GenDecl)
		if !ok {
			return
		}
		if group.Tok == token.CONST {
			l8D2ReadinessMarkConstantGroupNames(values, group)
			for pass := 0; pass <= len(group.Specs); pass++ {
				if !l8D2ReadinessApplyConstantGroup(values, group) {
					break
				}
			}
			return
		}
		for _, specification := range group.Specs {
			if declared, ok := specification.(*ast.ValueSpec); ok {
				for _, name := range declared.Names {
					values[name.Name] = constant.MakeUnknown()
				}
			}
		}
	case *ast.AssignStmt:
		if item.Tok != token.DEFINE {
			return
		}
		for _, expression := range item.Lhs {
			if name, ok := expression.(*ast.Ident); ok {
				values[name.Name] = constant.MakeUnknown()
			}
		}
	}
}

func l8D2ReadinessApplyContainingBindings(statement ast.Stmt, position token.Pos, values map[string]constant.Value) {
	applyBefore := func(candidate ast.Stmt) {
		if candidate != nil && candidate.End() < position {
			l8D2ReadinessApplyCompletedBinding(candidate, values)
		}
	}
	switch item := statement.(type) {
	case *ast.IfStmt:
		applyBefore(item.Init)
	case *ast.ForStmt:
		applyBefore(item.Init)
	case *ast.RangeStmt:
		if item.Tok == token.DEFINE {
			for _, expression := range []ast.Expr{item.Key, item.Value} {
				if name, ok := expression.(*ast.Ident); ok {
					values[name.Name] = constant.MakeUnknown()
				}
			}
		}
	case *ast.SwitchStmt:
		applyBefore(item.Init)
	case *ast.TypeSwitchStmt:
		applyBefore(item.Init)
		applyBefore(item.Assign)
	}
}

func l8D2ReadinessWrapperConstantValues(function *ast.FuncDecl, position token.Pos, environment l8D2ReadinessTerminalEnvironment) map[string]constant.Value {
	values := make(map[string]constant.Value, len(environment.constants))
	for name, value := range environment.constants {
		values[name] = value
	}
	if function == nil || function.Body == nil {
		return values
	}
	l8D2ReadinessRemoveFieldConstants(values, function.Recv)
	l8D2ReadinessRemoveFieldConstants(values, function.Type.Params)
	l8D2ReadinessRemoveFieldConstants(values, function.Type.Results)
	var blocks []*ast.BlockStmt
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if block, ok := node.(*ast.BlockStmt); ok && block.Pos() <= position && position <= block.End() {
			blocks = append(blocks, block)
		}
		return true
	})
	sort.Slice(blocks, func(left, right int) bool {
		if blocks[left].Pos() != blocks[right].Pos() {
			return blocks[left].Pos() < blocks[right].Pos()
		}
		return blocks[left].End() > blocks[right].End()
	})
	for _, block := range blocks {
		for _, statement := range block.List {
			if statement.End() < position {
				l8D2ReadinessApplyCompletedBinding(statement, values)
				continue
			}
			if statement.Pos() <= position && position <= statement.End() {
				l8D2ReadinessApplyContainingBindings(statement, position, values)
			}
			break
		}
	}
	return values
}

func l8D2ReadinessStaticBindingFromStatement(statement ast.Stmt, name string) (ast.Expr, bool) {
	switch item := statement.(type) {
	case *ast.DeclStmt:
		group, ok := item.Decl.(*ast.GenDecl)
		if !ok || group.Tok == token.CONST {
			return nil, false
		}
		for _, raw := range group.Specs {
			specification, ok := raw.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, candidate := range specification.Names {
				if candidate.Name != name {
					continue
				}
				if specification.Type != nil {
					return specification.Type, true
				}
				if index < len(specification.Values) {
					return specification.Values[index], true
				}
			}
		}
	case *ast.AssignStmt:
		if item.Tok != token.DEFINE {
			return nil, false
		}
		for index, raw := range item.Lhs {
			candidate, ok := raw.(*ast.Ident)
			if ok && candidate.Name == name && index < len(item.Rhs) {
				return item.Rhs[index], true
			}
		}
	}
	return nil, false
}

func l8D2ReadinessStaticBinding(function *ast.FuncDecl, name string, position token.Pos) ast.Expr {
	if function == nil || function.Body == nil {
		return nil
	}
	var result ast.Expr
	for _, fields := range []*ast.FieldList{function.Recv, function.Type.Params, function.Type.Results} {
		if fields == nil {
			continue
		}
		for _, field := range fields.List {
			for _, candidate := range field.Names {
				if candidate.Name == name {
					result = field.Type
				}
			}
		}
	}
	var blocks []*ast.BlockStmt
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if block, ok := node.(*ast.BlockStmt); ok && block.Pos() <= position && position <= block.End() {
			blocks = append(blocks, block)
		}
		return true
	})
	sort.Slice(blocks, func(left, right int) bool {
		if blocks[left].Pos() != blocks[right].Pos() {
			return blocks[left].Pos() < blocks[right].Pos()
		}
		return blocks[left].End() > blocks[right].End()
	})
	for _, block := range blocks {
		for _, statement := range block.List {
			if statement.End() < position {
				if binding, ok := l8D2ReadinessStaticBindingFromStatement(statement, name); ok {
					result = binding
				}
				continue
			}
			if statement.Pos() <= position && position <= statement.End() {
				var initializers []ast.Stmt
				switch item := statement.(type) {
				case *ast.IfStmt:
					initializers = append(initializers, item.Init)
				case *ast.ForStmt:
					initializers = append(initializers, item.Init)
				case *ast.SwitchStmt:
					initializers = append(initializers, item.Init)
				case *ast.TypeSwitchStmt:
					initializers = append(initializers, item.Init, item.Assign)
				}
				for _, initializer := range initializers {
					if initializer != nil && initializer.End() < position {
						if binding, ok := l8D2ReadinessStaticBindingFromStatement(initializer, name); ok {
							result = binding
						}
					}
				}
			}
			break
		}
	}
	return result
}

func l8D2ReadinessSubstituteType(expression ast.Expr, substitutions map[string]ast.Expr) ast.Expr {
	switch item := expression.(type) {
	case nil:
		return nil
	case *ast.Ident:
		if replacement := substitutions[item.Name]; replacement != nil {
			return replacement
		}
		return item
	case *ast.ParenExpr:
		return &ast.ParenExpr{X: l8D2ReadinessSubstituteType(item.X, substitutions)}
	case *ast.StarExpr:
		return &ast.StarExpr{X: l8D2ReadinessSubstituteType(item.X, substitutions)}
	case *ast.ArrayType:
		return &ast.ArrayType{Len: item.Len, Elt: l8D2ReadinessSubstituteType(item.Elt, substitutions)}
	case *ast.MapType:
		return &ast.MapType{Key: l8D2ReadinessSubstituteType(item.Key, substitutions), Value: l8D2ReadinessSubstituteType(item.Value, substitutions)}
	case *ast.ChanType:
		return &ast.ChanType{Dir: item.Dir, Value: l8D2ReadinessSubstituteType(item.Value, substitutions)}
	case *ast.IndexExpr:
		return &ast.IndexExpr{X: l8D2ReadinessSubstituteType(item.X, substitutions), Index: l8D2ReadinessSubstituteType(item.Index, substitutions)}
	case *ast.IndexListExpr:
		indices := make([]ast.Expr, len(item.Indices))
		for index, value := range item.Indices {
			indices[index] = l8D2ReadinessSubstituteType(value, substitutions)
		}
		return &ast.IndexListExpr{X: l8D2ReadinessSubstituteType(item.X, substitutions), Indices: indices}
	}
	return expression
}

func l8D2ReadinessNamedTypeApplication(expression ast.Expr) (string, []ast.Expr, bool) {
	switch item := expression.(type) {
	case *ast.Ident:
		return item.Name, nil, true
	case *ast.ParenExpr:
		return l8D2ReadinessNamedTypeApplication(item.X)
	case *ast.IndexExpr:
		if name, ok := item.X.(*ast.Ident); ok {
			return name.Name, []ast.Expr{item.Index}, true
		}
	case *ast.IndexListExpr:
		if name, ok := item.X.(*ast.Ident); ok {
			return name.Name, item.Indices, true
		}
	}
	return "", nil, false
}

func l8D2ReadinessResolveNamedType(expression ast.Expr, environment l8D2ReadinessTerminalEnvironment, visited map[string]bool) (ast.Expr, bool) {
	name, arguments, ok := l8D2ReadinessNamedTypeApplication(expression)
	if !ok || len(environment.namedTypes[name]) == 0 {
		return nil, false
	}
	identity := name
	for _, argument := range arguments {
		identity += "[" + types.ExprString(argument) + "]"
	}
	if visited[identity] {
		return nil, false
	}
	visited[identity] = true
	defer delete(visited, identity)
	var resolved ast.Expr
	for _, declaration := range environment.namedTypes[name] {
		if len(declaration.parameters) != len(arguments) {
			return nil, false
		}
		substitutions := make(map[string]ast.Expr, len(arguments))
		for index, parameter := range declaration.parameters {
			substitutions[parameter] = arguments[index]
		}
		candidate := l8D2ReadinessSubstituteType(declaration.underlying, substitutions)
		if nested, exact := l8D2ReadinessResolveNamedType(candidate, environment, visited); exact {
			candidate = nested
		}
		if resolved != nil && types.ExprString(resolved) != types.ExprString(candidate) {
			return nil, false
		}
		resolved = candidate
	}
	return resolved, resolved != nil
}

func l8D2ReadinessFunctionResultType(function *ast.FuncDecl, arguments []ast.Expr) ast.Expr {
	if function == nil || function.Type.Results == nil {
		return nil
	}
	count := 0
	var result ast.Expr
	for _, field := range function.Type.Results.List {
		fieldCount := len(field.Names)
		if fieldCount == 0 {
			fieldCount = 1
		}
		count += fieldCount
		result = field.Type
	}
	if count != 1 {
		return nil
	}
	var parameters []string
	if function.Type.TypeParams != nil {
		for _, field := range function.Type.TypeParams.List {
			for _, name := range field.Names {
				parameters = append(parameters, name.Name)
			}
		}
	}
	if len(parameters) != len(arguments) {
		if len(parameters) != 0 || len(arguments) != 0 {
			return nil
		}
		return result
	}
	substitutions := make(map[string]ast.Expr, len(arguments))
	for index, parameter := range parameters {
		substitutions[parameter] = arguments[index]
	}
	return l8D2ReadinessSubstituteType(result, substitutions)
}

func l8D2ReadinessReceiverTypeExpression(function *ast.FuncDecl, expression ast.Expr, position token.Pos, environment l8D2ReadinessTerminalEnvironment) ast.Expr {
	if function == nil || expression == nil {
		return nil
	}
	for {
		switch item := expression.(type) {
		case *ast.ParenExpr:
			expression = item.X
		case *ast.StarExpr:
			expression = item.X
		case *ast.UnaryExpr:
			if item.Op != token.AND {
				return nil
			}
			expression = item.X
		case *ast.CompositeLit:
			return item.Type
		case *ast.TypeAssertExpr:
			return item.Type
		case *ast.Ident:
			binding := l8D2ReadinessStaticBinding(function, item.Name, position)
			if binding == nil {
				return nil
			}
			expression = binding
		default:
			return nil
		}
	}
}

func l8D2ReadinessReceiverDeclarationType(function *ast.FuncDecl) ast.Expr {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 {
		return nil
	}
	expression := function.Recv.List[0].Type
	for {
		switch item := expression.(type) {
		case *ast.ParenExpr:
			expression = item.X
		case *ast.StarExpr:
			expression = item.X
		default:
			return expression
		}
	}
}

func l8D2ReadinessStaticMethodResultType(function *ast.FuncDecl, selector *ast.SelectorExpr, position token.Pos, environment l8D2ReadinessTerminalEnvironment) ast.Expr {
	if selector == nil {
		return nil
	}
	receiverType := l8D2ReadinessReceiverTypeExpression(function, selector.X, position, environment)
	if receiverType == nil {
		return nil
	}
	var result ast.Expr
	for _, declaration := range environment.declarations {
		if declaration.Recv == nil || declaration.Name.Name != selector.Sel.Name {
			continue
		}
		candidateReceiver := l8D2ReadinessReceiverDeclarationType(declaration)
		if candidateReceiver == nil || types.ExprString(candidateReceiver) != types.ExprString(receiverType) {
			continue
		}
		candidate := l8D2ReadinessFunctionResultType(declaration, nil)
		if candidate == nil {
			return nil
		}
		if result != nil && types.ExprString(result) != types.ExprString(candidate) {
			return nil
		}
		result = candidate
	}
	return result
}

func l8D2ReadinessFunctionLiteralResultType(literal *ast.FuncLit) ast.Expr {
	if literal == nil || literal.Type == nil || literal.Type.Results == nil {
		return nil
	}
	count := 0
	var result ast.Expr
	for _, field := range literal.Type.Results.List {
		fieldCount := len(field.Names)
		if fieldCount == 0 {
			fieldCount = 1
		}
		count += fieldCount
		result = field.Type
	}
	if count != 1 {
		return nil
	}
	return result
}

func l8D2ReadinessStaticCallResultType(function *ast.FuncDecl, call *ast.CallExpr, position token.Pos, environment l8D2ReadinessTerminalEnvironment) ast.Expr {
	if call == nil {
		return nil
	}
	var name string
	var arguments []ast.Expr
	switch called := call.Fun.(type) {
	case *ast.FuncLit:
		return l8D2ReadinessFunctionLiteralResultType(called)
	case *ast.Ident:
		if binding := l8D2ReadinessStaticBinding(function, called.Name, position); binding != nil {
			if literal, ok := binding.(*ast.FuncLit); ok {
				return l8D2ReadinessFunctionLiteralResultType(literal)
			}
			return nil
		}
		name = called.Name
	case *ast.SelectorExpr:
		return l8D2ReadinessStaticMethodResultType(function, called, position, environment)
	case *ast.IndexExpr:
		if identifier, ok := called.X.(*ast.Ident); ok {
			name, arguments = identifier.Name, []ast.Expr{called.Index}
		}
	case *ast.IndexListExpr:
		if identifier, ok := called.X.(*ast.Ident); ok {
			name, arguments = identifier.Name, called.Indices
		}
	}
	if name == "" || l8D2ReadinessStaticBinding(function, name, position) != nil {
		return nil
	}
	var result ast.Expr
	for _, declaration := range environment.declarations {
		if declaration.Recv != nil || declaration.Name.Name != name {
			continue
		}
		candidate := l8D2ReadinessFunctionResultType(declaration, arguments)
		if candidate == nil {
			return nil
		}
		if result != nil && types.ExprString(result) != types.ExprString(candidate) {
			return nil
		}
		result = candidate
	}
	return result
}

func l8D2ReadinessStaticExpressionType(function *ast.FuncDecl, expression ast.Expr, position token.Pos, environment l8D2ReadinessTerminalEnvironment, visited map[string]bool) ast.Expr {
	for {
		if resolved, exact := l8D2ReadinessResolveNamedType(expression, environment, make(map[string]bool)); exact {
			expression = resolved
		}
		switch item := expression.(type) {
		case nil:
			return nil
		case *ast.ParenExpr:
			expression = item.X
			continue
		case *ast.Ident:
			if visited[item.Name] {
				return nil
			}
			visited[item.Name] = true
			binding := l8D2ReadinessStaticBinding(function, item.Name, position)
			if binding == nil {
				return nil
			}
			return l8D2ReadinessStaticExpressionType(function, binding, position, environment, visited)
		case *ast.CallExpr:
			called, identifierCall := item.Fun.(*ast.Ident)
			if identifierCall && called.Name == "make" && len(item.Args) != 0 {
				if shadow, exists := l8D2ReadinessWrapperConstantValues(function, item.Pos(), environment)["make"]; !exists || shadow.Kind() != constant.Unknown {
					return l8D2ReadinessStaticExpressionType(function, item.Args[0], position, environment, visited)
				}
			}
			if identifierCall && called.Name == "new" && len(item.Args) == 1 {
				if shadow, exists := l8D2ReadinessWrapperConstantValues(function, item.Pos(), environment)["new"]; !exists || shadow.Kind() != constant.Unknown {
					return &ast.StarExpr{X: item.Args[0]}
				}
			}
			result := l8D2ReadinessStaticCallResultType(function, item, position, environment)
			return l8D2ReadinessStaticExpressionType(function, result, position, environment, visited)
		case *ast.CompositeLit:
			return l8D2ReadinessStaticExpressionType(function, item.Type, position, environment, visited)
		case *ast.TypeAssertExpr:
			return l8D2ReadinessStaticExpressionType(function, item.Type, position, environment, visited)
		case *ast.IndexExpr:
			container := l8D2ReadinessStaticExpressionType(function, item.X, position, environment, visited)
			switch value := container.(type) {
			case *ast.MapType:
				return value.Value
			case *ast.ArrayType:
				return value.Elt
			}
			return nil
		case *ast.SliceExpr:
			return l8D2ReadinessStaticExpressionType(function, item.X, position, environment, visited)
		case *ast.StarExpr:
			return l8D2ReadinessStaticExpressionType(function, item.X, position, environment, visited)
		case *ast.MapType, *ast.ArrayType:
			return expression
		}
		return nil
	}
}

func l8D2ReadinessStaticMapKeyType(function *ast.FuncDecl, collection ast.Expr, position token.Pos, environment l8D2ReadinessTerminalEnvironment) ast.Expr {
	environment.namedTypes = l8D2ReadinessWrapperNamedTypes(function, position, environment)
	container := l8D2ReadinessStaticExpressionType(function, collection, position, environment, make(map[string]bool))
	if mapping, ok := container.(*ast.MapType); ok {
		return mapping.Key
	}
	return nil
}

func l8D2ReadinessIndexedStorageMayBeMap(function *ast.FuncDecl, collection ast.Expr, position token.Pos, environment l8D2ReadinessTerminalEnvironment) bool {
	if collection == nil {
		return false
	}
	if container := l8D2ReadinessStaticExpressionType(function, collection, position, environment, make(map[string]bool)); container != nil {
		switch container.(type) {
		case *ast.ArrayType:
			return false
		case *ast.MapType:
			return true
		}
	}
	for {
		switch item := collection.(type) {
		case *ast.ParenExpr:
			collection = item.X
		case *ast.StarExpr:
			collection = item.X
		case *ast.TypeAssertExpr:
			collection = item.X
		case *ast.SliceExpr:
			return false
		case *ast.IndexExpr:
			collection = item.X
		case *ast.CallExpr, *ast.Ident, *ast.SelectorExpr:
			return true
		default:
			return true
		}
	}
}

func l8D2ReadinessStaticStorageIndex(function *ast.FuncDecl, collection, expression ast.Expr, environment l8D2ReadinessTerminalEnvironment) (string, bool) {
	value, exact := l8D2ReadinessConstantExpression(expression, l8D2ReadinessWrapperConstantValues(function, expression.Pos(), environment))
	if !exact {
		return "", false
	}
	target := l8D2ReadinessStaticMapKeyType(function, collection, expression.Pos(), environment)
	if target == nil && l8D2ReadinessIndexedStorageMayBeMap(function, collection, expression.Pos(), environment) {
		return "", false
	}
	if target != nil {
		environment.namedTypes = l8D2ReadinessWrapperNamedTypes(function, expression.Pos(), environment)
		if resolved, exact := l8D2ReadinessResolveNamedType(target, environment, make(map[string]bool)); exact {
			target = resolved
		}
		value, exact = l8D2ReadinessConvertConstantToTypeExpression(value, target)
		if !exact {
			return "", false
		}
	}
	switch value.Kind() {
	case constant.String:
		return "string:" + strconv.Quote(constant.StringVal(value)), true
	case constant.Bool:
		return "bool:" + value.ExactString(), true
	case constant.Int, constant.Float, constant.Complex:
		return "number:" + constant.ToComplex(value).ExactString(), true
	}
	return "", false
}

func l8D2ReadinessWrapperStorageKey(function *ast.FuncDecl, expression ast.Expr, environment l8D2ReadinessTerminalEnvironment) (string, bool) {
	if expression == nil {
		return "", false
	}
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name, value.Name != "_"
	case *ast.ParenExpr:
		return l8D2ReadinessWrapperStorageKey(function, value.X, environment)
	case *ast.StarExpr:
		return l8D2ReadinessWrapperStorageKey(function, value.X, environment)
	case *ast.UnaryExpr:
		if value.Op == token.AND {
			return l8D2ReadinessWrapperStorageKey(function, value.X, environment)
		}
	case *ast.TypeAssertExpr:
		return l8D2ReadinessWrapperStorageKey(function, value.X, environment)
	case *ast.SliceExpr:
		return l8D2ReadinessWrapperStorageKey(function, value.X, environment)
	case *ast.IndexListExpr:
		return l8D2ReadinessWrapperStorageKey(function, value.X, environment)
	case *ast.SelectorExpr:
		base, ok := l8D2ReadinessWrapperStorageKey(function, value.X, environment)
		if ok {
			return base + "." + value.Sel.Name, true
		}
	case *ast.IndexExpr:
		base, ok := l8D2ReadinessWrapperStorageKey(function, value.X, environment)
		if !ok {
			return "", false
		}
		if index, exact := l8D2ReadinessStaticStorageIndex(function, value.X, value.Index, environment); exact {
			return base + "[" + index + "]", true
		}
		return base + "[*]", true
	}
	return "", false
}

func l8D2ReadinessWrapperStorageSegments(key string) ([]string, bool) {
	if key == "" {
		return nil, false
	}
	var result []string
	for offset := 0; offset < len(key); {
		start := offset
		switch key[offset] {
		case '.':
			offset++
			for offset < len(key) && key[offset] != '.' && key[offset] != '[' {
				offset++
			}
		case '[':
			offset++
			quoted, escaped := false, false
			for offset < len(key) {
				character := key[offset]
				offset++
				if escaped {
					escaped = false
					continue
				}
				if quoted && character == '\\' {
					escaped = true
					continue
				}
				if character == '"' {
					quoted = !quoted
					continue
				}
				if character == ']' && !quoted {
					break
				}
			}
			if offset == 0 || key[offset-1] != ']' {
				return nil, false
			}
		default:
			for offset < len(key) && key[offset] != '.' && key[offset] != '[' {
				offset++
			}
		}
		if start == offset {
			return nil, false
		}
		result = append(result, key[start:offset])
	}
	return result, len(result) != 0
}

func l8D2ReadinessWrapperStorageSegmentsMatch(left, right string) bool {
	return left == right || (strings.HasPrefix(left, "[") && strings.HasPrefix(right, "[") && (left == "[*]" || right == "[*]"))
}

func l8D2ReadinessWrapperStorageMayAlias(left, right string) bool {
	leftSegments, leftOK := l8D2ReadinessWrapperStorageSegments(left)
	rightSegments, rightOK := l8D2ReadinessWrapperStorageSegments(right)
	if !leftOK || !rightOK || len(leftSegments) != len(rightSegments) {
		return false
	}
	for index := range leftSegments {
		if !l8D2ReadinessWrapperStorageSegmentsMatch(leftSegments[index], rightSegments[index]) {
			return false
		}
	}
	return true
}

func l8D2ReadinessWrapperStorageStateBound(function *ast.FuncDecl, environment l8D2ReadinessTerminalEnvironment) int {
	if function == nil || function.Body == nil {
		return 1
	}
	maximum := 1
	ast.Inspect(function.Body, func(node ast.Node) bool {
		expression, ok := node.(ast.Expr)
		if !ok {
			return true
		}
		key, exact := l8D2ReadinessWrapperStorageKey(function, expression, environment)
		if !exact {
			return true
		}
		if segments, valid := l8D2ReadinessWrapperStorageSegments(key); valid && len(segments) > maximum {
			maximum = len(segments)
		}
		return true
	})
	return maximum
}

func l8D2ReadinessWrapperLookup(function *ast.FuncDecl, aliases map[string]map[string]bool, expression ast.Expr, environment l8D2ReadinessTerminalEnvironment) map[string]bool {
	result := make(map[string]bool)
	key, ok := l8D2ReadinessWrapperStorageKey(function, expression, environment)
	if !ok {
		return result
	}
	merge := func(identities map[string]bool) {
		for identity := range identities {
			result[identity] = true
		}
	}
	for candidate, identities := range aliases {
		if l8D2ReadinessWrapperStorageMayAlias(candidate, key) {
			merge(identities)
		}
	}
	return result
}

func l8D2ReadinessMergeWrapperIdentities(function *ast.FuncDecl, aliases map[string]map[string]bool, expression ast.Expr, identities map[string]bool, environment l8D2ReadinessTerminalEnvironment) bool {
	changed := false
	key, ok := l8D2ReadinessWrapperStorageKey(function, expression, environment)
	if !ok {
		return false
	}
	if aliases[key] == nil {
		aliases[key] = make(map[string]bool)
	}
	for identity := range identities {
		if aliases[key][identity] {
			continue
		}
		aliases[key][identity] = true
		changed = true
	}
	return changed
}

func l8D2ReadinessTranslateWrapperStorageAliases(function *ast.FuncDecl, aliases map[string]map[string]bool, left, right ast.Expr, environment l8D2ReadinessTerminalEnvironment) bool {
	leftKey, leftOK := l8D2ReadinessWrapperStorageKey(function, left, environment)
	rightKey, rightOK := l8D2ReadinessWrapperStorageKey(function, right, environment)
	if !leftOK || !rightOK {
		return false
	}
	changed := false
	type entry struct {
		source     string
		identities map[string]bool
	}
	entries := make([]entry, 0, len(aliases))
	for source, identities := range aliases {
		entries = append(entries, entry{source: source, identities: identities})
	}
	leftSegments, leftSegmentsOK := l8D2ReadinessWrapperStorageSegments(leftKey)
	rightSegments, rightSegmentsOK := l8D2ReadinessWrapperStorageSegments(rightKey)
	if !leftSegmentsOK || !rightSegmentsOK {
		return false
	}
	stateBound := l8D2ReadinessWrapperStorageStateBound(function, environment)
	for _, item := range entries {
		source, identities := item.source, item.identities
		sourceSegments, ok := l8D2ReadinessWrapperStorageSegments(source)
		if !ok || len(sourceSegments) < len(rightSegments) {
			continue
		}
		matches := true
		for index := range rightSegments {
			if !l8D2ReadinessWrapperStorageSegmentsMatch(sourceSegments[index], rightSegments[index]) {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		targetSegments := append(append([]string(nil), leftSegments...), sourceSegments[len(rightSegments):]...)
		if len(targetSegments) > stateBound {
			continue
		}
		target := strings.Join(targetSegments, "")
		if target == source {
			continue
		}
		if aliases[target] == nil {
			aliases[target] = make(map[string]bool)
		}
		for identity := range identities {
			if aliases[target][identity] {
				continue
			}
			aliases[target][identity] = true
			changed = true
		}
	}
	return changed
}

func l8D2ReadinessMergeWrapperCompositeAssignment(function *ast.FuncDecl, aliases map[string]map[string]bool, left ast.Expr, composite *ast.CompositeLit, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if composite == nil {
		return false
	}
	changed := false
	for index, raw := range composite.Elts {
		var target ast.Expr
		var source ast.Expr
		if keyed, ok := raw.(*ast.KeyValueExpr); ok {
			source = keyed.Value
			switch key := keyed.Key.(type) {
			case *ast.Ident:
				target = &ast.SelectorExpr{X: left, Sel: ast.NewIdent(key.Name)}
			default:
				target = &ast.IndexExpr{X: left, Index: keyed.Key}
			}
		} else {
			source = raw
			target = &ast.IndexExpr{X: left, Index: &ast.BasicLit{Kind: token.INT, Value: strconv.Itoa(index)}}
		}
		if nested, ok := source.(*ast.CompositeLit); ok {
			if l8D2ReadinessMergeWrapperCompositeAssignment(function, aliases, target, nested, facts, environment) {
				changed = true
			}
			continue
		}
		identities := l8D2ReadinessWrapperIdentities(function, source, aliases, facts, environment)
		if l8D2ReadinessMergeWrapperIdentities(function, aliases, target, identities, environment) {
			changed = true
		}
	}
	return changed
}

func l8D2ReadinessWrapperCompositeExpression(expression ast.Expr) *ast.CompositeLit {
	for expression != nil {
		switch value := expression.(type) {
		case *ast.CompositeLit:
			return value
		case *ast.ParenExpr:
			expression = value.X
		case *ast.SliceExpr:
			expression = value.X
		case *ast.TypeAssertExpr:
			expression = value.X
		case *ast.UnaryExpr:
			expression = value.X
		case *ast.StarExpr:
			expression = value.X
		default:
			return nil
		}
	}
	return nil
}

func l8D2ReadinessWrapperIdentityAliases(function *ast.FuncDecl, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment, before token.Pos) map[string]map[string]bool {
	return l8D2ReadinessWrapperIdentityAliasesInNode(function, function.Body, nil, facts, environment, before)
}

func l8D2ReadinessWrapperIdentityAliasesInNode(function *ast.FuncDecl, root ast.Node, seeds map[string]map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment, before token.Pos) map[string]map[string]bool {
	aliases := make(map[string]map[string]bool)
	for key, identities := range seeds {
		aliases[key] = make(map[string]bool, len(identities))
		for identity := range identities {
			aliases[key][identity] = true
		}
	}
	if function == nil || function.Body == nil {
		return aliases
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(root, func(node ast.Node) bool {
			if literal, nested := node.(*ast.FuncLit); nested && literal != root {
				return false
			}
			switch value := node.(type) {
			case *ast.AssignStmt:
				if before.IsValid() && value.Pos() >= before {
					return false
				}
				for index, left := range value.Lhs {
					var right ast.Expr
					if index < len(value.Rhs) {
						right = value.Rhs[index]
					} else if len(value.Rhs) == 1 {
						right = value.Rhs[0]
					}
					if composite := l8D2ReadinessWrapperCompositeExpression(right); composite != nil {
						if l8D2ReadinessMergeWrapperCompositeAssignment(function, aliases, left, composite, facts, environment) {
							changed = true
						}
						continue
					}
					identities := l8D2ReadinessWrapperIdentities(function, right, aliases, facts, environment)
					if l8D2ReadinessMergeWrapperIdentities(function, aliases, left, identities, environment) || l8D2ReadinessTranslateWrapperStorageAliases(function, aliases, left, right, environment) {
						changed = true
					}
				}
			case *ast.ValueSpec:
				if before.IsValid() && value.Pos() >= before {
					return false
				}
				for index, name := range value.Names {
					var expression ast.Expr
					if index < len(value.Values) {
						expression = value.Values[index]
					} else if len(value.Values) == 1 {
						expression = value.Values[0]
					}
					if composite := l8D2ReadinessWrapperCompositeExpression(expression); composite != nil {
						if l8D2ReadinessMergeWrapperCompositeAssignment(function, aliases, name, composite, facts, environment) {
							changed = true
						}
						continue
					}
					identities := l8D2ReadinessWrapperIdentities(function, expression, aliases, facts, environment)
					if l8D2ReadinessMergeWrapperIdentities(function, aliases, name, identities, environment) || l8D2ReadinessTranslateWrapperStorageAliases(function, aliases, name, expression, environment) {
						changed = true
					}
				}
			}
			return true
		})
	}
	return aliases
}

func l8D2ReadinessWrapperIdentities(function *ast.FuncDecl, expression ast.Expr, aliases map[string]map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) map[string]bool {
	result := make(map[string]bool)
	merge := func(values map[string]bool) {
		for identity := range values {
			result[identity] = true
		}
	}
	var walk func(ast.Expr)
	walk = func(candidate ast.Expr) {
		if candidate == nil {
			return
		}
		merge(l8D2ReadinessWrapperLookup(function, aliases, candidate, environment))
		switch value := candidate.(type) {
		case *ast.Ident:
			merge(aliases[value.Name])
			if !l8D2ReadinessNameShadowedInFunction(function, value.Name) && (len(facts.terminalParameter[value.Name]) != 0 || len(facts.returnedWrappers[value.Name]) != 0) {
				result[value.Name] = true
			}
		case *ast.SelectorExpr:
			identity := l8D2ReadinessExactLocalCallIdentity(function, value)
			if len(facts.terminalParameter[identity]) != 0 || len(facts.returnedWrappers[identity]) != 0 {
				result[identity] = true
			}
		case *ast.ParenExpr:
			walk(value.X)
		case *ast.TypeAssertExpr:
			walk(value.X)
		case *ast.UnaryExpr:
			walk(value.X)
		case *ast.StarExpr:
			walk(value.X)
		case *ast.IndexExpr:
			return
		case *ast.IndexListExpr:
			walk(value.X)
		case *ast.SliceExpr:
			return
		case *ast.KeyValueExpr:
			walk(value.Key)
			walk(value.Value)
		case *ast.Ellipsis:
			walk(value.Elt)
		case *ast.CompositeLit:
			for _, element := range value.Elts {
				walk(element)
			}
		case *ast.FuncLit:
			innerAliases := l8D2ReadinessWrapperIdentityAliasesInNode(function, value.Body, aliases, facts, environment, value.End())
			ast.Inspect(value.Body, func(node ast.Node) bool {
				if nested, ok := node.(*ast.FuncLit); ok && nested != value {
					return false
				}
				returned, ok := node.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, returnedExpression := range returned.Results {
					merge(l8D2ReadinessWrapperIdentities(function, returnedExpression, innerAliases, facts, environment))
				}
				return false
			})
		case *ast.CallExpr:
			calleeIdentities := l8D2ReadinessWrapperIdentities(function, value.Fun, aliases, facts, environment)
			if identity := l8D2ReadinessExactLocalCallIdentity(function, value.Fun); identity != "" {
				calleeIdentities[identity] = true
			}
			for identity := range calleeIdentities {
				result[identity] = true
				merge(facts.returnedWrappers[identity])
			}
			for _, argument := range value.Args {
				walk(argument)
			}
		}
	}
	walk(expression)
	return result
}

func l8D2ReadinessCallNeverReturns(function *ast.FuncDecl, call *ast.CallExpr, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if call == nil {
		return false
	}
	if l8D2ReadinessTerminalCallableExpression(function, call.Fun, aliases, facts, environment) {
		return true
	}
	wrapperAliases := l8D2ReadinessWrapperIdentityAliases(function, facts, environment, call.Pos())
	identities := l8D2ReadinessWrapperIdentities(function, call.Fun, wrapperAliases, facts, environment)
	if identity := l8D2ReadinessExactLocalCallIdentity(function, call.Fun); identity != "" {
		identities[identity] = true
	}
	for identity := range identities {
		for index := range facts.terminalParameter[identity] {
			if index < len(call.Args) && l8D2ReadinessTerminalCallableExpression(function, call.Args[index], aliases, facts, environment) {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessExpressionsNeverReturn(function *ast.FuncDecl, expressions []ast.Expr, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	for _, expression := range expressions {
		if l8D2ReadinessExpressionNeverReturns(function, expression, aliases, facts, environment) {
			return true
		}
	}
	return false
}

func l8D2ReadinessExpressionNeverReturns(function *ast.FuncDecl, expression ast.Expr, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if expression == nil {
		return false
	}
	switch value := expression.(type) {
	case *ast.FuncLit:
		return false
	case *ast.CallExpr:
		if l8D2ReadinessExpressionNeverReturns(function, value.Fun, aliases, facts, environment) || l8D2ReadinessExpressionsNeverReturn(function, value.Args, aliases, facts, environment) {
			return true
		}
		return l8D2ReadinessCallNeverReturns(function, value, aliases, facts, environment)
	case *ast.ParenExpr:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment)
	case *ast.SelectorExpr:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment)
	case *ast.TypeAssertExpr:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment)
	case *ast.IndexExpr:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, value.Index, aliases, facts, environment)
	case *ast.IndexListExpr:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment)
	case *ast.SliceExpr:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, value.Low, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, value.High, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, value.Max, aliases, facts, environment)
	case *ast.UnaryExpr:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment)
	case *ast.StarExpr:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment)
	case *ast.BinaryExpr:
		if l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment) {
			return true
		}
		switch value.Op {
		case token.LAND:
			return l8D2ReadinessStaticallyTrue(value.X) && l8D2ReadinessExpressionNeverReturns(function, value.Y, aliases, facts, environment)
		case token.LOR:
			return l8D2ReadinessStaticallyFalse(value.X) && l8D2ReadinessExpressionNeverReturns(function, value.Y, aliases, facts, environment)
		default:
			return l8D2ReadinessExpressionNeverReturns(function, value.Y, aliases, facts, environment)
		}
	case *ast.KeyValueExpr:
		return l8D2ReadinessExpressionNeverReturns(function, value.Key, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, value.Value, aliases, facts, environment)
	case *ast.Ellipsis:
		return l8D2ReadinessExpressionNeverReturns(function, value.Elt, aliases, facts, environment)
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			if l8D2ReadinessExpressionNeverReturns(function, element, aliases, facts, environment) {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessDeferredCallEvaluationNeverReturns(function *ast.FuncDecl, call *ast.CallExpr, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	return call != nil && (l8D2ReadinessExpressionNeverReturns(function, call.Fun, aliases, facts, environment) || l8D2ReadinessExpressionsNeverReturn(function, call.Args, aliases, facts, environment))
}

func l8D2ReadinessStatementEvaluationNeverReturns(function *ast.FuncDecl, statement ast.Stmt, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if statement == nil {
		return false
	}
	switch value := statement.(type) {
	case *ast.ExprStmt:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment)
	case *ast.AssignStmt:
		return l8D2ReadinessExpressionsNeverReturn(function, value.Lhs, aliases, facts, environment) || l8D2ReadinessExpressionsNeverReturn(function, value.Rhs, aliases, facts, environment)
	case *ast.DeclStmt:
		declaration, ok := value.Decl.(*ast.GenDecl)
		if !ok {
			return false
		}
		for _, specification := range declaration.Specs {
			if values, ok := specification.(*ast.ValueSpec); ok && l8D2ReadinessExpressionsNeverReturn(function, values.Values, aliases, facts, environment) {
				return true
			}
		}
	case *ast.SendStmt:
		return l8D2ReadinessExpressionNeverReturns(function, value.Chan, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, value.Value, aliases, facts, environment)
	case *ast.IncDecStmt:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment)
	case *ast.ReturnStmt:
		return l8D2ReadinessExpressionsNeverReturn(function, value.Results, aliases, facts, environment)
	case *ast.DeferStmt:
		return l8D2ReadinessDeferredCallEvaluationNeverReturns(function, value.Call, aliases, facts, environment)
	case *ast.GoStmt:
		return l8D2ReadinessDeferredCallEvaluationNeverReturns(function, value.Call, aliases, facts, environment)
	case *ast.IfStmt:
		return l8D2ReadinessStatementEvaluationNeverReturns(function, value.Init, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, value.Cond, aliases, facts, environment)
	case *ast.ForStmt:
		return l8D2ReadinessStatementEvaluationNeverReturns(function, value.Init, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, value.Cond, aliases, facts, environment)
	case *ast.RangeStmt:
		return l8D2ReadinessExpressionNeverReturns(function, value.X, aliases, facts, environment)
	case *ast.SwitchStmt:
		if l8D2ReadinessStatementEvaluationNeverReturns(function, value.Init, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, value.Tag, aliases, facts, environment) {
			return true
		}
		return l8D2ReadinessSwitchCaseEvaluationNeverReturns(function, value, aliases, facts, environment)
	case *ast.TypeSwitchStmt:
		return l8D2ReadinessStatementEvaluationNeverReturns(function, value.Init, aliases, facts, environment) || l8D2ReadinessStatementEvaluationNeverReturns(function, value.Assign, aliases, facts, environment)
	case *ast.SelectStmt:
		for _, raw := range value.Body.List {
			clause, ok := raw.(*ast.CommClause)
			if ok && l8D2ReadinessSelectCommunicationEvaluationNeverReturns(function, clause.Comm, aliases, facts, environment) {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessSelectCommunicationEvaluationNeverReturns(function *ast.FuncDecl, communication ast.Stmt, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	switch item := communication.(type) {
	case nil:
		return false
	case *ast.SendStmt:
		return l8D2ReadinessExpressionNeverReturns(function, item.Chan, aliases, facts, environment) || l8D2ReadinessExpressionNeverReturns(function, item.Value, aliases, facts, environment)
	case *ast.ExprStmt:
		return l8D2ReadinessExpressionNeverReturns(function, item.X, aliases, facts, environment)
	case *ast.AssignStmt:
		// A receive's channel operand is evaluated when select enters. Its
		// destination expressions are evaluated only after that clause wins.
		return l8D2ReadinessExpressionsNeverReturn(function, item.Rhs, aliases, facts, environment)
	}
	return false
}

func l8D2ReadinessSwitchCaseEvaluationNeverReturns(function *ast.FuncDecl, statement *ast.SwitchStmt, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if statement == nil || statement.Body == nil {
		return false
	}
	for _, raw := range statement.Body.List {
		clause, ok := raw.(*ast.CaseClause)
		if !ok {
			return false
		}
		if clause.List == nil {
			// Default selection happens only after all case expressions have
			// been evaluated, regardless of the default clause's source order.
			continue
		}
		for _, expression := range clause.List {
			if l8D2ReadinessExpressionNeverReturns(function, expression, aliases, facts, environment) {
				return true
			}
			if statement.Tag == nil {
				condition, exact := l8D2ReadinessConstantExpression(expression, l8D2ReadinessWrapperConstantValues(function, expression.Pos(), environment))
				if exact && condition.Kind() == constant.Bool && !constant.BoolVal(condition) {
					continue
				}
				return false
			}
			left, leftExact := l8D2ReadinessConstantExpression(statement.Tag, l8D2ReadinessWrapperConstantValues(function, statement.Tag.Pos(), environment))
			right, rightExact := l8D2ReadinessConstantExpression(expression, l8D2ReadinessWrapperConstantValues(function, expression.Pos(), environment))
			if !leftExact || !rightExact || constant.Compare(left, token.EQL, right) {
				return false
			}
		}
	}
	return false
}

func l8D2ReadinessStatementAlwaysTerminates(function *ast.FuncDecl, statement ast.Stmt, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if l8D2ReadinessStatementEvaluationNeverReturns(function, statement, aliases, facts, environment) {
		return true
	}
	switch value := statement.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		return false
	case *ast.IfStmt:
		if l8D2ReadinessStaticallyTrue(value.Cond) {
			return l8D2ReadinessBlockAlwaysTerminates(function, value.Body, aliases, facts, environment)
		}
		if value.Else != nil {
			return l8D2ReadinessBlockAlwaysTerminates(function, value.Body, aliases, facts, environment) && l8D2ReadinessStatementAlwaysTerminates(function, value.Else, aliases, facts, environment)
		}
	case *ast.BlockStmt:
		return l8D2ReadinessBlockAlwaysTerminates(function, value, aliases, facts, environment)
	case *ast.LabeledStmt:
		return l8D2ReadinessStatementAlwaysTerminates(function, value.Stmt, aliases, facts, environment)
	case *ast.ForStmt:
		return value.Cond == nil || l8D2ReadinessStaticallyTrue(value.Cond)
	case *ast.SelectStmt:
		return len(value.Body.List) == 0
	case *ast.BranchStmt:
		return value.Tok == token.GOTO
	}
	return false
}

func l8D2ReadinessStatementNeverReturns(function *ast.FuncDecl, statement ast.Stmt, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if l8D2ReadinessStatementEvaluationNeverReturns(function, statement, aliases, facts, environment) {
		return true
	}
	switch value := statement.(type) {
	case *ast.ExprStmt:
		return false
	case *ast.IfStmt:
		if l8D2ReadinessStaticallyTrue(value.Cond) {
			return l8D2ReadinessBlockNeverReturns(function, value.Body, aliases, facts, environment)
		}
		return value.Else != nil && l8D2ReadinessBlockNeverReturns(function, value.Body, aliases, facts, environment) && l8D2ReadinessStatementNeverReturns(function, value.Else, aliases, facts, environment)
	case *ast.BlockStmt:
		return l8D2ReadinessBlockNeverReturns(function, value, aliases, facts, environment)
	case *ast.LabeledStmt:
		return l8D2ReadinessStatementNeverReturns(function, value.Stmt, aliases, facts, environment)
	case *ast.ForStmt:
		return value.Cond == nil || l8D2ReadinessStaticallyTrue(value.Cond)
	case *ast.SelectStmt:
		return len(value.Body.List) == 0
	case *ast.BranchStmt:
		return value.Tok == token.GOTO
	}
	return false
}

func l8D2ReadinessBlockNeverReturns(function *ast.FuncDecl, block *ast.BlockStmt, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if block == nil {
		return false
	}
	for _, statement := range block.List {
		if l8D2ReadinessStatementNeverReturns(function, statement, aliases, facts, environment) {
			return true
		}
	}
	return false
}

func l8D2ReadinessBlockAlwaysTerminates(function *ast.FuncDecl, block *ast.BlockStmt, aliases map[string]bool, facts l8D2ReadinessTerminalFacts, environment l8D2ReadinessTerminalEnvironment) bool {
	if block == nil {
		return false
	}
	for _, statement := range block.List {
		if l8D2ReadinessStatementAlwaysTerminates(function, statement, aliases, facts, environment) {
			return true
		}
	}
	return false
}

func l8D2ReadinessNoAuthorityAssignmentEscape(function *ast.FuncDecl, boundary token.Pos, allowed map[ast.Stmt]bool, protected []string) bool {
	if function == nil || function.Body == nil {
		return false
	}
	references := func(expression ast.Expr) bool {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if found {
				return false
			}
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			for _, name := range protected {
				if identifier.Name == name {
					found = true
					return false
				}
			}
			return true
		})
		return found
	}
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !valid || node == nil || node.Pos() <= boundary {
			return valid
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			if allowed[value] {
				return false
			}
			for _, expression := range append(append([]ast.Expr(nil), value.Lhs...), value.Rhs...) {
				if references(expression) {
					valid = false
					return false
				}
			}
		case *ast.ValueSpec:
			for _, expression := range value.Values {
				if references(expression) {
					valid = false
					return false
				}
			}
		case *ast.FuncLit:
			if references(value) {
				valid = false
				return false
			}
		}
		return true
	})
	return valid
}

func l8D2ReadinessUniqueDirectLocalExpression(body *ast.BlockStmt, name string, after, before token.Pos) (ast.Expr, ast.Stmt, bool) {
	var result ast.Expr
	var statement ast.Stmt
	total := 0
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for index, left := range assignment.Lhs {
			identifier, ok := left.(*ast.Ident)
			if ok && identifier.Name == name {
				total++
				if assignment.Pos() > after && assignment.Pos() < before && index < len(assignment.Rhs) {
					result = assignment.Rhs[index]
				}
			}
		}
		return true
	})
	for _, candidate := range body.List {
		assignment, ok := candidate.(*ast.AssignStmt)
		if !ok || assignment.Pos() <= after || assignment.Pos() >= before {
			continue
		}
		for index, left := range assignment.Lhs {
			identifier, ok := left.(*ast.Ident)
			if ok && identifier.Name == name && index < len(assignment.Rhs) && assignment.Rhs[index] == result {
				statement = candidate
			}
		}
	}
	return result, statement, total == 1 && result != nil && statement != nil
}

func l8D2ReadinessAuthorityExpressionsImmutableAfter(function *ast.FuncDecl, boundary token.Pos, protected []string, verifiedObservedHelpers bool) bool {
	if function == nil || function.Body == nil {
		return false
	}
	if !l8D2ReadinessPreGateAuthorityAliasesImmutable(function, boundary, protected, "", verifiedObservedHelpers) {
		return false
	}
	aliases := make(map[string]string)
	referencesProtected := func(expression ast.Expr) bool {
		text := types.ExprString(expression)
		for _, root := range protected {
			if text == root || strings.HasPrefix(text, root+".") || strings.HasPrefix(root, text+".") || aliases[text] != "" {
				return true
			}
		}
		return aliases[text] != ""
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.AssignStmt:
				for index, left := range value.Lhs {
					identifier, ok := left.(*ast.Ident)
					if ok && index < len(value.Rhs) && referencesProtected(value.Rhs[index]) && aliases[identifier.Name] == "" {
						aliases[identifier.Name] = types.ExprString(value.Rhs[index])
						changed = true
					}
				}
			case *ast.ValueSpec:
				for index, name := range value.Names {
					if index < len(value.Values) && referencesProtected(value.Values[index]) && aliases[name.Name] == "" {
						aliases[name.Name] = types.ExprString(value.Values[index])
						changed = true
					}
				}
			}
			return true
		})
	}
	immutable := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !immutable || node == nil || node.Pos() <= boundary {
			return immutable
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if referencesProtected(left) {
					immutable = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if referencesProtected(value.X) {
				immutable = false
				return false
			}
		case *ast.CallExpr:
			if selector, ok := value.Fun.(*ast.SelectorExpr); ok && referencesProtected(selector.X) {
				immutable = false
				return false
			}
			for _, argument := range value.Args {
				if referencesProtected(argument) {
					immutable = false
					return false
				}
			}
		}
		return true
	})
	return immutable
}

func l8D2ReadinessExactStdinCandidateOrigins(function *ast.FuncDecl, before token.Pos, receiver, observation, view string) bool {
	want := map[string]string{
		"candidateStdinOffset":  receiver + ".owner.stdinOffset + uint64(" + observation + ".owner.payloadLength)",
		"candidateStdinBytes":   receiver + ".owner.stdinBytes + uint64(" + observation + ".owner.payloadLength)",
		"candidateStdinRecords": receiver + ".owner.stdinRecords + 1",
		"candidateStdinEOF":     observation + ".owner.flags == HelperExecStreamFlagEOF",
	}
	for name, expected := range want {
		expression, statement, ok := l8D2ReadinessUniqueDirectLocalExpressionBefore(function.Body, name, before)
		if !ok || types.ExprString(expression) != expected || statement.Pos() >= before {
			return false
		}
	}
	for name, ownerField := range map[string]string{"candidateStdinHash": "stdinHash", "candidateTranscriptHash": "transcriptHash"} {
		expression, _, ok := l8D2ReadinessUniqueDirectLocalExpressionBefore(function.Body, name, before)
		call, callOK := expression.(*ast.CallExpr)
		if !ok || !callOK || !l8D2ReadinessExactNamedCall(call, "cloneHelperExecSHA256") || len(call.Args) != 1 || types.ExprString(call.Args[0]) != receiver+".owner."+ownerField {
			return false
		}
	}
	linkedToView := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || call.Pos() >= before || len(call.Args) != 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		owner, ownerOK := func() (*ast.Ident, bool) {
			if !ok {
				return nil, false
			}
			identifier, valid := selector.X.(*ast.Ident)
			return identifier, valid
		}()
		if !ownerOK || owner.Name != view || selector.Sel.Name != "WriteTo" {
			return true
		}
		sinkName, sinkOK := call.Args[1].(*ast.Ident)
		if !sinkOK {
			return true
		}
		sinkExpression, _, unique := l8D2ReadinessUniqueDirectLocalExpressionBefore(function.Body, sinkName.Name, call.Pos())
		sinkConstructor, sinkOK := sinkExpression.(*ast.CallExpr)
		if !unique || !sinkOK || !l8D2ReadinessExactNamedCall(sinkConstructor, "newHelperExecObservedStdinSink") || !l8D2ReadinessExactCallArgumentStrings(sinkConstructor, "candidateStdinHash", "candidateTranscriptHash") {
			return true
		}
		linkedToView = true
		return true
	})
	return linkedToView
}

func l8D2ReadinessUniqueDirectLocalExpressionBefore(body *ast.BlockStmt, name string, before token.Pos) (ast.Expr, ast.Stmt, bool) {
	var expression ast.Expr
	var statement ast.Stmt
	total := 0
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || assignment.Pos() >= before {
			return true
		}
		for index, left := range assignment.Lhs {
			identifier, ok := left.(*ast.Ident)
			if ok && identifier.Name == name && index < len(assignment.Rhs) {
				total++
				expression = assignment.Rhs[index]
			}
		}
		return true
	})
	for _, candidate := range body.List {
		assignment, ok := candidate.(*ast.AssignStmt)
		if !ok || assignment.Pos() >= before {
			continue
		}
		for index, left := range assignment.Lhs {
			identifier, ok := left.(*ast.Ident)
			if ok && identifier.Name == name && index < len(assignment.Rhs) && assignment.Rhs[index] == expression {
				statement = candidate
			}
		}
	}
	return expression, statement, total == 1 && expression != nil && statement != nil
}

func l8D2ReadinessUniqueLocalExpressionBefore(body *ast.BlockStmt, name string, before token.Pos) (ast.Expr, bool) {
	var result ast.Expr
	count := 0
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || assignment.Pos() >= before {
			return true
		}
		for index, left := range assignment.Lhs {
			identifier, ok := left.(*ast.Ident)
			if ok && identifier.Name == name && index < len(assignment.Rhs) {
				count++
				result = assignment.Rhs[index]
			}
		}
		return true
	})
	return result, count == 1
}

func l8D2ReadinessLastNamedCallEnd(function *ast.FuncDecl, name string) token.Pos {
	result := token.NoPos
	if function == nil || function.Body == nil {
		return result
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && l8D2ReadinessExactNamedCall(call, name) && call.End() > result {
			result = call.End()
		}
		return true
	})
	return result
}

func l8D2ReadinessSuccessfulAuthorityReturn(function *ast.FuncDecl) (*ast.ReturnStmt, ast.Expr) {
	var returned *ast.ReturnStmt
	count := 0
	if function == nil || function.Body == nil {
		return nil, nil
	}
	for _, statement := range function.Body.List {
		candidate, ok := statement.(*ast.ReturnStmt)
		if ok && len(candidate.Results) == 2 && l8D2ReadinessNilIdentifier(candidate.Results[1]) {
			returned = candidate
			count++
		}
	}
	if returned == nil || count != 1 {
		return nil, nil
	}
	return returned, returned.Results[0]
}

func l8D2ReadinessExactCompositeFields(expression ast.Expr, typeName string, pointer bool) map[string]ast.Expr {
	if expression == nil {
		return nil
	}
	if pointer {
		address, ok := expression.(*ast.UnaryExpr)
		if !ok || address.Op != token.AND {
			return nil
		}
		expression = address.X
	}
	literal, ok := expression.(*ast.CompositeLit)
	if !ok || types.ExprString(literal.Type) != typeName {
		return nil
	}
	fields := make(map[string]ast.Expr)
	for _, element := range literal.Elts {
		keyed, ok := element.(*ast.KeyValueExpr)
		if !ok {
			return nil
		}
		key, ok := keyed.Key.(*ast.Ident)
		if !ok || fields[key.Name] != nil {
			return nil
		}
		fields[key.Name] = keyed.Value
	}
	return fields
}

func l8D2ReadinessAuthorityInputsImmutableAfter(function *ast.FuncDecl, boundary token.Pos, parameters []string, allowedAssignment string, verifiedObservedHelpers bool) bool {
	if !l8D2ReadinessPreGateAuthorityAliasesImmutable(function, boundary, parameters, allowedAssignment, verifiedObservedHelpers) {
		return false
	}
	protected := make(map[string]bool)
	for _, name := range parameters {
		protected[name] = true
	}
	if receiver := l8D2ReadinessAnyReceiverName(function); receiver != "" {
		protected[receiver] = true
	}
	aliases := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.AssignStmt:
				for index, left := range value.Lhs {
					identifier, ok := left.(*ast.Ident)
					if ok && index < len(value.Rhs) && l8D2ReadinessExpressionRootProtected(value.Rhs[index], protected, aliases) && !aliases[identifier.Name] && !protected[identifier.Name] {
						aliases[identifier.Name] = true
						changed = true
					}
				}
			case *ast.ValueSpec:
				for index, name := range value.Names {
					if index < len(value.Values) && l8D2ReadinessExpressionRootProtected(value.Values[index], protected, aliases) && !aliases[name.Name] && !protected[name.Name] {
						aliases[name.Name] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	immutable := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !immutable || node == nil || node.Pos() <= boundary {
			return immutable
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if types.ExprString(left) == allowedAssignment {
					continue
				}
				if l8D2ReadinessExpressionRootProtected(left, protected, aliases) {
					immutable = false
					return false
				}
			}
			for _, right := range value.Rhs {
				if address, ok := right.(*ast.UnaryExpr); ok && address.Op == token.AND && l8D2ReadinessExpressionRootProtected(address.X, protected, aliases) {
					immutable = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if l8D2ReadinessExpressionRootProtected(value.X, protected, aliases) {
				immutable = false
				return false
			}
		case *ast.CallExpr:
			if selector, ok := value.Fun.(*ast.SelectorExpr); ok && l8D2ReadinessExpressionRootProtected(selector.X, protected, aliases) {
				immutable = false
				return false
			}
			for _, argument := range value.Args {
				if l8D2ReadinessExpressionRootProtected(argument, protected, aliases) {
					immutable = false
					return false
				}
			}
		}
		return true
	})
	return immutable
}

func l8D2ReadinessPreGateAuthorityAliasesImmutable(function *ast.FuncDecl, boundary token.Pos, protected []string, allowedAssignment string, verifiedObservedHelpers bool) bool {
	if function == nil || function.Body == nil || boundary == token.NoPos {
		return false
	}
	aliases := make(map[string]bool)
	callableAliases := make(map[string]bool)
	related := func(expression ast.Expr) bool {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if found {
				return false
			}
			candidate, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			text := types.ExprString(candidate)
			if identifier, ok := candidate.(*ast.Ident); ok && aliases[identifier.Name] {
				found = true
				return false
			}
			for _, root := range protected {
				if text == root || strings.HasPrefix(text, root+".") || strings.HasPrefix(root, text+".") {
					found = true
					return false
				}
			}
			return true
		})
		return found
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if node == nil || node.Pos() >= boundary {
				return false
			}
			switch value := node.(type) {
			case *ast.AssignStmt:
				for index, left := range value.Lhs {
					identifier, ok := left.(*ast.Ident)
					var right ast.Expr
					if index < len(value.Rhs) {
						right = value.Rhs[index]
					} else if len(value.Rhs) == 1 {
						right = value.Rhs[0]
					}
					if ok && right != nil && related(right) && !aliases[identifier.Name] {
						aliases[identifier.Name] = true
						changed = true
					}
					if ok && right != nil && l8D2ReadinessCallableCapturesAuthority(function, right, related, callableAliases, verifiedObservedHelpers) && !callableAliases[identifier.Name] {
						callableAliases[identifier.Name] = true
						changed = true
					}
				}
			case *ast.ValueSpec:
				for index, name := range value.Names {
					var expression ast.Expr
					if index < len(value.Values) {
						expression = value.Values[index]
					} else if len(value.Values) == 1 {
						expression = value.Values[0]
					}
					if expression != nil && related(expression) && !aliases[name.Name] {
						aliases[name.Name] = true
						changed = true
					}
					if expression != nil && l8D2ReadinessCallableCapturesAuthority(function, expression, related, callableAliases, verifiedObservedHelpers) && !callableAliases[name.Name] {
						callableAliases[name.Name] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	if len(aliases) == 0 && len(callableAliases) == 0 {
		return true
	}
	immutable := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if !immutable || node == nil || node.Pos() <= boundary {
			return immutable
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, right := range value.Rhs {
				if l8D2ReadinessExpressionCarriesCallableAlias(right, callableAliases) {
					immutable = false
					return false
				}
			}
			for _, left := range value.Lhs {
				leftText := types.ExprString(left)
				if leftText == allowedAssignment || (allowedAssignment == "" && strings.HasSuffix(leftText, ".pending")) {
					continue
				}
				if related(left) {
					immutable = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if related(value.X) {
				immutable = false
				return false
			}
		case *ast.CallExpr:
			if l8D2ReadinessExpressionInvokesCallableAlias(value.Fun, callableAliases) {
				immutable = false
				return false
			}
			if selector, ok := value.Fun.(*ast.SelectorExpr); ok && related(selector.X) {
				immutable = false
				return false
			}
			for _, argument := range value.Args {
				if related(argument) || l8D2ReadinessExpressionCarriesCallableAlias(argument, callableAliases) {
					immutable = false
					return false
				}
			}
		case *ast.SendStmt:
			if related(value.Chan) || related(value.Value) || l8D2ReadinessExpressionCarriesCallableAlias(value.Value, callableAliases) {
				immutable = false
				return false
			}
		case *ast.ReturnStmt:
			for _, result := range value.Results {
				if l8D2ReadinessExpressionCarriesCallableAlias(result, callableAliases) {
					immutable = false
					return false
				}
			}
		case *ast.ValueSpec:
			for _, expression := range value.Values {
				if l8D2ReadinessExpressionCarriesCallableAlias(expression, callableAliases) {
					immutable = false
					return false
				}
			}
		}
		return true
	})
	return immutable
}

func l8D2ReadinessCallableCapturesAuthority(function *ast.FuncDecl, expression ast.Expr, related func(ast.Expr) bool, callableAliases map[string]bool, verifiedObservedHelpers bool) bool {
	recurs := func(candidate ast.Expr) bool {
		return l8D2ReadinessCallableCapturesAuthority(function, candidate, related, callableAliases, verifiedObservedHelpers)
	}
	switch value := expression.(type) {
	case *ast.FuncLit:
		return related(value)
	case *ast.Ident:
		return callableAliases[value.Name]
	case *ast.ParenExpr:
		return recurs(value.X)
	case *ast.TypeAssertExpr:
		return recurs(value.X)
	case *ast.UnaryExpr:
		return recurs(value.X)
	case *ast.StarExpr:
		return recurs(value.X)
	case *ast.SelectorExpr:
		return related(value.X) || recurs(value.X)
	case *ast.IndexExpr:
		return recurs(value.X) || recurs(value.Index)
	case *ast.IndexListExpr:
		if recurs(value.X) {
			return true
		}
		for _, index := range value.Indices {
			if recurs(index) {
				return true
			}
		}
	case *ast.SliceExpr:
		return recurs(value.X) || recurs(value.Low) || recurs(value.High) || recurs(value.Max)
	case *ast.BinaryExpr:
		return false
	case *ast.KeyValueExpr:
		return recurs(value.Key) || recurs(value.Value)
	case *ast.Ellipsis:
		return recurs(value.Elt)
	case *ast.CallExpr:
		argumentsCarry := false
		for _, argument := range value.Args {
			if recurs(argument) {
				argumentsCarry = true
			}
		}
		if verifiedObservedHelpers && l8D2ReadinessExactAuthorityCloneOrSinkCall(function, value) {
			return false
		}
		return argumentsCarry || recurs(value.Fun)
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			candidate := ast.Expr(nil)
			switch item := element.(type) {
			case *ast.KeyValueExpr:
				candidate = item.Value
			case ast.Expr:
				candidate = item
			}
			if candidate != nil && recurs(candidate) {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessExactAuthorityCloneOrSinkCall(function *ast.FuncDecl, call *ast.CallExpr) bool {
	if function == nil || function.Name.Name != "ProposeObservedStdin" || call == nil {
		return false
	}
	called, direct := call.Fun.(*ast.Ident)
	if !direct || l8D2ReadinessNameShadowedInFunction(function, called.Name) {
		return false
	}
	receiver := l8D2ReadinessAnyReceiverName(function)
	switch called.Name {
	case "cloneHelperExecSHA256":
		if len(call.Args) != 1 {
			return false
		}
		argument := types.ExprString(call.Args[0])
		return argument == receiver+".owner.stdinHash" || argument == receiver+".owner.transcriptHash"
	case "newHelperExecObservedStdinSink":
		return len(call.Args) == 2 && types.ExprString(call.Args[0]) == "candidateStdinHash" && types.ExprString(call.Args[1]) == "candidateTranscriptHash"
	}
	return false
}

func l8D2ReadinessExactObservedStdinHelperImplementations(declarations []*ast.FuncDecl) bool {
	var clones, sinks []*ast.FuncDecl
	for _, declaration := range declarations {
		if declaration == nil || declaration.Recv != nil {
			continue
		}
		switch declaration.Name.Name {
		case "cloneHelperExecSHA256":
			clones = append(clones, declaration)
		case "newHelperExecObservedStdinSink":
			sinks = append(sinks, declaration)
		}
	}
	return len(clones) == 1 && len(sinks) == 1 && l8D2ReadinessExactHelperExecSHA256Clone(clones[0]) && l8D2ReadinessExactObservedStdinSinkConstructor(sinks[0])
}

func l8D2ReadinessExactHelperExecSHA256Clone(function *ast.FuncDecl) bool {
	parameters := l8D2ReadinessNamedParameters(function)
	if function == nil || function.Body == nil || len(parameters) != 1 || types.ExprString(parameters[0].typ) != "*helperExecSHA256" || function.Type.Results == nil || len(function.Type.Results.List) != 1 || types.ExprString(function.Type.Results.List[0].Type) != "*helperExecSHA256" || len(function.Body.List) != 3 {
		return false
	}
	owner := parameters[0].name
	nilGate, ok := function.Body.List[0].(*ast.IfStmt)
	if !ok || nilGate.Init != nil || nilGate.Else != nil || types.ExprString(nilGate.Cond) != owner+" == nil" || len(nilGate.Body.List) != 1 {
		return false
	}
	nilReturn, ok := nilGate.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(nilReturn.Results) != 1 || !l8D2ReadinessNilIdentifier(nilReturn.Results[0]) {
		return false
	}
	cloneAssignment, ok := function.Body.List[1].(*ast.AssignStmt)
	if !ok || cloneAssignment.Tok != token.DEFINE || len(cloneAssignment.Lhs) != 1 || len(cloneAssignment.Rhs) != 1 {
		return false
	}
	clone, cloneOK := cloneAssignment.Lhs[0].(*ast.Ident)
	dereference, dereferenceOK := cloneAssignment.Rhs[0].(*ast.StarExpr)
	if !cloneOK || !dereferenceOK || types.ExprString(dereference.X) != owner {
		return false
	}
	returned, ok := function.Body.List[2].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	address, ok := returned.Results[0].(*ast.UnaryExpr)
	return ok && address.Op == token.AND && types.ExprString(address.X) == clone.Name
}

func l8D2ReadinessExactObservedStdinSinkConstructor(function *ast.FuncDecl) bool {
	parameters := l8D2ReadinessNamedParameters(function)
	if function == nil || function.Body == nil || len(parameters) != 2 || types.ExprString(parameters[0].typ) != "*helperExecSHA256" || types.ExprString(parameters[1].typ) != "*helperExecSHA256" || function.Type.Results == nil || len(function.Type.Results.List) != 1 || types.ExprString(function.Type.Results.List[0].Type) != "*helperExecObservedStdinSink" || len(function.Body.List) != 1 {
		return false
	}
	returned, ok := function.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	fields := l8D2ReadinessExactCompositeFields(returned.Results[0], "helperExecObservedStdinSink", true)
	return len(fields) == 2 && types.ExprString(fields["stdin"]) == parameters[0].name && types.ExprString(fields["transcript"]) == parameters[1].name
}

func l8D2ReadinessNameShadowedInFunction(function *ast.FuncDecl, name string) bool {
	if function == nil || name == "" {
		return true
	}
	shadowed := false
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, parameter := range field.Names {
				shadowed = shadowed || parameter.Name == name
			}
		}
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if shadowed {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if identifier, ok := left.(*ast.Ident); ok && identifier.Name == name {
					shadowed = true
				}
			}
		case *ast.ValueSpec:
			for _, identifier := range value.Names {
				shadowed = shadowed || identifier.Name == name
			}
		}
		return !shadowed
	})
	return shadowed
}

func l8D2ReadinessExpressionInvokesCallableAlias(expression ast.Expr, callableAliases map[string]bool) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		return callableAliases[value.Name]
	case *ast.ParenExpr:
		return l8D2ReadinessExpressionInvokesCallableAlias(value.X, callableAliases)
	case *ast.TypeAssertExpr:
		return l8D2ReadinessExpressionInvokesCallableAlias(value.X, callableAliases)
	case *ast.IndexExpr:
		return l8D2ReadinessExpressionInvokesCallableAlias(value.X, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.Index, callableAliases)
	case *ast.IndexListExpr:
		if l8D2ReadinessExpressionInvokesCallableAlias(value.X, callableAliases) {
			return true
		}
		for _, index := range value.Indices {
			if l8D2ReadinessExpressionCarriesCallableAlias(index, callableAliases) {
				return true
			}
		}
	case *ast.SliceExpr:
		return l8D2ReadinessExpressionInvokesCallableAlias(value.X, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.Low, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.High, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.Max, callableAliases)
	case *ast.SelectorExpr:
		return l8D2ReadinessExpressionInvokesCallableAlias(value.X, callableAliases)
	case *ast.UnaryExpr:
		return l8D2ReadinessExpressionInvokesCallableAlias(value.X, callableAliases)
	case *ast.StarExpr:
		return l8D2ReadinessExpressionInvokesCallableAlias(value.X, callableAliases)
	case *ast.CallExpr:
		if l8D2ReadinessExpressionInvokesCallableAlias(value.Fun, callableAliases) {
			return true
		}
		for _, argument := range value.Args {
			if l8D2ReadinessExpressionCarriesCallableAlias(argument, callableAliases) {
				return true
			}
		}
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			if l8D2ReadinessExpressionCarriesCallableAlias(element, callableAliases) {
				return true
			}
		}
	}
	return false
}

func l8D2ReadinessExpressionCarriesCallableAlias(expression ast.Expr, callableAliases map[string]bool) bool {
	if expression == nil {
		return false
	}
	if l8D2ReadinessExpressionInvokesCallableAlias(expression, callableAliases) {
		return true
	}
	switch value := expression.(type) {
	case *ast.UnaryExpr:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.X, callableAliases)
	case *ast.StarExpr:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.X, callableAliases)
	case *ast.ParenExpr:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.X, callableAliases)
	case *ast.TypeAssertExpr:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.X, callableAliases)
	case *ast.SelectorExpr:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.X, callableAliases)
	case *ast.IndexExpr:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.X, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.Index, callableAliases)
	case *ast.IndexListExpr:
		if l8D2ReadinessExpressionCarriesCallableAlias(value.X, callableAliases) {
			return true
		}
		for _, index := range value.Indices {
			if l8D2ReadinessExpressionCarriesCallableAlias(index, callableAliases) {
				return true
			}
		}
	case *ast.SliceExpr:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.X, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.Low, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.High, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.Max, callableAliases)
	case *ast.BinaryExpr:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.X, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.Y, callableAliases)
	case *ast.KeyValueExpr:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.Key, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(value.Value, callableAliases)
	case *ast.Ellipsis:
		return l8D2ReadinessExpressionCarriesCallableAlias(value.Elt, callableAliases)
	case *ast.CallExpr:
		if l8D2ReadinessExpressionCarriesCallableAlias(value.Fun, callableAliases) {
			return true
		}
		for _, argument := range value.Args {
			if l8D2ReadinessExpressionCarriesCallableAlias(argument, callableAliases) {
				return true
			}
		}
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			switch item := element.(type) {
			case *ast.KeyValueExpr:
				if l8D2ReadinessExpressionCarriesCallableAlias(item.Key, callableAliases) || l8D2ReadinessExpressionCarriesCallableAlias(item.Value, callableAliases) {
					return true
				}
			case ast.Expr:
				if l8D2ReadinessExpressionCarriesCallableAlias(item, callableAliases) {
					return true
				}
			}
		}
	}
	return false
}

func l8D2ReadinessExpressionRootProtected(expression ast.Expr, protected, aliases map[string]bool) bool {
	for {
		switch value := expression.(type) {
		case *ast.Ident:
			return protected[value.Name] || aliases[value.Name]
		case *ast.SelectorExpr:
			expression = value.X
		case *ast.IndexExpr:
			expression = value.X
		case *ast.ParenExpr:
			expression = value.X
		case *ast.StarExpr:
			expression = value.X
		case *ast.UnaryExpr:
			expression = value.X
		default:
			return false
		}
	}
}

func l8D2ReadinessFunctionParameterNames(function *ast.FuncDecl) []string {
	var result []string
	if function == nil || function.Type.Params == nil {
		return result
	}
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			result = append(result, name.Name)
		}
	}
	return result
}

func l8D2ReadinessAnyReceiverName(function *ast.FuncDecl) string {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 || len(function.Recv.List[0].Names) != 1 {
		return ""
	}
	return function.Recv.List[0].Names[0].Name
}

func l8D2ReadinessEveryNamedHelperCallMatches(function *ast.FuncDecl, helper string, match func(*ast.CallExpr, map[string]ast.Expr) bool) bool {
	if function == nil || function.Body == nil {
		return false
	}
	total, valid := 0, 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && l8D2ReadinessExactNamedCall(call, helper) {
			total++
			aliases, unique := l8D2ReadinessLocalValueAliasesBefore(function.Body, call.Pos())
			if unique && match(call, aliases) {
				valid++
			}
		}
		return true
	})
	return total > 0 && total == valid
}

func l8D2ReadinessLocalValueAliasesBefore(body *ast.BlockStmt, before token.Pos) (map[string]ast.Expr, bool) {
	result := make(map[string]ast.Expr)
	counts := make(map[string]int)
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || assignment.Pos() >= before {
			return true
		}
		for index, left := range assignment.Lhs {
			identifier, identifierOK := left.(*ast.Ident)
			if identifierOK && identifier.Name != "_" && index < len(assignment.Rhs) {
				result[identifier.Name] = assignment.Rhs[index]
				counts[identifier.Name]++
			}
		}
		return true
	})
	for name, count := range counts {
		if count != 1 {
			delete(result, name)
			return result, false
		}
	}
	return result, true
}

func l8D2ReadinessExactCallArgumentStrings(call *ast.CallExpr, first, second string) bool {
	return call != nil && len(call.Args) == 2 && types.ExprString(call.Args[0]) == first && types.ExprString(call.Args[1]) == second
}

func l8D2ReadinessExactExpandedCallArguments(call *ast.CallExpr, aliases map[string]ast.Expr, first, second string) bool {
	return call != nil && len(call.Args) == 2 && l8D2ReadinessExpandedExpression(call.Args[0], aliases) == first && l8D2ReadinessExpandedExpression(call.Args[1], aliases) == second
}

func l8D2ReadinessExpandedExpression(expression ast.Expr, aliases map[string]ast.Expr) string {
	var expand func(ast.Expr, map[string]bool) string
	expand = func(value ast.Expr, stack map[string]bool) string {
		switch candidate := value.(type) {
		case *ast.Ident:
			if alias, ok := aliases[candidate.Name]; ok && !stack[candidate.Name] {
				stack[candidate.Name] = true
				result := expand(alias, stack)
				delete(stack, candidate.Name)
				return result
			}
			return candidate.Name
		case *ast.SelectorExpr:
			return expand(candidate.X, stack) + "." + candidate.Sel.Name
		case *ast.ParenExpr:
			return expand(candidate.X, stack)
		default:
			return types.ExprString(value)
		}
	}
	return expand(expression, make(map[string]bool))
}

func l8D2ReadinessDigestComesFromExactBorrowedView(function *ast.FuncDecl, digest ast.Expr, contextName, viewName string, aliases map[string]ast.Expr) bool {
	digestName, ok := digest.(*ast.Ident)
	if !ok {
		return false
	}
	digestSource, ok := aliases[digestName.Name].(*ast.CallExpr)
	if !ok || len(digestSource.Args) != 0 {
		return false
	}
	digestSelector, ok := digestSource.Fun.(*ast.SelectorExpr)
	sink, sinkOK := digestSelector.X.(*ast.Ident)
	if !ok || !sinkOK || digestSelector.Sel.Name != "Sum256" {
		return false
	}
	writes := 0
	var writePosition, digestPosition token.Pos
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 {
			identifier, identifierOK := assignment.Lhs[0].(*ast.Ident)
			if identifierOK && identifier.Name == digestName.Name && assignment.Rhs[0] == digestSource {
				digestPosition = assignment.Pos()
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		owner, ownerOK := selector.X.(*ast.Ident)
		if ownerOK && owner.Name == viewName && selector.Sel.Name == "WriteTo" && types.ExprString(call.Args[0]) == contextName && types.ExprString(call.Args[1]) == sink.Name {
			writes++
			writePosition = call.Pos()
		}
		return true
	})
	return writes == 1 && writePosition != token.NoPos && digestPosition != token.NoPos && writePosition < digestPosition
}

func l8D2ReadinessExactNamedCall(call *ast.CallExpr, name string) bool {
	if call == nil {
		return false
	}
	called, ok := call.Fun.(*ast.Ident)
	return ok && called.Name == name
}

func l8D2ReadinessCanonicalCallName(expression ast.Expr, aliases map[string]string) string {
	switch called := expression.(type) {
	case *ast.Ident:
		return called.Name
	case *ast.SelectorExpr:
		owner, ok := called.X.(*ast.Ident)
		if !ok {
			return ""
		}
		if aliases[owner.Name] == "crypto/subtle" {
			return "subtle." + called.Sel.Name
		}
		return owner.Name + "." + called.Sel.Name
	default:
		return ""
	}
}

func assertL8D2ReadinessExecClaimTransferBoundary(t *testing.T, path string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, content, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.Name == "NewReceivedExecPacket" {
			target = function
			break
		}
	}
	if target == nil || target.Body == nil {
		t.Error("missing NewReceivedExecPacket ownership-transfer body")
		return
	}
	functionText := string(content[fileSet.Position(target.Pos()).Offset:fileSet.Position(target.End()).Offset])
	for _, required := range []string{
		"transportContextPrecondition(ctx)",
		"claimed := false",
		"if success || !claimed",
		"claimErr := plan.claimAndMatch(decoded.Plan, &claimed)",
		"if !claimed",
		"failedReceivedInputs(ctx, request, body, nil, err)",
		"plan.destroy()",
	} {
		if !strings.Contains(functionText, required) {
			t.Errorf("NewReceivedExecPacket omits claim-transfer marker %q", required)
		}
	}
	for _, forbidden := range []string{"context.Background()", "context.TODO()"} {
		if strings.Contains(functionText, forbidden) {
			t.Errorf("NewReceivedExecPacket uses forbidden cleanup context %q", forbidden)
		}
	}
	preconditionOffset := strings.Index(functionText, "transportContextPrecondition(ctx)")
	claimOffset := strings.Index(functionText, "claimErr := plan.claimAndMatch(decoded.Plan, &claimed)")
	packetOffset := strings.Index(functionText, "newReceivedPacket(ctx, request")
	if preconditionOffset < 0 || claimOffset < 0 || preconditionOffset >= claimOffset {
		t.Error("NewReceivedExecPacket does not classify context before plan claim")
	}
	if claimOffset < 0 || packetOffset < 0 || claimOffset >= packetOffset {
		t.Error("NewReceivedExecPacket does not claim plan before request/body admission")
	}
	var claimPosition token.Pos
	ast.Inspect(target.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "claimAndMatch" && claimPosition == token.NoPos {
			claimPosition = call.Pos()
		}
		return true
	})
	for _, statement := range target.Body.List {
		if claimPosition != token.NoPos && statement.Pos() >= claimPosition {
			break
		}
		if _, deferred := statement.(*ast.DeferStmt); deferred {
			continue
		}
		statementText := string(content[fileSet.Position(statement.Pos()).Offset:fileSet.Position(statement.End()).Offset])
		for _, forbidden := range []string{"request.state", "body.Borrow", "body.Destroy", "right.Close", "newReceivedPacket("} {
			if strings.Contains(statementText, forbidden) {
				t.Errorf("NewReceivedExecPacket touches request/body/right before plan claim through %q", forbidden)
			}
		}
	}
}

func assertL8D2ReadinessLeadingContextConstructor(t *testing.T, dir, functionName string) {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			aliases, _ := l8D2ReadinessImportAliases(file)
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Recv != nil || function.Name.Name != functionName {
					continue
				}
				if function.Type.Params == nil || len(function.Type.Params.List) == 0 {
					t.Errorf("%s omits leading context.Context", functionName)
					return
				}
				selector, ok := function.Type.Params.List[0].Type.(*ast.SelectorExpr)
				if !ok {
					t.Errorf("%s first parameter is not context.Context", functionName)
					return
				}
				owner, ownerOK := selector.X.(*ast.Ident)
				if !ownerOK || aliases[owner.Name] != "context" || selector.Sel.Name != "Context" {
					t.Errorf("%s first parameter is not context.Context", functionName)
				}
				return
			}
		}
	}
	t.Errorf("credentialhelper production omits constructor %s", functionName)
}
