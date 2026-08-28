package credentialclient

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

func TestL8D6GuestPacketIssuersRemainPackagePrivate(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	protected := map[string]bool{
		"ControllerReceiveRequest": true, "ControllerPacket": true, "ControllerSendPacket": true,
		"HelperReceiveRequest": true, "HelperPacket": true, "HelperSendPacket": true,
		"controllerBodyCapability": true, "helperBodyCapability": true, "bodySegmentSink": true,
		"transportIdentity": true,
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !ast.IsExported(function.Name.Name) {
				continue
			}
			referencesProtected := false
			ast.Inspect(function.Type, func(node ast.Node) bool {
				identifier, ok := node.(*ast.Ident)
				if ok && protected[identifier.Name] {
					referencesProtected = true
				}
				return !referencesProtected
			})
			if referencesProtected {
				t.Fatalf("%s exports packet issuance or observation through %s", entry.Name(), function.Name.Name)
			}
		}
	}

	allowedMethods := map[string]bool{
		"Format": true, "GoString": true, "MarshalBinary": true, "MarshalJSON": true,
		"MarshalText": true, "String": true, "UnmarshalBinary": true, "UnmarshalJSON": true,
		"UnmarshalText": true,
	}
	for _, value := range []any{ControllerReceiveRequest{}, ControllerPacket{}, ControllerSendPacket{}, HelperReceiveRequest{}, HelperPacket{}, HelperSendPacket{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumMethod(); index++ {
			if method := typeOf.Method(index); !allowedMethods[method.Name] {
				t.Fatalf("%s exports functional packet method %s", typeOf.Name(), method.Name)
			}
		}
	}
}

func TestL8D6GuestPacketAuthorityHasNoLegacyParallelConstructors(t *testing.T) {
	for _, name := range []string{
		"newControllerReceiveRequest", "newControllerPacket", "newControllerSendPacket",
		"newHelperReceiveRequest", "newHelperPacket", "newHelperSendPacket",
	} {
		if _, ok := reflect.TypeOf(struct{}{}).MethodByName(name); ok {
			t.Fatalf("unexpected reflected method %s", name)
		}
	}
	source, err := os.ReadFile("contracts.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"newControllerReceiveRequest", "newControllerPacket", "newControllerSendPacket",
		"newHelperReceiveRequest", "newHelperPacket", "newHelperSendPacket",
	} {
		if strings.Contains(string(source), "func "+name+"(") {
			t.Fatalf("contracts.go retains parallel packet constructor %s", name)
		}
	}
}

func TestL8D6GuestPacketAuthorityHasNoExternalProductionReferences(t *testing.T) {
	repositoryRoot := guestControlRepositoryRoot(t)
	protected := map[string]bool{
		"ControllerReceiveRequest": true, "ControllerPacket": true, "ControllerSendPacket": true,
		"HelperReceiveRequest": true, "HelperPacket": true, "HelperSendPacket": true,
		"ControllerBodyCapability": true, "HelperBodyCapability": true, "BodySegmentSink": true,
		"AuthenticatedTransport": true, "TransportIdentity": true,
		"NewControlAcceptExpectation": true, "NewTransportIdentity": true,
		"NewControllerReceiveRequest": true, "NewHelperReceiveRequest": true,
		"NewControllerUnknownOperationPacket": true, "NewControllerMalformedKnownPacket": true,
		"NewControllerReadinessPacket": true, "NewControllerPreparePacket": true,
		"NewControllerRenewPacket": true, "NewControllerRevokePacket": true,
		"NewControllerExecPacket": true, "NewControllerPrivatePacket": true,
		"NewControllerStreamPacket": true, "NewControllerCreditPacket": true,
		"NewControllerCloseNotifyPacket": true, "NewHelperResponsePacket": true,
		"NewHelperEventPacket": true, "NewHelperExecStreamPacket": true,
		"NewHelperExecCreditPacket": true, "NewHelperSSHAcceptedPacket": true,
		"NewHelperCloseNotifyPacket": true,
	}
	const credentialClientImport = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		aliases := map[string]bool{}
		for _, imported := range file.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil || importPath != credentialClientImport {
				continue
			}
			alias := "credentialclient"
			if imported.Name != nil {
				alias = imported.Name.Name
			}
			aliases[alias] = true
		}
		var forbidden string
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return forbidden == ""
			}
			qualifier, qualifierOK := selector.X.(*ast.Ident)
			if qualifierOK && aliases[qualifier.Name] && protected[selector.Sel.Name] {
				forbidden = selector.Sel.Name
				return false
			}
			return forbidden == ""
		})
		if forbidden != "" {
			t.Fatalf("%s references package-private credential packet authority %s", path, forbidden)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func guestControlRepositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("repository root not found")
		}
		directory = parent
	}
}

func TestL8D6GuestControlContractHasNoSocketCreationAuthority(t *testing.T) {
	source, err := os.ReadFile("control_contract_red.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		`"net"`, `"os"`, `"syscall"`, `"golang.org/x/sys/unix"`,
		"net.Listen(", "ListenConfig", "unix.Bind(", "syscall.Bind(", "unix.Socket(", "os.NewFile(",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("guest control contract contains forbidden socket authority %q", forbidden)
		}
	}
}

func TestL8D6GuestControlOwnerIsVerifiedPreopenedAndFixedPort(t *testing.T) {
	owner := reflect.TypeOf((*ControlConnectionOwner)(nil)).Elem()
	if owner.NumMethod() != 2 || owner.Method(0).Name != "AcceptVerified" || owner.Method(1).Name != "Close" {
		t.Fatalf("ControlConnectionOwner methods = %v, want exact AcceptVerified/Close", owner)
	}
	stream := reflect.TypeOf((*VerifiedControlStream)(nil)).Elem()
	for _, forbidden := range []string{"Bind", "Listen", "Dial", "Accept"} {
		if _, ok := stream.MethodByName(forbidden); ok {
			t.Fatalf("VerifiedControlStream exposes forbidden %s authority", forbidden)
		}
	}

	identity := testControlSessionIdentity()
	expectation, err := newControlAcceptExpectation(identity)
	if err != nil {
		t.Fatalf("newControlAcceptExpectation() error = %v", err)
	}
	if expectation.Identity() != identity || expectation.Identity().GuestPort != session.ControlPort {
		t.Fatal("control accept expectation did not pin exact port-1025 identity")
	}
}

func TestL8D6GuestTransportIdentityIsImmutableAndFullyCorrelated(t *testing.T) {
	identity := testControlSessionIdentity()
	var sessionID [32]byte
	sessionID[0] = 1
	hardExpiry := time.Unix(1_700_000_000, 0).UTC()
	transportIdentity, err := newTransportIdentity(sessionID, identity, hardExpiry, "helper-generation-1")
	if err != nil {
		t.Fatalf("newTransportIdentity() error = %v", err)
	}
	if transportIdentity.sessionIDValue() != sessionID || transportIdentity.sessionIdentity() != identity ||
		!transportIdentity.hardExpiryValue().Equal(hardExpiry) || transportIdentity.helperGenerationValue() != credentialprotocol.SafeID("helper-generation-1") {
		t.Fatal("authenticated transport identity lost correlation")
	}
}

func TestL8D6GuestControllerUnionConsumesOneExactReceiveRequest(t *testing.T) {
	identity := testControlSessionIdentity()
	var sessionID [32]byte
	sessionID[0] = 1
	requestID, err := v2control.NewRequestID([16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := v2control.NewReadinessRequest(requestID, v2control.NewIdentityDigest(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	receive, err := newControlReceiveRequest(1, v2control.NewIdentityDigest(sessionID), true, session.MaxControlPlaintextBytes)
	if err != nil {
		t.Fatalf("newControlReceiveRequest() error = %v", err)
	}
	packet, err := newControllerReadinessPacket(receive, 1, sessionID, readiness)
	if err != nil {
		t.Fatalf("newControllerReadinessPacket() error = %v", err)
	}
	arm, ok := packet.readinessValue()
	if !ok || arm.RequestID() != requestID || packet.sequenceValue() != 1 || packet.sessionIDValue() != sessionID || identity.GuestPort != session.ControlPort {
		t.Fatal("controller packet did not retain exact typed ownership")
	}
	if _, err := newControllerReadinessPacket(receive, 1, sessionID, readiness); err == nil {
		t.Fatal("receive request was consumed twice")
	}
}

func TestL8D6GuestControllerCredentialPacketsMirrorReadinessDiscipline(t *testing.T) {
	sessionID := testCredentialPacketSessionID()
	identity := testCredentialPacketSessionIdentity(t, sessionID)
	digest := identityDigestForSession(t, identity)
	requestID := testPacketRequestID(t)
	prepare := testCredentialPreparePacketRequest(t, requestID, identity)
	renew := testCredentialRenewPacketRequest(t, requestID, identity)
	revoke := testCredentialRevokePacketRequest(t, requestID, identity)
	execReq := testCredentialExecPacketRequest(t, requestID, identity)
	otherSessionID := testCredentialPacketSessionID()
	otherSessionID[31] ^= 0xff

	type issueFn func(ControllerReceiveRequest, uint64, [32]byte) (ControllerPacket, error)
	cases := []struct {
		name    string
		digest  v2control.IdentityDigest
		issue   issueFn
		inspect func(ControllerPacket) bool
		zero    issueFn
	}{
		{
			name:   "prepare",
			digest: digest,
			issue: func(receive ControllerReceiveRequest, sequence uint64, id [32]byte) (ControllerPacket, error) {
				return newControllerPreparePacket(receive, sequence, id, prepare)
			},
			inspect: func(packet ControllerPacket) bool {
				arm, ok := packet.prepareValue()
				return ok && arm.RequestID() == requestID && arm.IdentityDigest() == digest
			},
			zero: func(receive ControllerReceiveRequest, sequence uint64, id [32]byte) (ControllerPacket, error) {
				return newControllerPreparePacket(receive, sequence, id, v2control.CredentialPrepareRequest{})
			},
		},
		{
			name:   "renew",
			digest: digest,
			issue: func(receive ControllerReceiveRequest, sequence uint64, id [32]byte) (ControllerPacket, error) {
				return newControllerRenewPacket(receive, sequence, id, renew)
			},
			inspect: func(packet ControllerPacket) bool {
				arm, ok := packet.renewValue()
				return ok && arm.RequestID() == requestID && arm.IdentityDigest() == digest
			},
			zero: func(receive ControllerReceiveRequest, sequence uint64, id [32]byte) (ControllerPacket, error) {
				return newControllerRenewPacket(receive, sequence, id, v2control.CredentialRenewRequest{})
			},
		},
		{
			name:   "revoke",
			digest: digest,
			issue: func(receive ControllerReceiveRequest, sequence uint64, id [32]byte) (ControllerPacket, error) {
				return newControllerRevokePacket(receive, sequence, id, revoke)
			},
			inspect: func(packet ControllerPacket) bool {
				arm, ok := packet.revokeValue()
				return ok && arm.RequestID() == requestID && arm.IdentityDigest() == digest
			},
			zero: func(receive ControllerReceiveRequest, sequence uint64, id [32]byte) (ControllerPacket, error) {
				return newControllerRevokePacket(receive, sequence, id, v2control.CredentialRevokeRequest{})
			},
		},
		{
			name:   "exec",
			digest: digest,
			issue: func(receive ControllerReceiveRequest, sequence uint64, id [32]byte) (ControllerPacket, error) {
				return newControllerExecPacket(receive, sequence, id, execReq)
			},
			inspect: func(packet ControllerPacket) bool {
				arm, ok := packet.execValue()
				return ok && arm.RequestID() == requestID && arm.IdentityDigest() == digest
			},
			zero: func(receive ControllerReceiveRequest, sequence uint64, id [32]byte) (ControllerPacket, error) {
				return newControllerExecPacket(receive, sequence, id, v2control.CredentialExecRequest{})
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name+"/happy", func(t *testing.T) {
			receive := mustControlReceiveRequest(t, 1, digest, true)
			packet, err := test.issue(receive, 1, sessionID)
			if err != nil {
				t.Fatalf("issue() error = %v", err)
			}
			if !test.inspect(packet) || packet.sequenceValue() != 1 || packet.sessionIDValue() != sessionID {
				t.Fatal("controller packet did not retain exact typed ownership")
			}
			if _, err := test.issue(receive, 1, sessionID); !errors.Is(err, errInvalidControlReceiveRequest) {
				t.Fatalf("consume-once error = %v", err)
			}
		})
		t.Run(test.name+"/first-prepare-identity-unset", func(t *testing.T) {
			if test.name != "prepare" {
				return
			}
			receive := mustControlReceiveRequest(t, 1, v2control.IdentityDigest{}, false)
			packet, err := test.issue(receive, 1, sessionID)
			if err != nil || !test.inspect(packet) {
				t.Fatalf("unset expected identity issue() = %v packet ok=%v", err, test.inspect(packet))
			}
		})
		t.Run(test.name+"/sequence-mismatch", func(t *testing.T) {
			receive := mustControlReceiveRequest(t, 1, digest, true)
			if _, err := test.issue(receive, 2, sessionID); !errors.Is(err, errInvalidControllerPacket) {
				t.Fatalf("sequence mismatch error = %v", err)
			}
			if _, err := test.issue(receive, 1, sessionID); !errors.Is(err, errInvalidControlReceiveRequest) {
				t.Fatalf("failed issue did not consume receive request: %v", err)
			}
		})
		t.Run(test.name+"/identity-mismatch", func(t *testing.T) {
			receive := mustControlReceiveRequest(t, 1, digest, true)
			if _, err := test.issue(receive, 1, otherSessionID); !errors.Is(err, errInvalidControllerPacket) {
				t.Fatalf("session identity mismatch error = %v", err)
			}
		})
		t.Run(test.name+"/expected-identity-mismatch", func(t *testing.T) {
			receive := mustControlReceiveRequest(t, 1, v2control.NewIdentityDigest(sessionID), true)
			if _, err := test.issue(receive, 1, sessionID); !errors.Is(err, errInvalidControllerPacket) {
				t.Fatalf("expected identity mismatch error = %v", err)
			}
		})
		t.Run(test.name+"/validator-failure", func(t *testing.T) {
			receive := mustControlReceiveRequest(t, 1, digest, true)
			if _, err := test.zero(receive, 1, sessionID); !errors.Is(err, errInvalidControllerPacket) {
				t.Fatalf("validator failure error = %v", err)
			}
		})
	}
}

func TestL8D6GuestControllerSendPacketsWriteCanonicalJSON(t *testing.T) {
	sessionID := testCredentialPacketSessionID()
	identity := testCredentialPacketSessionIdentity(t, sessionID)
	requestID := testPacketRequestID(t)
	prepareReq := testCredentialPreparePacketRequest(t, requestID, identity)
	renewReq := testCredentialRenewPacketRequest(t, requestID, identity)
	revokeReq := testCredentialRevokePacketRequest(t, requestID, identity)
	execReq := testCredentialExecPacketRequest(t, requestID, identity)
	prepareResp := testCredentialPreparePacketResponse(t, prepareReq)
	renewResp := mustCredentialRenewSuccess(t, renewReq)
	revokeResp := mustCredentialRevokeSuccess(t, revokeReq)
	execResp := mustCredentialExecSuccess(t, execReq)

	readinessReq, err := v2control.NewReadinessRequest(requestID, v2control.NewIdentityDigest(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	readinessResp, err := v2control.NewReadinessSuccessResponse(readinessReq, "helper-generation-1")
	if err != nil {
		t.Fatal(err)
	}

	type sendCase struct {
		name   string
		issue  func() (ControllerSendPacket, error)
		want   []byte
		access func(ControllerSendPacket) bool
	}
	cases := []sendCase{
		{
			name: "readiness",
			issue: func() (ControllerSendPacket, error) {
				return newControllerReadinessSendPacket(1, sessionID, readinessResp)
			},
			want: mustEncode(t, func() ([]byte, error) { return v2control.EncodeReadinessSuccessResponse(readinessResp) }),
			access: func(packet ControllerSendPacket) bool {
				arm, ok := packet.readinessResponseValue()
				return ok && arm.RequestID() == requestID
			},
		},
		{
			name: "prepare",
			issue: func() (ControllerSendPacket, error) {
				return newControllerPrepareSendPacket(1, sessionID, prepareResp)
			},
			want: mustEncode(t, func() ([]byte, error) { return v2control.EncodeCredentialPrepareSuccessResponse(prepareResp) }),
			access: func(packet ControllerSendPacket) bool {
				arm, ok := packet.prepareResponseValue()
				return ok && arm.RequestID() == requestID
			},
		},
		{
			name: "renew",
			issue: func() (ControllerSendPacket, error) {
				return newControllerRenewSendPacket(1, sessionID, renewResp)
			},
			want: mustEncode(t, func() ([]byte, error) { return v2control.EncodeCredentialRenewSuccessResponse(renewResp) }),
			access: func(packet ControllerSendPacket) bool {
				arm, ok := packet.renewResponseValue()
				return ok && arm.RequestID() == requestID
			},
		},
		{
			name: "revoke",
			issue: func() (ControllerSendPacket, error) {
				return newControllerRevokeSendPacket(1, sessionID, revokeResp)
			},
			want: mustEncode(t, func() ([]byte, error) { return v2control.EncodeCredentialRevokeSuccessResponse(revokeResp) }),
			access: func(packet ControllerSendPacket) bool {
				arm, ok := packet.revokeResponseValue()
				return ok && arm.RequestID() == requestID
			},
		},
		{
			name: "exec",
			issue: func() (ControllerSendPacket, error) {
				return newControllerExecSendPacket(1, sessionID, execResp)
			},
			want: mustEncode(t, func() ([]byte, error) { return v2control.EncodeCredentialExecSuccessResponse(execResp) }),
			access: func(packet ControllerSendPacket) bool {
				arm, ok := packet.execResponseValue()
				return ok && arm.RequestID() == requestID
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			packet, err := test.issue()
			if err != nil {
				t.Fatalf("send constructor error = %v", err)
			}
			if !test.access(packet) || packet.sequenceValue() != 1 || packet.sessionIDValue() != sessionID {
				t.Fatal("send packet did not retain exact typed ownership")
			}
			if packet.encodedBodyLengthValue() != uint32(len(test.want)) || packet.bodySHA256Value() != sha256.Sum256(test.want) {
				t.Fatal("send packet did not pin canonical body length and digest")
			}
			sink := &testCanonicalBodySink{capacity: packet.encodedBodyLengthValue()}
			if err := packet.writeCanonicalBody(sink); err != nil {
				t.Fatalf("writeCanonicalBody() error = %v", err)
			}
			if string(sink.buf) != string(test.want) {
				t.Fatalf("canonical body = %s, want %s", sink.buf, test.want)
			}
			if test.access(packet) {
				t.Fatal("consumed send packet still exposed typed arm")
			}
			if err := packet.writeCanonicalBody(sink); !errors.Is(err, errInvalidControllerSendPacket) {
				t.Fatalf("second writeCanonicalBody() error = %v", err)
			}
		})
	}

	if _, err := newControllerPrepareSendPacket(1, sessionID, v2control.CredentialPrepareSuccessResponse{}); !errors.Is(err, errInvalidControllerSendPacket) {
		t.Fatalf("invalid prepare send error = %v", err)
	}
	if err := (ControllerSendPacket{}).writeCanonicalBody(&testCanonicalBodySink{capacity: 1}); !errors.Is(err, ErrClientControlDependencyUnaccepted) && !errors.Is(err, errInvalidControllerSendPacket) {
		t.Fatalf("zero send packet write error = %v", err)
	}
}

func TestL8D6GuestControllerRemainingPacketsStayUnaccepted(t *testing.T) {
	receive := mustControlReceiveRequest(t, 1, v2control.IdentityDigest{}, false)
	var sessionID [32]byte
	sessionID[0] = 1
	if _, err := newControllerUnknownOperationPacket(receive, 1, sessionID, v2control.InspectedRequest{}); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("unknown packet error = %v", err)
	}
	if _, err := newControllerMalformedKnownPacket(receive, 1, sessionID, v2control.InspectedRequest{}); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("malformed packet error = %v", err)
	}
	if _, err := newControllerPrivatePacket(receive, 1, sessionID, 0, v2control.RequestID{}, v2control.IdentityDigest{}, 0, 0, 0, 0, [32]byte{}, nil); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("private packet error = %v", err)
	}
	if _, err := newControllerStreamPacket(receive, 1, sessionID, 0, 0, v2control.RequestID{}, v2control.IdentityDigest{}, 0, 0, [32]byte{}, nil); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("stream packet error = %v", err)
	}
	if _, err := newControllerCreditPacket(receive, 1, sessionID, 0, v2control.RequestID{}, v2control.IdentityDigest{}, 0); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("credit packet error = %v", err)
	}
	if _, err := newControllerCloseNotifyPacket(receive, 1, sessionID, 0); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("close notify packet error = %v", err)
	}
	if _, err := newHelperControlReceiveRequest(1, 1, 0, [16]byte{}, false, [32]byte{}); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("helper receive error = %v", err)
	}
	if _, err := newHelperResponsePacket(HelperReceiveRequest{}, credentialprotocol.HelperPacketHeader{}, nil, credentialprotocol.HelperResponseBody{}); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("helper response error = %v", err)
	}
	if err := (HelperSendPacket{}).writeCanonicalBody(nil); !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("helper writeCanonicalBody error = %v", err)
	}
}

func TestL8D6GuestPacketUnionsFreezeCompletePrivateOwnership(t *testing.T) {
	assertPrivateFields(t, ControllerReceiveRequest{}, "liveValue", "nextSequence", "expectedIdentity", "expectedIdentitySet", "maximumPlaintextBytes", "state")
	assertPrivateFields(t, ControllerPacket{}, "liveValue", "sequence", "sessionID", "arm", "body")
	assertPrivateFields(t, ControllerSendPacket{}, "liveValue", "sequence", "sessionID", "arm", "encodedBodyLength", "bodySHA256", "state")
	assertPrivateFields(t, HelperReceiveRequest{}, "liveValue", "nextSequence", "maximumBodyBytes", "maximumRights", "expectedRequestID", "expectedRequestIDSet", "expectedIdentity", "state")
	assertPrivateFields(t, HelperPacket{}, "liveValue", "header", "arm", "body", "right")
	assertPrivateFields(t, HelperSendPacket{}, "liveValue", "header", "arm", "encodedBodyLength", "bodySHA256", "state")
	assertPrivateFields(t, helperSendArm{}, "kind", "prepareBegin", "prepareFile", "prepareCommit", "renew", "revoke", "exec", "execPrivate", "execStream", "execCredit", "close")

	for _, value := range []any{ControlAcceptExpectation{}, transportIdentity{}} {
		assertFailsClosed(t, value)
	}
}

func assertPrivateFields(t *testing.T, value any, expected ...string) {
	t.Helper()
	typeOf := reflect.TypeOf(value)
	if typeOf.NumField() != len(expected) {
		t.Fatalf("%s field count = %d, want %d", typeOf.Name(), typeOf.NumField(), len(expected))
	}
	for index, name := range expected {
		field := typeOf.Field(index)
		if field.Name != name || field.PkgPath == "" {
			t.Fatalf("%s field %d = %#v, want private %q", typeOf.Name(), index, field, name)
		}
	}
}

func testControlSessionIdentity() session.Identity {
	var nonce, image [32]byte
	for index := range nonce {
		nonce[index] = byte(index + 1)
		image[index] = byte(index + 33)
	}
	return session.Identity{
		Channel:                      session.ChannelControl,
		GuestBootNonce:               nonce,
		GuestCID:                     session.GuestCID,
		GuestPort:                    session.ControlPort,
		ControllerKeyGeneration:      "controller-key-generation-1",
		RuntimeID:                    "runtime-1",
		RuntimeGeneration:            "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1",
		VsockGeneration:              "vsock-generation-1",
		BootGeneration:               "boot-generation-1",
		ImageGeneration:              "image-generation-1",
		ImageSHA256:                  image,
	}
}

func mustControlReceiveRequest(t *testing.T, sequence uint64, identity v2control.IdentityDigest, identitySet bool) ControllerReceiveRequest {
	t.Helper()
	receive, err := newControlReceiveRequest(sequence, identity, identitySet, session.MaxControlPlaintextBytes)
	if err != nil {
		t.Fatal(err)
	}
	return receive
}

func testCredentialPacketSessionID() [32]byte {
	var sessionID [32]byte
	for index := range sessionID {
		sessionID[index] = byte(index)
	}
	return sessionID
}

func testPacketRequestID(t *testing.T) v2control.RequestID {
	t.Helper()
	var raw [16]byte
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	requestID, err := v2control.NewRequestID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return requestID
}

func testCredentialPacketSessionIdentity(t *testing.T, sessionID [32]byte) v2control.GuestCredentialSessionIdentity {
	t.Helper()
	identity, err := v2control.GuestCredentialSessionIdentityFromRoot(sessionID, testCredentialPacketRoot(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func identityDigestForSession(t *testing.T, identity v2control.GuestCredentialSessionIdentity) v2control.IdentityDigest {
	t.Helper()
	digest, err := v2control.GuestCredentialSessionIdentityDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	return v2control.NewIdentityDigest(digest)
}

func testCredentialPacketRoot(sessionID [32]byte) sandboxruntime.JobCredentialIdentity {
	return sandboxruntime.JobCredentialIdentity{
		SandboxID: "sandbox-1", ExecutionID: "execution-1", WorkerID: "worker-1", HostID: "host-1",
		RuntimeDriver: "microvm", RuntimeID: "runtime-1", RuntimeGeneration: "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1", VsockGeneration: "vsock-generation-1",
		WorkerJobID: "worker-job-1", SubmissionID: "submission-1", PlanID: "plan-1",
		ActivationGeneration: "activation-generation-1", CredentialGeneration: "credential-generation-1",
		NetworkPlanID: "network-plan-1", PolicySnapshotID: "policy-snapshot-1", ProxySessionID: "proxy-session-1",
		ProxyGenerationID: "proxy-generation-1", TopologyGenerationID: "topology-generation-1", RuleGenerationID: "rule-generation-1",
		AdmissionGrantID: "grant-1", PrincipalID: "principal-1", TemplatePolicyID: "template-policy-1", WorkspacePolicyID: "workspace-policy-1",
		ControllerKeyGeneration: "controller-key-generation-1", GuestBootGeneration: "guest-boot-generation-1",
		GuestImageGeneration:   "guest-image-generation-1",
		GuestImageDigest:       "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		GuestSessionGeneration: base64.RawURLEncoding.EncodeToString(sessionID[:]), GuestHelperGeneration: "helper-generation-1",
		AdmissionGrantRevision: 7, IssuedAt: time.Unix(0, 1700000000123456789).UTC(),
		BindingIDs: []string{"binding-http", "binding-file"},
		DeliveryModes: []sandboxruntime.JobCredentialDeliveryMode{
			sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
			sandboxruntime.JobCredentialDeliveryModeFileTmpfs,
		},
	}
}

func testCredentialPreparePacketRequest(t *testing.T, requestID v2control.RequestID, identity v2control.GuestCredentialSessionIdentity) v2control.CredentialPrepareRequest {
	t.Helper()
	httpBinding, err := v2control.NewHTTPBindingManifest("binding-http", "azure-openai-responses-v1")
	if err != nil {
		t.Fatal(err)
	}
	fileBinding, err := v2control.NewFileBindingManifest("binding-file", "credentials/config", 7, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	request, err := v2control.NewCredentialPrepareRequest(requestID, identity, 1, 1700000001123456789, []v2control.BindingManifest{httpBinding, fileBinding}, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testCredentialPreparePacketResponse(t *testing.T, request v2control.CredentialPrepareRequest) v2control.CredentialPrepareSuccessResponse {
	t.Helper()
	proofs := []v2control.BindingProof{
		mustPacketBindingProof(t, "binding-http", v2control.DeliveryMode("http_proxy"), "proof-http"),
		mustPacketBindingProof(t, "binding-file", v2control.DeliveryMode("file_tmpfs"), "proof-file"),
	}
	response, err := v2control.NewCredentialPrepareSuccessResponse(request, 1, 1700000001123456789, "active-proof", "exec-binding", proofs)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func mustPacketBindingProof(t *testing.T, bindingID string, mode v2control.DeliveryMode, proofID string) v2control.BindingProof {
	t.Helper()
	proof, err := v2control.NewBindingProof(bindingID, mode, proofID)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func testCredentialRenewPacketRequest(t *testing.T, requestID v2control.RequestID, identity v2control.GuestCredentialSessionIdentity) v2control.CredentialRenewRequest {
	t.Helper()
	request, err := v2control.NewCredentialRenewRequest(requestID, identity, 8, 1700000600123456789, 1700001200123456789, 1700001800123456789, "active-proof-8")
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func mustCredentialRenewSuccess(t *testing.T, request v2control.CredentialRenewRequest) v2control.CredentialRenewSuccessResponse {
	t.Helper()
	response, err := v2control.NewCredentialRenewSuccessResponse(request, "replacement-proof-9")
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func testCredentialRevokePacketRequest(t *testing.T, requestID v2control.RequestID, identity v2control.GuestCredentialSessionIdentity) v2control.CredentialRevokeRequest {
	t.Helper()
	request, err := v2control.NewCredentialRevokeRequest(requestID, identity, 9, v2control.CredentialRevokeReasonRequested)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func mustCredentialRevokeSuccess(t *testing.T, request v2control.CredentialRevokeRequest) v2control.CredentialRevokeSuccessResponse {
	t.Helper()
	response, err := v2control.NewCredentialRevokeSuccessResponse(request, "cleanup-proof-9")
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func testCredentialExecPacketRequest(t *testing.T, requestID v2control.RequestID, identity v2control.GuestCredentialSessionIdentity) v2control.CredentialExecRequest {
	t.Helper()
	const proxyURL = "http://proxy-runtime/.well-known/hal/credential-http/v1/azure-openai-responses-v1/deployments/model-1"
	correlation, err := v2control.NewCredentialExecCorrelation(identity, 3, "exec-binding-3", true, proxyURL, 1, 321, strings.Repeat("a", 64), 1700000000000, 1700001800000, 1700001900000)
	if err != nil {
		t.Fatal(err)
	}
	env := []v2control.ExecEnvironment{mustPacketExecEnvironment(t, "MODE", v2control.ExecEnvironmentLiteral, "batch")}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env = append(env, mustPacketExecEnvironment(t, name, v2control.ExecEnvironmentGenerated, proxyURL))
	}
	timing, err := v2control.NewExecTiming(v2control.ExecTimingTimeoutMillis, 30000)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := v2control.NewExecPlan([]string{"/usr/bin/tool", "run"}, env, "/workspace", 1024, 2048, 4096, timing)
	if err != nil {
		t.Fatal(err)
	}
	request, err := v2control.NewCredentialExecRequest(requestID, correlation, plan)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func mustPacketExecEnvironment(t *testing.T, name string, source v2control.ExecEnvironmentSource, value string) v2control.ExecEnvironment {
	t.Helper()
	env, err := v2control.NewExecEnvironment(name, source, value)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func mustCredentialExecSuccess(t *testing.T, request v2control.CredentialExecRequest) v2control.CredentialExecSuccessResponse {
	t.Helper()
	empty := sha256.Sum256(nil)
	response, err := v2control.NewCredentialExecSuccessResponse(request, 0,
		0, hex.EncodeToString(empty[:]),
		1, strings.Repeat("b", 64), false,
		1, strings.Repeat("c", 64), false,
		strings.Repeat("d", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func mustEncode(t *testing.T, encode func() ([]byte, error)) []byte {
	t.Helper()
	body, err := encode()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type testCanonicalBodySink struct {
	capacity uint32
	buf      []byte
}

func (sink *testCanonicalBodySink) Capacity() uint32 { return sink.capacity }

func (sink *testCanonicalBodySink) WriteSegment(offset uint32, source []byte) error {
	if sink.buf == nil {
		sink.buf = make([]byte, sink.capacity)
	}
	if uint64(offset)+uint64(len(source)) > uint64(len(sink.buf)) {
		return errInvalidControllerSendPacket
	}
	copy(sink.buf[offset:], source)
	return nil
}
