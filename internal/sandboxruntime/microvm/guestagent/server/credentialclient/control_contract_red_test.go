package credentialclient

import (
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
	receive, err := newControlReceiveRequest(1, v2control.NewIdentityDigest(sessionID), false, session.MaxControlPlaintextBytes)
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
