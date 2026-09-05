package firecrackerhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialproxy"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8JobCredentialHTTPActivatorIssuesTicketAndExposesSafeServiceID(t *testing.T) {
	store, activator := l8JobCredentialHTTPActivatorForTest(t)
	identity, binding, source := l8JobCredentialHTTPActivatorFixture(t)

	handle, err := activator.Activate(context.Background(), identity, binding, source)
	if err != nil || l8JobCredentialRuntimeValueIsNil(handle) {
		t.Fatalf("Activate = %#v, %v", handle, err)
	}
	if got := handle.ServiceID(); got != binding.ServiceID || got != string(credentialproxy.ServiceIDAzureOpenAIResponsesV1) {
		t.Fatalf("ServiceID = %q, want binding service id", got)
	}
	owned, ok := handle.(*productionL8JobCredentialHTTPProxyHandle)
	if !ok || owned.ticket == nil {
		t.Fatal("Activate did not retain a TicketStore ticket")
	}
	if owned.correlation.BindingID != binding.ID || owned.correlation.ServiceID != credentialproxy.ServiceIDAzureOpenAIResponsesV1 {
		t.Fatalf("ticket correlation = %#v", owned.correlation)
	}
	if err := store.Validate(context.Background(), owned.ticket, owned.correlation); err != nil {
		t.Fatalf("TicketStore.Validate after Activate: %v", err)
	}
	if source.(*l8JobCredentialHTTPActivatorSecretSource).fills != 0 {
		t.Fatal("Activate consumed LiveSecretSource")
	}
}

func TestL8JobCredentialHTTPActivatorRejectsNonHTTPAndInvalidIdentity(t *testing.T) {
	_, activator := l8JobCredentialHTTPActivatorForTest(t)
	identity, binding, source := l8JobCredentialHTTPActivatorFixture(t)

	tmpfs := binding
	tmpfs.Mode = sandboxruntime.JobCredentialDeliveryModeFileTmpfs
	if handle, err := activator.Activate(context.Background(), identity, tmpfs, source); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeUnsupported) {
		t.Fatalf("tmpfs mode = %#v, %v", handle, err)
	}

	empty := binding
	empty.Mode = ""
	if handle, err := activator.Activate(context.Background(), identity, empty, source); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("empty mode = %#v, %v", handle, err)
	}

	unknownService := binding
	unknownService.ServiceID = "other-service-v1"
	if handle, err := activator.Activate(context.Background(), identity, unknownService, source); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeUnsupported) {
		t.Fatalf("unknown service = %#v, %v", handle, err)
	}

	rawService := binding
	rawService.ServiceID = "https://unsafe.invalid/raw-secret"
	handle, err := activator.Activate(context.Background(), identity, rawService, source)
	if !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("raw service = %#v, %v", handle, err)
	}
	l8JobCredentialHTTPActivatorAssertSafeError(t, err)

	neighbor := binding
	neighbor.ID = "binding-neighbor"
	if handle, err := activator.Activate(context.Background(), identity, neighbor, source); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("neighbor binding = %#v, %v", handle, err)
	}

	partial := identity
	partial.RuntimeGeneration = ""
	if handle, err := activator.Activate(context.Background(), partial, binding, source); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("partial identity = %#v, %v", handle, err)
	}

	var typedNilSource *l8JobCredentialHTTPActivatorSecretSource
	if handle, err := activator.Activate(context.Background(), identity, binding, typedNilSource); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("typed-nil source = %#v, %v", handle, err)
	}
}

func TestL8JobCredentialHTTPActivatorRenewAndRevokeUseTicketStore(t *testing.T) {
	store, activator := l8JobCredentialHTTPActivatorForTest(t)
	identity, binding, source := l8JobCredentialHTTPActivatorFixture(t)
	handle, err := activator.Activate(context.Background(), identity, binding, source)
	if err != nil {
		t.Fatal(err)
	}
	owned := handle.(*productionL8JobCredentialHTTPProxyHandle)
	if err := handle.Renew(context.Background()); err != nil {
		t.Fatalf("Renew = %v", err)
	}
	if err := store.Validate(context.Background(), owned.ticket, owned.correlation); err != nil {
		t.Fatalf("Validate after Renew: %v", err)
	}
	if err := handle.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke = %v", err)
	}
	if owned.ticket != nil || !owned.revoked {
		t.Fatal("successful Revoke retained ticket ownership")
	}
	if err := handle.Renew(context.Background()); !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("Renew after Revoke = %v", err)
	}
	if err := handle.Revoke(context.Background()); err != nil {
		t.Fatalf("idempotent Revoke = %v", err)
	}
}

func TestL8JobCredentialHTTPActivatorFailedRevokeRetainsOwnership(t *testing.T) {
	store, activator := l8JobCredentialHTTPActivatorForTest(t)
	identity, binding, source := l8JobCredentialHTTPActivatorFixture(t)
	handle, err := activator.Activate(context.Background(), identity, binding, source)
	if err != nil {
		t.Fatal(err)
	}
	owned := handle.(*productionL8JobCredentialHTTPProxyHandle)
	ticket := owned.ticket
	if err := store.Close(context.Background()); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := handle.Revoke(context.Background()); !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("Revoke after store close = %v, want invalid", err)
	}
	if owned.revoked || owned.ticket != ticket {
		t.Fatal("failed Revoke dropped ticket ownership")
	}
}

func TestL8JobCredentialHTTPActivatorNilTypedNilAndPanicFailClosed(t *testing.T) {
	identity, binding, source := l8JobCredentialHTTPActivatorFixture(t)
	var typedNilActivator *ProductionL8JobCredentialHTTPProxyActivator
	if handle, err := typedNilActivator.Activate(context.Background(), identity, binding, source); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("typed-nil activator = %#v, %v", handle, err)
	}

	_, activator := l8JobCredentialHTTPActivatorForTest(t)
	if handle, err := activator.Activate(nil, identity, binding, source); !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("nil context = %#v, %v", handle, err)
	}

	activator.now = func() time.Time {
		panic("sk_live=/private/http-activator.sock")
	}
	handle, err := activator.Activate(context.Background(), identity, binding, source)
	if !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialRuntimeUnavailable) {
		t.Fatalf("panic now = %#v, %v", handle, err)
	}
	l8JobCredentialHTTPActivatorAssertSafeError(t, err)

	var typedNilHandle *productionL8JobCredentialHTTPProxyHandle
	if typedNilHandle.ServiceID() != "" {
		t.Fatal("typed-nil handle ServiceID leaked a value")
	}
	if err := typedNilHandle.Renew(context.Background()); !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("typed-nil Renew = %v", err)
	}
	if err := typedNilHandle.Revoke(context.Background()); !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("typed-nil Revoke = %v", err)
	}
}

func TestL8JobCredentialHTTPActivatorRedactsSecretsAndDeniesSerialization(t *testing.T) {
	store, activator := l8JobCredentialHTTPActivatorForTest(t)
	identity, binding, source := l8JobCredentialHTTPActivatorFixture(t)
	source.(*l8JobCredentialHTTPActivatorSecretSource).payload = []byte("sk_live=/private/http-activator.sock")
	handle, err := activator.Activate(context.Background(), identity, binding, source)
	if err != nil {
		t.Fatal(err)
	}

	values := []any{
		activator,
		*activator,
		handle,
		ProductionL8JobCredentialHTTPProxyActivator{},
		&ProductionL8JobCredentialHTTPProxyActivator{},
		&productionL8JobCredentialHTTPProxyHandle{},
	}
	for _, value := range values {
		encoded, marshalErr := json.Marshal(value)
		if marshalErr == nil || encoded != nil || !errors.Is(marshalErr, ErrL8JobCredentialRuntimeSerialization) {
			t.Fatalf("json.Marshal(%T) = %q, %v", value, encoded, marshalErr)
		}
		for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), fmt.Sprintf("%+v", value)} {
			if rendered != l8JobCredentialHTTPActivatorValuePlaceholder {
				t.Fatalf("format %T = %q", value, rendered)
			}
			l8JobCredentialHTTPActivatorAssertSafeText(t, rendered)
		}
	}

	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	revokeErr := handle.Revoke(context.Background())
	if !errors.Is(revokeErr, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("closed-store Revoke = %v", revokeErr)
	}
	l8JobCredentialHTTPActivatorAssertSafeError(t, revokeErr)
}

func TestL8JobCredentialHTTPActivatorConstructorRejectsInvalidConfig(t *testing.T) {
	store, err := credentialproxy.NewTicketStore("daemon-generation-01")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	valid := ProductionL8JobCredentialHTTPProxyActivatorConfig{
		Store: store, CatalogGeneration: "catalog-generation-01", ListenerGeneration: 7,
		LocalAuthority: "runtime-credential.internal:8080",
	}
	if _, err := NewProductionL8JobCredentialHTTPProxyActivator(valid); err != nil {
		t.Fatalf("valid config: %v", err)
	}

	missingStore := valid
	missingStore.Store = nil
	if activator, err := NewProductionL8JobCredentialHTTPProxyActivator(missingStore); activator != nil || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("missing store = %#v, %v", activator, err)
	}

	rawAuthority := valid
	rawAuthority.LocalAuthority = "https://unsafe.invalid/secret"
	if activator, err := NewProductionL8JobCredentialHTTPProxyActivator(rawAuthority); activator != nil || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("raw authority = %#v, %v", activator, err)
	}
}

func TestL8JobCredentialRuntimeUsesProductionHTTPActivator(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	clock := &l8JobCredentialRuntimeClock{now: now.Add(time.Second)}
	_, activator := l8JobCredentialHTTPActivatorForTest(t)
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy})
	guest := l8JobCredentialGuestSessionFakeForTest(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest}, activator, nil, nil)
	runtime.deps.Now = clock.Now
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	identity := preflight.Identity()
	request := l8JobCredentialRuntimePrepareRequest(t, identity)
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil || l8JobCredentialRuntimeValueIsNil(session) {
		t.Fatalf("prepare with production HTTP activator = %#v, %v", session, err)
	}
	if len(guest.lastManifests) != 1 || guest.lastManifests[0].ServiceID != string(credentialproxy.ServiceIDAzureOpenAIResponsesV1) {
		t.Fatalf("guest HTTP manifest = %#v", guest.lastManifests)
	}
	clock.now = now.Add(2 * time.Second)
	if _, err := session.Renew(context.Background()); err != nil {
		t.Fatalf("runtime Renew: %v", err)
	}
	if _, err := session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested")); err != nil {
		t.Fatalf("runtime Revoke: %v", err)
	}
}

func TestProductionL8JobCredentialHTTPProxyActivatorRemainsDefaultOff(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	set := token.NewFileSet()
	callers := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(set, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				name = function.Name
			case *ast.SelectorExpr:
				name = function.Sel.Name
			}
			if name == "NewProductionL8JobCredentialHTTPProxyActivator" {
				callers++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers != 0 {
		t.Fatalf("production NewProductionL8JobCredentialHTTPProxyActivator callers = %d, want zero", callers)
	}

	for _, name := range []string{"adapter.go", "live_driver.go", "l7_live_composition.go", "l8_job_credential_runtime.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), "NewProductionL8JobCredentialHTTPProxyActivator") {
			t.Fatalf("%s wires production HTTP activator constructor", name)
		}
	}
}

func l8JobCredentialHTTPActivatorForTest(t *testing.T) (*credentialproxy.TicketStore, *ProductionL8JobCredentialHTTPProxyActivator) {
	t.Helper()
	store, err := credentialproxy.NewTicketStore("daemon-generation-01")
	if err != nil {
		t.Fatalf("NewTicketStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	activator, err := NewProductionL8JobCredentialHTTPProxyActivator(ProductionL8JobCredentialHTTPProxyActivatorConfig{
		Store: store, CatalogGeneration: "catalog-generation-01", ListenerGeneration: 7,
		LocalAuthority: "runtime-credential.internal:8080",
	})
	if err != nil {
		t.Fatalf("NewProductionL8JobCredentialHTTPProxyActivator: %v", err)
	}
	return store, activator
}

func l8JobCredentialHTTPActivatorFixture(t *testing.T) (sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialBindingRequest, sandboxruntime.LiveSecretSource) {
	t.Helper()
	now := l8JobCredentialRuntimeNow()
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy})
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	request := l8JobCredentialRuntimePrepareRequest(t, identity)
	source := &l8JobCredentialHTTPActivatorSecretSource{payload: []byte("sk_live=/private/http-activator.sock")}
	return identity, request.Admission.Bindings[0], source
}

func l8JobCredentialHTTPActivatorAssertSafeError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	l8JobCredentialHTTPActivatorAssertSafeText(t, err.Error())
}

func l8JobCredentialHTTPActivatorAssertSafeText(t *testing.T, text string) {
	t.Helper()
	for _, forbidden := range []string{
		"sk_live", "OPENAI_API_KEY", "/private/", "http-activator.sock",
		"unsafe.invalid", "runtime-credential.internal", "raw-secret",
		"secret-bytes", "helper-generation-runtime",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("leaked %q: %q", forbidden, text)
		}
	}
}

type l8JobCredentialHTTPActivatorSecretSource struct {
	payload []byte
	fills   int
}

func (source *l8JobCredentialHTTPActivatorSecretSource) FillSecret(_ context.Context, sink sandboxruntime.JobCredentialSecretSink) error {
	source.fills++
	if source.payload == nil {
		panic("sk_live=/private/http-activator.sock")
	}
	if len(source.payload) > sink.MaxCredentialBytes() {
		return ErrL8JobCredentialRuntimeInvalid
	}
	return sink.WriteCredential(source.payload)
}
