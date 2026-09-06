package firecrackerhost

import (
	"bytes"
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
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8JobCredentialHandleRecordRoundTripOmitsSecretsAndHostPaths(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	_, identity, _ := l8JobCredentialRuntimePrepareFixture(t, now)
	record, err := l8JobCredentialHandleRecordFromManifests(identity, 1, []l8JobCredentialGuestBindingManifest{
		{BindingID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeHTTPProxy, ServiceID: "azure-openai-responses-v1"},
		{BindingID: identity.BindingIDs[1], Mode: sandboxruntime.JobCredentialDeliveryModeFileTmpfs, TargetPath: identity.BindingIDs[1], DeclaredFileBytes: 9, FileSHA256: strings.Repeat("ab", 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeL8JobCredentialHandleRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"sk_live", "OPENAI_API_KEY", "secret-bytes", "/tmp/", "/private/", ".hal",
		"ticket", "BEGIN", "ssh-rsa",
	} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("handle record JSON leaked %q: %s", forbidden, payload)
		}
	}
	decoded, err := decodeL8JobCredentialHandleRecord(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindL8JobCredentialHandleRecord(decoded, identity); err != nil {
		t.Fatal(err)
	}
	if decoded.Revision != 1 || decoded.Bindings[0].ServiceID != "azure-openai-responses-v1" || decoded.Bindings[1].TargetPath != identity.BindingIDs[1] {
		t.Fatalf("decoded record = %#v", decoded)
	}

	rawPath := record
	rawPath.Bindings[1].TargetPath = "/private/tmpfs/secret"
	if _, err := encodeL8JobCredentialHandleRecord(rawPath); !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("host path target = %v", err)
	}
}

func TestL8JobCredentialMemoryHandleStoreMissingIdentityStaysUnaccepted(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	_, identity, _ := l8JobCredentialRuntimePrepareFixture(t, now)
	store := newL8JobCredentialMemoryHandleStore()
	record, present, err := store.Load(context.Background(), identity)
	if present || err != nil || record.Revision != 0 {
		t.Fatalf("empty store load = %#v present=%t err=%v", record, present, err)
	}

	saved, err := l8JobCredentialHandleRecordFromManifests(identity, 1, []l8JobCredentialGuestBindingManifest{
		{BindingID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeHTTPProxy, ServiceID: "azure-openai-responses-v1"},
		{BindingID: identity.BindingIDs[1], Mode: sandboxruntime.JobCredentialDeliveryModeFileTmpfs, TargetPath: identity.BindingIDs[1], DeclaredFileBytes: 4, FileSHA256: strings.Repeat("cd", 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), saved); err != nil {
		t.Fatal(err)
	}
	loaded, present, err := store.Load(context.Background(), identity)
	if err != nil || !present || loaded.Revision != 1 {
		t.Fatalf("saved load = %#v present=%t err=%v", loaded, present, err)
	}

	neighbor := identity
	neighbor.WorkerJobID = "job-neighbor"
	missing, present, err := store.Load(context.Background(), neighbor)
	if present || err != nil || missing.Revision != 0 {
		t.Fatalf("neighbor load = %#v present=%t err=%v", missing, present, err)
	}
}

func TestL8JobCredentialHandleStoreConstructorRemainsDefaultOff(t *testing.T) {
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
		if strings.Contains(filepath.ToSlash(path), "l8_job_credential_handle_store.go") {
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
			if name == "NewProductionL8JobCredentialHandleStore" {
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
		t.Fatalf("production NewProductionL8JobCredentialHandleStore callers = %d, want zero", callers)
	}
	runtimeSource, err := os.ReadFile("l8_job_credential_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(runtimeSource, []byte("NewProductionL8JobCredentialHandleStore")) {
		t.Fatal("NewProductionL8JobCredentialRuntime constructs a handle store")
	}
	for _, name := range []string{"adapter.go", "live_driver.go", "l7_live_composition.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"NewProductionL8JobCredentialHandleStore", "l8JobCredentialLinuxHandleStore"} {
			if bytes.Contains(source, []byte(forbidden)) {
				t.Fatalf("%s wires handle store marker %q", name, forbidden)
			}
		}
	}
}

type l8JobCredentialMemoryHandleStore struct {
	mu      sync.Mutex
	records map[[32]byte]l8JobCredentialHandleRecordV1
}

func newL8JobCredentialMemoryHandleStore() *l8JobCredentialMemoryHandleStore {
	return &l8JobCredentialMemoryHandleStore{records: map[[32]byte]l8JobCredentialHandleRecordV1{}}
}

func (store *l8JobCredentialMemoryHandleStore) Save(ctx context.Context, record l8JobCredentialHandleRecordV1) error {
	if store == nil || l8JobCredentialRuntimeValueIsNil(ctx) {
		return ErrL8JobCredentialRuntimeInvalid
	}
	if ctx.Err() != nil {
		return ErrL8JobCredentialRuntimeUnavailable
	}
	if err := validateL8JobCredentialHandleRecordShape(record); err != nil {
		return err
	}
	digest, err := l8JobCredentialHandleDigestFromRecord(record)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.records == nil {
		store.records = map[[32]byte]l8JobCredentialHandleRecordV1{}
	}
	cloned := record
	cloned.Bindings = append([]l8JobCredentialStoredBindingV1(nil), record.Bindings...)
	store.records[digest] = cloned
	return nil
}

func (store *l8JobCredentialMemoryHandleStore) Load(ctx context.Context, identity sandboxruntime.JobCredentialIdentity) (l8JobCredentialHandleRecordV1, bool, error) {
	if store == nil || l8JobCredentialRuntimeValueIsNil(ctx) {
		return l8JobCredentialHandleRecordV1{}, false, ErrL8JobCredentialRuntimeInvalid
	}
	if ctx.Err() != nil {
		return l8JobCredentialHandleRecordV1{}, false, ErrL8JobCredentialRuntimeUnavailable
	}
	digest, err := sandboxruntime.JobCredentialIdentityDigest(identity)
	if err != nil {
		return l8JobCredentialHandleRecordV1{}, false, sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, present := store.records[digest]
	if !present {
		return l8JobCredentialHandleRecordV1{}, false, nil
	}
	if err := bindL8JobCredentialHandleRecord(record, identity); err != nil {
		return l8JobCredentialHandleRecordV1{}, false, err
	}
	cloned := record
	cloned.Bindings = append([]l8JobCredentialStoredBindingV1(nil), record.Bindings...)
	return cloned, true, nil
}

func (store *l8JobCredentialMemoryHandleStore) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (store *l8JobCredentialMemoryHandleStore) String() string {
	return l8JobCredentialHandleStoreValuePlaceholder
}
func (store *l8JobCredentialMemoryHandleStore) GoString() string {
	return l8JobCredentialHandleStoreValuePlaceholder
}
func (store *l8JobCredentialMemoryHandleStore) Format(state fmt.State, verb rune) {
	redactL8JobCredentialHandleStore(state, verb)
}

func TestL8JobCredentialMemoryHandleStoreRedactsAndDeniesSerialization(t *testing.T) {
	store := newL8JobCredentialMemoryHandleStore()
	if encoded, err := json.Marshal(store); err == nil || encoded != nil || !errors.Is(err, ErrL8JobCredentialRuntimeSerialization) {
		t.Fatalf("json.Marshal(memory store) = %q, %v", encoded, err)
	}
	for _, rendered := range []string{fmt.Sprint(store), fmt.Sprintf("%#v", store), fmt.Sprintf("%+v", store)} {
		if rendered != l8JobCredentialHandleStoreValuePlaceholder {
			t.Fatalf("format memory store = %q", rendered)
		}
	}
}

var (
	_ l8JobCredentialHandleStore         = (*l8JobCredentialMemoryHandleStore)(nil)
	_ l8JobCredentialStoredHandleRevoker = (*l8JobCredentialHTTPProxyFake)(nil)
	_ l8JobCredentialStoredHandleRevoker = (*l8JobCredentialFileTmpfsFake)(nil)
	_ l8JobCredentialStoredHandleRevoker = (*l8JobCredentialSSHRelayFake)(nil)
)
