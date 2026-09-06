//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeLockRejectsIncompleteAndAmbiguousDocuments(t *testing.T) {
	original, err := os.ReadFile("../native-sources.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	root := pin{SHA256: "ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58"}
	for _, scenario := range []string{"valid", "null", "trailing", "unknown", "duplicate_key", "case_alias", "missing", "extra", "traversal", "changed_upstream", "wrong_tree_buildroot"} {
		t.Run(scenario, func(t *testing.T) {
			data := append([]byte(nil), original...)
			var lock map[string]any
			if json.Unmarshal(data, &lock) != nil {
				t.Fatal("fixture")
			}
			switch scenario {
			case "null":
				data = []byte("null")
			case "trailing":
				data = append(data, []byte("{}")...)
			case "duplicate_key":
				data = []byte(strings.Replace(string(data), `"schemaVersion":`, `"schemaVersion":"forged","schemaVersion":`, 1))
			case "case_alias":
				data = []byte(strings.Replace(string(data), `"schemaVersion":`, `"SchemaVersion":`, 1))
			default:
				switch scenario {
				case "unknown":
					lock["verified"] = true
				case "missing":
					lock["records"] = lock["records"].([]any)[1:]
				case "extra":
					lock["records"] = append(lock["records"].([]any), lock["records"].([]any)[0])
				case "traversal":
					lock["records"].([]any)[0].(map[string]any)["name"] = "../foreign"
				case "changed_upstream":
					lock["records"].([]any)[0].(map[string]any)["upstreamDigest"] = strings.Repeat("f", 64)
				case "wrong_tree_buildroot":
					lock["buildroot"].(map[string]any)["archiveSHA256"] = strings.Repeat("f", 64)
				}
				data, err = json.Marshal(lock)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = parseNative(data, root)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("native lock admission=%v", err)
			}
		})
	}
}

func TestNativeRetainedCacheCopiesNeverWriteReplacement(t *testing.T) {
	for _, scenario := range []string{"valid", "missing", "corrupt", "symlink", "source_replaced", "destination_replaced", "extra"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if os.Chmod(root, 0700) != nil {
				t.Fatal("chmod")
			}
			for _, name := range []string{"source", "destination"} {
				if os.Mkdir(filepath.Join(root, name), 0700) != nil {
					t.Fatal("mkdir")
				}
			}
			source, err := openDirectory(filepath.Join(root, "source"), true)
			if err != nil {
				t.Fatal(err)
			}
			defer source.close()
			dest, err := openDirectory(filepath.Join(root, "destination"), true)
			if err != nil {
				t.Fatal(err)
			}
			defer dest.close()
			body := []byte("verified bytes")
			p := pin{Name: "source.tar.gz", Size: int64(len(body)), SHA256: digest(body)}
			if os.WriteFile(filepath.Join(source.name, p.Name), body, 0600) != nil {
				t.Fatal("fixture")
			}
			switch scenario {
			case "missing":
				if os.Remove(filepath.Join(source.name, p.Name)) != nil {
					t.Fatal("remove")
				}
			case "corrupt":
				if os.WriteFile(filepath.Join(source.name, p.Name), []byte("corrupt bytes!"), 0600) != nil {
					t.Fatal("fixture")
				}
			case "symlink":
				if os.Rename(filepath.Join(source.name, p.Name), filepath.Join(root, p.Name)) != nil || os.Symlink(filepath.Join(root, p.Name), filepath.Join(source.name, p.Name)) != nil {
					t.Fatal("link")
				}
			case "extra":
				if os.WriteFile(filepath.Join(source.name, "extra"), body, 0600) != nil {
					t.Fatal("extra")
				}
			case "source_replaced", "destination_replaced":
				replaced := source
				if scenario == "destination_replaced" {
					replaced = dest
				}
				if os.Rename(replaced.name, replaced.name+"-retained") != nil || os.Mkdir(replaced.name, 0700) != nil || os.WriteFile(filepath.Join(replaced.name, "foreign-canary"), body, 0600) != nil {
					t.Fatal("replacement")
				}
			}
			err = source.exact(map[string]pin{p.Name: p})
			if err == nil {
				err = copyVerified(context.Background(), source, dest, p, nil)
			}
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("copy admission=%v", err)
			}
			if strings.HasSuffix(scenario, "replaced") {
				replacement := source.name
				if scenario == "destination_replaced" {
					replacement = dest.name
				}
				entries, err := os.ReadDir(replacement)
				if err != nil || len(entries) != 1 || entries[0].Name() != "foreign-canary" {
					t.Fatalf("foreign replacement changed: %v %v", entries, err)
				}
			}
		})
	}
}

func TestNativeOwnedChildNeverWritesReplacementParent(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("chmod")
	}
	name := filepath.Join(root, "parent")
	if os.Mkdir(name, 0700) != nil {
		t.Fatal("mkdir")
	}
	parent, err := openDirectory(name, true)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	child, err := ownedChild(parent, "source")
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	if child.current() != nil {
		t.Fatal("new retained child not current")
	}
	if os.Rename(name, name+"-retained") != nil || os.Mkdir(name, 0700) != nil || os.WriteFile(filepath.Join(name, "foreign-canary"), []byte("unchanged"), 0600) != nil {
		t.Fatal("replacement")
	}
	if child, err := ownedChild(parent, "cache"); err == nil {
		child.close()
		t.Fatal("replaced parent accepted")
	}
	entries, err := os.ReadDir(name)
	if err != nil || len(entries) != 1 || entries[0].Name() != "foreign-canary" {
		t.Fatalf("foreign parent changed: %v %v", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(name, "foreign-canary"))
	if err != nil || string(data) != "unchanged" {
		t.Fatal("foreign canary changed")
	}
}
