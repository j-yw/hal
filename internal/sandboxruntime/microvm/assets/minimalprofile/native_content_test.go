//go:build linux

package minimalprofile

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const nativeContentTypeCheck = `typeof arg.aws_secret_access_key === "string"`
const nativeContentPlaceholder = "export AWS_SECRET_ACCESS_KEY=...\n"

func TestMinimalNativeContentHarmlessSyntax(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"providers_placeholder", nativeContentPlaceholder},
		{"aws_commonjs_type_check", "const isStaticCredsProfile = (arg) =>\n    " + nativeContentTypeCheck + ";\n"},
		{"aws_es_type_check", "export const isStaticCredsProfile = (arg) => (\n    " + nativeContentTypeCheck + "\n);\n"},
		{"placeholder_eof", "AWS_SECRET_ACCESS_KEY=..."},
		{"placeholder_horizontal_space", "\t export\taws_secret_access_key = ... \t\r\n"},
		{"token_placeholder", "_authToken=...\n"},
		{"two_placeholder_lines", nativeContentPlaceholder + "_authToken=...\n"},
		{"type_check_loose_equality", `typeof config.aws_secret_access_key == "string"`},
		{"type_check_single_quote", `typeof config.nested._authToken === 'string'`},
		{"type_check_identifier_and_space", "typeof\t$arg._nested.AWS_SECRET_ACCESS_KEY\t===\t\"string\""},
		{"type_check_in_condition", "if (" + nativeContentTypeCheck + " && enabled) {}\n"},
		{"combined_document", "Example:\n" + nativeContentPlaceholder + "\n" + nativeContentTypeCheck + ";\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive, pins := nativeContentFixture(t, tc.content)
			result, err := inspectNativeContent(t, archive, pins, tc.content)
			if err != nil {
				t.Fatalf("harmless syntax rejected after actual inode content read: %v", err)
			}
			if len(result.Executables) != 4 || result.Inventory.LogicalBytes == 0 || result.Inventory.Findings == nil || len(result.Inventory.Findings) != 0 || result.InstalledPiTreeSHA256 != pins.InstalledPiTreeSHA256 {
				t.Fatal("complete independently pinned measurement missing")
			}
		})
	}
}

func TestMinimalNativeContentRejectsAssignmentsAndLookalikes(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"aws_assignment", "AWS_SECRET_ACCESS_KEY=synthetic-value"},
		{"token_assignment", "_authToken=synthetic-value"},
		{"assignment_case_space", "aWs_SeCrEt_AcCeSs_KeY \t= synthetic-value"},
		{"empty_assignment", "AWS_SECRET_ACCESS_KEY="},
		{"empty_value_spaces", "_authToken= \t\r\n"},
		{"quoted_value", `AWS_SECRET_ACCESS_KEY="synthetic-value"`},
		{"single_quoted_value", `_authToken='synthetic-value'`},
		{"multiline_value", "AWS_SECRET_ACCESS_KEY=\nsynthetic-value"},
		{"continued_value", "AWS_SECRET_ACCESS_KEY=\\\nsynthetic-value"},
		{"placeholder_suffix", "AWS_SECRET_ACCESS_KEY=...suffix\n"},
		{"placeholder_four_dots", "AWS_SECRET_ACCESS_KEY=....\n"},
		{"placeholder_two_dots", "AWS_SECRET_ACCESS_KEY=..\n"},
		{"placeholder_unicode", "AWS_SECRET_ACCESS_KEY=…\n"},
		{"placeholder_quoted", `AWS_SECRET_ACCESS_KEY="..."`},
		{"placeholder_semicolon", "AWS_SECRET_ACCESS_KEY=...;\n"},
		{"placeholder_comment", "AWS_SECRET_ACCESS_KEY=... # example\n"},
		{"placeholder_extra_word", "AWS_SECRET_ACCESS_KEY=... synthetic-value\n"},
		{"placeholder_command_prefix", "echo AWS_SECRET_ACCESS_KEY=...\n"},
		{"placeholder_identifier_prefix", "PREFIX_AWS_SECRET_ACCESS_KEY=...\n"},
		{"placeholder_bare_cr", "AWS_SECRET_ACCESS_KEY=...\r"},
		{"placeholder_control", "AWS_SECRET_ACCESS_KEY=...\x00\n"},
		{"placeholder_continuation", "AWS_SECRET_ACCESS_KEY=...\\\nsynthetic-value"},
		{"placeholder_multiline", "AWS_SECRET_ACCESS_KEY=\n...\n"},
		{"second_assignment_same_line", "AWS_SECRET_ACCESS_KEY=... _authToken=synthetic-value\n"},
		{"second_assignment_next_line", nativeContentPlaceholder + "_authToken=synthetic-value\n"},
		{"first_assignment_before_placeholder", "_authToken=synthetic-value\n" + nativeContentPlaceholder},
		{"first_assignment_same_line", "_authToken=synthetic-value; AWS_SECRET_ACCESS_KEY=...\n"},
		{"shell_double_equals", "AWS_SECRET_ACCESS_KEY==synthetic-value"},
		{"shell_triple_equals", "_authToken===synthetic-value"},
		{"shell_export_equals", "export AWS_SECRET_ACCESS_KEY===\"string\""},
		{"type_check_assignment", `typeof arg.aws_secret_access_key = "string"`},
		{"type_check_extra_equals", `typeof arg.aws_secret_access_key ==== "string"`},
		{"type_check_split_equals", `typeof arg.aws_secret_access_key = == "string"`},
		{"type_check_missing_rhs", `typeof arg.aws_secret_access_key ===`},
		{"type_check_unquoted_rhs", `typeof arg.aws_secret_access_key === string`},
		{"type_check_unknown_rhs", `typeof arg.aws_secret_access_key === "synthetic-value"`},
		{"type_check_unclosed_quote", `typeof arg.aws_secret_access_key === "string`},
		{"type_check_escaped_quote", `typeof arg.aws_secret_access_key === \"string\"`},
		{"type_check_rhs_suffix", nativeContentTypeCheck + "suffix"},
		{"type_check_rhs_assignment", nativeContentTypeCheck + "=synthetic-value"},
		{"type_check_no_object", `typeof aws_secret_access_key === "string"`},
		{"type_check_keyword_prefix", `notypeof arg.aws_secret_access_key === "string"`},
		{"type_check_property_keyword", `arg.typeof arg.aws_secret_access_key === "string"`},
		{"type_check_wrong_keyword_case", `TYPEOF arg.aws_secret_access_key === "string"`},
		{"type_check_wrong_rhs_case", `typeof arg.aws_secret_access_key === "String"`},
		{"type_check_invalid_identifier", `typeof 1arg.aws_secret_access_key === "string"`},
		{"type_check_split_keyword", "type\nof arg.aws_secret_access_key === \"string\""},
		{"type_check_multiline", "typeof arg.aws_secret_access_key ===\n\"string\""},
		{"type_check_second_assignment", nativeContentTypeCheck + " && (_authToken=synthetic-value)"},
		{"type_check_first_assignment", "_authToken=synthetic-value; " + nativeContentTypeCheck},
		{"type_check_second_assignment_next_line", nativeContentTypeCheck + "\nAWS_SECRET_ACCESS_KEY=synthetic-value\n"},
		{"many_type_checks_then_assignment", strings.Repeat(nativeContentTypeCheck+";\n", 128) + "_authToken=synthetic-value"},
		{"private_key", "-----BEGIN PRIVATE KEY-----"},
		{"rsa_private_key", "-----BEGIN RSA PRIVATE KEY-----"},
		{"openssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		{"private_key_after_placeholder", nativeContentPlaceholder + "-----BEGIN EC PRIVATE KEY-----"},
		{"private_key_after_type_check", nativeContentTypeCheck + "; /* -----BEGIN PRIVATE KEY----- */"},
		{"private_key_before_type_check", "/* -----BEGIN PRIVATE KEY----- */ " + nativeContentTypeCheck},
		{"canary", "HAL_CONTENT_CANARY"},
		{"canary_after_placeholder", nativeContentPlaceholder + "hal_content_canary"},
		{"canary_before_placeholder", "HAL_CONTENT_CANARY\n" + nativeContentPlaceholder},
		{"canary_after_type_check", nativeContentTypeCheck + "; HAL_CONTENT_CANARY"},
		{"canary_before_type_check", "HAL_CONTENT_CANARY; " + nativeContentTypeCheck},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive, pins := nativeContentFixture(t, tc.content)
			result, err := inspectNativeContent(t, archive, pins, tc.content)
			if !errors.Is(err, errImage) || !reflect.DeepEqual(result, Measurement{}) {
				t.Fatal("unsafe syntax issued measurement or unsanitized error")
			}
		})
	}
}

func TestMinimalNativeContentIndependentControls(t *testing.T) {
	content := "module.exports = 'independent harmless control';\n"
	archive, pins := nativeContentFixture(t, content)
	t.Run("valid_recomputed_tree", func(t *testing.T) {
		result, err := inspectNativeContent(t, archive, pins, content)
		if err != nil || result.InstalledPiTreeSHA256 != pins.InstalledPiTreeSHA256 || len(result.Executables) != 4 {
			t.Fatal("independent baseline cannot reach complete measurement")
		}
	})
	t.Run("wrong_tree_pin", func(t *testing.T) {
		selected := pins
		selected.InstalledPiTreeSHA256 = strings.Repeat("a", 64)
		result, err := inspectNativeContent(t, archive, selected, content)
		if err == nil || !reflect.DeepEqual(result, Measurement{}) {
			t.Fatal("content predicate bypassed independent tree pin")
		}
	})
	t.Run("wrong_executable_pin", func(t *testing.T) {
		selected := pins
		selected.NodeSHA256 = strings.Repeat("a", 64)
		result, err := inspectNativeContent(t, archive, selected, content)
		if err == nil || !reflect.DeepEqual(result, Measurement{}) {
			t.Fatal("content predicate bypassed independent executable pin")
		}
	})
}

// Expected pins derive from the test's known entry map, never inspector output.
// This updates the dependency bytes and tree pin together so rejection cannot
// be attributed to the old fixture pin. No production fixture/helper is edited.
func nativeContentFixture(t *testing.T, content string) (string, Pins) {
	t.Helper()
	var tree strings.Builder
	archive, pins := stagedFixture(t, func(entries map[string]fixtureEntry) {
		entry := entries["usr/lib/pi/node_modules/dependency/index.js"]
		entry.data = content
		entries["usr/lib/pi/node_modules/dependency/index.js"] = entry
		for _, name := range sortedEntryNames(entries) {
			if name != "usr/lib/pi" && !strings.HasPrefix(name, "usr/lib/pi/") {
				continue
			}
			e := entries[name]
			kind, digest := "regular", hash([]byte(e.data))
			if e.dir {
				kind, digest = "directory", ""
			} else if e.link != "" {
				kind, digest = "symlink", hash([]byte(e.link))
			}
			fmt.Fprintf(&tree, "%s\x00%s\x00%o\x00%d\x00%d\x00%s\n", "/"+name, kind, e.mode, e.uid, e.uid, digest)
		}
	})
	recomputed := hash([]byte(tree.String()))
	if recomputed == pins.InstalledPiTreeSHA256 {
		t.Fatal("content fixture did not replace independently pinned bytes")
	}
	pins.InstalledPiTreeSHA256 = recomputed
	return archive, pins
}

func inspectNativeContent(t *testing.T, archive string, pins Pins, content string) (Measurement, error) {
	t.Helper()
	transcript := fakeTranscript(t, archive)
	reads := 0
	result, err := inspect(func(command string) ([]byte, error) {
		data, exists := transcript[command]
		if !exists {
			t.Fatalf("unexpected numeric inode command: %q", command)
		}
		if strings.HasPrefix(command, "cat <") && bytes.Equal(data, []byte(content)) {
			reads++
		}
		return data, nil
	}, pins)
	if reads != 1 {
		t.Fatalf("actual inspector read candidate file %d times, want exactly once", reads)
	}
	return result, err
}
