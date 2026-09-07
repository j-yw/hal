//go:build linux

package minimalprofile

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestMinimalNativeContentTokenBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		accepted      bool
	}{
		{"left_equal", "result=" + nativeContentTypeCheck, true},
		{"left_negation", "!" + nativeContentTypeCheck, true},
		{"left_newline", "\n" + nativeContentTypeCheck, true},
		{"right_question", nativeContentTypeCheck + "?yes:no", true},
		{"right_brace", nativeContentTypeCheck + "}", true},
		{"right_tab", nativeContentTypeCheck + "\t", true},
		{"left_identifier", "x" + nativeContentTypeCheck, false},
		{"left_dollar", "$" + nativeContentTypeCheck, false},
		{"left_underscore", "_" + nativeContentTypeCheck, false},
		{"left_quote", "'" + nativeContentTypeCheck, false},
		{"left_backslash", "\\" + nativeContentTypeCheck, false},
		{"left_control", "\x00" + nativeContentTypeCheck, false},
		{"left_vertical_tab", "\v" + nativeContentTypeCheck, false},
		{"left_nonascii", "λ" + nativeContentTypeCheck, false},
		{"right_quote", nativeContentTypeCheck + "'", false},
		{"right_period", nativeContentTypeCheck + ".property", false},
		{"right_dollar", nativeContentTypeCheck + "$", false},
		{"right_backslash", nativeContentTypeCheck + "\\", false},
		{"right_control", nativeContentTypeCheck + "\x00", false},
		{"right_vertical_tab", nativeContentTypeCheck + "\v", false},
		{"right_nonascii", nativeContentTypeCheck + "λ", false},
		{"double_dot", `typeof arg..aws_secret_access_key === "string"`, false},
		{"space_before_dot", `typeof arg .aws_secret_access_key === "string"`, false},
		{"space_after_dot", `typeof arg. aws_secret_access_key === "string"`, false},
		{"invalid_nested_identifier", `typeof arg.1nested.aws_secret_access_key === "string"`, false},
		{"nonascii_identifier", `typeof λ.aws_secret_access_key === "string"`, false},
		{"nonascii_key_placeholder", "AWS_SECRET_ACCESS_KEY=...\n", false},
		{"nonascii_key_type_test", `typeof arg._authToKen === "string"`, false},
		{"placeholder_wrong_export_case", "EXPORT AWS_SECRET_ACCESS_KEY=...\n", false},
		{"placeholder_joined_export", "exportAWS_SECRET_ACCESS_KEY=...\n", false},
		{"placeholder_repeated_export", "export export AWS_SECRET_ACCESS_KEY=...\n", false},
		{"placeholder_vertical_tab", "\vAWS_SECRET_ACCESS_KEY=...\n", false},
		{"placeholder_formfeed", "AWS_SECRET_ACCESS_KEY=...\f\n", false},
		{"allowed_then_unknown_same_marker", nativeContentTypeCheck + ` && typeof arg.aws_secret_access_key === "synthetic-value"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive, pins := nativeContentFixture(t, tc.content)
			result, err := inspectNativeContent(t, archive, pins, tc.content)
			if tc.accepted {
				if err != nil || result.InstalledPiTreeSHA256 != pins.InstalledPiTreeSHA256 {
					t.Fatalf("valid exact boundary rejected: %v", err)
				}
			} else if err == nil || !reflect.DeepEqual(result, Measurement{}) {
				t.Fatal("unknown lexical boundary accepted")
			}
		})
	}
}

func TestMinimalNativeContentManyOccurrences(t *testing.T) {
	for _, count := range []int{1, 128, 2048} {
		for _, separator := range []string{"; ", ";\n"} {
			for _, suffix := range []string{"", "_authToken=synthetic-value", "HAL_CONTENT_CANARY", "-----BEGIN PRIVATE KEY-----"} {
				t.Run(fmt.Sprintf("%d/%q/%q", count, separator, suffix), func(t *testing.T) {
					content := strings.Repeat(nativeContentTypeCheck+separator, count) + suffix
					archive, pins := nativeContentFixture(t, content)
					result, err := inspectNativeContent(t, archive, pins, content)
					if suffix == "" {
						if err != nil || result.InstalledPiTreeSHA256 != pins.InstalledPiTreeSHA256 {
							t.Fatalf("repeated harmless syntax rejected: %v", err)
						}
					} else if err == nil || !reflect.DeepEqual(result, Measurement{}) {
						t.Fatal("earlier harmless occurrences masked unsafe final content")
					}
				})
			}
		}
	}
}
