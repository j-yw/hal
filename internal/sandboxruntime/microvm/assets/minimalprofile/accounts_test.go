//go:build linux

package minimalprofile

import (
	"errors"
	"strings"
	"testing"
)

func TestMinimalLockedAccountCorrelation(t *testing.T) {
	for _, scenario := range []string{"valid", "valid_extra_account", "unlocked_root", "inline_password", "duplicate_workload", "missing_root", "missing_workload", "root_uid_alias", "missing_group", "duplicate_group", "group_gid_alias", "inline_group_password", "unknown_group_member", "duplicate_group_member", "missing_shadow", "duplicate_shadow", "orphan_shadow", "unlocked_shadow", "invalid_shadow_age", "malformed_passwd"} {
		t.Run(scenario, func(t *testing.T) {
			archive, pins := stagedFixture(t, func(entries map[string]fixtureEntry) {
				passwd, group, shadow := entries["etc/passwd"], entries["etc/group"], entries["etc/shadow"]
				switch scenario {
				case "valid_extra_account":
					passwd.data += "nobody:x:65534:65534:Nobody:/:/bin/false\n"
					group.data += "nobody:x:65534:\n"
					shadow.data += "nobody:*:0:0:99999:7:::\n"
				case "unlocked_root":
					passwd.data = strings.Replace(passwd.data, "root:x:", "root::", 1)
				case "inline_password":
					passwd.data = strings.Replace(passwd.data, "root:x:", "root:hash:", 1)
				case "duplicate_workload":
					passwd.data = "workload:x:0:0:Workload:/root:/bin/sh\n" + passwd.data
				case "missing_root":
					passwd.data = strings.Replace(passwd.data, "root:x:0:0:root:/root:/bin/sh\n", "", 1)
				case "missing_workload":
					passwd.data = strings.Replace(passwd.data, "workload:x:1000:1000:Workload:/workspace:/bin/sh\n", "", 1)
				case "root_uid_alias":
					passwd.data += "alias:x:0:0:Alias:/root:/bin/sh\n"
					shadow.data += "alias:!:::::::\n"
				case "missing_group":
					group.data = strings.Replace(group.data, "root:x:0:\n", "", 1)
				case "duplicate_group":
					group.data = "workload:x:0:\n" + group.data
				case "group_gid_alias":
					group.data += "alias:x:0:\n"
				case "inline_group_password":
					group.data = strings.Replace(group.data, "root:x:", "root:hash:", 1)
				case "unknown_group_member":
					group.data = strings.Replace(group.data, "root:x:0:", "root:x:0:missing", 1)
				case "duplicate_group_member":
					group.data = strings.Replace(group.data, "root:x:0:", "root:x:0:root,root", 1)
				case "missing_shadow":
					shadow.data = strings.Replace(shadow.data, "root:!:::::::\n", "", 1)
				case "duplicate_shadow":
					shadow.data += "root:!:::::::\n"
				case "orphan_shadow":
					shadow.data += "missing:!:::::::\n"
				case "unlocked_shadow":
					shadow.data = strings.Replace(shadow.data, "root:!:", "root::", 1)
				case "invalid_shadow_age":
					shadow.data = strings.Replace(shadow.data, "root:!:::::::", "root:!:invalid::::::", 1)
				case "malformed_passwd":
					passwd.data = strings.Replace(passwd.data, "root:x:0:0:root:/root:/bin/sh", "root:x:0:0:root:/root:/bin/sh:extra", 1)
				}
				entries["etc/passwd"], entries["etc/group"], entries["etc/shadow"] = passwd, group, shadow
			})
			transcript := fakeTranscript(t, archive)
			_, err := inspect(func(command string) ([]byte, error) {
				data, ok := transcript[command]
				if !ok {
					return nil, errors.New("missing fake response")
				}
				return data, nil
			}, pins)
			valid := scenario == "valid" || scenario == "valid_extra_account"
			if (err == nil) != valid {
				t.Fatalf("account scenario=%s accepted=%v", scenario, err == nil)
			}
		})
	}
}
