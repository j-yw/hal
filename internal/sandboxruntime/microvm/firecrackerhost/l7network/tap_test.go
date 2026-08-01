//go:build linux

package l7network

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
)

func TestLinuxTAPUsesOnlyNamespaceBoundStaticConfiguration(t *testing.T) {
	command := &fakeNamespaceCommand{}
	tap, err := NewLinuxTAP(TAPOptions{IPPath: "/usr/sbin/ip", SysctlPath: "/usr/sbin/sysctl", NsenterPath: "/usr/bin/nsenter", Command: command})
	if err != nil {
		t.Fatal(err)
	}
	spec := staticTAPSpec(testIdentity(), netip.MustParseAddr("192.0.2.2"), 43123)
	state, err := tap.CreateConfigure(context.Background(), &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !state.valid(spec) {
		t.Fatal("created TAP state did not retain exact private generation")
	}
	for _, call := range command.snapshot() {
		joined := strings.Join(call.args, " ")
		for _, forbidden := range []string{"iptables", "masquerade", " snat", " dnat", "dhcp", "dns", "0.0.0.0", "::/0"} {
			if strings.Contains(strings.ToLower(" "+joined), forbidden) {
				t.Fatalf("TAP command contains forbidden host-global/NAT/service behavior: %#v", call)
			}
		}
	}
	if err := tap.Delete(context.Background(), &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, state, spec); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxTAPRollsBackEveryPartialCreateFailure(t *testing.T) {
	for failAt := 1; failAt <= 8; failAt++ {
		t.Run(string(rune('a'+failAt-1)), func(t *testing.T) {
			command := &fakeNamespaceCommand{failAt: failAt}
			tap, err := NewLinuxTAP(TAPOptions{IPPath: "/usr/sbin/ip", SysctlPath: "/usr/sbin/sysctl", NsenterPath: "/usr/bin/nsenter", Command: command})
			if err != nil {
				t.Fatal(err)
			}
			spec := staticTAPSpec(testIdentity(), netip.MustParseAddr("192.0.2.2"), 43123)
			if _, err := tap.CreateConfigure(context.Background(), &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, spec); !errors.Is(err, ErrTopologyPrepareFailed) {
				t.Fatalf("CreateConfigure() = %v", err)
			}
			calls := command.snapshot()
			if failAt > 1 {
				last := calls[len(calls)-1]
				if !reflect.DeepEqual(last.args, []string{"link", "delete", "dev", spec.name}) {
					t.Fatalf("partial rollback last call = %#v", last)
				}
			}
		})
	}
}

func TestLinuxTAPInspectionRejectsExtraAddressesAndRoutes(t *testing.T) {
	spec := staticTAPSpec(testIdentity(), netip.MustParseAddr("192.0.2.2"), 43123)
	extraAddress := []byte(`[{"ifname":"` + spec.name + `","addr_info":[` +
		`{"family":"inet","local":"172.31.255.1","prefixlen":30},` +
		`{"family":"inet6","local":"fd00:6861:6c::1","prefixlen":126},` +
		`{"family":"inet6","local":"fe80::1234","prefixlen":64}]}]`)
	if inspectTAPAddresses(extraAddress, spec) {
		t.Fatal("address inspection accepted an extra link-local address")
	}
	extraRoute := []byte(`[{"dst":"172.31.255.2/32","dev":"` + spec.name + `"},` +
		`{"dst":"169.254.169.254/32","dev":"` + spec.name + `"}]`)
	if inspectTAPRoutes(extraRoute, spec.name, "172.31.255.2/32") {
		t.Fatal("route inspection accepted an extra metadata route")
	}
	duplicateRoute := []byte(`[{"dst":"172.31.255.2/32","dev":"` + spec.name + `"},` +
		`{"dst":"172.31.255.2/32","dev":"` + spec.name + `"}]`)
	if inspectTAPRoutes(duplicateRoute, spec.name, "172.31.255.2/32") {
		t.Fatal("route inspection accepted a duplicate route")
	}
}

func TestLinuxTAPDeleteDoesNotTreatInspectionFailureAsAbsence(t *testing.T) {
	command := &fakeNamespaceCommand{absenceErr: errors.New("permission denied while checking absence")}
	tap, err := NewLinuxTAP(TAPOptions{IPPath: "/usr/sbin/ip", SysctlPath: "/usr/sbin/sysctl", NsenterPath: "/usr/bin/nsenter", Command: command})
	if err != nil {
		t.Fatal(err)
	}
	spec := staticTAPSpec(testIdentity(), netip.MustParseAddr("192.0.2.2"), 43123)
	state, err := tap.CreateConfigure(context.Background(), &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := tap.Delete(context.Background(), &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, state, spec); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Delete() = %v, want ErrCleanupIncomplete", err)
	}
}

type tapCommandCall struct {
	path string
	args []string
}
type fakeNamespaceCommand struct {
	calls      []tapCommandCall
	failAt     int
	deleted    bool
	mac        string
	absenceErr error
}

func (c *fakeNamespaceCommand) Run(_ context.Context, _ NamespaceLease, command NamespaceCommandRequest, _ int64) ([]byte, error) {
	c.calls = append(c.calls, tapCommandCall{path: command.Path, args: append([]string(nil), command.Args...)})
	if c.failAt > 0 && len(c.calls) == c.failAt {
		return nil, errors.New("raw private command failure")
	}
	joined := strings.Join(command.Args, " ")
	if strings.Contains(joined, "link set") {
		for i, arg := range command.Args {
			if arg == "address" && i+1 < len(command.Args) {
				c.mac = command.Args[i+1]
			}
		}
	}
	if strings.Contains(joined, "link delete") {
		c.deleted = true
		return nil, nil
	}
	if strings.Contains(joined, "-j link show") {
		if c.deleted {
			if c.absenceErr != nil {
				return nil, c.absenceErr
			}
			return nil, errors.New("absent")
		}
		name := command.Args[len(command.Args)-1]
		return json.Marshal([]map[string]any{{"ifname": name, "address": c.mac, "flags": []string{"BROADCAST", "UP"}}})
	}
	if strings.Contains(joined, "-j address show") {
		name := command.Args[len(command.Args)-1]
		return json.Marshal([]map[string]any{{"ifname": name, "addr_info": []map[string]any{
			{"family": "inet", "local": "172.31.255.1", "prefixlen": 30},
			{"family": "inet6", "local": "fd00:6861:6c::1", "prefixlen": 126},
		}}})
	}
	if strings.Contains(joined, "-j -4 route") {
		return []byte(`[{"dst":"172.31.255.2/32","dev":"` + command.Args[len(command.Args)-1] + `"}]`), nil
	}
	if strings.Contains(joined, "-j -6 route") {
		return []byte(`[{"dst":"fd00:6861:6c::2/128","dev":"` + command.Args[len(command.Args)-1] + `"}]`), nil
	}
	if command.Path == "/usr/sbin/sysctl" && len(command.Args) > 0 && command.Args[0] == "-n" {
		return []byte("1\n"), nil
	}
	return nil, nil
}
func (c *fakeNamespaceCommand) snapshot() []tapCommandCall {
	return append([]tapCommandCall(nil), c.calls...)
}
