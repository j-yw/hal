package l7network_test

import (
	"maps"
	"strings"
	"testing"
)

func TestMinimalPreexecCompositionGuard(t *testing.T) {
	sources := readFirecrackerHostTopologySources(t)
	const host = "minimal_preexec_host_linux.go"
	const assembly = "minimal_preexec_assembler_linux.go"
	t.Run("reviewed private composition", func(t *testing.T) {
		if err := validateFirecrackerHostTopologySources(sources); err != nil {
			t.Fatal(err)
		}
	})
	mutations := []struct{ name, file, before, after string }{
		{"Start caller", "minimal_launch_template_handoff_linux.go", "owner.sealed = true", "owner.prepareMinimalInputs(nil); owner.sealed = true"},
		{"default caller", "live_driver.go", "", "\nfunc defaultPreexec() { newMinimalPreexecHost(nil, nil, minimalPreexecHostInputs{}) }"},
		{"new caller", "unreviewed.go", "", "\nfunc hidden(owner *minimalTemplateAssetOwner) { owner.prepareMinimalInputs(nil) }"},
		{"existing exempt caller", "l7_live_composition.go", "", "\nfunc hidden(owner *minimalTemplateAssetOwner) { owner.prepareMinimalInputs(nil) }"},
		{"init activation", host, "", "\nfunc init() { newMinimalPreexecHost(nil, nil, minimalPreexecHostInputs{}) }"},
		{"global activation", host, "", "\nvar hidden, hiddenErr = newMinimalPreexecHost(nil, nil, minimalPreexecHostInputs{})"},
		{"global callable escape", host, "", "\nvar hidden = newMinimalPreexecHostForUID"},
		{"method callable escape", assembly, "", "\nvar hidden = (*minimalTemplateAssetOwner).prepareMinimalInputsWithOps"},
		{"local callable escape", assembly, "", "\nfunc hidden() { call := newMinimalPreexecNetwork; _ = call }"},
		{"exported host entry", host, "func newMinimalPreexecHost(", "func NewMinimalPreexecHost("},
		{"exported prepare entry", assembly, ") prepareMinimalInputs(", ") PrepareMinimalInputs("},
		{"root check removed", host, "os.Geteuid() != 0", "false"},
		{"prepare root removed", assembly, "host == nil || host.uid != 0 || os.Geteuid() != 0", "host == nil"},
		{"guest proof enabled", assembly, "return l7network.RunningGuestRawPacketIsolationProof{}, sandboxruntime.ErrMinimalLaunchUnavailable", "return l7network.RunningGuestRawPacketIsolationProof{}, nil"},
		{"terminal proof enabled", assembly, "return l7network.VMTerminationProof{}, sandboxruntime.ErrMinimalLaunchUnavailable", "return l7network.VMTerminationProof{}, nil"},
		{"host constructor activation", host, "if _, err := policyproxy.New(input.proxy);", "input.proxy.ApplicationRoutes.Start(context.Background()); if _, err := policyproxy.New(input.proxy);"},
		{"network constructor activation", assembly, "proxy, err := l7network.NewProductionProxy(adapter)", "adapter.StartProxyListener(nil, networkenforcement.ProxyListenerLifecycleRequest{}); proxy, err := l7network.NewProductionProxy(adapter)"},
		{"network constructor alias", assembly, "adapter, err := policyproxy.New(proxyConfig)", "construct := policyproxy.New; adapter, err := construct(proxyConfig)"},
		{"new constructor body", assembly, "", "\nfunc hidden() { l7network.New(l7network.Options{}) }"},
		{"third file imports", "unreviewed.go", "", "\nimport \"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network\"\nvar _ *l7network.Coordinator"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := maps.Clone(sources)
			source := string(candidate[mutation.file])
			if source == "" {
				source = "package firecrackerhost\n"
			}
			if mutation.before == "" {
				source += mutation.after
			} else {
				if strings.Count(source, mutation.before) != 1 {
					t.Fatal("mutation did not identify exactly one actual source prerequisite")
				}
				source = strings.Replace(source, mutation.before, mutation.after, 1)
			}
			candidate[mutation.file] = []byte(source)
			err := validateFirecrackerHostTopologySources(candidate)
			want := "selected preexec"
			if mutation.name == "third file imports" {
				want = "default Firecracker host path unreviewed.go"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("mutation was not rejected at the selected preexec boundary: %v", err)
			}
		})
	}
}
