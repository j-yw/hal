//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestMinimalPreexecHostRejectsUntrustedInputs(t *testing.T) {
	for _, fault := range []string{"copied provider", "wrong UID", "canceled", "root mode", "key mode", "key size", "borrowed alias", "exe digest", "scope policy", "proxy routing", "firewall mode", "raw allow", "private allow", "metadata audit", "allowlist mismatch", "typed nil", "unsafe anchor"} {
		t.Run(fault, func(t *testing.T) {
			f := newMinimalPreexecFixture(t)
			input, provider, uid := f.inputs, f.handoff.provider, uint32(os.Geteuid())
			ctx, cancel := context.WithCancel(f.preparation)
			defer cancel()
			plan := input.proxy.Policy.PlanMetadata()
			switch fault {
			case "copied provider":
				copy := *provider
				provider = &copy
			case "wrong UID":
				uid++
			case "canceled":
				cancel()
			case "root mode":
				if input.stateRoot.Chmod(0o750) != nil {
					t.Fatal("chmod control")
				}
				defer input.stateRoot.Chmod(0o700)
			case "key mode":
				if input.stableKey.Chmod(0o640) != nil {
					t.Fatal("chmod control")
				}
				defer input.stableKey.Chmod(0o600)
			case "key size":
				if input.stableKey.Truncate(31) != nil {
					t.Fatal("truncate fixture key")
				}
			case "borrowed alias":
				input.stableKey = input.stateRoot
			case "exe digest":
				input.executableSHA256[0] ^= 1
			case "scope policy":
				input.networkPolicyID = "different-policy"
			case "proxy routing":
				plan.Proxy.HTTP = networkenforcement.ProxyRoutingModeBypassProxy
			case "firewall mode":
				plan.Firewall.Mode = networkenforcement.FirewallIntentModeNone
			case "raw allow":
				plan.RawProtocols = &networkenforcement.RawProtocolPlan{TCP: networkenforcement.PostureAllow}
			case "private allow":
				plan.Category = &networkenforcement.CategoryPosturePlan{PrivateNetwork: networkenforcement.PostureAllow}
			case "metadata audit":
				plan.Category = &networkenforcement.CategoryPosturePlan{MetadataEndpoint: networkenforcement.PostureAudit}
			case "allowlist mismatch":
				plan.Allowlist = &networkenforcement.AllowlistPlan{Mode: networkenforcement.AllowlistModeEnforce, RuleIDs: []string{"missing-rule"}}
			case "typed nil":
				var command *minimalL7ConfigTestTAP
				input.tap.Command = command
			case "unsafe anchor":
				input.policy.TrustedAnchor = "/"
			}
			input.proxy.Policy = networkenforcement.NewPolicyProxyPolicyInput(plan, input.proxy.Policy.AllowlistRules)
			host, err := newMinimalPreexecHostForUID(ctx, provider, input, uid)
			if host != nil {
				defer host.close()
			}
			if err == nil || host != nil {
				t.Fatal("trusted constructor accepted invalid input", fault)
			}
			for _, file := range []*os.File{f.inputs.stateRoot, f.inputs.stableKey, f.inputs.executable} {
				if _, err := file.Stat(); err != nil {
					t.Fatal("constructor consumed caller borrow", err)
				}
			}
		})
	}
}
