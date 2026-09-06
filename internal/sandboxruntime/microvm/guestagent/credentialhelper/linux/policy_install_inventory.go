package linux

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

const policyInstallInventoryDomain = "hal/l8/d4-native-install-table/linux-amd64/v1"

// policyInstallBinding is one D7-generated correlation between a native D4
// bootstrap plan and the only D2 role/kind pair that may authorize it. It is
// data-only and confers neither an install right nor syscall authority.
type policyInstallBinding struct {
	installRole rolebootstrap.Role
	policyRole  syscallpolicy.Role
	binaryKind  syscallpolicy.BinaryBindingKind
}

// policyAdapterCallsite is generated only from a D7 adapter row's exact
// positive input. An empty inventory is intentionally not live-ready.
type policyAdapterCallsite struct {
	role             syscallpolicy.Role
	stage            syscallpolicy.Stage
	facts            syscallpolicy.StateFact
	rawSyscallNumber uint32
	arguments        [6]uint64
}

func policyInstallInventorySHA256() ([32]byte, error) {
	want := [...]policyInstallBinding{
		{installRole: rolebootstrap.RolePID1, policyRole: syscallpolicy.RoleLaunchBootstrap, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
		{installRole: rolebootstrap.RoleController, policyRole: syscallpolicy.RoleControllerBootstrap, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
		{installRole: rolebootstrap.RoleAgent, policyRole: syscallpolicy.RoleAgentBootstrap, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
		{installRole: rolebootstrap.RoleMonitor, policyRole: syscallpolicy.RoleMonitorBootstrap, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
		{installRole: rolebootstrap.RoleWorkloadShim, policyRole: syscallpolicy.RoleWorkloadTransition, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
	}
	generated, generatedSHA256 := generatedPolicyInstallInventory()
	if generated != want || generatedSHA256 == ([32]byte{}) {
		return [32]byte{}, credentialhelper.ErrContractDependency
	}
	preimage := make([]byte, 4+len(want)*4)
	binary.BigEndian.PutUint16(preimage[:2], uint16(len(want)))
	for index, binding := range want {
		offset := 4 + index*4
		preimage[offset] = byte(binding.installRole)
		preimage[offset+1] = byte(binding.policyRole)
		preimage[offset+2] = byte(binding.binaryKind)
	}
	digest := framedPolicyInstallInventorySHA256(preimage)
	if subtle.ConstantTimeCompare(digest[:], generatedSHA256[:]) != 1 {
		return [32]byte{}, credentialhelper.ErrContractDependency
	}
	return digest, nil
}

func framedPolicyInstallInventorySHA256(preimage []byte) [32]byte {
	domain := []byte(policyInstallInventoryDomain)
	framed := make([]byte, 2+len(domain)+len(preimage))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(domain)))
	copy(framed[2:], domain)
	copy(framed[2+len(domain):], preimage)
	return sha256.Sum256(framed)
}

func policyAdapterCallsiteInventoryReady(policy *syscallpolicy.Policy) bool {
	callsites := generatedPolicyAdapterCallsiteInventory()
	if policy == nil || len(callsites) == 0 {
		return false
	}
	profiles := make(map[syscallpolicy.Role]syscallpolicy.FilterProfile)
	for _, callsite := range callsites {
		state, err := syscallpolicy.NewState(callsite.role, callsite.stage, callsite.facts)
		if err != nil {
			return false
		}
		input, err := syscallpolicy.NewFilterInput(state, 0xc000003e, callsite.rawSyscallNumber, callsite.arguments)
		if err != nil {
			return false
		}
		profile, ok := profiles[callsite.role]
		if !ok {
			profile, err = policy.FilterProfile(callsite.role)
			if err != nil || profile.SHA256() == ([32]byte{}) {
				return false
			}
			profiles[callsite.role] = profile
		}
		filterDecision := profile.Decide(0xc000003e, callsite.rawSyscallNumber, callsite.arguments)
		decision := policy.Decide(input)
		ticket, ticketErr := decision.Ticket()
		if filterDecision.Action() != syscallpolicy.ActionAllow || !decision.Allowed() || ticketErr != nil || ticket.SHA256() == ([32]byte{}) || ticket.RuleSHA256() != filterDecision.RuleSHA256() {
			return false
		}
	}
	return true
}
