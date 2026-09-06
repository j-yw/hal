package sandboxworker

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMinimalLaunchDefaultPrivateJSONPreservesLegacyOmission(t *testing.T) {
	for _, state := range []storedJobStateV2{{}, {
		JobV2: JobV2{ID: "job-legacy"}, RequestKey: "legacy-request", PrincipalID: "legacy-principal", DaemonGeneration: "legacy-daemon",
		CredentialState: &storedJobCredentialStateV2{}, CredentialRecoveryReceipt: &storedJobCredentialRuntimeRecoveryReceiptV1{},
	}} {
		// Independent original six-field encoder shape, including field order.
		legacy := struct {
			JobV2                     JobV2
			RequestKey                string                                       `json:"requestKey"`
			PrincipalID               string                                       `json:"principalId"`
			DaemonGeneration          string                                       `json:"daemonGeneration"`
			CredentialState           *storedJobCredentialStateV2                  `json:"credentialState,omitempty"`
			CredentialRecoveryReceipt *storedJobCredentialRuntimeRecoveryReceiptV1 `json:"credentialRecoveryReceipt,omitempty"`
		}{state.JobV2, state.RequestKey, state.PrincipalID, state.DaemonGeneration, state.CredentialState, state.CredentialRecoveryReceipt}
		want, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		got, err := encodeStoredJobStateV2(state)
		if err != nil || !bytes.Equal(got, want) || bytes.Contains(got, []byte("minimalLaunch")) {
			t.Fatal("default private JSON changed legacy bytes or gained minimal metadata")
		}
	}
}
