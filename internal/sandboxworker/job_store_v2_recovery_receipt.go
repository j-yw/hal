package sandboxworker

import (
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// storedJobCredentialRuntimeRecoveryReceiptV1ToRuntime reconstructs only the
// sealed neutral value needed for an idempotent commit-only recovery binding.
// The concrete binding reauthenticates the HMAC against its private owner key.
func storedJobCredentialRuntimeRecoveryReceiptV1ToRuntime(stored storedJobCredentialRuntimeRecoveryReceiptV1) (receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, err error) {
	receipt.CommitID = stored.CommitID
	receipt.FinalizedRevision = stored.FinalizedRevision
	if stored.ContractVersion != storedJobCredentialRuntimeRecoveryReceiptContractV1 || sandboxruntime.ValidateJobCredentialRuntimeRecoveryCommitReceipt(receipt) != nil {
		receipt.CommitID = ""
		receipt.FinalizedRevision = 0
		return receipt, errors.New("worker job credential recovery receipt is invalid")
	}
	return receipt, nil
}
