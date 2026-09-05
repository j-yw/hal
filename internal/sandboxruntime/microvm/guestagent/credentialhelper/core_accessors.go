package credentialhelper

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"

func (value CorePrepareRequest) RequestID() [16]byte          { return value.correlation.requestID }
func (value CorePrepareRequest) IdentityDigest() [32]byte     { return value.correlation.identityDigest }
func (value CorePrepareRequest) Revision() uint64             { return value.correlation.revision }
func (value CorePrepareRequest) Generations() CoreGenerations { return value.generations }
func (value CorePrepareRequest) ExpiresUnixNano() int64       { return value.expiresUnixNano }
func (value CorePrepareRequest) FixedLimitSetID() credentialprotocol.SafeID {
	return value.fixedLimitSetID
}
func (value CorePrepareRequest) Manifest() ManifestCapability { return value.manifest }
func (value CorePrepareRequest) ManifestSHA256() [32]byte     { return value.manifestSHA256 }
func (value CorePrepareRequest) Preparation() CorePreparationCapability {
	return value.preparation
}
func (value CorePrepareRequest) Prepared() CorePreparedCapability { return value.prepared }
func (value CorePrepareRequest) Cleanup() CoreCleanupCapability   { return value.cleanup }

func (value CoreFileRequest) RequestID() [16]byte      { return value.correlation.requestID }
func (value CoreFileRequest) IdentityDigest() [32]byte { return value.correlation.identityDigest }
func (value CoreFileRequest) Revision() uint64         { return value.correlation.revision }
func (value CoreFileRequest) Job() credentialprotocol.SafeID {
	return value.job
}
func (value CoreFileRequest) Preparation() CorePreparationCapability { return value.preparation }
func (value CoreFileRequest) BindingID() credentialprotocol.SafeID   { return value.bindingID }
func (value CoreFileRequest) BindingIndex() uint16                   { return value.bindingIndex }
func (value CoreFileRequest) Target() RelativePathCapability         { return value.target }
func (value CoreFileRequest) FileLength() uint32                     { return value.fileLength }
func (value CoreFileRequest) FileSHA256() [32]byte                   { return value.fileSHA256 }

func (value CoreCommitRequest) RequestID() [16]byte      { return value.correlation.requestID }
func (value CoreCommitRequest) IdentityDigest() [32]byte { return value.correlation.identityDigest }
func (value CoreCommitRequest) Revision() uint64         { return value.correlation.revision }
func (value CoreCommitRequest) Job() credentialprotocol.SafeID {
	return value.job
}
func (value CoreCommitRequest) Preparation() CorePreparationCapability { return value.preparation }
func (value CoreCommitRequest) ManifestSHA256() [32]byte               { return value.manifestSHA256 }
func (value CoreCommitRequest) TransactionSHA256() [32]byte            { return value.transactionSHA256 }
func (value CoreCommitRequest) Prepared() CorePreparedCapability       { return value.prepared }

func (value CorePreparedResult) Generations() CoreGenerations { return value.generations }
func (value CorePreparedResult) ExpiresUnixNano() int64       { return value.expiresUnixNano }
func (value CorePreparedResult) BindingCount() uint16         { return value.bindingCount }
func (value CorePreparedResult) ManifestSHA256() [32]byte     { return value.manifestSHA256 }
func (value CorePreparedResult) TransactionSHA256() [32]byte  { return value.transactionSHA256 }
func (value CorePreparedResult) Prepared() CorePreparedCapability {
	return value.prepared
}

func (value CoreExecRequest) RequestID() [16]byte          { return value.correlation.requestID }
func (value CoreExecRequest) IdentityDigest() [32]byte     { return value.correlation.identityDigest }
func (value CoreExecRequest) Revision() uint64             { return value.correlation.revision }
func (value CoreExecRequest) Generations() CoreGenerations { return value.generations }
func (value CoreExecRequest) FixedLimitSetID() credentialprotocol.SafeID {
	return value.fixedLimitSetID
}
func (value CoreExecRequest) ExecBindingID() credentialprotocol.SafeID { return value.execBindingID }
func (value CoreExecRequest) PrivateLength() uint32                    { return value.privateLength }
func (value CoreExecRequest) PrivateSHA256() [32]byte                  { return value.privateSHA256 }
func (value CoreExecRequest) ExecBodyLength() uint32                   { return value.execBodyLength }
func (value CoreExecRequest) ExecBodySHA256() [32]byte                 { return value.execBodySHA256 }
func (value CoreExecRequest) Plan() ExecPlanCapability                 { return value.plan }
func (value CoreExecRequest) Prepared() CorePreparedCapability         { return value.prepared }
func (value CoreExecRequest) Execution() CoreExecutionCapability       { return value.execution }
func (value CoreExecRequest) Cleanup() CoreCleanupCapability           { return value.cleanup }

func (value CoreRenewRequest) RequestID() [16]byte          { return value.correlation.requestID }
func (value CoreRenewRequest) IdentityDigest() [32]byte     { return value.correlation.identityDigest }
func (value CoreRenewRequest) Revision() uint64             { return value.correlation.revision }
func (value CoreRenewRequest) Generations() CoreGenerations { return value.generations }
func (value CoreRenewRequest) ExpiresUnixNano() int64       { return value.expiresUnixNano }
func (value CoreRenewRequest) Prepared() CorePreparedCapability {
	return value.prepared
}

func (value CoreRevokeRequest) RequestID() [16]byte          { return value.correlation.requestID }
func (value CoreRevokeRequest) IdentityDigest() [32]byte     { return value.correlation.identityDigest }
func (value CoreRevokeRequest) Revision() uint64             { return value.correlation.revision }
func (value CoreRevokeRequest) Generations() CoreGenerations { return value.generations }
func (value CoreRevokeRequest) Reason() credentialprotocol.RevokeReason {
	return value.reason
}
func (value CoreRevokeRequest) Prepared() CorePreparedCapability { return value.prepared }
func (value CoreRevokeRequest) Cleanup() CoreCleanupCapability   { return value.cleanup }

func (value CoreInspectRequest) IdentityDigest() [32]byte     { return value.identityDigest }
func (value CoreInspectRequest) Revision() uint64             { return value.revision }
func (value CoreInspectRequest) Generations() CoreGenerations { return value.generations }
func (value CoreInspectRequest) Prepared() CorePreparedCapability {
	return value.prepared
}

func (value CoreOutputRequest) RequestID() [16]byte      { return value.correlation.requestID }
func (value CoreOutputRequest) IdentityDigest() [32]byte { return value.correlation.identityDigest }
func (value CoreOutputRequest) Revision() uint64         { return value.correlation.revision }
func (value CoreOutputRequest) Job() credentialprotocol.SafeID {
	return value.job
}
func (value CoreOutputRequest) Execution() CoreExecutionCapability { return value.execution }
func (value CoreOutputRequest) Kind() credentialprotocol.HelperExecStreamKind {
	return value.kind
}
func (value CoreOutputRequest) Offset() uint64   { return value.offset }
func (value CoreOutputRequest) Capacity() uint32 { return value.capacity }

func (value CoreOutputResult) Execution() CoreExecutionCapability { return value.execution }
func (value CoreOutputResult) Kind() credentialprotocol.HelperExecStreamKind {
	return value.kind
}
func (value CoreOutputResult) Offset() uint64    { return value.offset }
func (value CoreOutputResult) ByteCount() uint32 { return value.byteCount }
func (value CoreOutputResult) SHA256() [32]byte  { return value.sha256 }
func (value CoreOutputResult) EOF() bool         { return value.eof }
func (value CoreOutputResult) Truncated() bool   { return value.truncated }

func (value CoreExecResult) Execution() CoreExecutionCapability { return value.execution }
func (value CoreExecResult) ExitCategory() CoreExecExitCategory { return value.exitCategory }
func (value CoreExecResult) ExitCode() int32                    { return value.exitCode }
func (value CoreExecResult) StdinBytes() uint64                 { return value.stdinBytes }
func (value CoreExecResult) StdinSHA256() [32]byte              { return value.stdinSHA256 }
func (value CoreExecResult) StdinTranscriptSHA256() [32]byte    { return value.stdinTranscriptSHA256 }
func (value CoreExecResult) StdoutBytes() uint64                { return value.stdoutBytes }
func (value CoreExecResult) StdoutSHA256() [32]byte             { return value.stdoutSHA256 }
func (value CoreExecResult) StdoutTruncated() bool              { return value.stdoutTruncated }
func (value CoreExecResult) StderrBytes() uint64                { return value.stderrBytes }
func (value CoreExecResult) StderrSHA256() [32]byte             { return value.stderrSHA256 }
func (value CoreExecResult) StderrTruncated() bool              { return value.stderrTruncated }
func (value CoreExecResult) ExecTransactionSHA256() [32]byte    { return value.execTransactionSHA256 }

func (value CoreCleanupResult) Cleanup() CoreCleanupCapability { return value.cleanup }
func (value CoreCleanupResult) Category() CoreCleanupCategory  { return value.category }
func (value CoreCleanupResult) AuthorityAbsent() bool          { return value.authorityAbsent }
func (value CoreCleanupResult) ResourcesAbsent() bool          { return value.resourcesAbsent }

func (value CoreInspection) Prepared() CorePreparedCapability { return value.prepared }
func (value CoreInspection) State() CoreInspectionState       { return value.state }
func (value CoreInspection) Generations() CoreGenerations     { return value.generations }
func (value CoreInspection) ExpiresUnixNano() int64           { return value.expiresUnixNano }
func (value CoreInspection) ActiveExecutions() uint16         { return value.activeExecutions }
func (value CoreInspection) AuthorityPresent() bool           { return value.authorityPresent }
func (value CoreInspection) ResourcesPresent() bool           { return value.resourcesPresent }
